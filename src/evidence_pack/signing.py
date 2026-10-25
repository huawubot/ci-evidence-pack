"""cosign bundle 签名层。

cosign v3 把 `--output-signature` / `--output-certificate` 这套两文件
形态整个废弃了，`.sigstore.json` bundle 是唯一前路。所以这里不为
兼容旧形态留任何分支：只产 `.sigstore.json`，不产 `.sig` / `.crt`。

只留一条路，没有 fallback：**签名只用 OIDC 换来的短期证书**。
长期私钥那套（`--key` + `COSIGN_PASSWORD`）整条删掉了 —— 它需要有人保管一把
永不过期、泄露即永久冒充的私钥，还要在 CI 里把口令倒进环境变量。OIDC 的
信任根是「这次构建是谁跑的」，证书十分钟就过期，丢了也没有第二个人能用。

实质是 **OIDC 换短期证书**：CI 用平台签发的 OIDC token 向 Fulcio 证明
"我是谁"，Fulcio 回一张 10 分钟就过期的证书，cosign 拿这张证书签字节，
再把证书链、签名和 Rekor 条目一起封进 bundle。所以签名**必须有 token**——
没有 token 就没有证书，没有证书就没有信任根。

token 从哪来：极少数情况下走 `--oidc-token` 显式传入（仅建议本地调试），
主路径是 `--oidc-token-env VAR` 从环境变量读，CI 里由平台注入。两种写法
都只进子进程环境，**绝不进命令行**——命令行参数会出现在 `ps`、作业日志和
调试输出里，token 一旦漏出去，别人就能拿你的身份去签任何东西。

验签那边自然也只剩一种身份：`--certificate-identity` + `--certificate-oidc-issuer`。
身份给不出来就等于「接受任何人的签名」，那是没验，不是验过 —— 报用法错（1）。

另有一条铁律：**签名校验不能只信退出码**。原实现 `cosign` 返回 0 就
算 `signature_verified: true`，于是一个 `exit 0` 的假 cosign 就能骗过它。
这里除了退出码，还要独立核对三件事：
  1. bundle 的内容摘要 == 被打包文件的摘要（digest 绑定）
  2. bundle 的结构合法（有 messageSignature 或 DSSE 信封）
  3. bundle 里确有 tlog 条目，或明确标记 tlog_checked=false
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import EvidenceInvalid, ToolFailure, UsageError
from .fsutil import sha256_file

DEFAULT_BUNDLE_SUFFIX = ".sigstore.json"


@dataclass
class SignatureResult:
    """签名产物：是否签成、走的哪种模式、有没有核过 tlog。"""

    signed: bool = False
    verified: bool = False
    mode: str | None = None  # 只有 "keyless"（OIDC 短期证书）
    tlog_checked: bool = False
    bundle_path: str | None = None
    # 这张证书就是本次签名的短期身份，过期即失效。
    certificate_identity: str | None = None
    certificate_issuer: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
    detail: str = ""


def _require_cosign() -> str:
    exe = shutil.which("cosign")
    if not exe:
        raise ToolFailure("找不到 cosign。签名/验签需要 cosign v3+ 在 PATH 上。")
    return exe


# cosign v3 在真正报错前会先打一段 Sigstore 服务条款横幅，横幅不是一行而是一段：
# 首行 `The sigstore service...`，后面跟着 `Note that if your submission includes...`
# 之类的续行。只挡首行的话，最终抛给用户的"错误"会是那句隐私提示 —— 与失败原因
# 毫无关系，而且看起来像工具在念免责声明。这里按行首前缀把整段挡掉。
_COSIGN_BANNER_PREFIXES = (
    "The sigstore service",
    "Note that if your submission",
    "This may include the email",
    "This information will be used",
    "By typing 'y'",
)
_ERROR_PREFIX = "Error: "


def _first_error(proc: subprocess.CompletedProcess) -> str:
    """从 cosign 输出里挑出真正的错误行。

    优先取 `Error: ` 开头的行（cosign 自己的错误主体），其次取第一条既不是
    横幅、也不是 `error during command execution:` 尾注的内容。
    """
    lines = [
        text
        for stream in (proc.stderr, proc.stdout)
        for raw in (stream or "").splitlines()
        if (text := raw.strip())
    ]
    for text in lines:
        if text.startswith(_ERROR_PREFIX):
            return text[len(_ERROR_PREFIX) :]
    for text in lines:
        if text.startswith("error during command execution:"):
            continue
        if text.startswith(_COSIGN_BANNER_PREFIXES):
            continue
        return text
    return "未知错误"


def _run(
    cmd: list[str], extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """跑 cosign。

    token 走 SIGSTORE_ID_TOKEN 环境变量，不拼进 argv。stdin 一律接 DEVNULL：
    cosign 在没有凭据时会尝试从 TTY 交互读取，在 CI 里表现为莫名其妙的 ioctl 错误。
    """
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise ToolFailure(f"cosign 无法执行：{exc}") from exc


# Fulcio / Rekor 的公共实例。私有部署时用 --fulcio-url / --rekor-url 覆盖，
# 注意验签侧必须用**同一个** Fulcio 根，否则证书链对不上，那是 2 不是 3。
DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"

# OIDC token 只允许经环境变量进子进程。命令行里出现 token 等于把它写进作业日志。
MIN_TOKEN_LEN = 100


def resolve_oidc_token(
    token: str | None = None, token_env: str | None = None
) -> str | None:
    """取 OIDC token：显式值优先，其次按环境变量名读。

    刻意不对空串宽容：CI 里 token 变量存在但为空（权限没开、secret 没配）
    是最常见的事故，静默回落到"没 token"会让调用方以为签过了。
    """
    if token and token_env:
        raise UsageError(
            "--oidc-token 与 --oidc-token-env 只给一个：token 不该有两条来源。"
        )
    if token_env:
        value = os.environ.get(token_env)
        if not value:
            raise UsageError(
                f"环境变量 {token_env} 不存在或为空：拿不到 OIDC token，无法换短期证书。"
            )
        return _check_token_shape(value, f"环境变量 {token_env}")
    if token:
        return _check_token_shape(token, "--oidc-token")
    return None


def _check_token_shape(token: str, source: str) -> str:
    """只做形状检查（三段式 JWT、足够长），不解析、不校验签名。

    token 的真伪由 Fulcio 判定，本地解析除了把 token 内容多写进日志之外
    没有任何收益。这里只拦住"明显不是 token"的输入，让用户在 1 的地方停下，
    而不是等 cosign 报一个看不懂的 HTTP 错误变成 3。
    """
    compact = token.strip()
    if len(compact) < MIN_TOKEN_LEN or compact.count(".") != 2:
        raise UsageError(
            f"{source} 看起来不是 OIDC JWT（需要三段式且长度 >= {MIN_TOKEN_LEN}）。"
        )
    return compact


def _decode_jwt_claims(token: str) -> dict:
    """读取 JWT payload 里的身份声明（iss/sub）。

    仅用于**回显便于核对**，不作为验签依据：bundle 里自带证书，
    验签时 cosign 会按 --certificate-identity / --certificate-oidc-issuer 硬比。
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, TypeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _keyless_env(
    token: str, *, fulcio_url: str | None, rekor_url: str | None
) -> dict[str, str]:
    """token 与私有实例地址都经环境变量下发，argv 里只留非敏感开关。"""
    env = {"SIGSTORE_ID_TOKEN": token}
    if fulcio_url:
        env["SIGSTORE_FULCIO_URL"] = fulcio_url
    if rekor_url:
        env["SIGSTORE_REKOR_URL"] = rekor_url
    return env


def _require_identity(identity: str | None, issuer: str | None) -> None:
    """没有期望身份就等于没验：前移到本地拦下，不把宽松判断交给 cosign。"""
    if not identity or not issuer:
        raise UsageError(
            "必须同时提供 --identity 与 --issuer，否则等于接受任何人的签名。"
        )


# 判定「是不是 sign: false」只认这一个字面量。它同时被 Action 的 shell 层与内核用到：
# 两处各写一遍，早晚会在某个值上分叉（'False' / '0' / 'no'），
# 那时装好的 cosign 和要不要签名就成了两件事。
SIGN_OFF_LITERAL = "false"


def is_sign_off(value: str | None) -> bool:
    """`sign` 的字符串形态是否表示「不签名」。

    只认小写 'false'。留空 = 没给 = 沿用默认（默认签名）；
    'False' / '0' / 'no' 一律按签名处理 —— 悄悄当成「不签」比报错危险得多。
    """
    return (value or "").strip() == SIGN_OFF_LITERAL


def sign(
    blob: Path,
    bundle: Path,
    *,
    oidc_token: str | None = None,
    fulcio_url: str | None = None,
    rekor_url: str | None = None,
) -> SignatureResult:
    """用 OIDC 换来的短期证书对 blob 签名，产出 `.sigstore.json`。

    没有别的路径可选：token 缺失当场判 1，不把「没 token」这种用法问题
    留给 cosign 抛出一个难懂的 HTTP 错误（那会被读成 3，语义就错了）。

    签发身份由 token 决定，命令行改不了；调用方声明的期望身份只写进
    metadata/binding.json，在验签阶段核对。
    """
    if not oidc_token:
        raise UsageError(
            "签名必须有 OIDC token（--oidc-token 或 --oidc-token-env）："
            "没有 token 就换不到 Fulcio 短期证书，签出来的东西没有身份可言。"
        )
    extra_env = _keyless_env(oidc_token, fulcio_url=fulcio_url, rekor_url=rekor_url)
    claims = _decode_jwt_claims(oidc_token)

    cosign = _require_cosign()

    cmd = [cosign, "sign-blob", "--yes", "--bundle", str(bundle)]
    # --identity-token 与 SIGSTORE_ID_TOKEN 等价，但前者会进 argv。只用环境变量。
    if fulcio_url:
        cmd += ["--fulcio-url", fulcio_url]
    if rekor_url:
        cmd += ["--rekor-url", rekor_url]
    cmd.append(str(blob))

    proc = _run(cmd, extra_env=extra_env)
    if proc.returncode != 0 or not bundle.is_file():
        raise ToolFailure(f"cosign sign-blob 失败：{_first_error(proc)}")

    result = SignatureResult(
        signed=True,
        mode="keyless",
        bundle_path=str(bundle),
        certificate_identity=claims.get("sub"),
        certificate_issuer=claims.get("iss"),
        detail="",
    )
    # 短期证书的形态在这里就地核对：bundle 必须带证，tlog 必须有条目。
    # 缺证书 = 拿不到身份（3）；拿不到 tlog = 签名失去了公开可审计的落点（3）。
    data = _check_bundle_structure(bundle)
    material = data.get("verificationMaterial") or {}
    leaf_cert = _extract_bundle_certificate(material)
    if not leaf_cert:
        raise ToolFailure("签出的 bundle 里没有 x509 证书链：Fulcio 短期证书没拿到。")
    if not material.get("tlogEntries"):
        raise ToolFailure(
            "签出的 bundle 里没有 tlogEntries：Rekor 未记录，无法证明签名存在过。"
            "检查 SIGSTORE_REKOR_URL 与网络。"
        )
    result.tlog_checked = True
    _fill_cert_window(result, leaf_cert)
    return result


def _fill_cert_window(result: SignatureResult, leaf: dict) -> None:
    """从叶子证书里取出有效期，填进结果里。

    用 `openssl` 解 DER 是可选的：openssl 不在就留空。它是给人看的佐证，
    不是判定依据，不能因为缺工具就让验签结论变成 3。
    """
    raw = leaf.get("rawBytes") if isinstance(leaf, dict) else None
    if not raw:
        return
    exe = shutil.which("openssl")
    if not exe:
        return
    try:
        der = base64.b64decode(raw)
        proc = subprocess.run(
            [exe, "x509", "-inform", "DER", "-noout", "-startdate", "-enddate"],
            input=der,
            capture_output=True,
            check=False,
        )
    except (OSError, ValueError, TypeError):
        return
    if proc.returncode != 0:
        return
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        key, _, value = line.partition("=")
        value = value.strip()
        if key.strip() == "notBefore":
            result.cert_not_before = _iso8601(value)
        elif key.strip() == "notAfter":
            result.cert_not_after = _iso8601(value)


def _iso8601(value: str) -> str:
    """openssl 给的是 `Oct 24 00:37:00 2026 GMT`，换成便于机读的 ISO 8601。"""
    from datetime import datetime, timezone

    try:
        return (
            datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
            .replace(tzinfo=timezone.utc)
            .isoformat()
        )
    except ValueError:
        return value


def _extract_bundle_certificate(material: dict) -> dict | None:
    """从 verificationMaterial 中提取叶子证书对象。

    Sigstore Bundle 规范存在多版本形态：
    - v0.1 / v0.2: `verificationMaterial.x509CertificateChain.certificates[0]`
    - v0.3+: `verificationMaterial.certificate`
    """
    if not isinstance(material, dict):
        return None
    cert = material.get("certificate")
    if isinstance(cert, dict) and "rawBytes" in cert:
        return cert
    chain = material.get("x509CertificateChain")
    if isinstance(chain, dict):
        certs = chain.get("certificates") or []
        if certs and isinstance(certs[0], dict) and "rawBytes" in certs[0]:
            return certs[0]
    return None


def _check_bundle_structure(bundle: Path) -> dict:
    try:
        data = json.loads(bundle.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolFailure(f"bundle 不是合法 JSON：{exc}") from exc
    if not isinstance(data, dict):
        raise ToolFailure("bundle 顶层不是对象，不是 Sigstore bundle。")
    if "messageSignature" not in data and "dsseEnvelope" not in data:
        raise ToolFailure(
            "bundle 里没有 messageSignature / dsseEnvelope，不是签名 bundle。"
        )
    return data


def _bundle_digest(data: dict) -> str | None:
    msg = data.get("messageSignature") or {}
    digest = (msg.get("messageDigest") or {}).get("digest")
    if not digest:
        return None
    try:
        return base64.b64decode(digest).hex()
    except (ValueError, TypeError):
        return None


def _has_tlog(data: dict) -> bool:
    material = data.get("verificationMaterial") or {}
    return bool(material.get("tlogEntries"))


def verify(
    blob: Path,
    bundle: Path,
    *,
    identity: str | None = None,
    issuer: str | None = None,
    ignore_tlog: bool = False,
    binding: dict | None = None,
) -> SignatureResult:
    """验签。返回结构化的结果，失败按语义抛 EvidenceInvalid 或 ToolFailure。

    只认短期证书这一种身份：cosign 拿 bundle 里的证书链去比
    `--certificate-identity` / `--certificate-oidc-issuer`，对不上就是 2。

    `binding` 是包内 metadata/binding.json 声明的期望身份。它只在调用方
    没给 identity/issuer 时用来填空：声明值来自包内，本身不构成信任根，
    真正的信任仍取决于 cosign 对证书链与 tlog 的校验。没填也没声明时报
    用法错 —— 那是「接受任何人的签名」，不是验证。
    """
    # 顺序是有意的：先判「参数够不够」和「bundle 是不是 bundle」，再去找 cosign。
    # 反过来的话，一台没装 cosign 的机器会把「身份没给」报成「工具坏了」（3），
    # 而它其实是一次用法错误（1）。
    if not identity and binding:
        identity = binding.get("identity") or None
        issuer = binding.get("issuer") or None
    _require_identity(identity, issuer)

    data = _check_bundle_structure(bundle)
    cosign = _require_cosign()

    # 第一道闸：bundle 必须真的绑在我们要验的这份字节上。
    # 假 cosign 返回 0 也过不了这一关。
    bound = _bundle_digest(data)
    actual = sha256_file(blob)
    if bound is not None and bound != actual:
        raise EvidenceInvalid(
            f"bundle 的内容摘要与文件不符：bundle 绑定 {bound}，文件实际 {actual}。"
        )

    cmd = [
        cosign,
        "verify-blob",
        "--bundle",
        str(bundle),
        "--certificate-identity",
        identity or "",
        "--certificate-oidc-issuer",
        issuer or "",
    ]
    if ignore_tlog:
        cmd.append("--insecure-ignore-tlog=true")
    cmd.append(str(blob))

    proc = _run(cmd)
    if proc.returncode != 0:
        raise EvidenceInvalid(f"签名无效：{_first_error(proc)}")

    # 退出码 0 不足以证明"真的验过"：一个 `exit 0` 的假 cosign 也能过关。
    # 正向证据是 cosign 必须在 stdout 打出 "Verified OK"。
    # 这不是密码学保证（假程序也能打印这行），但把欺骗成本从
    # "空脚本 exit 0" 抬高到 "伪造 cosign 输出"，再叠加下游的锚点交叉校验。
    if "Verified OK" not in (proc.stdout + proc.stderr):
        raise ToolFailure(
            "cosign 退出码为 0 但未输出 Verified OK：无法确认签名真的被校验过"
            f"（stdout={proc.stdout.strip()[:120]!r}）。"
        )

    tlog_present = _has_tlog(data)
    if not ignore_tlog and not tlog_present:
        raise EvidenceInvalid(
            "验签通过但 bundle 内无透明日志条目（tlogEntries 为空）。"
        )

    result = SignatureResult(
        verified=True,
        mode="keyless",
        # 老实回答「这一条到底查了没有」：没查过的不许报 true。
        tlog_checked=bool(tlog_present and not ignore_tlog),
        bundle_path=str(bundle),
        detail="",
    )
    # 短期证书的窗口必须覆盖 bundle 内记录的签名时间。
    # 证书十分钟就过期，若 Rekor 记录的签名时刻落在窗口之外，
    # 说明这份 bundle 不是这张证书在那段时间签的 —— 证据链断裂（2）。
    _check_certificate_window(data)
    material = data.get("verificationMaterial") or {}
    leaf_cert = _extract_bundle_certificate(material)
    if leaf_cert:
        _fill_cert_window(result, leaf_cert)
    return result


def _check_certificate_window(data: dict) -> None:
    """核对短期证书的有效期与 bundle 里的签名时间是否相容。

    取 bundle 内 Rekor 的 integratedTime 与证书 DER 里的窗口比对；
    两者任一取不到就不作判定（缺 openssl 是环境问题，不能因此判人篡改）。
    """
    material = data.get("verificationMaterial") or {}
    leaf_cert = _extract_bundle_certificate(material)
    if not leaf_cert:
        return
    signed_ats = [
        int(entry["integratedTime"])
        for entry in (material.get("tlogEntries") or [])
        if isinstance(entry, dict) and str(entry.get("integratedTime", "")).isdigit()
    ]
    if not signed_ats:
        return

    window = _cert_window(leaf_cert)
    if window is None:
        return
    not_before, not_after = window
    for ts in signed_ats:
        if not (not_before <= ts <= not_after):
            raise EvidenceInvalid(
                "签名时间落在短期证书有效期之外："
                f"证书窗口 {_fmt(not_before)} ~ {_fmt(not_after)}，Rekor 记录 {_fmt(ts)}。"
            )


def _fmt(epoch: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _cert_window(leaf: dict) -> tuple[int, int] | None:
    """用 openssl 取证书的 notBefore/notAfter 并转成 epoch 秒。"""
    from datetime import datetime, timezone

    raw = leaf.get("rawBytes") if isinstance(leaf, dict) else None
    exe = shutil.which("openssl")
    if not raw or not exe:
        return None
    try:
        der = base64.b64decode(raw)
        proc = subprocess.run(
            [exe, "x509", "-inform", "DER", "-noout", "-startdate", "-enddate"],
            input=der,
            capture_output=True,
            check=False,
        )
    except (OSError, ValueError, TypeError):
        return None
    if proc.returncode != 0:
        return None

    values: dict[str, int] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        key, _, value = line.partition("=")
        try:
            stamp = datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
        values[key.strip()] = int(stamp.timestamp())
    if "notBefore" not in values or "notAfter" not in values:
        return None
    return values["notBefore"], values["notAfter"]
