#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# wist-cred 接入包 · 验证方 __PEER_NAME__
#
# 这个脚本只做一件事：让本机拿到自己的服务器证书，之后 cred 能用 mTLS 调你。
#
# 分工（与 center ↔ gwlinkd 入场同一套口径）：
#   · 密钥对**在本机生成**，私钥永远不出这台机器；
#   · 只把 CSR（只含公钥）交给可信方签发；
#   · 证书主体（CN / SAN）由签发方填，不取 CSR 里声明的。
#
# ⚠ 这条命令里带着一张**一次性券**：跑过一次就作废，别转发、别贴进 ticket。
#
# 用法：
#   curl -fsSLk '<url>' | bash                                   # 只落材料 + 打印片段
#   curl -fsSLk '<url>' | bash -s -- --config /etc/x/ctrl.toml    # 顺带写进配置
#   curl -fsSLk '<url>' | bash -s -- --config /etc/x/ctrl.toml \
#                                   --restart 'systemctl restart x-ctrl'
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PEER_NAME='__PEER_NAME__'
# 名字是操作者给的。下面两个是**本机自己知道的东西**，默认从内嵌值起头、
# 可以被 --host / --advertise 覆盖，没给就自己算（见下面“确定身份”）。
PEER_HOST='__PEER_HOST__'
PEER_ENDPOINT='__PEER_ENDPOINT__'
# 本机能验的角色（逗号分隔）：登记时上报，之后发凭证只能从这里选。
PEER_ROLES='__PEER_ROLES__'
ENROLL_URL='__ENROLL_URL__'

INSTALL_DIR="${WIST_CRED_INSTALL_DIR:-/etc/wist/$PEER_NAME}"
CONFIG_FILE=""
RESTART_CMD=""
CA_CERT=""

say()  { printf '  %s\n' "$*"; }
step() { printf '\n▶ %s\n' "$*"; }
die()  { printf '\n✗ %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
用法: bash -s -- [选项]

  --dir <dir>       材料安装目录（默认 /etc/wist/<peer>）
  --config <file>   把配置片段追加进这个 TOML（默认只打印，不改任何文件）
  --restart <cmd>   落盘后执行的重启命令（例如 'systemctl restart wist-ingest-ctrl'）
  --cacert <pem>    校验签发方 TLS 的 CA（默认 -k，见下）
  --endpoint <url>  覆盖内嵌的登记地址（入口换了地址时用）
  --host <fqdn>     证书 SAN（默认从 --advertise 推导，否则用本机 hostname -f）
  --advertise <url> 本机收摘要的地址（登记时报给 cred；不填 = 只做手工分发）
  --roles <a,b>     本机能验的角色（逗号分隔）；之后对方只能从这些里选
                    重跑本脚本会**覆盖**对方那边的角色表（空 = 不改）
  -h, --help        显示本帮助

需要 root（要写 /etc）。不带 --config 时本脚本只落材料并打印片段。
重复运行是安全的：已有私钥不覆盖，同一段配置会被原位替换。

关于 -k：入口的 TLS 证书通常是自签的（平台部署惯例，center 的安装脚本同样用
curl -fsSLk）。所以这里不靠 TLS 校验收据的真伪，而是两条硬校验：
  1. 返回的证书公钥必须与**本机私钥**匹配；
  2. 证书里必须有 DNS:<peer_host> 的 SAN。
中间人既换不了证书（私钥不在他手上），也换不了名字。
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)      [[ $# -ge 2 ]] || die "--dir 需要一个值";      INSTALL_DIR="$2"; shift 2 ;;
    --config)   [[ $# -ge 2 ]] || die "--config 需要一个值";    CONFIG_FILE="$2"; shift 2 ;;
    --restart)  [[ $# -ge 2 ]] || die "--restart 需要一个值";   RESTART_CMD="$2"; shift 2 ;;
    --cacert)   [[ $# -ge 2 ]] || die "--cacert 需要一个值";    CA_CERT="$2"; shift 2 ;;
    --endpoint) [[ $# -ge 2 ]] || die "--endpoint 需要一个值";  ENROLL_URL="$2"; shift 2 ;;
    --host)     [[ $# -ge 2 ]] || die "--host 需要一个值";      PEER_HOST="$2"; shift 2 ;;
    --advertise) [[ $# -ge 2 ]] || die "--advertise 需要一个值"; PEER_ENDPOINT="$2"; shift 2 ;;
    --roles)    [[ $# -ge 2 ]] || die "--roles 需要一个值";     PEER_ROLES="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *)          die "未知参数：$1（-h 看用法）" ;;
  esac
done

# ── 前置检查 ────────────────────────────────────────────────────────────────
step "检查前置条件"
[[ "$(id -u)" == "0" ]] || die "请用 root 运行（要写 ${INSTALL_DIR}）"
command -v openssl >/dev/null 2>&1 || die "需要 openssl"
command -v curl >/dev/null 2>&1 || die "需要 curl"
say "root ✓   openssl ✓   curl ✓"

# ── 确定身份：主机名（证书 SAN）与收数地址 ────────────────────────
step "确定本机身份"
# 受众就是系统名，不另外问。
AUDIENCE="$PEER_NAME"
if [[ -z "$PEER_HOST" && -n "$PEER_ENDPOINT" ]]; then
  PEER_HOST="$(printf '%s' "$PEER_ENDPOINT" | sed -e 's#^https://##' -e 's#[/:].*##')"
fi
if [[ -z "$PEER_HOST" ]]; then
  PEER_HOST="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
fi
[[ -n "$PEER_HOST" ]] || die "无法确定主机名，请用 --host 指定"
say "证书 SAN：${PEER_HOST}"
if [[ -n "$PEER_ENDPOINT" ]]; then
  say "收数地址：${PEER_ENDPOINT}"
else
  say "收数地址：未上报（只做手工分发；可用 --advertise 补）"
fi
if [[ -n "$PEER_ROLES" ]]; then
  say "可验角色：${PEER_ROLES}"
else
  say "可验角色：未上报（对方将无法给你发凭证；用 --roles 补登）"
fi

# ── 客户端信任锚（公开材料：cred 出示的客户端证书由它签）──────────────────
step "安装客户端信任锚到 $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
prev_umask="$(umask)"
umask 077
cat >"$INSTALL_DIR/client-ca.pem" <<'WIST_CRED_CLIENT_CA_PEM'
__CLIENT_CA_PEM__
WIST_CRED_CLIENT_CA_PEM
umask "$prev_umask"
chmod 0644 "$INSTALL_DIR/client-ca.pem"
say "client-ca.pem ✓"

# ── 签发方的授权签名公钥（公开材料）──────────────────────────────────────────
# 验证方用它验每条授权记录的签名。没有它就只能“盲信”推过来的内容。
ISSUER_PUB_HEX='__ISSUER_SIGNING_PUB__'
if [[ -n "$ISSUER_PUB_HEX" ]]; then
  printf '%s\n' "$ISSUER_PUB_HEX" >"$INSTALL_DIR/issuer-signing.pub"
  chmod 0644 "$INSTALL_DIR/issuer-signing.pub"
  say "issuer-signing.pub ✓"
else
  say "未配置签发方签名公钥（下游开了 require_signature 时会拒收）"
fi

# ── 密钥对：本机生成，**已存在就不动**（换钥会打断已经生效的 mTLS）────────
step "准备本机密钥对"
KEY="$INSTALL_DIR/server.key"
CSR="$INSTALL_DIR/server.csr"

if [[ -f "$KEY" ]]; then
  say "已有私钥，复用：$KEY"
else
  prev_umask="$(umask)"
  umask 077
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY" 2>/dev/null \
    || die "生成私钥失败"
  umask "$prev_umask"
  say "已生成私钥：${KEY}（0600，永不上送）"
fi
chmod 0600 "$KEY"

# ── CSR：只含公钥 ──────────────────────────────────────────────────────────
step "生成 CSR"
openssl req -new -key "$KEY" -subj "/CN=$PEER_HOST" -out "$CSR" 2>/dev/null \
  || die "生成 CSR 失败"
chmod 0600 "$CSR"
say "已生成 CSR（只含公钥；声明的 CN 会被签发方忽略）"

# ── 登记：交 CSR，换自己的服务器证书 ───────────────────────────────────────
step "向签发方登记"
if [[ -n "$CA_CERT" ]]; then
  [[ -f "$CA_CERT" ]] || die "找不到 --cacert 指定的文件：$CA_CERT"
  TLS_OPTS=(--cacert "$CA_CERT")
  say "TLS：用 --cacert $CA_CERT 校验"
else
  TLS_OPTS=(-k)
  say "TLS：-k（自签入口；真伪由下面的公钥/SAN 校验兜）"
fi

tmp_body="$(mktemp)"
trap 'rm -f "$tmp_body"' EXIT

# CSR 里会有换行与引号：按 JSON 字符串转义后再拼进请求体。
csr_escaped="$(awk '{ gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); printf "%s\\n", $0 }' "$CSR")"

# 角色 → JSON 字符串数组（BSD awk 不接受在 ? 前换行，保持单行表达式）。
roles_json='[]'
if [[ -n "$PEER_ROLES" ]]; then
  roles_json="$(printf '%s' "$PEER_ROLES" | tr ',' '\n' | awk '{ gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "") printf "%s\"%s\"", (n++ ? "," : ""), $0 } END{ }')"
  roles_json="[${roles_json}]"
fi

if [[ -n "$PEER_ENDPOINT" ]]; then
  payload="{\"certificate_signing_request\":\"${csr_escaped}\",\"host\":\"${PEER_HOST}\",\"endpoint\":\"${PEER_ENDPOINT}\",\"roles\":${roles_json}}"
else
  payload="{\"certificate_signing_request\":\"${csr_escaped}\",\"host\":\"${PEER_HOST}\",\"roles\":${roles_json}}"
fi

http_code="$(curl -sS "${TLS_OPTS[@]}" -X POST "$ENROLL_URL" \
  -H 'accept: application/x-pem-file' \
  -H 'content-type: application/json' \
  --data-binary "$payload" \
  -o "$tmp_body" -w '%{http_code}')" || die "连不上签发方：$ENROLL_URL"

if [[ "$http_code" != "200" ]]; then
  printf '\n  签发方返回 HTTP %s：\n\n' "$http_code" >&2
  sed 's/^/    /' "$tmp_body" >&2 || true
  echo >&2
  die "登记失败。若提示券已用过，请让管理员重新生成一条接入命令。"
fi

[[ "$(head -c 30 "$tmp_body")" == *"BEGIN CERTIFICATE"* ]] \
  || die "签发方返回的不是证书（见 ${tmp_body}）"
chmod 0644 "$tmp_body"
say "已取得服务器证书"

# ── 硬校验：这张证书确实属于本机，且名字对得上 ─────────────────────────────
step "校验证书"
cert_pub="$(openssl x509 -in "$tmp_body" -noout -pubkey | openssl sha256)"
key_pub="$(openssl pkey -in "$KEY" -pubout | openssl sha256)"
[[ "$cert_pub" == "$key_pub" ]] \
  || die "证书公钥与本机私钥不匹配 —— 有人在中间换证书，已中止"
say "公钥与私钥匹配 ✓"

san="$(openssl x509 -in "$tmp_body" -noout -ext subjectAltName 2>/dev/null | sed -n '2,$p' | tr -d ' \n' || true)"
case "$san" in
  *"DNS:$PEER_HOST"*) say "SAN 覆盖 $PEER_HOST ✓" ;;
  *) die "证书 SAN 不含 ${PEER_HOST}（实际：${san:-<空>}）—— 已中止" ;;
esac

mv -f "$tmp_body" "$INSTALL_DIR/server.crt"
chmod 0644 "$INSTALL_DIR/server.crt"
say "server.crt ✓"

# ── 配置片段 ────────────────────────────────────────────────────────────────
snippet="$(mktemp)"
trap 'rm -f "$tmp_body" "$snippet"' EXIT

cat >"$snippet" <<EOF
# >>> wist-cred mTLS · $PEER_NAME · 本段由接入脚本维护，重跑会原位替换 >>>
[ctrl.credentials]
enabled = true
audience = "$AUDIENCE"
allowed_issuers = ["wist-cred"]
# 授权哪些能力由你自己定（cred 只证明「来的是 cred」，不替你决定给什么权）：
# known_roles = ["investigation:run"]
# 要求每条授权记录带签发方签名（公钥就是上面落下的 issuer-signing.pub）：
# require_signature = true
# issuer_public_key = "$INSTALL_DIR/issuer-signing.pub"

[ctrl.tls]
cert_file      = "$INSTALL_DIR/server.crt"
key_file       = "$INSTALL_DIR/server.key"
client_ca_file = "$INSTALL_DIR/client-ca.pem"
# <<< wist-cred mTLS · $PEER_NAME <<<
EOF

if [[ -z "$CONFIG_FILE" ]]; then
  step "配置片段（追加到你的服务配置里，改完重启）"
  echo
  cat "$snippet"
  echo
  say "自动写入：重跑本脚本并加 --config <配置文件> —— 但一次性券已经用掉了，"
  say "所以请让管理员重新生成一条命令，再带 --config 跑。"
  exit 0
fi

# ── 写进配置文件（可重复：先删旧段再追加）───────────────────────────────────
step "写入 $CONFIG_FILE"
[[ -f "$CONFIG_FILE" ]] || die "配置文件不存在：$CONFIG_FILE"
backup="$CONFIG_FILE.wist-cred.bak"
[[ -f "$backup" ]] || cp "$CONFIG_FILE" "$backup"
say "首次写入，原文件已备份为 $backup"

stripped="$(mktemp)"
trap 'rm -f "$tmp_body" "$snippet" "$stripped"' EXIT
awk '
  index($0, "# >>> wist-cred mTLS") == 1 { skip = 1; next }
  index($0, "# <<< wist-cred mTLS") == 1 { skip = 0; next }
  !skip { print }
' "$CONFIG_FILE" >"$stripped"
{ cat "$stripped"; echo; cat "$snippet"; } >"$CONFIG_FILE"
say "已写入（旧的 wist-cred 段已替换）"

# ── 重启 ────────────────────────────────────────────────────────────────────
if [[ -n "$RESTART_CMD" ]]; then
  step "重启服务"
  sh -c "$RESTART_CMD"
  say "已执行：$RESTART_CMD"
else
  say "记得重启你的服务让配置生效（或用 --restart 交给本脚本）"
fi

step "完成"
say "cred 来调你 → 出示 CA-I 签发的客户端证书（CN=wist-cred），你用 client_ca_file 验它"
say "你的服务器证书由签发方按本机 CSR 签出（CN/SAN=${PEER_HOST}），私钥从未离开本机"
say "材料目录：${INSTALL_DIR}"
