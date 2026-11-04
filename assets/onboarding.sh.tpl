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
#   curl -fsSLk '<url>' | bash                                   # 落材料 + 生成 cred.toml
#   curl -fsSLk '<url>' | bash -s -- --dir ./configs/wist-cred    # 指定落点目录
#   curl -fsSLk '<url>' | bash -s -- --restart 'gops run stop && gops run start'
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

# 材料目录：显式给了就用（--dir / WIST_CRED_INSTALL_DIR）；否则用页面为该认证系统
# 存的落点（烘进脚本，所以 `curl … | bash` 裸跑也能落对地方）；都没有才按身份取默认值。
INSTALL_DIR="${WIST_CRED_INSTALL_DIR:-__INSTALL_DIR__}"
# 接入落点：由操作者在页面上为该认证系统设置，签发时烘进本脚本。
# 给了 CONFIG_FILE 就**自动写入配置**（不用再回头重新开一张券），
# 给了 RESTART_CMD 就顺手重启。命令行 `--config` / `--restart` 仍可覆盖。
CONFIG_FILE="${WIST_CRED_CONFIG_FILE:-__CONFIG_FILE__}"
RESTART_CMD="${WIST_CRED_RESTART_CMD:-__RESTART_CMD__}"
CA_CERT=""

say()  { printf '  %s\n' "$*"; }
step() { printf '\n▶ %s\n' "$*"; }
die()  { finished=1; printf '\n✗ %s\n' "$*" >&2; exit 1; }

# 退出清理 + **状态兜底**。
# bash 3.2（macOS 自带）在 EXIT trap 存在时，会把 `set -u` 展开失败这类中断记成退出码 0
#（连 trap 里的 `$?` 都是 0）。表现：错误打了、文件写了一半、`bash join.sh` 却返回成功，
# 自动化会误判。所以用显式的“跑完了”标记：只有走到最后 / 显式 `die` / `--help` 才允许 0。
finished=0
cleanup() {
  local rc=$?
  rm -f "${tmp_body:-}"
  if [[ $rc -eq 0 && ${finished:-0} != 1 ]]; then
    rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
用法: bash -s -- [选项]

  --dir <dir>       材料与 cred.toml 的落点（默认：root → /etc/wist/<peer>；普通用户 → ./wist-cred/<peer>）
  --config <file>   只改 cred.toml 的文件名/位置（必须与材料同目录；换目录用 --dir）
  --restart <cmd>   落盘后执行的重启命令（例如 'gops run stop && gops run start'）
  --cacert <pem>    校验签发方 TLS 的 CA（默认 -k，见下）
  --endpoint <url>  覆盖内嵌的登记地址（入口换了地址时用）
  --host <fqdn>     证书 SAN（默认从 --advertise 推导，否则用本机 hostname -f）
  --advertise <url> 本机收摘要的地址（登记时报给 cred；不填 = 只做手工分发）
  --roles <a,b>     本机能验的角色（逗号分隔）；之后对方只能从这些里选
                    重跑本脚本会**覆盖**对方那边的角色表（空 = 不改）
  -h, --help        显示本帮助

不要求 root，只要求材料目录可写：容器栈部署就 cd 到栈根直接跑（材料落 ./wist-cred/<peer>），
或用 --dir 指到栈里的目录（例如 --dir ./identity/<peer>；具体看该栈的 README）。
**在部署栈里（栈根有 sys-prj.yml 与 identity/）必须落 identity/ 下**，否则脚本会拒跑 ——
但会把**完整可粘的命令**（带 --dir）打出来，券不会作废。
**总是会生成 cred.toml**（与程序无关：只写 [identity] 与 [verify]），程序启动时
加一行 `--credentials <cred.toml>` 指过来就行 —— 不需要改程序自己的配置。
重复运行是安全的：已有私钥不覆盖，cred.toml 整份重写。

关于 -k：入口的 TLS 证书通常是自签的（平台部署惯例，center 的安装脚本同样用
curl -fsSLk）。所以这里不靠 TLS 校验收据的真伪，而是两条硬校验：
  1. 返回的证书公钥必须与**本机私钥**匹配；
  2. 证书里必须有 DNS:<peer_host> 的 SAN。
中间人既换不了证书（私钥不在他手上），也换不了名字。

通过管道执行时**必须带 `-s --`**：
  curl -fsSLk '<url>' | bash -s -- --config /etc/x/app.toml
不加 `-s --` 的话，`--config` 会被 bash 自己吃掉（报 invalid option）——
因为管道时 bash 读的是 stdin，参数只能走 `-s` 后的 `--`。
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)      [[ $# -ge 2 ]] || die "--dir 需要一个值（材料目录，例如：bash -s -- --dir ./identity/x）"; INSTALL_DIR="$2"; shift 2 ;;
    --config)   [[ $# -ge 2 ]] || die "--config 需要一个值（例如：bash -s -- --config /etc/x/app.toml）"; CONFIG_FILE="$2"; shift 2 ;;
    --restart)  [[ $# -ge 2 ]] || die "--restart 需要一个值（例如：bash -s -- --restart 'systemctl restart x'）"; RESTART_CMD="$2"; shift 2 ;;
    --cacert)   [[ $# -ge 2 ]] || die "--cacert 需要一个值（PEM 路径）";    CA_CERT="$2"; shift 2 ;;
    --endpoint) [[ $# -ge 2 ]] || die "--endpoint 需要一个值（登记地址）";  ENROLL_URL="$2"; shift 2 ;;
    --host)     [[ $# -ge 2 ]] || die "--host 需要一个值（证书 SAN）";      PEER_HOST="$2"; shift 2 ;;
    --advertise) [[ $# -ge 2 ]] || die "--advertise 需要一个值（收数地址）"; PEER_ENDPOINT="$2"; shift 2 ;;
    --roles)    [[ $# -ge 2 ]] || die "--roles 需要一个值（逗号分隔，如 admin,read）";     PEER_ROLES="$2"; shift 2 ;;
    -h|--help)  usage; finished=1; exit 0 ;;
    *)          die "未知参数：${1}（-h 看用法）" ;;
  esac
done

# ── 前置检查 ────────────────────────────────────────────────────────────────
step "检查前置条件"
command -v openssl >/dev/null 2>&1 || die "需要 openssl"
command -v curl >/dev/null 2>&1 || die "需要 curl"

# 不按“是不是 root”拦人：能不能装材料只看**目录写不写得进去**。
# root 只是为了让默认的 /etc/wist/<peer> 可写；在栈目录下跑不必提权。
if [[ -z "$INSTALL_DIR" ]]; then
  if [[ "$(id -u)" == "0" ]]; then
    INSTALL_DIR="/etc/wist/$PEER_NAME"
  else
    INSTALL_DIR="./wist-cred/$PEER_NAME"
  fi
fi
# 部署栈里别把身份材料落在任意目录：栈根有 sys-prj.yml 时，身份要进 identity/
# （contract + 备份），其它目录通常**不会被 .gitignore 挡住** —— 一份私钥躺在
# `git status` 里就是一次事故。
#
# 这里**硬失败**而不是猜一个目录：猜错了材料会落在消费方不看的地方，
# 而券已经烧掉了（只能再开一张）。失败发生在登记之前，券还能重跑。
suggest_identity_dir() {
  local dirs=()
  local entry
  for entry in identity/*/; do
    [[ -d "$entry" ]] || continue
    dirs+=("$(basename "$entry")")
  done
  # 栈通常一个服务一个目录：只有一个就建议它（如 identity/center → ./identity/center/cred）。
  if [[ ${#dirs[@]} -eq 1 ]]; then
    printf './identity/%s/cred' "${dirs[0]}"
  else
    printf './identity/%s' "$PEER_NAME"
  fi
}

if [[ -f sys-prj.yml && -d identity ]]; then
  case "$INSTALL_DIR" in
    ./identity/*|identity/*) ;;
    *)
      if [[ "${WIST_CRED_ALLOW_UNSAFE_DIR:-}" == "1" ]]; then
        say "⚠ 部署栈里把身份材料放在了 ${INSTALL_DIR}（已用 WIST_CRED_ALLOW_UNSAFE_DIR=1 放行）"
        say "  私钥会被 git 看到；identity/ 才进 contract/备份"
      else
        SUGGESTED_DIR="$(suggest_identity_dir)"
        die "这是部署栈：身份材料要落在 identity/ 下（现在指向 ${INSTALL_DIR}）

  直接重跑（券还没用掉，整条粘过去就行）：
      curl -fsSLk '${ENROLL_URL}' | bash -s -- --dir ${SUGGESTED_DIR}

  该栈若规定了别的落点（例如 wist-center-stack 用 ./identity/center/cred），以它的 README 为准。
  确实要放别处：WIST_CRED_ALLOW_UNSAFE_DIR=1 bash -s -- --dir ${INSTALL_DIR}"
      fi
      ;;
  esac
fi
if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
  die "建不了材料目录：${INSTALL_DIR}（非 root 默认落 ./wist-cred/${PEER_NAME}；要写 /etc 请用 root 跑，或用 --dir 指到可写目录）"
fi
[[ -w "$INSTALL_DIR" ]] \
  || die "材料目录不可写：${INSTALL_DIR}（用 --dir 指到可写目录，或该目录换个属主）"
say "openssl ✓   curl ✓   材料目录 ${INSTALL_DIR} ✓"

# ── 确定身份：主机名（证书 SAN）与收数地址 ────────────────────────
step "确定本机身份"
# 受众就是系统名，不另外问。
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

# ── 统一接入文件 cred.toml（本脚本维护，程序只读）──────────────────────────
# 正文由签发方渲染后内嵌（内容取决于“有没有下发签名公钥 / 本机上报了什么角色”），
# 这里只负责落盘：不在运行时拼 TOML，错一处就整份不可用。
CRED_FILE="${CONFIG_FILE:-$INSTALL_DIR/cred.toml}"
[[ -d "$CRED_FILE" ]] && die "--config 指向的是一个目录：${CRED_FILE}（要的是文件路径）"
mkdir -p "$(dirname "$CRED_FILE")" 2>/dev/null \
  || die "建不了 cred.toml 的目录：$(dirname "$CRED_FILE")"
# `[identity]` 里是**相对文件名**，按 cred.toml 所在目录解 —— 所以它必须与材料同目录，
# 否则那几个名字会指到虚处。换目录请用 --dir。
if [[ "$(cd "$(dirname "$CRED_FILE")" && pwd)" != "$(cd "$INSTALL_DIR" && pwd)" ]]; then
  die "cred.toml 必须与材料同目录（现在在 ${CRED_FILE}）；要换目录请用 --dir <目录>"
fi

cat >"$CRED_FILE" <<'WIST_CRED_TOML'
__CRED_TOML__
WIST_CRED_TOML
chmod 0644 "$CRED_FILE"
say "cred.toml ✓（${CRED_FILE}）"

step "接入文件（与程序无关，程序只需指过来）"
cat "$CRED_FILE"

step "下一步"
say "1) 把这个目录挂进容器（只读）：$INSTALL_DIR"
say "2) 程序启动命令加一行：--credentials <容器里的 cred.toml 路径>"
say "3) 重启用：gops run stop && gops run start（systemd 部署用 systemctl restart <服务>）"

if [[ -n "$RESTART_CMD" ]]; then
  step "重启服务"
  sh -c "$RESTART_CMD"
  say "已执行：$RESTART_CMD"
fi

step "完成"
say "cred 来调你 → 出示 CA-I 签发的客户端证书（CN=wist-cred），你用 client-ca.pem 验它"
say "你的服务器证书由签发方按本机 CSR 签出（CN/SAN=${PEER_HOST}），私钥从未离开本机"
say "材料目录：${INSTALL_DIR}"
finished=1
