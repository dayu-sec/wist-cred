# Changelog

## [0.4.2-alpha] - 2026-11-03

### 修复：接入脚本里的登记地址丢端口

- 现象：在 `https://cred…:4444` 下跑接入命令，取脚本、生成密钥都成功，最后一步登记拿到 **404**。
- 原因：脚本里的 `ENROLL_URL` 是 cred 按请求头拼的绝对地址，而入口 nginx 用的是
  `proxy_set_header Host $host` —— **`$host` 不带端口**，于是拼成 `https://cred…/enroll/<券>/certificate`，
  机器把 CSR 打到了 443 上（那里不是 cred，所以是空体 404，而不是券过期的 410）。
- 新增 `[server].public_base_url`（如 `https://cred.example.com:4444`）：配了就原样用它，
  不配才回落到请求头。与网关的 `[server] public_base_url` 同一个口径。
- 加载期校验：必须是绝对 `http(s)` URL；末尾 `/` 会去掉（否则拼出 `//enroll/…`）。
- 部署侧配合：`wist-cred-stack` 把 nginx 的 `/enroll/` 改成转发 `$http_host`（兜底），
  并在 localize 时用 `WEB_DOMAIN` + `WEB_HOST_PORT` 渲染 `public_base_url`。

## [0.4.1-alpha] - 2026-11-03

### 修复：接入脚本不再要求 root

- 以前不管 `--dir` 指到哪，脚本开头都 `[[ "$(id -u)" == "0" ]] || die`，在容器栈目录下
  跑必须先 sudo（`wist-cred-stack/dev/svc.sh` 甚至为此伪造了一个 `id`）。
- 改为**只看目录可不可写**（`mkdir -p` + `[[ -w ]]`）。默认目录按身份取：
  root → `/etc/wist/<peer>`（systemd 部署的老行为不变），普通用户 → `./wist-cred/<peer>`。
- `--dir` / `WIST_CRED_INSTALL_DIR` 仍然优先；错误提示直接给出三种出路。

### 变更：接入面改成语义化的路径（破坏性，但券 ≤ 1h）

| 旧 | 新 |
|---|---|
| `GET  /api/v1/onboarding/peers` | `GET  /api/v1/peers` |
| `POST /api/v1/onboarding/peers` | `POST /api/v1/peers` |
| `POST /api/v1/onboarding/peers/{name}/endpoint` | `POST /api/v1/peers/{name}/endpoint` |
| `POST /api/v1/onboarding/peers/{name}/script` | `POST /api/v1/peers/{name}/enrollment-tickets` |
| `GET  /onboarding/script/{token}` | `GET  /enroll/{token}/join.sh` |
| `POST /onboarding/enroll/{token}` | `POST /enroll/{token}/certificate` |

- 划法：`/api/v1/peers*` 是**人在管理面**对资源做的事；`/enroll/{token}/*` 是**机器拿着券**
  兑换的具体产物。两套鉴权不同，路径上也分得开；`script` 是实现名、`onboarding` 是过程名，
  两者都不该当资源名。
- 机器面**不留别名**：券寿命 ≤ 1h 且一次即废，升级窗口内的在途链接最多失效一小时。
- 管理面 `/api/v1/onboarding/peers*` 保留**一版别名**：cred 与 cred-web 是两个镜像，
  灰度期页面可能还在调旧路径；下个版本删。
- 入口反代的白名单路径同步从 `/onboarding/` 改为 `/enroll/`（`wist-cred-stack` 侧）。

### 升级注意

- `wist-cred-stack` ≥ 0.4.1（nginx 的白名单路径跟版）；`wist-cred-web` ≥ 0.2.1（调新路径）。
- 已经生成、尚未使用的接入命令在升级后会 404，回页面重新生成一条即可。

## [0.4.0-alpha] - 2026-11-03

### 新增：授权记录签名（Ed25519）

- `[issue].signing_key`：授权记录的签发私钥（PKCS#8/PEM，推荐 Ed25519）。
  推送 `register` 时对整条授权内容签名；`revoke` 也对“已撤销的记录”重新签名。
- 签名覆盖：凭据指纹、程序名、角色、资源、受众、有效期、版本号、撤销状态。
  验证方改任何一项都无法通过验签（收到的和磁盘上加载的各验一次）。
- 接入脚本追加下发 `issuer-signing.pub`（裸 32 字节 hex 公钥）——验证方只拿公开材料，
  私钥永远不出 cred。
- 示例验证方新增 `--issuer-public-key <hex>` / `--issuer-public-key-file <path>`：
  给了就开验签；`wist-cred-stack` 的 demo peer 已接上（缺文件时降级为不验签并提示）。
- `scripts/gen-pki.sh` 首次运行生成 `identity/cred/signing.key`（已存在不重签）；
  `scripts/init-cred.sh` 也会补生成，并派生公开的 `signing.pub`。
- 私钥文件被 group/others 可读时启动期告警（建议 `0600`）。
- 没配 `signing_key` 时仍可签发，但推送的是未签名记录：验证方开了 `require_signature`
  会拒收，启动日志会明确告警。

### 升级注意

- 配合 `wist-auth 0.3` / `wist-cred-peer 0.2`。
- **验证方要先升**（peer 0.2，先保持 `require_signature = false`），再升 cred，最后开启验签：
  peer 0.1 的撤销请求体是 `deny_unknown_fields`，新 cred 多发的字段会被旧验证方拒掉。
- 已有验证方需要**重新跑一次接入命令**，把 `issuer-signing.pub` 补下来；旧记录没有签名，
  开启验签后会被丢弃，需要在 cred 页面「重推」。

## [0.3.0-alpha] - 2026-11-03

### 新增：示例验证方（`wist-cred-example` 镜像）

- `examples/peer_example.rs`：一个真的双向认证验证方（收 register/revoke、自己存摘要表、心跳、
  联调时的 `POST /verify`），依赖 crates.io 上的 `wist-cred-peer` —— 下游接入的样板。
- **自己的镜像**：`wist-cred:vX.Y.Z-example`（同一个包名 + `-example` 后缀，ghcr / TCR 双推）。
  生态惯例是一个镜像一个二进制，所以**不**把它塞进服务镜像；名字用 tag 后缀而不是另开包，
  是因为 GHCR 只允许推本仓同名包。
- release tarball 里也带 `wist-cred-example` 二进制（不想用容器时直接跑）。

## [0.2.0-alpha] - 2026-11-03

### 新增：人机面的验证改由本服务自己做（`mode = "token"`）

以前人身份由内网反代注入 `x-wist-operator`（浏览器 basic auth 弹窗，页面上没有登录框、
没有登出，也不属于产品）。现在多一个模式，发布态用它：

- `mode = "token"`：页面输口令 → `Authorization: Bearer <口令>` → **本服务验**；
  配置里只写 `admin_password = "${SEC_CRED_WEB_PASSWORD}"`，加载时算成 `sha256`、明文丢弃。
  错误码与 gateway 管理面逐字一致（`missing_admin_bearer_token` / `invalid_admin_bearer_token`），
  页面一套 401 处理能用两处。
- 审计里的发起人：`admin:<sha256(口令) 前 12 位>`（与 gateway 的 `admin_actor()` 同形）。
- `mode = "ingress"` 保留（开发态 / 已经有入口认证的场合）。
- 加载期新增约束：`token` 模式必须有口令（缺失 / 展开不出来都拒启）；
  S1（不得绑 unspecified 地址）对两种模式都生效。
- 依赖：`wist-auth`（`bearer_token` / `token_matches` / `sha256_hex`），不再自己写比对。

### 修复（自查）

- **接入面（取脚本 / 登记）不能因为 `trusted_peers` 为空就全 401**：以前那里是“空 = 全拒”，
  而 `ingress` 模式又强制非空，所以看不出来；`token` 模式下 `trusted_peers` 是可选的，
  不统一就会出现“人机面能用、取接入脚本 401”的隐形故障。现在两处用同一个 `peer_denied()`：
  **空 = 不限**。
- `admin_password` 写在非 `token` 模式下 → **拒启**（写了但不生效比写错键更危险）。
- 口令两端带空白 → **拒启**（两端都会 trim，否则永远对不上）。
- 错口令的 warn 日志带上对端地址（不记口令）。

### 升级注意

- 页面必须跟 `wist-cred-web` ≥ 0.2.0：旧页面不会带 `Authorization`，只会看到 401。
- 弹部署栈请先写好 `cred_web_password`（栈的 `wist-cred-stack` ≥ 0.2.0 已跟进配置）。

## [0.1.1-alpha] - 2026-11-03

### 变更

- **镜像发布到腾讯云 TCR**：`dy-sec.tencentcloudcr.com/cloud/wist-cred:<tag>`，
  amd64 / arm64 多架构，部署侧从那里拉取。GitHub Release 上的 Linux tarball 不变。

## [0.1.0-alpha] - 2026-11-03

首个可部署版本：为程序签发**访问凭据**（明文只出现一次、服务端只存摘要），把摘要推给验证方，
并支持一键把验证方接进双向认证。

### 新增

- **凭据签发与撤销**：`POST /api/v1/credentials` 为程序创建凭据；明文只在响应里出现一次，
  服务端只保留 `sha256` 摘要。支持查询、幂等撤销，以及**重新投递**（投递失败或对方登记表
  丢了时补推一次，不改任何字段）。
- **镜像随 tag 发布**：`v*.*.*` 标签触发构建，多架构（amd64 / arm64）镜像推送到
  `ghcr.io/dayu-sec/wist-cred:<tag>`，同时附 Linux tarball（含 `config.example.toml`）。
- **认证系统注册表**：验证方在页面上新建即可生效，不用改配置、不用重启。它的证书主机名、
  收数地址由接入时自己上报；**角色表也由它自己声明**，签发时只能从那张表里选。
- **一键接入**：为某个认证系统生成一条可直接粘贴的 `curl … | bash` 命令。
  **私钥全程不离开对方机器**，只上交证书签名请求；命令 15 分钟有效、登记一次即作废。
- **可联通探测**：按周期用双向证书探对方，页面能看到 在线 / 不通 / 未探测 与延迟。
  证书过期、链不对、时钟偏移都会在推送失败之前先暴露出来。
- **签发策略**：`GET /api/v1/policy` 给出有效期上限（普通 / 应急），页面据此把超限选项
  标出来 —— 选「1 年」被静默压到 30 天是不应该发生的。
- `examples/closed_loop.rs`：签发 → 登记 → 验证 → 撤销 → 再验证 的完整闭环示例，可当接入参考。

### 变更

- **破坏性**：配置里的 `[[issue.targets]]` 被移除，推送目标改为认证系统注册表 + 一套共用身份。
  推送目标现在是运行期实体，写死在配置里必然与注册表脱节。
- 凭据的 `subject`（调用方身份）变成可选：页面不再问它，不给时用受众名填充；脚本仍可显式指定。
- **角色只认注册表**：一个都没登记时直接拒签（而不是让页面手填），避免签出一把
  「对方永远验不过」的钥匙。对方重新接入并声明新角色时，角色表随之更新。

### 安全

- **只信任自己的 CA**：推送通道只接受本平台 CA 签发的服务端证书 —— 某张证书被公共 CA
  信任，并不足以让它拿到凭据。
- **接入命令里没有任何私钥**；接入券是一次性随机值（分钟级有效、兑现即废），
  公开端点的失败响应不区分「没券 / 过期 / 已用」。
- 管理面要求操作者身份头 + 来源地址白名单；监听地址不得绑定全网卡，否则拒绝启动；
  来源地址白名单写错也在启动时就报错，而不是变成「所有人都 401」。
- 凭据文件 `0600`，写入走临时文件 + rename。

### 修复

- 接入脚本里的参数按 shell 字面量转义，地址 / 角色只接受安全字符集 —— 接入方上报的内容
  不能变成签发方宿主机上的命令。
- 上报值不合法（主机名 / 地址 / 角色）时不再浪费一次性接入券。
- 注册表写盘失败时回滚内存状态，不会出现「接口报错、内存里却已经有这条」或「重试撞冲突」。
- 签发时先归一化角色（去空白 / 去重 / 限字符集），避免 `" read "` 这种值发出去后被对方裁掉、
  变成一把静默少权限的钥匙。
- 撤销广播并发进行：一个响应慢的验证方不再把整次撤销拖成多倍超时；心跳也不会把旧地址的
  探测结论写回到刚改过地址的系统上。
- 受众有收数地址、而本部署没配推送时**拒绝签发**，不再「假装发出去了」。
- `purpose` / `subject` / `audience` 加上长度上限，一次请求不能把兆级内容写进表和日志。
