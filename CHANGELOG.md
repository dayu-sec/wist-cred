# Changelog

## [0.5.0-alpha] - 2026-11-05

### 变更（破坏性）：收数地址是**部署登记的事实**，接入脚本不再接受地址

上一版把地址做成了接入脚本的必填参数（`--advertise`，后来又给了个 `--manual` 退化）。
这是错的：地址是不是真的，命令行管不了 —— 结果只是把“地址从哪儿来”换了个地方让人猜。

现在：

- **地址只能登记，不能传入**：
  - 建系统必须给地址（`POST /api/v1/peers`，缺失 `400 endpoint_required`）；
  - 部署栈里写 `CRED_PKI_PEERS` 的第三个字段（`name=host=https://…`，`gen-pki.sh` 缺地址直接报错）；
  - 接入时带 `endpoint` 一律拒（`400 endpoint_not_accepted`），不静默忽略。
- **接入脚本删了 `--advertise` 与 `--manual`**：它只上报自己的主机名（`--host` > `hostname -f`）与角色。
- **没有登记地址的系统不允许接入**：`400 endpoint_required`，**券不烧**；补上地址后同一张券继续用。
  之前是“先发证书、运行期永远收不到推送”，人看到的却是“接好了”。
- 建系统时 `host` 与地址主机名不一致直接拒（`400 invalid_peer`）：证书 SAN 必须对上推数时连的地址。
- 页面（`wist-cred-web` 0.3.0）新建表单变成「名称 + 收数地址」，命令面板不再问地址。

升级注意：`--advertise` / `--manual` 已不存在；旧命令重跑会得到 `endpoint_not_accepted`（不会烧券）。
部署栈必须给 `CRED_PKI_PEERS` 补上地址，否则 `gops sys localize` 阶段就报错。

## [0.4.17-alpha] - 2026-11-05

### 修复：没有收数地址的系统不再显示成「未探测」（错误不能隐藏）

以前不给 `--advertise` 也能接入：cred 存下一条**没有 endpoint** 的记录，心跳直接跳过它，
状态永远是 `unknown`。页面显示「未探测」，和「刚建好、等第一次心跳」一模一样 ——
于是现场看到的是“接入成功，然后什么都不动”，凭据签了也送不到。

现在这条错误在三处显式暴露：

- **接入脚本**：没地址且没 `--manual` 就在生成材料之前拒跑（**券不消耗**），
  并给出两条出路。确实只做人工分发时必须显式 `--manual`，脚本会打印“不会探活，也不会收到推送”。
- **运行期状态**：新增 `no_endpoint`（与 `unknown` 分开）。它是从注册表推导的事实，
  重启不丢，补上地址后下一轮心跳才转 `up` / `down`；清空地址会退回它。
- **日志**：启动时逐条告警，心跳循环每个 peer 只告警一次（不刷屏）。

页面（`wist-cred-web` 0.2.9）同步：红标「缺收数地址」+ 原因 + 就地补地址；
为这种系统签接入命令时提前警告。

升级注意：`GET /api/v1/peers` 的 `health` 多了一个取值 `no_endpoint`。
只看 `up` / `down` 的消费方不受影响；按白名单校验 `health` 的需跟版。

## [0.4.16-alpha] - 2026-11-04

### 新增：部署栈可以声明「认证系统 → 材料目录」（`peer_dirs`）

上一版把落点做成了认证系统的属性，但**初始值还是要人填**，而且静态预置里我写的
`./identity/<peer>/cred` 对某些栈是错的（`wist-center-stack` 用的是 `identity/center/cred`，
服务目录名和 peer 名对不上）。猜不出来，只能拦 —— 而拦一次就烧一张券。

现在由**部署栈自己声明**（`wist-cred-stack` 的 `CRED_PEER_DIRS` →
`[onboarding] peer_dirs = "name=目录,name=目录"`），cred 启动时写进注册表：

- **只补空**：页面上存过的优先（人可能更清楚，且重启不应该改回去）；
- 声明了还没注册的系统：告警 + 跳过，不拦启动；
- 值不一致：告警，保留现有值；
- **加载期校验格式**：忘写 `=目录` / 名字为空 / 重复 / 带控制字符 → 启动就报，
  而不是变成一条“没生效的声明”。

写法：用逗号分隔的字符串而不是 TOML 数组 —— 这个值要穿过栈的模板变量，
数组得把引号也塞进模板，模板引擎一转义就坏了。

用例：`peer_dirs_are_parsed_into_pairs`、`a_malformed_peer_dir_fails_at_load_time`、
`a_peer_dir_with_control_characters_is_rejected`、`listing_the_same_auth_system_twice_is_rejected`、
`declared_peer_dirs_fill_only_the_empty_slot`（含未注册系统跳过 + 落盘）、
`seeding_the_same_value_again_is_a_no_op`（不重复 bump revision）。

> 升级注意：`[onboarding]` 是 `deny_unknown_fields` 的 —— 新版模板 + 旧版镜像会拒启，
> 两者必须一起升（栈 0.4.16 钉的就是本版）。

## [0.4.15-alpha] - 2026-11-04

### 新增：材料目录成了认证系统的属性（`install_dir`）

上一版只是把「护栏报错」改得好用了一点，但命令还是得人自己拼 `--dir` —— 那不对：
落点是这个系统的**事实**，该跟名称 / 收数地址 / 重启命令一样存下来。

- `POST /api/v1/peers/{name}/setup` 新增 `install_dir`（材料目录），随 peer 落 `state/peers.json`；
  `GET /api/v1/peers` 回显它。
- **签发时烘进脚本**：`INSTALL_DIR="${WIST_CRED_INSTALL_DIR:-<存的目录>}"`。
  所以页面给的那行 `curl … | bash` **裸跑就落对地方**，不必再补参数；
  命令行 `--dir` / 环境变量 `WIST_CRED_INSTALL_DIR` 仍然优先。
- 校验：单行、≤512 字节（无控制字符）—— 与 `config_path` 同一条口径。

web 侧（`wist-cred-web` 0.2.7）在「接入命令」面板加了「材料目录」输入框，
生成的命令自带 `--dir '…'`。

用例：`setup_fields_round_trip_and_reject_control_characters`（存 / 重开 / 清空 / 拒换行）、
`the_material_dir_is_embedded_so_the_bare_command_works`、
以及 e2e `a_stored_material_dir_makes_the_bare_command_work_inside_a_stack`
（起真 cred → 存落点 → 在栈根**不带任何参数**跑 → 必须落在 `identity/center/cred/cred.toml`）。

## [0.4.14-alpha] - 2026-11-04

### 修复：部署栈里的接入命令把人顶死了

在部署栈（栈根有 `sys-prj.yml` + `identity/`）里直接粘页面给的命令，脚本会硬失败 ——
护栏本身是对的（私钥不能进 `git status`），但报错只说「加 `--dir ./identity/<peer>` 重跑」，
而**管道进来的调用者没法“加个参数再跑”**：整条 `curl … | bash -s -- …` 得自己拼回去。

现在报错直接给**整条可粘的命令**，并且落点是按栈里的实际目录推的：

- `identity/` 下**只有一个**子目录 → 建议 `./identity/<那个>/cred`
  （正好是 `wist-center-stack` 的真实布局 `identity/center/cred`）；
- 多个或没有 → 退回 `./identity/<peer>`，并注明以该栈 README 为准。

仍然**不自动落盘**：猜错的话材料会放在消费方不看的地方，而那时券已经烧掉了。
失败仍然发生在登记之前（券可重跑）。

用例：单元 `stack_roots_refuse_identity_outside_identity_dir` 补了「必须带完整命令」；
新增 e2e `a_stack_with_one_identity_dir_suggests_the_dir_its_consumer_expects`
（造一个只有 `identity/center` 的栈 → 把报错里的建议原样重跑 → 必须成功且落在 `identity/center/cred/cred.toml`）。

## [0.4.13-alpha] - 2026-11-04

### 三轮 review 对 0.4.12 的补齐（同一条线，未发布就别留着）

| 问题 | 处置 |
|---|---|
| **种子导入绕过归一化** —— `peer.json`（`gen-pki.sh` 从 `CRED_PKI_PEERS` 写的）走 `into_peer`，只校验不归一，填裸 origin 照样「探活绿、推送 404」 | 第三条写入口也接上 `normalize_endpoint` |
| 路径字符集没约束（空白 / 控制字符） | 拒绝：这些字符会原样进推送请求、也进接入脚本 |
| `revoke` 的 404 静默当「已撤销」 —— 收数地址写错也是 404，那意味着 token 在对方那边**仍然有效** | 返回值不变（撤销必须幂等），但落一条 warn 点名这个歧义 |
| `DEFAULT_PUSH_PATH` 插错了位置，把 `origin_of` 的文档注释顶走了 | 位置修正 |
| 陈旧文档（`fill_endpoint` 早改名为 `report`；README 没写归一化行为） | 一并修正 |

新增用例：`a_path_with_whitespace_or_control_characters_is_rejected`、
`a_bare_origin_still_yields_the_host`、`a_stored_endpoint_that_is_not_a_url_does_not_block_startup`、
`a_seed_with_a_bare_origin_is_normalized_on_import`、
`a_404_points_at_the_missing_push_path`、`other_failures_keep_the_plain_message`。

## [0.4.12-alpha] - 2026-11-04

### 修复：收数地址少了路径 —— 「探活绿、推送 404」

`endpoint`（X 的收数地址）在两个地方用，口径本来就不一样：

| 用途 | 取值 |
|---|---|
| 心跳探活 | `origin` + `/healthz`（`probe_url` 会把路径剥掉） |
| 推送 register / revoke | `POST endpoint` **原样** |

而校验只看了 scheme + authority，所以 `https://host:3103` 这种只给 origin 的写法
**存得进去、探得活，但每条推送都打到根路径 → `404 Not Found`**，报错里也没有任何线索。
本地联调时就这么坑了一次（凭据建出来了但没送到，只能 `redeliver`）。

现在：

- **落库前归一化**（`create` / 接入上报 `report` / 改地址 `set_endpoint` 三条写路径统一）：
  没有路径或只有 `/` → 补上默认收数路径；**已经有路径就原样保留**（X 可以把 listener 挂在别处）。
  尾斜杠会被去掉（axum 的精确路由不认尾斜杠）。
- **加载旧存储时也迁移一次**：升级前就存进去的裸 origin 会被补上路径并回写，
  不用重跑接入命令。
- **推送 404 的报错点名原因**：直接说 endpoint 没命中收数路由、应该带上哪个路径。

默认收数路径常量复制了一份（服务二进制不引 `wist-cred-peer`，它只是示例验证方的 dev-dependency），
并由 `default_push_path_matches_the_peer_crate` 钉住两边一致。

新增用例：`a_bare_origin_gets_the_push_path`、`a_trailing_slash_is_trimmed_but_an_explicit_path_is_kept`、
`set_endpoint_normalizes_a_bare_origin`、`report_normalizes_a_bare_origin`、
`a_stored_bare_origin_is_migrated_on_open`、`default_push_path_matches_the_peer_crate`，
以及 API 层的 `an_endpoint_posted_without_a_path_comes_back_normalized`。

## [0.4.11-alpha] - 2026-11-03

### 新增：真正跑脚本的端到端测试（`tests/onboarding_e2e.rs`）

之前所有测试都只断言“渲染出来的文本”，于是运行时才有问题的那一类全部漏掉：
`$VAR（` 被 bash 吃成变量名、在部署栈里落错目录、中途崩了却返回成功。

现在起一个真 cred（真 CA + axum），用 `curl` 取脚本、用 `bash` 执行，看磁盘上留下了什么：

- `happy_path_writes_materials_and_cred_toml`：材料 + `cred.toml` 落盘，内容对；
- `stack_root_refuses_outside_identity_and_keeps_the_ticket`：栈里不带 `--dir` 拒绝，
  而且**券还能重跑**（失败发生在登记之前）；
- `config_outside_the_material_dir_is_refused`：跨目录写 `cred.toml` 拒绝。

测试里固定 `LC_ALL=en_US.UTF-8` —— 那个 `$VAR（` 的坑**只在 UTF-8 locale 下复现**，
C locale 会假绿（已做变异验证：改回 `$CRED_FILE）` 三个用例全红）。

### 修复：脚本中途失败却返回退出码 0

bash 3.2（macOS 自带）在存在 `EXIT` trap 时，会把 `set -u` 展开失败这类中断记成 **0**（
连 trap 里的 `$?` 都是 0）。表现：错误打了、文件写了一半、`bash join.sh` 却“成功”。

现在用显式的“跑完了”标记兜底：只有走到最后 / 显式 `die` / `--help` 才允许 0，
否则一律非零。另新增一条单测钉住 **`cleanup` / `trap` 只能各一个**
（重复定义会让后一个覆盖前一个，兜底静默失效）。

## [0.4.10-alpha] - 2026-11-03

### 变更：部署栈里把身份落点改成**硬失败**

0.4.9 只警告，现场仍然在栈里直接跑（不带 `--dir`）—— 结果 `./wist-cred/<peer>/` 下又出了一套私钥，
而 `identity/center/cred/` 里已经有一套：两套私钥、其中一套在 `git status` 里。

现在在部署栈里（栈根有 `sys-prj.yml` + `identity/`）而落点不在 `identity/` 下时，**登记之前就退出**：

```
这是部署栈：身份材料必须落 ./identity/<peer>（现在指向 ./wist-cred/wist-center）
  处置：用同一条命令加 --dir ./identity/<peer> 重跑（券还没用掉）；
        确实要放别处：WIST_CRED_ALLOW_UNSAFE_DIR=1 bash -s -- …
```

两个关键点：失败的时点在前置检查（**券不会被烧掉**，同一条命令加 `--dir` 就能重跑）；
确实要放别处时用环境变量显式放行。

## [0.4.9-alpha] - 2026-11-03

### 新增：部署栈里的落点警告

`./wist-cred/<peer>` 只是脚本给非 root 用的默认值，不是约定。在部署栈里（栈根有
`sys-prj.yml` + `identity/`）它**不被 `.gitignore` 挡住** —— 一行 `git status` 就能看到 `server.key`。

现在脚本会当场提醒：

```
⚠ 当前目录是一个部署栈：身份材料建议用 --dir ./identity/<peer>
  （identity/ 进 contract/备份且被 .gitignore 挡住；其它目录里的私钥会被 git 看到）
```

不拦：临时跑一次也合理；但得让人知道 `identity/` 才是它的位置。

## [0.4.8-alpha] - 2026-11-03

### 修复：`$VAR` 紧跟全角标点 → bash 把它吃进变量名

现场跑到 `cred.toml ✓（…）` 时：

```
bash: line 305: CRED_FILE（: unbound variable
```

原因：`set -u` + UTF-8 locale 下，bash 把 `$CRED_FILE（` 里的全角括号当成了变量名的一部分。
已把两处改成 `${VAR}`：

- `say "cred.toml ✓（${CRED_FILE}）"`
- `die "未知参数：${1}（-h 看用法）"`

### 测试

新增 `script_never_puts_a_bare_variable_next_to_wide_characters`：扫渲染结果里每个 `$`，
只要变量名后面紧跟非 ASCII 字符就失败 —— 这类错 shellcheck 不会报，只能靠这条钉住。

## [0.4.7-alpha] - 2026-11-03

### 修复：cred.toml 的三个真问题（review 第一/二遍）

1. **没下发签名公钥也会写 `require_signature = true`** —— 验证方会拿一个不存在的
   `issuer-signing.pub` 去验签，然后拒绝一切授权记录（比“不验”更难查）。
   现在只有真下发了公钥才写这两行；否则留成注释并说明原因。
2. **`cred.toml` 被挪出材料目录时相对路径会指到虚处**。
   现在强制同目录（`--dir` 换整个目录），并在错误信息里说清楚。
3. **`--config` 指到目录 / 父目录不存在**时 `mv` 会静默做怪事（把文件搬进目录）。
   现在先判目录 + `mkdir -p`。

### 变更：cred.toml 正文改由服务端渲染

以前正文在 bash 里用 heredoc 拼（条件分支没法测，写错一处整份不可用）。
现在 `render_script` 里的 `cred_toml()` 生成正文，脚本只负责 `cat > … <<'EOF'` 原样落盘。

- 字段名 `issuer_public_key` → **`issuer_public_key_file`**（它是路径，不是公钥本身）。
- 角色为空时**不写** `roles = []`（空数组在有些消费方 = 一个角色都不发），留成注释。
- 正文里补一句“相对路径按本文件所在目录解”。
- 删掉死变量 `AUDIENCE`（`shellcheck SC2034`）。

### 测试

- `script_writes_a_uniform_cred_toml`：正文在、没有 `[ctrl.*]`、同目录约束在。
- `cred_toml_only_requires_signature_when_the_key_is_shipped`：有/无公钥两种分支。
- `cred_toml_carries_reported_roles_when_any`：有角色写数组、没角色不写空数组。
- 共 118 passed；模板过 `shellcheck -S warning`。

## [0.4.6-alpha] - 2026-11-03

### 变更：接入不再改目标程序的配置，改产出一份统一的 `cred.toml`

以前脚本会把 `[ctrl.credentials]` / `[ctrl.tls]` 片段写进“目标程序自己的配置”。
问题是：**每个程序的 schema 都不一样**（center 是 `[credentials]` 且 TLS 并进去，ingest/console 又各不相同），
脚本既不知道、也不该知道；而栈部署的配置还是 localize 渲染的，写进去会被覆盖。

现在只产出一份**与程序无关**的文件，落在材料目录里（默认 `<dir>/cred.toml`）：

```toml
[identity]
cert      = "server.crt"      # 相对本文件所在目录
key       = "server.key"
client_ca = "client-ca.pem"

[verify]
audience          = "wist-center"
allowed_issuers   = ["wist-cred"]
require_signature = true
issuer_public_key = "issuer-signing.pub"
```

- 程序启动时加一行 `--credentials <cred.toml>` 指过来即可（服务侧支持随后接入）。
- 相对路径按**文件所在目录**解 ⇒ 把整个材料目录一起挂进容器就行，不用关心宿主机路径。
- 不再修改、不再备份目标程序自己的配置文件；`--config` 现在只是“把 cred.toml 放到别处”。
- 脚本末尾直接打印下一步：挂目录 → 加 `--credentials` → `gops run stop && gops run start`。

## [0.4.5-alpha] - 2026-11-03

### 修复：参数缺值时的报错不再只给一句“需要一个值”

现场把 `--config` 写成光杆（`| bash -s -- --config`），只得到 `--config 需要一个值`，
还得自己去翻用法。现在每个选项缺值时都直接给出**完整可粘贴的写法**：

```
--config 需要一个值（例如：bash -s -- --config /etc/x/app.toml）
--restart 需要一个值（例如：bash -s -- --restart 'systemctl restart x'）
```

（`--dir` / `--host` / `--advertise` / `--roles` / `--cacert` / `--endpoint` 同样处理。）

## [0.4.4-alpha] - 2026-11-03

### 修复：手动补参数的提示写错了语法

现场按提示写成 `curl … | bash --config`，被 bash 当成自己的参数拒掉：`--config: invalid option`。
管道执行时参数必须走 `-s --`：

```
curl -fsSLk '<url>' | bash -s -- --config /etc/x/app.toml
```

- 脚本打印的提示改成**先推页面的「接入落点」**（保存后重签一条自带参数的命令），
  再给出手动形式的准确写法（带 `-s --`）。
- `--help` 里补一段说明为什么必须 `bash -s --`。
- 测试：提示里必须出现 `bash -s -- --config`，且不得再出现旧句式（115 passed）。

## [0.4.3-alpha] - 2026-11-03

### 新增：接入命令自带「接入落点」

以前接入脚本只打印配置片段，要真写进配置得**回头重新开一张券**带 `--config` —— 面子上很难看。
现在把落点存在**认证系统**上（与 `host` / `roles` 同类事实），签发时直接烘进脚本：

- `POST /api/v1/peers/{name}/setup`：`{config_path, restart_cmd}`（两者皆可选，`null` = 清空）。
- 签发出来的脚本不再需要任何参数：`CONFIG_FILE` / `RESTART_CMD` 以内嵌默认值出现，
  命令行 `--config` / `--restart` 仍可覆盖；不配则回到旧行为（只落材料 + 打印片段）。
- 校验：两个字段都必须是**单行**、无控制字符、≤ 512 字节；重启命令是脚本里的单行赋值，
  换行会把后面的内容变成新命令。脚本侧仍走单引号字面量转义。
- 页面（≥ 0.2.3）在「接入命令」面板里可填可改；改完点「保存并更新命令」会自动重签一张券。

### 注意

- **栈部署的系统（center / ingest）不要填 `config_path`**：它们的配置由 localize 渲染、只读挂载，
  脚本写进去会被下一次渲染覆盖 —— 那些系统改模板。

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
