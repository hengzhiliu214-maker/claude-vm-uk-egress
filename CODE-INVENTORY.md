# 开源代码包 v1 — 文件清单（CODE-INVENTORY）

本包为「Claude 专用虚拟机 + 英国网络环境」分享包的代码部分，全部文件取自实际运行环境原件，
仅做敏感值替换，未改动代码逻辑。配套文档见仓库 `docs/流程与工作框架.md`。

## 脱敏口径与占位符

| 占位符 | 含义 |
|---|---|
| `<VPS_IP>` | 中转 VPS 的公网地址 |
| `<VPS_IPV6>` / `<VPS_LINK_LOCAL>` | 中转 VPS 的公网 IPv6 / 对应链路本地地址 |
| `<出口_IP>` | 最终出口（SOCKS 上游）的地址 |
| `<SOCKS_USER>` / `<SOCKS_PASSWORD>` | SOCKS 上游账号 / 口令（在 VPS 上远程遮蔽，真值未离开 VPS） |
| `<WG_PRIVATE_KEY>` / `<WG_PEER_PUBLIC_KEY>` | WireGuard 私钥 / 对端公钥（在 VPS 上远程遮蔽） |
| `<用户>` / `<GUEST_USER>` | 宿主机登录名 / 来宾机登录名及其家目录 |
| `<外置盘>` | 宿主机外置盘卷名 |
| `<VM卷名>` | 虚拟机镜像挂载后的卷名 |
| `<TAILSCALE_IP>` | 宿主机在组网中的地址（本包实际未出现，口径预置） |

设计常量保留原值并在此注明：隧道内网 `10.66.0.0/24`（服务端 `.1`、来宾 `.2`、手机 `.3`）、
Lima 虚拟网络 `192.168.5.0/24`、sing-box TUN 段 `172.18.0.1/30`、示例端口 `12324`（SOCKS 上游端口，按部署填写）。

模板文件（templates/）的文件头已注明 TEMPLATE 与需填项；`egress.json.template` 因 JSON 不支持注释，
其模板说明只写在本清单内（见该文件条目）。

## vps/（中转 VPS，5 个文件）

| 文件 | 来源位置 | 作用 | 脱敏替换 | 行数 |
|---|---|---|---|---|
| sing-box-egress-net.sh | /usr/local/libexec/sing-box-egress-net.sh | 全套机制的核心状态机脚本：事实生成与严格校验、放行凭证校验/撤销、独立守卫规则（sbguard）生成、路由表 167 与规则核对、UFW 钩子入口 | 出口 IP ×6 → `<出口_IP>`；VPS 自身公网 IPv4 ×1 → `<VPS_IP>`、公网 IPv6 ×1 → `<VPS_IPV6>`、链路本地地址 ×1 → `<VPS_LINK_LOCAL>`（与原件逐行 diff 核对，共 9 行变化，均为敏感值替换与赋值引号，无逻辑改动） | 1229 |
| sing-box-egress.service | /etc/systemd/system/sing-box-egress.service | sing-box 主服务单元（以专用低权用户运行，启停挂接核心脚本） | 无（文件内 `wg-quick@wg0` 为 systemd 模板单元名，非邮箱） | 22 |
| sing-box-egress-route.service | /etc/systemd/system/sing-box-egress-route.service | 路由与放行阶段的 oneshot 单元（调核心脚本 up/down） | 无 | 11 |
| sbguard.service | /etc/systemd/system/sbguard.service | 独立守卫层服务单元（开机先于 ufw 应用无许可基线） | 无 | 11 |
| after.init | /etc/ufw/after.init | UFW 启动钩子：ufw start 时调核心脚本 `ufw-after` 恢复标记/规则，失败则回滚并停服（须保持可执行权限） | 无（文件内无 SB-MARK 字样，钩子以调用脚本实现）；第三方文件：Canonical 版权、GPLv3，见 THIRD-PARTY-NOTICES.md | 49 |

## guest/（来宾虚拟机，15 个文件）

| 文件 | 来源位置 | 作用 | 脱敏替换 | 行数 |
|---|---|---|---|---|
| guest-env-strip.sh | /usr/local/sbin/guest-env-strip.sh | 每次开机清除宿主经 Lima 写入 /etc/environment 的代理变量 | 无 | 14 |
| guest-env-strip.service | /etc/systemd/system/guest-env-strip.service | 上项的 oneshot 单元 | 无 | 8 |
| guest-env-strip.timer | /etc/systemd/system/guest-env-strip.timer | 开机 20 秒后及每 5 分钟重跑上项 | 无 | 11 |
| guest-tz-london.service | /etc/systemd/system/guest-tz-london.service | 把来宾时区钉回 Europe/London（命令内嵌于单元，无独立脚本文件） | 无 | 6 |
| guest-tz-london.timer | /etc/systemd/system/guest-tz-london.timer | 开机 45 秒后及每 5 分钟重申时区 | 无 | 11 |
| guest-user-mgr-reset.service | /etc/systemd/system/guest-user-mgr-reset.service | 开机后重启一次登录用户管理器，甩掉其继承的宿主代理环境 | 登录名 → `<用户>` | 7 |
| guest-user-mgr-reset.timer | /etc/systemd/system/guest-user-mgr-reset.timer | 开机 60 秒一次性触发上项 | 无 | 10 |
| vncserver-guest.service | /etc/systemd/system/vncserver-guest.service | TigerVNC:1 桌面服务（开机自启、防自匹配守护） | User → `<用户>`；HOME → `/home/<GUEST_USER>` | 15 |
| 99-wg-rules-keep.conf | /etc/systemd/networkd.conf.d/99-wg-rules-keep.conf | networkd drop-in：`ManageForeignRoutingPolicyRules=no`，防 networkd 重启清掉 wg-quick 策略规则 | 无 | 6 |
| keyring-start.sh | ~/.config/autostart/keyring-start.sh | 桌面会话启动时以空口令解锁 GNOME Keyring（无 PAM 登录环境下使用） | 原件为单行字面转义形式（写入时换行未生效、且原件自启实际未生效），本包按原意恢复为正常格式并在文件内注明，逻辑未改 | 3 |
| gnome-keyring.desktop | ~/.config/autostart/gnome-keyring.desktop | 上项的自启入口 | 同上恢复格式；Exec 路径登录名 → `<GUEST_USER>` | 5 |
| noblank.desktop | ~/.config/autostart/noblank.desktop | 自启关闭屏保空白（xset s off / noblank） | 同上恢复格式 | 5 |
| light-locker.desktop | ~/.config/autostart/light-locker.desktop | 隐藏 light-locker 自启（禁用锁屏器） | 同上恢复格式 | 6 |
| fcitx5.desktop | ~/.config/autostart/fcitx5.desktop | Fcitx5 输入法框架自启（系统自带文件） | 无 | 9 |
| fcitx5-profile | ~/.config/fcitx5/profile | Fcitx5 配置：默认组、键盘 us + 拼音、默认输入法 pinyin | 无 | 23 |

## mac/（宿主机 Mac，4 个文件）

| 文件 | 来源位置 | 作用 | 脱敏替换 | 行数 |
|---|---|---|---|---|
| proxy-guard.sh | ~/bin/proxy-guard.sh | 系统代理守护：本地代理端口在听时把 macOS 系统代理钉回该端口，不在听则不动作 | 无 | 44 |
| com.muse.proxyguard.plist | ~/Library/LaunchAgents/com.muse.proxyguard.plist | 每 180 秒拉起 proxy-guard.sh 的 LaunchAgent | `/Users/<用户名>` ×3 → `/Users/<用户>` | 21 |
| 打开Claude桌面.command | ~/Desktop/打开Claude桌面.command | 一键入口：挂载虚拟机镜像 → 启动虚拟机 → 确保 VNC 在跑 → 打开远程桌面 | 外置盘卷名 → `<外置盘>`；VM 卷名 → `<VM卷名>` | 10 |
| 打开Claude虚拟机.command | ~/Desktop/打开Claude虚拟机.command | 一键入口：挂载镜像 → 启动虚拟机 → 进入其 shell | 外置盘卷名 → `<外置盘>`；VM 卷名 → `<VM卷名>` | 9 |

## templates/（模板，4 个文件）

| 文件 | 来源位置 | 作用 | 脱敏替换 | 行数 |
|---|---|---|---|---|
| egress.json.template | /etc/sing-box/egress.json | sing-box 出口配置模板：TUN 入站（gvisor 栈）→ SOCKS 出站、DNS 劫持与拒绝规则。因 JSON 不支持注释，TEMPLATE 说明在本清单：需填 `<出口_IP>`、`<SOCKS_USER>`、`<SOCKS_PASSWORD>` 与上游端口 | server → `<出口_IP>`；username/password 在 VPS 上远程遮蔽后分别替换为 `<SOCKS_USER>` / `<SOCKS_PASSWORD>`，真值未离开 VPS | 65 |
| wg0.conf.template | /etc/wireguard/wg0.conf | WireGuard 服务端配置模板（文件头已注需填项） | PrivateKey / 各 Peer 的 PublicKey 在 VPS 上远程遮蔽为 `<WG_PRIVATE_KEY>` / `<WG_PEER_PUBLIC_KEY>`，真值未离开 VPS | 15 |
| lima.yaml.template | 宿主机 $LIMA_HOME/claude-vm/lima.yaml | Lima 来宾机定义模板（文件头已注调整项）；当前值为 6 核 / 16GiB / 40GiB，propagateProxyEnv=false | 无敏感值（原件本就不含登录名与个性化路径） | 15 |
| nftables-guest-ruleset.txt | 来宾机 `sudo nft list ruleset` 实时导出 | 来宾杀开关规则快照模板：killswitch 表（默认 drop，仅放行 lo / wg0 / VPS 隧道端点 / DHCP / 宿主侧 SSH·VNC）+ wg-quick 自建表 + Lima NAT 表 | VPS 隧道端点 IP → `<VPS_IP>`；192.168.5.0/24 与 10.66.0.0/24 为设计常量保留（文件头已注） | 56 |

## 缺失 / 跳过登记

- guest-tz-london、guest-user-mgr-reset 没有独立脚本文件（命令内嵌于 systemd 单元），已按实情收录单元本身，不另造脚本。
- /etc/systemd/networkd.conf 本体只含发行版默认注释行（被注释的 `#ManageForeignRoutingPolicyRules=yes`），实际生效的是 networkd.conf.d 里的 drop-in，故只收 drop-in。
- 清单内其余文件全部取回，无其他缺失。

## 终检扫描（本包全部文件，含本清单）

| 模式 | 计数 |
|---|---|
| VPS 真实 IP | 0 |
| 出口真实 IP | 0 |
| Tailscale 网段地址 | 0 |
| 真实手机号片段 | 0 |
| 登录名 / 主机名 / 外置盘卷名原文 | 0 |
| 常见邮箱域名（gmail / outlook / 163 / qq） | 0 |
| 远程遮蔽残留标记 | 0 |
| 长 base64 令牌疑似密钥 | 0（唯一命中为脚本内 sha256 全零占位常量，已核对） |

代码总量：28 个代码/配置文件 + 本清单；核心脚本与原件逐行核对一致（仅脱敏行不同）。
