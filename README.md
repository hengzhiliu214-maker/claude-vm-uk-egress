# claude-vm-uk-egress

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A dedicated egress environment that runs inside a local VM, transits a WireGuard tunnel to a London VPS, and exits through a UK residential connection — fail-closed by design, with every conclusion verified by fault injection.

一套在本机虚拟机内运行、经 WireGuard 隧道转发至境外服务器、最终从英国住宅网络出口的专用网络环境。防泄漏为默认丢弃（fail-closed），全部结论经故障注入实测验证。本仓库记录该环境的最终形态：架构与工作框架的结论、验收结论，以及实际运行的代码。

## 架构

```text
Mac（宿主机）
 └─ Lima 虚拟机 guest（Ubuntu 24.04）
      └─ WireGuard 隧道 ──► 伦敦 VPS（sing-box，仅 SOCKS 出口、无直连回落）
                               └─ 英国住宅网络出口
```

- guest 无直出路径：隧道断开即断网，不回落到本地网络。
- 移动设备可作为第二条 WireGuard peer 接入同一出口；注意当前发布版的守卫脚本把手机对端（10.66.0.3/32）的路由与放行列入强制校验，不使用手机对端时需先调整相应校验项。

## 内容

- `docs/流程与工作框架.md` — 全文：问题定义、最终架构、逐项验收结论、协作工作框架、长期运维纪律与踩坑结论。
- `vps/` — 出口服务器侧：出口守护脚本、systemd 单元、防火墙恢复钩子。
- `guest/` — 虚拟机侧：防泄漏守护、时区与代理环境修正、桌面会话自启配置。
- `mac/` — 宿主机侧：系统代理守护脚本、开机自启配置、拉起桌面的命令脚本。
- `templates/` — sing-box、nftables、WireGuard、Lima 的配置模板（占位符版）。
- `CODE-INVENTORY.md` — 每个文件的来源位置、行数、脱敏方式与暂不公开项说明。

## 使用方式

本仓库发布的是一套已建成并验收的环境实录，不是安装包：

1. 先读 `docs/流程与工作框架.md` 的适用前提与验收方法；
2. 按角色（vps / guest / mac）部署对应文件，`templates/` 中的占位符全部替换为自己的值，密钥材料自行生成；
3. 部署后按文档的故障注入方法自验 fail-closed，不要只以"能连通"为准。

## 验收结论（摘要）

- 出口一致性复检与基线零漂移；
- 出口认证失败注入：guest 立即断网，抓包仅见白名单流量；
- 来宾机自动更新对网络组件的副作用已定位并由持久化守护吸收，重启与更新后复验通过；
- 整链备份与恢复演练完成（四种场景）。

验收结论全文见 `docs/流程与工作框架.md`。

## 复用前必读

- **放行凭证是外部控制点。** 守卫脚本包含放行凭证的校验与撤销，但不含签发工具：`release` 文件由部署者以 root 身份、0600 权限在带外流程写入 `/run/sing-box-egress/release`。未签发时链路保持断网，这是设计，不是缺陷。
- **硬编码项必须按部署环境核对。** 守卫规则写死服务账号 UID `999`（sing-box 运行用户）与 VPS 网卡名 `enp1s0`；隧道网段 `10.66.0.0/24`、手机对端 `10.66.0.3/32`、示例端口 `12324` 均为本部署的值。各文件的占位符约定见 `CODE-INVENTORY.md`。
- **安全取舍不是通用默认。** 来宾机钥匙圈为空口令、VNC 监听非回环地址、关闭锁屏，均为单用途隔离环境的取舍；`guest/` 中的 nftables 内容是快照而非完整启动部署文件。不要原样照抄到多用途机器。

## 说明

- 文中与代码中的地址、账号、密钥、运营商均为占位符，不含任何真实凭据与真实地址。
- 本仓库只发布已经形成的结果与结论；采购渠道、账号注册等操作细节不在公开范围。
- 部分组件依赖特定平台行为（虚拟化平台对来宾机的环境注入、系统更新对网络组件的影响等），结论与适用前提以全文为准。

## License

本仓库自有代码为 MIT，见 [LICENSE](LICENSE)。例外：`vps/after.init` 是 Canonical 的 ufw 组件文件，按 GPLv3 提供，见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
