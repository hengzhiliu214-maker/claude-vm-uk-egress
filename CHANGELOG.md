# Changelog

本仓库的公开版本记录。

## v1.1.0 — 2026-11-16

- 同步隧道传输层加固：WireGuard 改经 TLS WebSocket（TCP 443）承载，新增 `vps/wstunnel.service`、`guest/wg-transport.service` 与 `templates/wg0-client.conf.template`；来宾机杀开关快照收敛为仅放行 TCP 443。
- 《流程与工作框架》更新至 v1.1：新增传输层加固说明与实施结果行，踩坑录增补 7.11–7.13，已知残留增补手机对端一项。

## v1.0.0 — 2026-11-15

- 首个公开发布：出口链路代码（vps / guest / mac 三侧）、配置模板（`templates/`）与《流程与工作框架》全文（`docs/`）。
- 采用 MIT 许可证。
- 附第三方许可说明：`vps/after.init` 为 Canonical GPLv3 文件（见 THIRD-PARTY-NOTICES.md）；README 增「复用前必读」（放行凭证为外部控制点、硬编码核对项、安全取舍）。
