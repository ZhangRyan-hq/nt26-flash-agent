---
name: nt26-flash-agent
description: 在 Linux 上检查、诊断和烧录利尔达 NT26F6D0（F6D_A / EC718PM_PRD）开发板的 v111 binpkg 固件，自动备份并回读校验。用于该板的固件升级和 USB 串口识别，不用于其他 STM32 或通用 EC718 开发板。
---

# NT26 Linux 烧录

本目录是自包含工具包。将本文件所在目录作为包根目录；所有脚本都可从任意工作目录调用。当前包版本见 `agent-tool.json`。不要依赖原开发机的路径或过去的串口编号。

## 入口

- `scripts/check-environment.py`：离线检查 Python、pyserial、Linux 和分发文件完整性，输出 JSON；不打开串口。
- `scripts/nt26-flash`：原生 CLI，成功结果为 stdout JSON，进度和错误为 stderr。`--help` / `--version` 输出普通文本。
- [references/cli.md](references/cli.md)：完整参数、输出字段、退出码及可复制调用示例。
- [references/recovery.md](references/recovery.md)：串口不可见、断连、写入失败及恢复边界。
- [references/validation.md](references/validation.md)：支持范围、已完成的实机验证和限制。
- `agent-tool.json`：供通用 Agents 读取的本地 CLI 契约；不是 MCP 服务或通用框架的自动注册文件。

## 执行顺序

1. 运行环境自检。缺少 pyserial 时按 [README.md](README.md) 安装依赖。离线 `inspect` 仅需 Python 标准库；硬件操作需要 Linux、pyserial 及真实 USB 串口权限。
2. 只需检查包时，直接 `inspect <固件绝对路径> --mode full|app`。这是离线动作，不能证明板型兼容。仅支持 **L-CT4IT00-YP00W-01_V04 / NT26F6D0 / F6D_A** 的已验证布局。
3. 需接触设备时先 `devices`。它可能列出同一正常模式设备的多个接口；**只有 interface_number=3 才是 AT 口**。`probe --at-port <枚举结果>` 仅发送 `AT`、`AT+CGMR`。不要向诊断口发送 AT 指令，不要猜测 `/dev/ttyUSB1`。
4. 烧录前确定用户选定的固件、目标设备和模式；已有明确烧录授权时继续执行，不要重复询问。单纯查询、检查或打包请求不包含烧录授权。`diagnose` 虽不写 Flash，仍会运行 RAM 引导并复位、打断业务；不要把它当成普通版本查询。
5. 使用刚检查过的 **64 位 package_sha256** 作为 `--confirm-sha256`，准备父目录已存在、路径全新的 `--backup-dir`。运行正常模式设备时指定 `--at-port` 并加 `--enter-rom`；已在下载模式时指定 `--port`，不使用过期 AT 端口。多板时必须明确选择目标，不能遍历设备逐个尝试写入。
6. 保持进程运行并收集 stderr；完整备份和回读包含大量串口往返，持续有进度时不要设短超时杀掉进程。已有会话仍在运行时继续等待该会话，不重复启动烧录。
7. 成功须同时满足退出码 0、stdout 中 `success/readback_verified/generated_headers_verified/preserved_regions_verified/reset_acknowledged` 均为 true，且新备份目录存在 `success.json`。保留备份路径、包 SHA256 和结果供用户复核。之后可 `probe` 确认 AT 响应；版本字符串不是固件身份的充分证据，TCP 入网需单独验收。

## 模式和失败处理

- `full`：更新 AP、CP、应用，最后 BL；核对两个原厂自动生成的启动头及全部保留区。
- `app`：只更新 PKGFLXAPP。工具从完整备份核对板上 BL/AP/CP 与包内一致；不匹配则写入前失败。用户只授权更新应用时，不能自动扩大为 full。
- 在任何擦写前，工具先保存完整 **4 MiB** Flash 并校验落盘哈希。禁止跳过备份或通过改代码绕过型号、布局、SHA256、ROM 和 AgentBoot 检查。
- 非零退出或缺少成功记录均不能宣称成功。擦写开始后的失败可能留下部分固件；不要用原备份目录覆盖重试，也不要无限自动复位/重试。保留最早的完整备份，按恢复说明判断下一步。
- 包中的历史验证不是新的烧录授权。包内不含用户固件、IMEI 或设备备份；备份由每次实际烧录生成。原厂 RAM agent 的来源与权利见 `tool/assets/SOURCE.txt`。
