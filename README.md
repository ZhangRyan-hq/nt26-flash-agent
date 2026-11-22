# NT26 Linux 烧录工具 · Agents 调用包

这份包把已经实机验证的 Linux 烧录器、原厂 RAM 引导程序、82 项离线测试和调用说明放在一起。支持 **L-CT4IT00-YP00W-01_V04 开发板上的 NT26F6D0 / F6D_A / EC718PM_PRD**，固件为已验证四镜像布局的 v111 `.binpkg`。

不需要 Windows 或 Wine。工具版本为 **0.1.0**；此 Agent 分发包版本为 **1.0.0**。

## 解压与依赖

```bash
tar -xzf nt26-flash-agent-1.0.0.tar.gz
cd nt26-flash-agent
python3 scripts/check-environment.py
```

运行环境：Linux、Python 3.10+、pyserial 3.5。当前开发机已有依赖。其他 Ubuntu 主机可用系统包：

```bash
sudo apt install python3-serial
```

也可在包外建立虚拟环境（需系统提供 Python venv）：

```bash
python3 -m venv "$HOME/.venvs/nt26-flash"
"$HOME/.venvs/nt26-flash/bin/python" -m pip install -r requirements.txt
"$HOME/.venvs/nt26-flash/bin/python" scripts/check-environment.py
"$HOME/.venvs/nt26-flash/bin/python" scripts/nt26-flash --version
```

自检只读取文件并检查依赖，不访问串口。它不能证明 USB 已连接或串口访问权限正常。归档提供 SHA256 清单用于发现缺失/损坏；清单不是数字签名。

## 交给 Agents

通用 Agent：提供解压目录，让它先读 `SKILL.md`；机器入口和副作用定义在 `agent-tool.json`。可直接复制这段任务模板并替换尖括号内容：

> 请使用 `<包的绝对路径>/SKILL.md` 中的流程，检查 `<固件的绝对路径>.binpkg`，先给出设备识别和离线烧录计划。仅在我明确要求烧录时执行 flash。

Codex Skill：将完整的 `nt26-flash-agent` 文件夹放进 `~/.codex/skills/` 或当前 Codex 配置的 skills 目录。已有同名目录时先检查版本，避免合并覆盖。之后可通过 `$nt26-flash-agent` 调用；是否立即刷新取决于客户端，可新开会话读取。文件夹中的 `tool/`、`scripts/`、`references/` 都要保留，不能只复制 `SKILL.md`。

无需安装 Skill 也能直接运行 CLI。正常命令成功时 stdout 是一个 JSON 值，日志在 stderr，可分别采集。无需启动 MCP 服务。

## 常用命令

以下在包根目录运行；所有入口也支持绝对路径调用：

```bash
./scripts/nt26-flash devices
./scripts/nt26-flash probe --at-port /dev/nt26-at
./scripts/nt26-flash inspect /absolute/path/firmware.binpkg --mode full
```

`/dev/nt26-at` 仅是原开发机已有的别名；其他机器须使用 `devices` 枚举得到的接口 03 端口。仅检查文件不需要连接开发板。

实际烧录命令、退出码与结果判据：[CLI 使用说明](references/cli.md)。故障处理：[恢复说明](references/recovery.md)。完整流程供 Agent 阅读：[SKILL.md](SKILL.md)。

## 验证与内容

```bash
python3 scripts/self-test.py
sha256sum -c SHA256SUMS
```

离线测试不打开真实串口。`PACKAGE_VALIDATION.json` 记录本次打包验证；`tool/VALIDATION.json` 记录 2026-11-21 的实机烧录结果摘要。二者不能替代未来每次烧录的回读校验。

```text
nt26-flash-agent/
├── SKILL.md                  Agent 工作流程
├── agent-tool.json           命令、参数、输出及副作用契约
├── scripts/                  CLI、环境自检、离线测试入口
├── references/               CLI、恢复、验证说明
├── agents/openai.yaml        Codex Skill 展示信息
├── tool/nt26flash/           原生 Python 实现
├── tool/assets/              已固定 SHA256 的原厂 RAM agent
├── tool/tests/               82 项测试与原厂参考向量
├── requirements.txt          pyserial 依赖
└── SHA256SUMS                分发文件完整性清单
```

固件 `.binpkg` 和板上 Flash 备份由使用者独立保存，不包含在此包中。原厂 RAM agent 并非开源文件，来源和权利说明在 `tool/assets/SOURCE.txt`；上游代码许可证在 `tool/THIRD_PARTY_NOTICES.txt`。
