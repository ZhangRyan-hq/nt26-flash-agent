# CLI 调用契约

入口为 `<包根目录>/scripts/nt26-flash`，也可用指定虚拟环境的 Python 解释器运行此脚本。相对固件、报告、备份路径按调用进程工作目录解释；原厂 agent 自动相对工具目录定位。Agents 建议全部传绝对路径。

## 参数和副作用

| 命令 | 参数 | 设备副作用 | 文件副作用 |
|---|---|---|---|
| `devices` | 无 | 枚举 USB 串口，不打开端口 | 无 |
| `inspect` | `package`；`--mode full\|app`，默认 full | 无 | 读取固件 |
| `probe` | 可选 `--at-port PATH` | 打开 AT 接口，发送 AT、AT+CGMR | 无 |
| `diagnose` | 可选 `--at-port PATH`、`--port PATH`、`--enter-rom`、`--report PATH`、`--agent PATH` | 下载模式、RAM 引导、配置接口、读 240 字节、复位；不擦写 Flash | 可新建诊断报告 |
| `flash` | `package`；必需 `--confirm-sha256 HEX64`、`--backup-dir NEW_DIR`；可选 `--mode full\|app` 及 diagnose 的设备/agent 参数 | 下载模式、完整备份、擦写、回读校验、复位 | 新建备份目录及记录 |

`flash` 没有 `--report`，`probe` 没有 `--port`。`--agent` 只接受与随包 agent 完全相同的 50,788 字节文件及 SHA256，通常省略。

`--enter-rom` 显式允许通过 AT 触发下载模式。正常 USB ID 为 `3505:0003`，AT 为接口 `03`；下载 ID 为 `17d1:0001`。AT 到 ROM 用 USB 物理位置关联。`devices` 中 runtime 接口不全是 AT 口。

## 示例

离线检查和普通 AT 查询：

```bash
NT26_ROOT=/absolute/path/nt26-flash-agent
NT26_FIRMWARE=/absolute/path/firmware.binpkg
"$NT26_ROOT/scripts/nt26-flash" inspect "$NT26_FIRMWARE" --mode full > /tmp/nt26-plan.json
"$NT26_ROOT/scripts/nt26-flash" devices
"$NT26_ROOT/scripts/nt26-flash" probe --at-port /dev/nt26-at
```

将 `/dev/nt26-at` 替换为枚举确认的 AT 口。多板时须明确目标。`inspect` 的 `device_compatibility_verified` 始终为 false，它不接触设备。

用户要求诊断并允许业务中断时：

```bash
"$NT26_ROOT/scripts/nt26-flash" diagnose \
  --at-port /dev/nt26-at --enter-rom \
  --report /absolute/path/diagnostic-new.json
```

以下是实际擦写命令，仅在用户已指定固件、目标板并要求烧录时执行。先完成 inspect、阅读计划并准备已有的备份父目录。备份目录本身必须不存在：

```bash
NT26_PACKAGE_SHA=$(python3 -c 'import json; print(json.load(open("/tmp/nt26-plan.json"))["package_sha256"])')
"$NT26_ROOT/scripts/nt26-flash" flash "$NT26_FIRMWARE" \
  --mode full --at-port /dev/nt26-at --enter-rom \
  --confirm-sha256 "$NT26_PACKAGE_SHA" \
  --backup-dir /absolute/path/backups/run-001 \
  > /absolute/path/backups/run-001.stdout.json \
  2> /absolute/path/backups/run-001.stderr.log
```

日志放在备份目录外，因为 CLI 必须自己创建新目录。也可由 Agent 工具直接保存 stdout/stderr。

已手动进入 ROM 时，使用 `--port <枚举到的下载口>`，省略 `--enter-rom`、`--at-port`。不要传入已消失的 AT 端口。仅更新应用时，inspect 和 flash 两处均使用 `--mode app`，工具在擦写前核对底层镜像匹配。

Python Agent 调用示例（只检查，不接触设备）：

```python
import json
import subprocess
import sys
from pathlib import Path

root = Path("/absolute/path/nt26-flash-agent")
firmware = Path("/absolute/path/firmware.binpkg")
run = subprocess.run(
    [sys.executable, str(root / "scripts/nt26-flash"),
     "inspect", str(firmware), "--mode", "full"],
    capture_output=True, text=True, check=True,
)
plan = json.loads(run.stdout)
print(plan["package_sha256"], plan["regions"])
```

使用参数数组，避免拼接 shell 字符串。flash 是长操作；宿主有单次工具时限时，以可继续等待的进程会话运行。不要将短轮询时限作为杀进程时限，也不要因 stdout 暂无内容重复启动；进度位于 stderr。

## 输出与退出码

| 命令 | 成功 stdout |
|---|---|
| `devices` | JSON 数组：`port`, `realpath`, `vid`, `pid`, `role`, `interface_number`, `physical_location`；数字为十进制。空数组仍可退出 0。 |
| `inspect` | JSON 对象：`product`, `profile`, `package_sha256`, `mode`, `regions`, `generated_headers`, `preserved_regions`, `protected_regions`, `base_payload_sha256`, `requires_matching_base`, `device_compatibility_verified` 等；地址为十进制。 |
| `probe` | JSON 对象：`port`, `physical_location`, `at_ok`, `firmware_version`。 |
| `diagnose` | JSON 对象：`device`, `rom_version_raw`, `runtime_result`, `read_test_bytes`, `read_test_sha256`, `flash_written: false`, `reset_acknowledged: true`。 |
| `flash` | JSON 对象：`device`, `rom_version_raw`, `runtime_result`, `timestamp`, `package_sha256`, `backup_dir` 及成功标志。 |

功能命令成功后输出一个 JSON 值；stdout/stderr 分开收集。失败时可能没有 JSON。`--help`、`--version` 是纯文本，不应按日志中文措辞判断成功。

- `0`：命令完成；烧录还需检查成功标志及 `success.json`。
- `1`：文件、依赖、设备、协议或校验失败，详情在 stderr。
- `2`：参数解析失败，尚未执行硬件动作。
- `130`：捕获到键盘中断。其他信号、异常退出也视为失败/状态未知。

烧录成功标志：`success`, `readback_verified`, `generated_headers_verified`, `preserved_regions_verified`, `reset_acknowledged` 全部为 true。app 模式没有生成启动头，`generated_headers_verified: true` 表示空检查集合通过。`timestamp` 是连接后的记录时间，不是完成时间保证。

## 备份内容

新目录权限 0700；完整 4 MiB `flash-before.bin` 权限 0600。

| 文件 | 含义 |
|---|---|
| `plan.json` | 固件、模式和允许改动范围；存在不代表已擦写 |
| `device.json` | USB 目标、ROM、板级配置及包哈希 |
| `flash-before.bin` + `backup.json` | 当次开始时的完整 Flash 和哈希；落盘校验成功后才擦写 |
| `verified-*.json` | 全部写入结束后的所选镜像回读校验 |
| `verified-header-BL.json`, `verified-header-AP.json` | full 模式两个 272 字节启动头的精确比对 |
| `success.json` | 回读、保留区检查及复位应答全部成功后的结果 |

当前没有独立的 `backup`、`restore`、`verify` 或任意 `at` 子命令，不提供全片擦除和 IMEI/eFuse 操作。离线计划用 `inspect`，不存在额外 `--dry-run` 参数。
