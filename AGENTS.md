# 使用此包

本目录是一份可移植的 Agent Skill 与 CLI 分发包。先读 [SKILL.md](SKILL.md)，CLI 契约见 [agent-tool.json](agent-tool.json)。硬件驱动实现位于 `tool/nt26flash/`。

仅整理或测试此包时使用离线测试，不触发设备复位或烧录。修改分发文件后需重新生成 `SHA256SUMS` 并验证环境自检。测试缓存不属于分发文件。
