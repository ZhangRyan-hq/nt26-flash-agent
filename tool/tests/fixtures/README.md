# 离线原厂参考向量

这些文件从原调查的已验证向量原样复制。单元测试只读数据，不运行 Windows 程序，不打开串口。来源为用户提供的 lierda_upgrade_tool_V2.0.0_261119.zip，归档哈希见 ../../assets/SOURCE.txt。

- vendor-header-vectors.json：隔离 Wine 调用原厂 Image.pyd 序列化器，输入 ASCII vector-test-data；记录 AG/BL/AP/CP/FLEX 的完整 272 字节头。
- actual-agent-header.bin：对实际 50,788 字节 USB agent 与实际板级字段调用原厂 ImageInfo.GenAgImgHdBuf 得到的完整头。
- vendor-rom-erase-vectors.json：原厂 DLDManage.CompRomVerIntSingle 版本比较与 LPCCmd.CmdBytes() 擦除帧参考，生成时串口全部模拟。JSON 中 evidence 路径标识原研究档案，不是本包运行时依赖。

原厂擦除应答允许不透明正文，但状态及 CRC 必须正确。ROM 版本接受 8 或 12 字节响应，比对前 8 字节，并保留日期字段。
