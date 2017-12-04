## MysqlSniff

基于 libpcap, 魔改 Wireshark Mysql 协议 Dissector 部分代码:

1. 保留协议解析状态机 
2. 替换 buffer 实现, 移除 全部 offset 处理
3. 移除协议树处理, 移除 SSL 处理
4. FIX Wireshark 在 Mysql 5.7 协议下省略 EOF 包的特性
5. 相比 360开源的工具, 支持预编译语句与更多协议细节

经过 php mysqli 与 java mysql connector 测试;