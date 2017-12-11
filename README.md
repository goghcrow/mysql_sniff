## MysqlSniff

基于 libpcap, 移植 Wireshark Mysql Dissector 状态机:

- 加入一个易用的 buffer 实现
- 加入一个简易的libpcap tcpsniff 封装
- 加入一个简易的 mysql 连接会话存储结构
- 修复 Wireshark 在 Mysql 5.7 协议下 CLIENT_DEPRECATE_EOF 选项未处理的BUG
- 仅保留协议解析状态机, 替换 buffer 实现
- 移除协议树处理, 移除 SSL 处理
- 支持多端口, 多版本 mysql 协议同时监听
- 其他

相比 https://github.com/Qihoo360/mysql-sniffer 支持Mysql Statement 解析, 支持更多协议细节;

在 php mysqli 与 java mysql connector 测试通过大部分场景;

### install

```
# CentOS
yum install -y libpcap-devel.x86_64

# Mac
brew install libpcap

make
```

### Usage

```
Usage:
   ./mysqlsniff -i <interface> -p <mysql_server_port1>,<port2>,<port3>... [-v]

Example:
   ./mysqlsniff -i any -p 3306
```