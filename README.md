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

### 问题

发现 CentOS 2.6.32-696.3.1.el6.x86_64 下 libpcap 丢包严重;

加入检测, 退出程序, 否则会造成捕获报文不完整, 解析异常;

```
ERROR Packet loss found(recv=566, drop=12, ifddrop=0).
ERROR Packet loss found(recv=2234, drop=289, ifddrop=0).
```

### 解决方案

安装 PF_RING, 编译并加载内核模块;

```
git clone https://github.com/ntop/PF_RING.git
cd PF_RING
make
cd kernel
sudo insmod ./pf_ring.ko
```

其中 PF_RING/userland 会产生适配 PF_RING 的 libpcap 与 tcpdump

观察安装前后 tcpdump 版本验证;

```
$ tcpdump --version
tcpdump version 4.1-PRE-CVS_2017_03_21
libpcap version 1.4.0
```
安装后:

```
$ tcpdump --version
tcpdump version 4.9.0
libpcap version 1.8.1
```