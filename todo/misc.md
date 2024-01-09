<details>

<summary><strong>从零开始学习AWS黑客技术，成为英雄级人物</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks上看到你的公司广告**或者**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>


在ping响应的TTL中：\
127 = Windows\
254 = Cisco\
其他，某些linux

$1$- md5\
$2$或 $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

如果你不知道服务背后是什么，尝试发起一个HTTP GET请求。

**UDP扫描**\
nc -nv -u -z -w 1 \<IP> 160-16

向特定端口发送一个空的UDP数据包。如果UDP端口是开放的，目标机器不会发送回复。如果UDP端口是关闭的，目标机器应该发送一个ICMP端口不可达的数据包回来。\

UDP端口扫描通常不可靠，因为防火墙和路由器可能会丢弃ICMP\
数据包。这可能导致你的扫描出现误报，你会经常看到\
UDP端口扫描显示扫描的机器上所有UDP端口都是开放的。\
o 大多数端口扫描器不会扫描所有可用的端口，通常有一个预设的\
“有趣端口”列表被扫描。

# CTF - 技巧

在**Windows**中使用**Winzip**来搜索文件。\
**Alternate data Streams**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## 加密

**featherduster**


**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> 以 "_begin \<mode> \<filename>_" 开始，使用奇怪字符\
**Xxencoding** --> 以 "_begin \<mode> \<filename>_" 开始，使用B64\
\
**Vigenere** (频率分析) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (字符偏移) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> 使用空格和制表符隐藏信息

# 字符

%E2%80%AE => RTL 字符 (反向编写有效载荷)


<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为英雄，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>!</strong></summary>

其他支持HackTricks的方式：

* 如果你想在 **HackTricks中看到你的公司广告** 或者 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现 [**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享你的黑客技巧。

</details>
