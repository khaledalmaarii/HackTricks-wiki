<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


在ping响应中TTL：\
127 = Windows\
254 = Cisco\
Lo demás,algunlinux

$1$- md5\
$2$或 $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

如果您不知道服务背后是什么，请尝试进行HTTP GET请求。

**UDP扫描**\
nc -nv -u -z -w 1 \<IP> 160-16

向特定端口发送一个空的UDP数据包。如果UDP端口开放，目标机器不会发送回复。如果UDP端口关闭，目标机器应该发送一个ICMP端口不可达的数据包回复。\

UDP端口扫描通常不可靠，因为防火墙和路由器可能会丢弃ICMP\
数据包。这可能导致扫描中出现误报，您将经常看到\
UDP端口扫描显示扫描的机器上所有UDP端口都是开放的。\
o 大多数端口扫描工具不会扫描所有可用端口，通常会有一个预设的“有趣端口”列表\
进行扫描。

# CTF - 技巧

在**Windows**中使用**Winzip**来搜索文件。\
**备用数据流**：_dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## 加密

**featherduster**\

**Base64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> 以 "_begin \<mode> \<filename>_" 开头，后跟奇怪的字符\
**Xxencoding** --> 以 "_begin \<mode> \<filename>_" 开头，后跟B64\
\
**Vigenere** (频率分析) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (字符偏移) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> 使用空格和制表符隐藏消息

# 字符

%E2%80%AE => RTL字符（反向编写有效负载）


<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
