# Wireshark技巧

## Wireshark技巧

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 提升你的Wireshark技能

### 教程

以下教程非常适合学习一些酷炫的基本技巧：

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析信息

**专家信息**

点击 _**Analyze** --> **Expert Information**_，你将获得对**分析的数据包**的**概述**：

![](<../../../.gitbook/assets/image (570).png>)

**解析的地址**

在 _**Statistics --> Resolved Addresses**_ 下，你可以找到Wireshark解析的一些信息，比如端口/传输协议到协议的映射，MAC地址到制造商的映射等。了解通信中涉及的内容非常有趣。

![](<../../../.gitbook/assets/image (571).png>)

**协议层次结构**

在 _**Statistics --> Protocol Hierarchy**_ 下，你可以找到通信中涉及的**协议**以及与它们相关的数据。

![](<../../../.gitbook/assets/image (572).png>)

**会话**

在 _**Statistics --> Conversations**_ 下，你可以找到通信中的**会话摘要**以及与它们相关的数据。

![](<../../../.gitbook/assets/image (573).png>)

**端点**

在 _**Statistics --> Endpoints**_ 下，你可以找到通信中的**端点摘要**以及每个端点的数据。

![](<../../../.gitbook/assets/image (575).png>)

**DNS信息**

在 _**Statistics --> DNS**_ 下，你可以找到关于捕获的DNS请求的统计信息。

![](<../../../.gitbook/assets/image (577).png>)

**I/O图表**

在 _**Statistics --> I/O Graph**_ 下，你可以找到通信的**图表**。

![](<../../../.gitbook/assets/image (574).png>)

### 过滤器

在这里，你可以找到根据协议进行的Wireshark过滤器：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
其他有趣的过滤器：

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP和初始的HTTPS流量
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP和初始的HTTPS流量 + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP和初始的HTTPS流量 + TCP SYN + DNS请求

### 搜索

如果你想在会话的数据包中**搜索**内容，请按下CTRL+f。你可以通过按右键然后编辑列来向主要信息栏添加新的图层（编号、时间、源等）。

练习：[https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## 识别域名

你可以添加一个显示Host HTTP头的列：

![](<../../../.gitbook/assets/image (403).png>)

还可以添加一个从初始的HTTPS连接中添加服务器名称的列（**ssl.handshake.type == 1**）：

![](<../../../.gitbook/assets/image (408) (1).png>)
## 识别本地主机名

### 通过DHCP

在当前的Wireshark中，不再使用`bootp`，而是需要搜索`DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### 通过NBNS

![](<../../../.gitbook/assets/image (405).png>)

## 解密TLS

### 使用服务器私钥解密https流量

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

点击_Edit_并添加服务器和私钥的所有数据（_IP、端口、协议、密钥文件和密码_）

### 使用对称会话密钥解密https流量

事实证明，Firefox和Chrome都支持将用于加密TLS流量的对称会话密钥记录到文件中。然后，您可以将Wireshark指向该文件，即可解密TLS流量。更多信息请参见：[https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
要检测此项，请在环境中搜索变量`SSLKEYLOGFILE`

共享密钥文件的格式如下：

![](<../../../.gitbook/assets/image (99).png>)

要在Wireshark中导入此文件，请转到\_edit > preference > protocol > ssl > 并将其导入到(Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

## ADB通信

从ADB通信中提取发送的APK文件：
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告**吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我的 **推特** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
