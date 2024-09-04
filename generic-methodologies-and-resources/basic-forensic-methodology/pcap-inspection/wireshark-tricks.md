# Wireshark tricks

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}


## 提升你的 Wireshark 技能

### 教程

以下教程非常适合学习一些酷炫的基本技巧：

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析信息

**专家信息**

点击 _**分析** --> **专家信息**_ 你将获得一个 **概述**，了解在 **分析** 的数据包中发生了什么：

![](<../../../.gitbook/assets/image (256).png>)

**已解析地址**

在 _**统计 --> 已解析地址**_ 下，你可以找到 Wireshark "已解析" 的多种 **信息**，如端口/传输到协议、MAC 到制造商等。了解通信中涉及的内容是很有趣的。

![](<../../../.gitbook/assets/image (893).png>)

**协议层次**

在 _**统计 --> 协议层次**_ 下，你可以找到通信中涉及的 **协议** 及其相关数据。

![](<../../../.gitbook/assets/image (586).png>)

**对话**

在 _**统计 --> 对话**_ 下，你可以找到通信中的 **对话摘要** 及其相关数据。

![](<../../../.gitbook/assets/image (453).png>)

**端点**

在 _**统计 --> 端点**_ 下，你可以找到通信中的 **端点摘要** 及其相关数据。

![](<../../../.gitbook/assets/image (896).png>)

**DNS 信息**

在 _**统计 --> DNS**_ 下，你可以找到捕获的 DNS 请求的统计信息。

![](<../../../.gitbook/assets/image (1063).png>)

**I/O 图**

在 _**统计 --> I/O 图**_ 下，你可以找到 **通信图**。

![](<../../../.gitbook/assets/image (992).png>)

### 过滤器

在这里你可以找到根据协议的 Wireshark 过滤器：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
其他有趣的过滤器：

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP 和初始 HTTPS 流量
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP 和初始 HTTPS 流量 + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP 和初始 HTTPS 流量 + TCP SYN + DNS 请求

### 搜索

如果你想在会话的 **数据包** 中 **搜索** **内容**，请按 _CTRL+f_。你可以通过右键单击并编辑列来添加新的层到主信息栏（编号、时间、源等）。

### 免费 pcap 实验室

**通过以下免费挑战进行练习：** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## 识别域名

你可以添加一个显示 Host HTTP 头的列：

![](<../../../.gitbook/assets/image (639).png>)

以及一个添加发起 HTTPS 连接的服务器名称的列 (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## 识别本地主机名

### 从 DHCP

在当前的 Wireshark 中，你需要搜索 `DHCP` 而不是 `bootp`

![](<../../../.gitbook/assets/image (1013).png>)

### 从 NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## 解密 TLS

### 使用服务器私钥解密 HTTPS 流量

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

按 _编辑_ 并添加服务器和私钥的所有数据 (_IP、端口、协议、密钥文件和密码_)

### 使用对称会话密钥解密 HTTPS 流量

Firefox 和 Chrome 都具有记录 TLS 会话密钥的能力，这可以与 Wireshark 一起使用以解密 TLS 流量。这允许对安全通信进行深入分析。有关如何执行此解密的更多详细信息，请参阅 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) 的指南。

要检测此内容，请在环境中搜索变量 `SSLKEYLOGFILE`

共享密钥的文件看起来像这样：

![](<../../../.gitbook/assets/image (820).png>)

要在 Wireshark 中导入此文件，请转到 _edit > preference > protocol > ssl > 并将其导入 (Pre)-Master-Secret 日志文件名：

![](<../../../.gitbook/assets/image (989).png>)

## ADB 通信

从 ADB 通信中提取 APK，其中 APK 被发送：
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
{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
