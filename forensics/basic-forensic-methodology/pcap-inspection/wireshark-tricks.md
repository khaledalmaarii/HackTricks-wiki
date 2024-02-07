# Wireshark技巧

## Wireshark技巧

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 提升您的Wireshark技能

### 教程

以下教程非常适合学习一些很酷的基本技巧：

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析信息

**专家信息**

点击 _**Analyze** --> **Expert Information**_ 您将获得对**分析**的数据包的**概述**：

![](<../../../.gitbook/assets/image (570).png>)

**解析地址**

在 _**Statistics --> Resolved Addresses**_ 下，您可以找到Wireshark解析的一些信息，如端口/传输到协议，MAC到制造商等。了解通信中涉及的内容是很有趣的。

![](<../../../.gitbook/assets/image (571).png>)

**协议层次结构**

在 _**Statistics --> Protocol Hierarchy**_ 下，您可以找到通信中涉及的**协议**及其相关数据。

![](<../../../.gitbook/assets/image (572).png>)

**对话**

在 _**Statistics --> Conversations**_ 下，您可以找到通信中对话的**摘要**及其相关数据。

![](<../../../.gitbook/assets/image (573).png>)

**端点**

在 _**Statistics --> Endpoints**_ 下，您可以找到通信中端点的**摘要**及每个端点的相关数据。

![](<../../../.gitbook/assets/image (575).png>)

**DNS信息**

在 _**Statistics --> DNS**_ 下，您可以找到有关捕获的DNS请求的统计信息。

![](<../../../.gitbook/assets/image (577).png>)

**I/O图**

在 _**Statistics --> I/O Graph**_ 下，您可以找到通信的**图表**。

![](<../../../.gitbook/assets/image (574).png>)

### 过滤器

在这里，您可以找到根据协议的Wireshark过滤器：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
其他有趣的过滤器：

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP和初始HTTPS流量
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP和初始HTTPS流量 + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP和初始HTTPS流量 + TCP SYN + DNS请求

### 搜索

如果您想在会话的数据包中**搜索**内容，请按下CTRL+f。您可以通过按右键然后编辑列来向主信息栏添加新层（编号、时间、来源等）。

### 免费的pcap实验室

**练习免费挑战：[https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)**

## 识别域名

您可以添加一个显示Host HTTP标头的列：

![](<../../../.gitbook/assets/image (403).png>)

以及添加一个从初始HTTPS连接中添加服务器名称的列（**ssl.handshake.type == 1**）：

![](<../../../.gitbook/assets/image (408) (1).png>)

## 识别本地主机名

### 从DHCP

在当前的Wireshark中，您需要搜索`DHCP`而不是`bootp`

![](<../../../.gitbook/assets/image (404).png>)

### 从NBNS

![](<../../../.gitbook/assets/image (405).png>)

## 解密TLS

### 使用服务器私钥解密https流量

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

点击_Edit_，然后添加服务器和私钥的所有数据（_IP、端口、协议、密钥文件和密码_）

### 使用对称会话密钥解密https流量

Firefox和Chrome都可以记录TLS会话密钥，这些密钥可以与Wireshark一起用于解密TLS流量。这允许对安全通信进行深入分析。有关如何执行此解密的更多详细信息，请参阅[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)的指南。

要检测此内容，请在环境中搜索变量`SSLKEYLOGFILE`

共享密钥文件如下所示：

![](<../../../.gitbook/assets/image (99).png>)

要将其导入Wireshark，请转到_edit > preference > protocol > ssl > 并将其导入到（Pre）-Master-Secret日志文件名中：

![](<../../../.gitbook/assets/image (100).png>)

## ADB通信

从发送APK的ADB通信中提取APK：
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

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索我们的独家[**NFTs**]收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
