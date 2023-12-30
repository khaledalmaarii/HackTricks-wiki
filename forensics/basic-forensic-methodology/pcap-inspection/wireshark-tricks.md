# Wireshark 技巧

## Wireshark 技巧

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 **HackTricks** 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>

## 提升你的 Wireshark 技能

### 教程

以下教程非常适合学习一些基本的酷炫技巧：

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析信息

**专家信息**

点击 _**分析** --> **专家信息**_，您将获得对分析中的数据包发生情况的**概览**：

![](<../../../.gitbook/assets/image (570).png>)

**解析地址**

在 _**统计 --> 解析地址**_ 下，您可以找到 Wireshark 解析的各种**信息**，如端口/传输协议到协议，MAC 到制造商等。了解哪些内容涉及通信是很有趣的。

![](<../../../.gitbook/assets/image (571).png>)

**协议层次结构**

在 _**统计 --> 协议层次结构**_ 下，您可以找到通信中涉及的**协议**及其数据。

![](<../../../.gitbook/assets/image (572).png>)

**对话**

在 _**统计 --> 对话**_ 下，您可以找到通信中**对话的摘要**及其数据。

![](<../../../.gitbook/assets/image (573).png>)

**端点**

在 _**统计 --> 端点**_ 下，您可以找到通信中**端点的摘要**及其每个端点的数据。

![](<../../../.gitbook/assets/image (575).png>)

**DNS 信息**

在 _**统计 --> DNS**_ 下，您可以找到捕获的 DNS 请求的统计信息。

![](<../../../.gitbook/assets/image (577).png>)

**I/O 图表**

在 _**统计 --> I/O 图表**_ 下，您可以找到**通信图表**。

![](<../../../.gitbook/assets/image (574).png>)

### 过滤器

在这里，您可以根据协议找到 Wireshark 过滤器：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
其他有趣的过滤器：

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTP 和初始 HTTPS 流量
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTP 和初始 HTTPS 流量 + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTP 和初始 HTTPS 流量 + TCP SYN + DNS 请求

### 搜索

如果您想要在会话的**数据包**中**搜索**内容，请按 _CTRL+f_。您可以通过右键单击然后编辑列，向主信息栏（编号、时间、来源等）添加新层。

实践：[https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## 识别域名

您可以添加一个显示 HTTP Host 头的列：

![](<../../../.gitbook/assets/image (403).png>)

以及一个添加来自初始 HTTPS 连接的服务器名称的列（**ssl.handshake.type == 1**）：

![](<../../../.gitbook/assets/image (408) (1).png>)

## 识别本地主机名

### 来自 DHCP

在当前的 Wireshark 中，您需要搜索 `DHCP` 而不是 `bootp`

![](<../../../.gitbook/assets/image (404).png>)

### 来自 NBNS

![](<../../../.gitbook/assets/image (405).png>)

## 解密 TLS

### 使用服务器私钥解密 https 流量

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

按 _编辑_ 并添加服务器和私钥的所有数据（_IP、端口、协议、密钥文件和密码_）

### 使用对称会话密钥解密 https 流量

Firefox 和 Chrome 都支持将用于加密 TLS 流量的对称会话密钥记录到文件中。然后，您可以指向 Wireshark 该文件，即可！解密的 TLS 流量。更多信息：[https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
要检测这一点，请在环境内搜索变量 `SSLKEYLOGFILE`

共享密钥的文件看起来像这样：

![](<../../../.gitbook/assets/image (99).png>)

要在 wireshark 中导入此文件，请转到 _edit > preference > protocol > ssl > 并将其导入 (Pre)-Master-Secret log filename：

![](<../../../.gitbook/assets/image (100).png>)

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
<details>

<summary><strong>从零到英雄学习AWS黑客技术，参加</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
