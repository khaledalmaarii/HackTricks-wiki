<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 检查BSSID

当您收到一个主要流量为Wifi的捕获时，您可以使用WireShark开始调查捕获中的所有SSID，方法是_Wireless --> WLAN Traffic_：

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## 暴力破解

该屏幕的一列指示**在pcap中是否找到任何身份验证**。如果是这种情况，您可以尝试使用`aircrack-ng`进行暴力破解：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
# 数据在信标/侧通道中

如果您怀疑**数据正在Wifi网络的信标中泄漏**，您可以使用类似以下过滤器来检查网络的信标：`wlan contains <NAMEofNETWORK>`，或者 `wlan.ssid == "NAMEofNETWORK"`，在过滤后的数据包中搜索可疑字符串。

# 在Wifi网络中查找未知MAC地址

以下链接将有助于找到**在Wifi网络中发送数据的设备**：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果您已经知道**MAC地址，您可以从输出中删除它们**，添加类似这样的检查：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

一旦您发现**在网络中通信的未知MAC地址**，您可以使用类似以下的**过滤器**：`wlan.addr==<MAC地址> && (ftp || http || ssh || telnet)` 来过滤其流量。请注意，如果您已解密流量，ftp/http/ssh/telnet过滤器将非常有用。

# 解密流量

编辑 --> 首选项 --> 协议 --> IEEE 802.11--> 编辑

![](<../../../.gitbook/assets/image (426).png>)
