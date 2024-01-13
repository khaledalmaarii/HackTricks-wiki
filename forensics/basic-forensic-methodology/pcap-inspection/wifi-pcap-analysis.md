<details>

<summary><strong>零基础学习AWS黑客攻击直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 检查BSSIDs

当你接收到一个主要流量是使用WireShark的Wifi的捕获时，你可以开始调查捕获中所有的SSIDs，方法是 _Wireless --> WLAN Traffic_：

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## 暴力破解

该屏幕的其中一列显示是否在pcap中**发现了任何认证**。如果是这样，你可以尝试使用`aircrack-ng`进行暴力破解：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例如，它将检索保护PSK（预共享密钥）的WPA密码短语，稍后将需要它来解密流量。

# 数据在信标 / 旁道信道中

如果您怀疑**数据正在Wifi网络的信标中泄露**，您可以使用类似以下的过滤器来检查网络的信标：`wlan contains <NAMEofNETWORK>`，或者`wlan.ssid == "NAMEofNETWORK"`在过滤后的数据包中搜索可疑字符串。

# 在Wifi网络中找到未知的MAC地址

以下链接将有助于找到**在Wifi网络内发送数据的设备**：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果您已经知道**MAC地址，您可以通过添加像这样的检查来从输出中删除它们**：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

一旦您检测到在网络内通信的**未知MAC**地址，您可以使用类似以下的**过滤器**：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`来过滤其流量。请注意，如果您已经解密了流量，ftp/http/ssh/telnet过滤器将会很有用。

# 解密流量

编辑 --> 偏好设置 --> 协议 --> IEEE 802.11--> 编辑

![](<../../../.gitbook/assets/image (426).png>)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
