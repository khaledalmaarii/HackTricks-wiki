# Wifi Pcap 分析

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想看到您的**公司在 HackTricks 中做广告**或**下载 PDF 格式的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们**。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 检查 BSSIDs

当您收到一个主要流量为 Wifi 的捕获时，可以使用 WireShark 开始调查捕获中的所有 SSID，路径为 _Wireless --> WLAN Traffic_：

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### 暴力破解

该屏幕的一列指示**在 pcap 中是否找到任何身份验证**。如果是这种情况，您可以尝试使用 `aircrack-ng` 进行暴力破解：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
## 在信标/侧通道中的数据

如果你怀疑**数据正在Wifi网络的信标中泄露**，你可以使用类似以下过滤器来检查网络的信标：`wlan contains <NETWORK名称>`，或者 `wlan.ssid == "NETWORK名称"`，在过滤后的数据包中搜索可疑字符串。

## 在Wifi网络中查找未知的MAC地址

以下链接将有助于找到**在Wifi网络中发送数据的设备**：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果你已经知道**MAC地址，你可以从输出中删除它们**，添加类似这样的检查：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

一旦你发现了**在网络中通信的未知MAC地址**，你可以使用类似以下的**过滤器**：`wlan.addr==<MAC地址> && (ftp || http || ssh || telnet)` 来过滤其流量。请注意，ftp/http/ssh/telnet 过滤器在你解密了流量后会很有用。

## 解密流量

编辑 --> 首选项 --> 协议 --> IEEE 802.11--> 编辑

![](<../../../.gitbook/assets/image (499).png>)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想看到你的**公司在 HackTricks 中做广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** 上关注我们**。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。

</details>
