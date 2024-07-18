{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}


# 检查BSSIDs

当你收到一个主要流量为Wifi的捕获文件时，你可以使用 WireShark 开始调查捕获文件中所有的 SSID，路径为_Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## 暴力破解

屏幕的一列指示了 pcap 文件中是否找到**任何身份验证**。如果是这种情况，你可以尝试使用 `aircrack-ng` 进行暴力破解：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
# 在信标/侧通道中的数据

如果你怀疑**数据正在泄漏到Wifi网络的信标中**，你可以使用类似以下过滤器来检查网络的信标：`wlan contains <NETWORK名称>`，或者 `wlan.ssid == "NETWORK名称"`，在过滤后的数据包中搜索可疑字符串。

# 在Wifi网络中查找未知的MAC地址

以下链接将有助于找到**在Wifi网络中发送数据的设备**：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果你已经知道**MAC地址，你可以从输出中删除它们**，添加类似这样的检查：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

一旦你发现**在网络中通信的未知MAC地址**，你可以使用类似以下的**过滤器**：`wlan.addr==<MAC地址> && (ftp || http || ssh || telnet)` 来过滤其流量。请注意，如果你已解密流量，ftp/http/ssh/telnet过滤器将非常有用。

# 解密流量

编辑 --> 首选项 --> 协议 --> IEEE 802.11--> 编辑

![](<../../../.gitbook/assets/image (426).png>)
