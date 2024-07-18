# Wifi Pcap 分析

{% hint style="success" %}
学习与实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习与实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## 检查 BSSID

当你收到一个主要流量为 Wifi 的捕获文件时，使用 WireShark 你可以开始调查捕获中的所有 SSID，方法是选择 _Wireless --> WLAN Traffic_：

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### 暴力破解

该屏幕的其中一列指示是否在 pcap 中发现了 **任何身份验证**。如果是这种情况，你可以尝试使用 `aircrack-ng` 进行暴力破解：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例如，它将检索保护PSK（预共享密钥）的WPA密码短语，这将在稍后解密流量时需要。

## 信标中的数据 / 侧信道

如果您怀疑**数据在Wifi网络的信标中泄露**，可以使用以下过滤器检查网络的信标：`wlan contains <NAMEofNETWORK>`，或`wlan.ssid == "NAMEofNETWORK"`，在过滤后的数据包中搜索可疑字符串。

## 在Wifi网络中查找未知MAC地址

以下链接将有助于查找**在Wifi网络中发送数据的机器**：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果您已经知道**MAC地址，可以通过添加检查将其从输出中移除**，例如：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

一旦您检测到**在网络中通信的未知MAC**地址，可以使用**过滤器**，例如：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`来过滤其流量。请注意，ftp/http/ssh/telnet过滤器在您解密流量后非常有用。

## 解密流量

编辑 --> 首选项 --> 协议 --> IEEE 802.11--> 编辑

![](<../../../.gitbook/assets/image (499).png>)

{% hint style="success" %}
学习和实践AWS黑客攻击：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践GCP黑客攻击：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**在** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注我们。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub库提交PR分享黑客技巧。

</details>
{% endhint %}
