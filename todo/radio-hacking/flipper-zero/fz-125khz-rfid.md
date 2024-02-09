# FZ - 125kHz RFID

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 简介

有关125kHz标签工作原理的更多信息，请查看：

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## 操作

有关这些类型标签的更多信息，请[**阅读此简介**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz)。

### 读取

尝试**读取**卡片信息。然后可以**模拟**它们。

{% hint style="warning" %}
请注意，一些对讲机会通过在读取之前发送写入命令来防止密钥复制。如果写入成功，则该标签被视为伪造的。当Flipper模拟RFID时，读卡器无法区分它与原始卡之间的区别，因此不会出现此类问题。
{% endhint %}

### 手动添加

您可以在Flipper Zero中创建**指示手动输入数据**的**伪造卡**，然后进行模拟。

#### 卡片上的ID

有时，当您获得一张卡时，您会发现卡片上写有ID（或部分ID）。

* **EM Marin**

例如，在这张EM-Marin卡中，可以在物理卡上**清晰地读取最后的5字节中的3字节**。\
如果无法从卡片上读取，另外的2字节可以通过暴力破解获得。

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

在这张HID卡中，只有3字节中的2字节可以在卡片上找到

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### 模拟/写入

在**复制**卡片或**手动输入**ID后，可以使用Flipper Zero进行**模拟**，或将其**写入**真实卡片中。

## 参考

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
