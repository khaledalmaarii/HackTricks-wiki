# FZ - NFC

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要在HackTricks上看到您的**公司广告**吗？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[NFT收藏品](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向** [**hacktricks仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧**。

</details>

## 简介 <a href="#id-9wrzi" id="id-9wrzi"></a>

有关RFID和NFC的信息，请查看以下页面：

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## 支持的NFC卡 <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
除了NFC卡外，Flipper Zero还支持**其他类型的高频卡**，如几种**Mifare** Classic和Ultralight以及**NTAG**。
{% endhint %}

新类型的NFC卡将被添加到支持卡列表中。Flipper Zero支持以下**NFC卡类型A**（ISO 14443A）：

* ﻿**银行卡（EMV）** — 仅读取UID、SAK和ATQA，不保存。
* ﻿**未知卡** — 读取（UID、SAK、ATQA）并模拟UID。

对于**NFC卡类型B、类型F和类型V**，Flipper Zero能够读取UID但不保存。

### NFC卡类型A <a href="#uvusf" id="uvusf"></a>

#### 银行卡（EMV） <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero只能读取UID、SAK、ATQA和银行卡上的存储数据，**不保存**。

银行卡读取屏幕对于银行卡，Flipper Zero只能读取数据，**不能保存和模拟**。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 未知卡 <a href="#id-37eo8" id="id-37eo8"></a>

当Flipper Zero**无法确定NFC卡的类型**时，只能读取和保存**UID、SAK和ATQA**。

未知卡读取屏幕对于未知的NFC卡，Flipper Zero只能模拟UID。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC卡类型B、F和V <a href="#wyg51" id="wyg51"></a>

对于**NFC卡类型B、F和V**，Flipper Zero只能读取和显示UID，不保存。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## 操作

有关NFC的简介，请阅读[**此页面**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)。

### 读取

Flipper Zero可以**读取NFC卡**，但是它**不理解**基于ISO 14443的所有协议。然而，由于**UID是低级属性**，您可能会发现自己处于一种情况，即**UID已被读取，但高级数据传输协议仍然未知**。您可以使用Flipper读取、模拟和手动输入UID，用于使用UID进行授权的基本读卡器。

#### 读取UID与读取内部数据的区别 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

在Flipper中，读取13.56 MHz标签可以分为两部分：

* **低级读取** — 仅读取UID、SAK和ATQA。Flipper尝试根据从卡中读取的数据猜测高级协议。由于这仅是基于某些因素的假设，您无法百分之百确定。
* **高级读取** — 使用特定的高级协议从卡的存储器中读取数据。这将是读取Mifare Ultralight上的数据，读取Mifare Classic中的扇区，或者从PayPass/Apple Pay中读取卡的属性。

### 特定读取

如果Flipper Zero无法从低级数据中找到卡的类型，在`额外操作`中，您可以选择`读取特定卡类型`，**手动** **指定您想要读取的卡的类型**。

#### EMV银行卡（PayPass、payWave、Apple Pay、Google Pay） <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

除了简单读取UID外，您还可以从银行卡中提取更多数据。可以**获取完整的卡号**（卡片正面的16位数字）、**有效日期**，在某些情况下甚至可以获取**持卡人姓名**以及**最近交易清单**。\
但是，**无法通过此方式读取CVV**（卡片背面的3位数字）。此外，**银行卡受到重放攻击的保护**，因此使用Flipper复制卡片然后尝试模拟支付某物是行不通的。
## 参考资料

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要在HackTricks中看到您的**公司广告**？ 或者想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR**来分享您的黑客技巧。

</details>
