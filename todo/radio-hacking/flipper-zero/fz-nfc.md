# FZ - NFC

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}

## 介绍 <a href="#id-9wrzi" id="id-9wrzi"></a>

有关 RFID 和 NFC 的信息，请查看以下页面：

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## 支持的 NFC 卡 <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
除了 NFC 卡，Flipper Zero 还支持 **其他类型的高频卡**，例如几种 **Mifare** Classic 和 Ultralight 以及 **NTAG**。
{% endhint %}

新的 NFC 卡类型将被添加到支持的卡列表中。Flipper Zero 支持以下 **NFC 卡类型 A** (ISO 14443A):

* ﻿**银行卡 (EMV)** — 仅读取 UID、SAK 和 ATQA，而不保存。
* ﻿**未知卡** — 读取 (UID, SAK, ATQA) 并模拟一个 UID。

对于 **NFC 卡类型 B、F 和 V**，Flipper Zero 能够读取 UID 而不保存。

### NFC 卡类型 A <a href="#uvusf" id="uvusf"></a>

#### 银行卡 (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero 只能读取银行卡的 UID、SAK、ATQA 和存储数据 **而不保存**。

银行卡读取界面对于银行卡，Flipper Zero 只能读取数据 **而不保存和模拟**。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 未知卡 <a href="#id-37eo8" id="id-37eo8"></a>

当 Flipper Zero **无法确定 NFC 卡的类型**时，仅能 **读取和保存 UID、SAK 和 ATQA**。

未知卡读取界面对于未知 NFC 卡，Flipper Zero 只能模拟一个 UID。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC 卡类型 B、F 和 V <a href="#wyg51" id="wyg51"></a>

对于 **NFC 卡类型 B、F 和 V**，Flipper Zero 只能 **读取和显示 UID** 而不保存。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## 操作

有关 NFC 的介绍 [**请阅读此页面**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)。

### 读取

Flipper Zero 可以 **读取 NFC 卡**，但是它 **不理解所有基于 ISO 14443 的协议**。然而，由于 **UID 是一个低级属性**，您可能会发现自己处于一种情况，即 **UID 已经被读取，但高级数据传输协议仍然未知**。您可以使用 Flipper 读取、模拟和手动输入 UID，以便为使用 UID 进行授权的原始读取器。

#### 读取 UID 与读取内部数据 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

在 Flipper 中，读取 13.56 MHz 标签可以分为两个部分：

* **低级读取** — 仅读取 UID、SAK 和 ATQA。Flipper 尝试根据从卡片读取的数据猜测高级协议。您不能对此 100% 确定，因为这只是基于某些因素的假设。
* **高级读取** — 使用特定的高级协议从卡片的内存中读取数据。这将是读取 Mifare Ultralight 上的数据、从 Mifare Classic 读取扇区，或从 PayPass/Apple Pay 读取卡片的属性。

### 读取特定

如果 Flipper Zero 无法从低级数据中找到卡片的类型，在 `额外操作` 中，您可以选择 `读取特定卡片类型` 并 **手动** **指明您想要读取的卡片类型**。

#### EMV 银行卡 (PayPass、payWave、Apple Pay、Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

除了简单地读取 UID，您还可以从银行卡中提取更多数据。可以 **获取完整的卡号**（卡片正面的 16 位数字）、**有效期**，在某些情况下甚至可以获取 **持卡人姓名** 以及 **最近交易** 的列表。\
但是，您 **无法通过这种方式读取 CVV**（卡片背面的 3 位数字）。此外，**银行卡受到重放攻击的保护**，因此使用 Flipper 复制后再尝试模拟支付是行不通的。

## 参考

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
