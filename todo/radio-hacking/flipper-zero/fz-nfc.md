# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**？或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**？查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组**](https://t.me/peass) 或 **关注** 我在 **推特** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。
* 通过向 **hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

发现最重要的漏洞，以便更快修复。Intruder 跟踪您的攻击面，运行主动威胁扫描，发现从 API 到 Web 应用程序和云系统的问题。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 简介 <a href="#9wrzi" id="9wrzi"></a>

有关 RFID 和 NFC 的信息，请查看以下页面：

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## 支持的 NFC 卡 <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
除了 NFC 卡外，Flipper Zero 还支持**其他类型的高频卡**，如几种**Mifare** Classic 和 Ultralight 以及**NTAG**。
{% endhint %}

新类型的 NFC 卡将被添加到支持卡列表中。Flipper Zero 支持以下**NFC 卡类型 A** (ISO 14443A)：

* ﻿**银行卡 (EMV)** — 仅读取 UID、SAK 和 ATQA，不保存。
* ﻿**未知卡** — 读取 (UID、SAK、ATQA) 并模拟一个 UID。

对于**NFC 卡类型 B、类型 F 和类型 V**，Flipper Zero 能够读取 UID，但不保存。

### NFC 卡类型 A <a href="#uvusf" id="uvusf"></a>

#### 银行卡 (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero 只能读取银行卡的 UID、SAK、ATQA 和存储数据，**不保存**。

银行卡读取屏幕对于银行卡，Flipper Zero 只能读取数据，**不保存和模拟**。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 未知卡 <a href="#37eo8" id="37eo8"></a>

当 Flipper Zero **无法确定 NFC 卡的类型**时，只能读取和保存**UID、SAK 和 ATQA**。

未知卡读取屏幕对于未知的 NFC 卡，Flipper Zero 只能模拟一个 UID。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC 卡类型 B、F 和 V <a href="#wyg51" id="wyg51"></a>

对于**NFC 卡类型 B、F 和 V**，Flipper Zero 只能读取和显示 UID，不保存。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## 操作

有关 NFC 的简介，请阅读[**此页面**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)。

### 读取

Flipper Zero 可以**读取 NFC 卡**，但它**不理解**基于 ISO 14443 的所有协议。然而，由于**UID 是低级属性**，您可能会发现自己处于一种情况，即**UID 已经被读取，但高级数据传输协议仍然未知**。您可以使用 Flipper 为使用 UID 进行授权的原始读卡器读取、模拟和手动输入 UID。

#### 读取 UID 与读取内部数据的区别 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

在 Flipper 中，读取 13.56 MHz 标签可以分为两部分：

* **低级读取** — 仅读取 UID、SAK 和 ATQA。Flipper 试图根据从卡中读取的数据猜测高级协议。由于这只是基于某些因素的假设，您无法百分之百确定。
* **高级读取** — 使用特定的高级协议从卡的存储器中读取数据。这将是读取 Mifare Ultralight 上的数据，读取 Mifare Classic 中的扇区，或者从 PayPass/Apple Pay 中读取卡的属性。

### 读取特定卡

如果 Flipper Zero 无法从低级数据中找到卡的类型，在 `额外操作` 中，您可以选择 `读取特定卡类型` 并**手动指定您想要读取的卡的类型**。

#### EMV 银行卡 (PayPass、payWave、Apple Pay、Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

除了简单读取 UID 外，您还可以从银行卡中提取更多数据。可以**获取完整的卡号**（卡片正面的 16 位数字）、**有效日期**，在某些情况下甚至可以获取**持卡人姓名**以及**最近交易清单**。\
但是，**无法通过此方式读取 CVV**（卡片背面的 3 位数字）。此外，**银行卡受到重放攻击的保护**，因此使用 Flipper 复制卡片然后尝试模拟支付可能不起作用。

## 参考

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

发现最重要的漏洞，以便更快修复。Intruder 跟踪您的攻击面，运行主动威胁扫描，发现从 API 到 Web 应用程序和云系统的问题。[**立即免费试用**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在 HackTricks 中看到你的**公司广告**？或者想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**？查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 探索我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组**](https://t.me/peass) 或 **关注** 我在 **推特** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。
* 通过向 **hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。

</details>
