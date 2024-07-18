# FZ - NFC

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}

## はじめに <a href="#id-9wrzi" id="id-9wrzi"></a>

RFIDおよびNFCに関する情報は、以下のページを確認してください：

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## 対応するNFCカード <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
NFCカードの他に、Flipper Zeroは**他のタイプの高周波カード**、例えばいくつかの**Mifare** ClassicおよびUltralight、**NTAG**をサポートしています。
{% endhint %}

新しいタイプのNFCカードがサポートカードのリストに追加されます。Flipper Zeroは以下の**NFCカードタイプA**（ISO 14443A）をサポートしています：

* ﻿**銀行カード（EMV）** — UID、SAK、ATQAのみを読み取り、保存しません。
* ﻿**不明なカード** — UID、SAK、ATQAを読み取り、UIDをエミュレートします。

**NFCカードタイプB、タイプF、タイプV**については、Flipper ZeroはUIDを読み取ることができますが、保存はできません。

### NFCカードタイプA <a href="#uvusf" id="uvusf"></a>

#### 銀行カード（EMV） <a href="#kzmrp" id="kzmrp"></a>

Flipper Zeroは銀行カードのUID、SAK、ATQA、および保存されたデータを**保存せずに**読み取ることができます。

銀行カード読み取り画面銀行カードについて、Flipper Zeroはデータを**保存せずにエミュレートすることなく**読み取ることができます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 不明なカード <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zeroが**NFCカードのタイプを特定できない場合**、UID、SAK、ATQAのみを**読み取り、保存**できます。

不明なカード読み取り画面不明なNFCカードについて、Flipper ZeroはUIDのみをエミュレートできます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFCカードタイプB、F、V <a href="#wyg51" id="wyg51"></a>

**NFCカードタイプB、F、V**について、Flipper ZeroはUIDを**読み取り、表示することができますが、保存はできません**。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## アクション

NFCについてのイントロは[**このページを読んでください**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)。

### 読み取り

Flipper Zeroは**NFCカードを読み取ることができますが、ISO 14443に基づくすべてのプロトコルを理解しているわけではありません**。ただし、**UIDは低レベルの属性であるため、**UIDがすでに読み取られているが、高レベルのデータ転送プロトコルがまだ不明な状況に遭遇することがあります。Flipperを使用して、UIDを読み取り、エミュレートし、手動で入力することができます。

#### UIDの読み取りと内部データの読み取りの違い <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Flipperでは、13.56 MHzタグの読み取りは2つの部分に分けられます：

* **低レベルの読み取り** — UID、SAK、ATQAのみを読み取ります。Flipperは、カードから読み取ったこのデータに基づいて高レベルのプロトコルを推測しようとします。これは特定の要因に基づく仮定に過ぎないため、100%確実ではありません。
* **高レベルの読み取り** — 特定の高レベルプロトコルを使用してカードのメモリからデータを読み取ります。これは、Mifare Ultralightのデータを読み取ったり、Mifare Classicのセクターを読み取ったり、PayPass/Apple Payからカードの属性を読み取ったりすることです。

### 特定の読み取り

Flipper Zeroが低レベルデータからカードのタイプを見つけられない場合、`Extra Actions`で`Read Specific Card Type`を選択し、**手動で読み取りたいカードのタイプを指定**できます。

#### EMV銀行カード（PayPass、payWave、Apple Pay、Google Pay） <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UIDを単に読み取るだけでなく、銀行カードからはさらに多くのデータを抽出できます。**カード番号全体**（カードの前面にある16桁）、**有効期限**、場合によっては**所有者の名前**や**最近の取引のリスト**さえ取得できます。\
ただし、この方法では**CVVを読み取ることはできません**（カードの裏面にある3桁の数字）。また、**銀行カードはリプレイ攻撃から保護されているため**、Flipperでコピーしてからエミュレートして支払いに使用することはできません。

## 参考文献

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
