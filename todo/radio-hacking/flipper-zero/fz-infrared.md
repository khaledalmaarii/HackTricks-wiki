# FZ - 赤外線

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}

## はじめに <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

赤外線の仕組みについての詳細は、以下を確認してください：

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper ZeroのIR信号受信機 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

FlipperはデジタルIR信号受信機TSOPを使用しており、**IRリモコンからの信号を傍受することができます**。Xiaomiのような**スマートフォン**の中にはIRポートを持つものもありますが、**ほとんどは信号を送信することしかできず**、受信することはできません。

Flipperの赤外線**受信機は非常に敏感です**。リモコンとテレビの間にいる状態でも**信号をキャッチすることができます**。リモコンをFlipperのIRポートに直接向ける必要はありません。これは、誰かがテレビの近くでチャンネルを切り替えているときに便利で、あなたとFlipperが少し離れた場所にいる場合でも機能します。

**赤外線信号のデコードは**ソフトウェア側で行われるため、Flipper Zeroは**あらゆるIRリモコンコードの受信と送信をサポートする可能性があります**。認識できない**未知の**プロトコルの場合、Flipperは受信したままの生信号を**記録して再生します**。

## アクション

### ユニバーサルリモコン

Flipper Zeroは、**任意のテレビ、エアコン、またはメディアセンターを制御するためのユニバーサルリモコンとして使用できます**。このモードでは、Flipperは**SDカードの辞書に基づいて**すべてのサポートされているメーカーの**既知のコードを総当たりで試します**。レストランのテレビを消すために特定のリモコンを選ぶ必要はありません。

ユニバーサルリモコンモードで電源ボタンを押すだけで、Flipperは知っているすべてのテレビの「電源オフ」コマンドを**順次送信します**：Sony、Samsung、Panasonic...など。テレビが信号を受信すると、反応してオフになります。

このような総当たりには時間がかかります。辞書が大きいほど、完了するまでの時間が長くなります。テレビが正確にどの信号を認識したかを知ることはできません。テレビからのフィードバックがないためです。

### 新しいリモコンを学ぶ

Flipper Zeroで**赤外線信号をキャプチャする**ことが可能です。データベース内で信号を**見つけた場合**、Flipperは自動的に**このデバイスが何であるかを知り**、それと対話できるようになります。\
見つからない場合、Flipperは**信号を保存**し、**再生する**ことを許可します。

## 参考文献

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}
