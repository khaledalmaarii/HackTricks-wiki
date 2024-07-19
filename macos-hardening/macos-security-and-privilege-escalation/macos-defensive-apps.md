# macOS Defensive Apps

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## ファイアウォール

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html)：各プロセスによって行われるすべての接続を監視します。モード（接続を静かに許可、接続を静かに拒否し警告）に応じて、新しい接続が確立されるたびに**警告を表示**します。また、この情報をすべて見るための非常に良いGUIがあります。
* [**LuLu**](https://objective-see.org/products/lulu.html)：Objective-Seeのファイアウォール。これは、疑わしい接続に対して警告を出す基本的なファイアウォールです（GUIはありますが、Little Snitchのものほど豪華ではありません）。

## 永続性検出

* [**KnockKnock**](https://objective-see.org/products/knockknock.html)：**マルウェアが永続している可能性のある**いくつかの場所を検索するObjective-Seeのアプリケーションです（これは一回限りのツールで、監視サービスではありません）。
* [**BlockBlock**](https://objective-see.org/products/blockblock.html)：KnockKnockのように、永続性を生成するプロセスを監視します。

## キーロガー検出

* [**ReiKey**](https://objective-see.org/products/reikey.html)：キーボードの「イベントタップ」をインストールする**キーロガー**を見つけるためのObjective-Seeのアプリケーションです。
