# メモリダンプ分析

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

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの一つです。**技術知識の促進**を使命とし、この会議はあらゆる分野の技術およびサイバーセキュリティ専門家の熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## 開始

**pcap**内で**マルウェア**を**検索**し始めます。 [**マルウェア分析**](../malware-analysis.md)で言及されている**ツール**を使用してください。

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatilityはメモリダンプ分析のための主要なオープンソースフレームワークです**。このPythonツールは、外部ソースまたはVMware VMからのダンプを分析し、ダンプのOSプロファイルに基づいてプロセスやパスワードなどのデータを特定します。プラグインで拡張可能であり、法医学的調査に非常に柔軟です。

**[ここにチートシートがあります](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**


## ミニダンプクラッシュレポート

ダンプが小さい場合（数KB、場合によっては数MB）これはおそらくミニダンプクラッシュレポートであり、メモリダンプではありません。

![](<../../../.gitbook/assets/image (216).png>)

Visual Studioがインストールされている場合、このファイルを開いてプロセス名、アーキテクチャ、例外情報、実行中のモジュールなどの基本情報をバインドできます：

![](<../../../.gitbook/assets/image (217).png>)

例外をロードして、デコンパイルされた命令を見ることもできます

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

いずれにせよ、Visual Studioはダンプの深さの分析を行うための最良のツールではありません。

**IDA**または**Radare**を使用して**深く**検査するために**開く**べきです。



​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの一つです。**技術知識の促進**を使命とし、この会議はあらゆる分野の技術およびサイバーセキュリティ専門家の熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

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
