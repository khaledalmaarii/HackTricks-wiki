# macOS Apple Scripts

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Apple Scripts

リモートプロセスと対話するためのタスク自動化に使用されるスクリプト言語です。これは、他のプロセスにいくつかのアクションを実行するように要求することを非常に簡単にします。**マルウェア**は、これらの機能を悪用して他のプロセスによってエクスポートされた機能を悪用する可能性があります。\
例えば、マルウェアは**ブラウザで開かれたページに任意のJSコードを注入する**ことができます。または、ユーザーに要求された許可を**自動的にクリック**することができます；
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
ここにいくつかの例があります: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
マルウェアに関する詳細情報は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)で確認できます。

Appleスクリプトは簡単に「**コンパイル**」できます。これらのバージョンは`osadecompile`を使用して簡単に「**デコンパイル**」できます。

しかし、これらのスクリプトは「読み取り専用」としても**エクスポート**できます（「エクスポート...」オプションを介して）:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
そして、この場合、`osadecompile`を使用してもコンテンツは逆コンパイルできません。

しかし、この種の実行可能ファイルを理解するために使用できるツールはいくつかあります。[**詳細についてはこの研究をお読みください**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。ツール[**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler)と[**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile)は、スクリプトの動作を理解するのに非常に役立ちます。

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
