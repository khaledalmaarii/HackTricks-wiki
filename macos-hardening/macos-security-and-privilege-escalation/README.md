# macOSセキュリティ＆特権昇格

{% hint style="success" %}
AWSハッキングの学習と実践：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取るために[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)サーバーに参加しましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加しましょう

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界を最新の状態に保ちましょう

**最新のアナウンス**\
最新のバグバウンティの開始や重要なプラットフォームのアップデートについて情報を得ましょう

**[Discord](https://discord.com/invite/N3FrSbmwdy)に参加**して、今日からトップハッカーと協力を始めましょう！

## 基本的なMacOS

MacOSに慣れていない場合は、MacOSの基本を学ぶべきです：

* 特別なMacOS **ファイルと権限:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 一般的なMacOS **ユーザー**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **カーネルの** **アーキテクチャ**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 一般的なMacOS **ネットワークサービスとプロトコル**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **オープンソース**MacOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* `tar.gz`をダウンロードするには、[https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)のようなURLを[https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)に変更します

### MacOS MDM

企業では、**macOS**システムはおそらく**MDMで管理**される可能性が高いです。したがって、攻撃者の視点からは、**それがどのように機能するか**を知ることが重要です：

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 検査、デバッグ、およびFuzzing

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOSセキュリティ保護

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 攻撃対象

### ファイル権限

**rootとして実行されるプロセスが**ユーザーによって制御可能なファイルに書き込む場合、ユーザーはこれを悪用して**特権を昇格**する可能性があります。\
これは次の状況で発生する可能性があります：

* 使用されるファイルはすでにユーザーによって作成されていた（ユーザー所有）
* 使用されるファイルはグループによって書き込み可能である
* 使用されるファイルはユーザーが所有するディレクトリ内にある（ユーザーがファイルを作成できる）
* 使用されるファイルはrootが所有するディレクトリ内にありますが、ユーザーがグループによる書き込みアクセス権を持っているため（ユーザーがファイルを作成できる）

**rootが使用するファイル**を**作成できる**ようになると、ユーザーはその内容を**利用**したり、別の場所を指す**シンボリックリンク/ハードリンク**を作成したりすることができます。

この種の脆弱性をチェックする際には、**脆弱な`.pkg`インストーラー**を忘れないでください：

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### ファイル拡張子とURLスキームアプリハンドラ

ファイル拡張子によって登録された奇妙なアプリケーションは悪用され、異なるアプリケーションが特定のプロトコルを開くように登録される可能性があります

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP特権昇格

macOSでは、**アプリケーションやバイナリには**他のものよりも特権の高いフォルダや設定にアクセスする**権限**が与えられることがあります。

したがって、macOSマシンを成功裏に侵害したい攻撃者は、**TCC権限を昇格**する必要があります（または、必要に応じて**SIPをバイパス**する必要があります）。

これらの特権は、アプリケーションが署名されている**権限**として付与される場合があり、アプリケーションがいくつかのアクセスを要求し、**ユーザーがそれらを承認**した後、それらは**TCCデータベース**で見つけることができます。プロセスがこれらの特権を取得する別の方法は、それらが通常**継承**されるため、それらの**特権を持つプロセス**の**子プロセス**であることです。

これらのリンクに従って、[**TCCで特権を昇格**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)するさまざまな方法、[**TCCをバイパス**](macos-security-protections/macos-tcc/macos-tcc-bypasses/)する方法、過去に**SIPがバイパス**された方法を見つけてください。

## macOS従来の特権昇格

もちろん、レッドチームの視点からは、rootに昇格することにも興味を持つべきです。いくつかのヒントについては、次の投稿をチェックしてください：

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## 参考文献

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) サーバーに参加して、経験豊富なハッカーやバグバウンティハンターとコミュニケーションを取りましょう！

**ハッキングの洞察**\
ハッキングのスリルとチャレンジに深く入り込むコンテンツに参加しましょう

**リアルタイムハックニュース**\
リアルタイムのニュースと洞察を通じて、ハッキングの世界の速いペースについていきましょう

**最新の発表**\
最新のバグバウンティの開始や重要なプラットフォームの更新について情報を得ましょう

[**Discord**](https://discord.com/invite/N3FrSbmwdy) に参加して、今日からトップハッカーと協力を始めましょう！

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop) をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** をフォローしてください。**
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
