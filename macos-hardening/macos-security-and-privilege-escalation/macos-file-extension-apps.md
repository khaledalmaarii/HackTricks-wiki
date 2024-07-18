# macOSファイル拡張子＆URLスキームアプリハンドラ

{% hint style="success" %}
AWSハッキングの学習と実践:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と実践: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加**または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して**ハッキングトリックを共有**してください。

</details>
{% endhint %}

## LaunchServicesデータベース

これはmacOSにインストールされているすべてのアプリケーションのデータベースであり、各インストールされたアプリケーションに関する情報を取得できるようにクエリを実行できます。それは、次のようにこのデータベースをダンプすることが可能です:

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

または、ツール[**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)を使用する。

**`/usr/libexec/lsd`**はデータベースの中枢です。`.lsd.installation`、`.lsd.open`、`.lsd.openurl`などの**複数のXPCサービス**を提供します。ただし、`.launchservices.changedefaulthandler`や`.launchservices.changeurlschemehandler`などのXPC機能を使用するために、アプリケーションにはいくつかの権限が**必要**です。mimeタイプやURLスキームのデフォルトアプリを変更するための`.launchservices.changedefaulthandler`や`.launchservices.changeurlschemehandler`などが含まれます。

**`/System/Library/CoreServices/launchservicesd`**はサービス`com.apple.coreservices.launchservicesd`を所有し、実行中のアプリケーションに関する情報を取得するためにクエリできます。システムツール/**`usr/bin/lsappinfo`**または[**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)を使用してクエリできます。

## ファイル拡張子とURLスキームのアプリハンドラ

次の行は、拡張子に応じてファイルを開くことができるアプリケーションを見つけるのに役立ちます：

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
{% endcode %}

または、[**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)のようなものを使用します：
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
あるアプリケーションがサポートする拡張子をチェックすることもできます。
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
