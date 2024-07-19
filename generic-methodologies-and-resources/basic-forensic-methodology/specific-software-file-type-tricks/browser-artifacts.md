# ブラウザのアーティファクト

{% hint style="success" %}
AWSハッキングを学び、実践する:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts)を使用して、世界で最も高度なコミュニティツールによって駆動される**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

## ブラウザのアーティファクト <a href="#id-3def" id="id-3def"></a>

ブラウザのアーティファクトには、ナビゲーション履歴、ブックマーク、キャッシュデータなど、ウェブブラウザによって保存されるさまざまな種類のデータが含まれます。これらのアーティファクトは、オペレーティングシステム内の特定のフォルダーに保存され、ブラウザごとに場所と名前が異なりますが、一般的には同様のデータタイプを保存しています。

最も一般的なブラウザのアーティファクトの概要は次のとおりです：

* **ナビゲーション履歴**: ユーザーが訪れたウェブサイトを追跡し、悪意のあるサイトへの訪問を特定するのに役立ちます。
* **オートコンプリートデータ**: 頻繁な検索に基づく提案で、ナビゲーション履歴と組み合わせることで洞察を提供します。
* **ブックマーク**: ユーザーが迅速にアクセスするために保存したサイト。
* **拡張機能とアドオン**: ユーザーがインストールしたブラウザの拡張機能またはアドオン。
* **キャッシュ**: ウェブコンテンツ（例：画像、JavaScriptファイル）を保存し、ウェブサイトの読み込み時間を改善します。法医学的分析にとって価値があります。
* **ログイン情報**: 保存されたログイン資格情報。
* **ファビコン**: ウェブサイトに関連付けられたアイコンで、タブやブックマークに表示され、ユーザーの訪問に関する追加情報に役立ちます。
* **ブラウザセッション**: 開いているブラウザセッションに関連するデータ。
* **ダウンロード**: ブラウザを通じてダウンロードされたファイルの記録。
* **フォームデータ**: ウェブフォームに入力された情報で、将来のオートフィル提案のために保存されます。
* **サムネイル**: ウェブサイトのプレビュー画像。
* **Custom Dictionary.txt**: ユーザーがブラウザの辞書に追加した単語。

## Firefox

Firefoxは、ユーザーデータをプロファイル内に整理し、オペレーティングシステムに基づいて特定の場所に保存します：

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

これらのディレクトリ内の`profiles.ini`ファイルには、ユーザープロファイルがリストされています。各プロファイルのデータは、`profiles.ini`内の`Path`変数に名前が付けられたフォルダーに保存され、`profiles.ini`自体と同じディレクトリにあります。プロファイルのフォルダーが欠けている場合は、削除された可能性があります。

各プロファイルフォルダー内には、いくつかの重要なファイルがあります：

* **places.sqlite**: 履歴、ブックマーク、ダウンロードを保存します。Windows上の[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)のようなツールで履歴データにアクセスできます。
* 特定のSQLクエリを使用して、履歴とダウンロード情報を抽出します。
* **bookmarkbackups**: ブックマークのバックアップを含みます。
* **formhistory.sqlite**: ウェブフォームデータを保存します。
* **handlers.json**: プロトコルハンドラーを管理します。
* **persdict.dat**: カスタム辞書の単語。
* **addons.json**および**extensions.sqlite**: インストールされたアドオンと拡張機能に関する情報。
* **cookies.sqlite**: クッキーの保存、Windows上での検査には[MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)が利用可能です。
* **cache2/entries**または**startupCache**: キャッシュデータで、[MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html)のようなツールを通じてアクセスできます。
* **favicons.sqlite**: ファビコンを保存します。
* **prefs.js**: ユーザー設定と好み。
* **downloads.sqlite**: 古いダウンロードデータベースで、現在はplaces.sqliteに統合されています。
* **thumbnails**: ウェブサイトのサムネイル。
* **logins.json**: 暗号化されたログイン情報。
* **key4.db**または**key3.db**: 機密情報を保護するための暗号化キーを保存します。

さらに、ブラウザのフィッシング対策設定を確認するには、`prefs.js`内の`browser.safebrowsing`エントリを検索し、安全なブラウジング機能が有効または無効になっているかを示します。

マスターパスワードを解読しようとする場合は、[https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)を使用できます。\
次のスクリプトと呼び出しを使用して、ブルートフォースするパスワードファイルを指定できます：

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (692).png>)

## Google Chrome

Google Chromeは、オペレーティングシステムに基づいて特定の場所にユーザープロファイルを保存します：

* **Linux**: `~/.config/google-chrome/`
* **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
* **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

これらのディレクトリ内で、ほとんどのユーザーデータは**Default/**または**ChromeDefaultData/**フォルダーにあります。以下のファイルには重要なデータが含まれています：

* **History**: URL、ダウンロード、検索キーワードを含みます。Windowsでは、[ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html)を使用して履歴を読むことができます。「Transition Type」列には、リンクのクリック、入力されたURL、フォームの送信、ページの再読み込みなど、さまざまな意味があります。
* **Cookies**: クッキーを保存します。検査には、[ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html)が利用可能です。
* **Cache**: キャッシュデータを保持します。検査するには、Windowsユーザーは[ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html)を利用できます。
* **Bookmarks**: ユーザーのブックマーク。
* **Web Data**: フォーム履歴を含みます。
* **Favicons**: ウェブサイトのファビコンを保存します。
* **Login Data**: ユーザー名やパスワードなどのログイン資格情報を含みます。
* **Current Session**/**Current Tabs**: 現在のブラウジングセッションとオープンタブに関するデータ。
* **Last Session**/**Last Tabs**: Chromeが閉じられる前の最後のセッション中にアクティブだったサイトに関する情報。
* **Extensions**: ブラウザ拡張機能やアドオンのディレクトリ。
* **Thumbnails**: ウェブサイトのサムネイルを保存します。
* **Preferences**: プラグイン、拡張機能、ポップアップ、通知などの設定を含む情報が豊富なファイル。
* **Browser’s built-in anti-phishing**: フィッシング対策とマルウェア保護が有効かどうかを確認するには、`grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`を実行します。出力に`{"enabled: true,"}`があるか確認します。

## **SQLite DB Data Recovery**

前のセクションで観察できるように、ChromeとFirefoxの両方はデータを保存するために**SQLite**データベースを使用しています。**削除されたエントリを回復することが可能です** [**sqlparse**](https://github.com/padfoot999/sqlparse) **または** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)を使用して。

## **Internet Explorer 11**

Internet Explorer 11は、データとメタデータをさまざまな場所で管理し、保存された情報とその対応する詳細を分離して簡単にアクセスおよび管理できるようにします。

### メタデータストレージ

Internet Explorerのメタデータは、`%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`に保存されます（VXはV01、V16、またはV24です）。これに伴い、`V01.log`ファイルは`WebcacheVX.data`との修正時間の不一致を示すことがあり、`esentutl /r V01 /d`を使用して修復が必要です。このメタデータはESEデータベースに格納されており、photorecや[**ESEDatabaseView**](https://www.nirsoft.net/utils/ese\_database\_view.html)などのツールを使用して回復および検査できます。**Containers**テーブル内では、各データセグメントが保存されている特定のテーブルやコンテナを識別でき、Skypeなどの他のMicrosoftツールのキャッシュ詳細も含まれています。

### キャッシュ検査

[IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html)ツールを使用してキャッシュを検査できます。キャッシュデータ抽出フォルダーの場所が必要です。キャッシュのメタデータには、ファイル名、ディレクトリ、アクセス回数、URLの起源、キャッシュ作成、アクセス、修正、期限切れのタイムスタンプが含まれます。

### クッキー管理

クッキーは[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)を使用して調査でき、メタデータには名前、URL、アクセス回数、さまざまな時間関連の詳細が含まれます。永続的なクッキーは`%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`に保存され、セッションクッキーはメモリに存在します。

### ダウンロード詳細

ダウンロードのメタデータは[**ESEDatabaseView**](https://www.nirsoft.net/utils/ese\_database\_view.html)を介してアクセス可能で、特定のコンテナにはURL、ファイルタイプ、ダウンロード場所などのデータが保持されています。物理ファイルは`%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`にあります。

### ブラウジング履歴

ブラウジング履歴を確認するには、[BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html)を使用でき、抽出された履歴ファイルの場所とInternet Explorerの設定が必要です。ここでのメタデータには、修正およびアクセス時間、アクセス回数が含まれます。履歴ファイルは`%userprofile%\Appdata\Local\Microsoft\Windows\History`にあります。

### 入力されたURL

入力されたURLとその使用時間は、`NTUSER.DAT`の`Software\Microsoft\InternetExplorer\TypedURLs`および`Software\Microsoft\InternetExplorer\TypedURLsTime`のレジストリに保存され、ユーザーが入力した最後の50のURLとその最後の入力時間を追跡します。

## Microsoft Edge

Microsoft Edgeは、`%userprofile%\Appdata\Local\Packages`にユーザーデータを保存します。さまざまなデータタイプのパスは次のとおりです：

* **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
* **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
* **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
* **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
* **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safariデータは`/Users/$User/Library/Safari`に保存されます。主なファイルは次のとおりです：

* **History.db**: `history_visits`および`history_items`テーブルにURLと訪問タイムスタンプが含まれています。`sqlite3`を使用してクエリを実行します。
* **Downloads.plist**: ダウンロードされたファイルに関する情報。
* **Bookmarks.plist**: ブックマークされたURLを保存します。
* **TopSites.plist**: 最も頻繁に訪問されたサイト。
* **Extensions.plist**: Safariブラウザ拡張機能のリスト。`plutil`または`pluginkit`を使用して取得します。
* **UserNotificationPermissions.plist**: プッシュ通知を許可されたドメイン。`plutil`を使用して解析します。
* **LastSession.plist**: 最後のセッションのタブ。`plutil`を使用して解析します。
* **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`を使用して確認します。1の応答は機能がアクティブであることを示します。

## Opera

Operaのデータは`/Users/$USER/Library/Application Support/com.operasoftware.Opera`にあり、履歴とダウンロードの形式はChromeと共有されています。

* **Browser’s built-in anti-phishing**: `Preferences`ファイル内の`fraud_protection_enabled`が`true`に設定されているか確認することで検証します。`grep`を使用します。

これらのパスとコマンドは、さまざまなウェブブラウザによって保存されたブラウジングデータにアクセスし、理解するために重要です。

## References

* [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
* [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
* [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
* **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=browser-artifacts)を使用して、世界で最も高度なコミュニティツールによって駆動される**ワークフローを簡単に構築および自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=browser-artifacts" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する： <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
