# Windows Artifacts

## Windows Artifacts

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

## Generic Windows Artifacts

### Windows 10 Notifications

パス `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` には、データベース `appdb.dat`（Windows アニバーサリー前）または `wpndatabase.db`（Windows アニバーサリー後）があります。

この SQLite データベース内には、興味深いデータを含む可能性のあるすべての通知（XML 形式）の `Notification` テーブルがあります。

### Timeline

Timeline は、訪問したウェブページ、編集した文書、実行したアプリケーションの**時系列履歴**を提供する Windows の機能です。

データベースは、パス `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` にあります。このデータベースは、SQLite ツールまたはツール [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) で開くことができ、**2 つのファイルを生成し、ツール** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **で開くことができます。**

### ADS (Alternate Data Streams)

ダウンロードされたファイルには、イントラネット、インターネットなどから**どのように**ダウンロードされたかを示す**ADS Zone.Identifier**が含まれている場合があります。一部のソフトウェア（ブラウザなど）は、ファイルがダウンロードされた**URL**など、さらに**多くの情報**を提供することがよくあります。

## **File Backups**

### Recycle Bin

Vista/Win7/Win8/Win10 では、**Recycle Bin**はドライブのルートにあるフォルダー **`$Recycle.bin`** にあります（`C:\$Recycle.bin`）。\
このフォルダーでファイルが削除されると、2 つの特定のファイルが作成されます：

* `$I{id}`: ファイル情報（削除された日時）
* `$R{id}`: ファイルの内容

![](<../../../.gitbook/assets/image (1029).png>)

これらのファイルがあれば、ツール [**Rifiuti**](https://github.com/abelcheung/rifiuti2) を使用して削除されたファイルの元のアドレスと削除された日時を取得できます（Vista – Win10 には `rifiuti-vista.exe` を使用）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### ボリュームシャドウコピー

シャドウコピーは、使用中のコンピュータファイルやボリュームの**バックアップコピー**やスナップショットを作成できるMicrosoft Windowsに含まれる技術です。

これらのバックアップは通常、ファイルシステムのルートから`\System Volume Information`にあり、名前は以下の画像に示されている**UID**で構成されています。

![](<../../../.gitbook/assets/image (94).png>)

**ArsenalImageMounter**でフォレンジックイメージをマウントすると、ツール[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html)を使用してシャドウコピーを検査し、シャドウコピーのバックアップから**ファイルを抽出**することができます。

![](<../../../.gitbook/assets/image (576).png>)

レジストリエントリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`には、**バックアップしない**ファイルとキーが含まれています：

![](<../../../.gitbook/assets/image (254).png>)

レジストリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`にも、`ボリュームシャドウコピー`に関する構成情報が含まれています。

### Office自動保存ファイル

Officeの自動保存ファイルは次の場所にあります：`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## シェルアイテム

シェルアイテムは、別のファイルにアクセスする方法に関する情報を含むアイテムです。

### 最近の文書 (LNK)

Windowsは、ユーザーが次の場所で**ファイルを開く、使用する、または作成する**際に、これらの**ショートカット**を**自動的に****作成**します：

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダーが作成されると、フォルダーへのリンク、親フォルダーへのリンク、および祖父フォルダーへのリンクも作成されます。

これらの自動的に作成されたリンクファイルは、**ファイル**か**フォルダー**か、**MAC** **タイム**、**ファイルが保存されているボリューム情報**、および**ターゲットファイルのフォルダー**など、**起源に関する情報**を**含んでいます**。この情報は、ファイルが削除された場合にそれらを回復するのに役立ちます。

また、リンクファイルの**作成日**は、元のファイルが**最初に使用された****時間**であり、リンクファイルの**最終更新日**は、元のファイルが使用された**最後の時間**です。

これらのファイルを検査するには、[**LinkParser**](http://4discovery.com/our-tools/)を使用できます。

このツールでは、**2セット**のタイムスタンプが見つかります：

* **最初のセット:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **2番目のセット:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate。

最初のセットのタイムスタンプは**ファイル自体のタイムスタンプ**を参照します。2番目のセットは**リンクされたファイルのタイムスタンプ**を参照します。

同じ情報は、Windows CLIツール[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)を実行することで取得できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In this case, the information is going to be saved inside a CSV file.

### ジャンプリスト

これらは、アプリケーションごとに示される最近のファイルです。各アプリケーションでアクセスできる**アプリケーションによって使用された最近のファイルのリスト**です。これらは**自動的に作成されるか、カスタムで作成される**ことがあります。

自動的に作成された**ジャンプリスト**は、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存されます。ジャンプリストは、最初のIDがアプリケーションのIDである`{id}.autmaticDestinations-ms`という形式で命名されます。

カスタムジャンプリストは、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`に保存され、通常はファイルに**重要な**ことが起こったためにアプリケーションによって作成されます（お気に入りとしてマークされたかもしれません）。

任意のジャンプリストの**作成時間**は、**ファイルが最初にアクセスされた時間**を示し、**修正時間は最後にアクセスされた時間**を示します。

ジャンプリストは[**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md)を使用して検査できます。

![](<../../../.gitbook/assets/image (168).png>)

(_JumplistExplorerによって提供されるタイムスタンプは、ジャンプリストファイル自体に関連しています_)

### シェルバッグ

[**このリンクをフォローしてシェルバッグについて学んでください。**](interesting-windows-registry-keys.md#shellbags)

## Windows USBの使用

USBデバイスが使用されたことを特定することは、以下の作成によって可能です：

* Windows Recent Folder
* Microsoft Office Recent Folder
* ジャンプリスト

一部のLNKファイルは、元のパスを指すのではなく、WPDNSEフォルダーを指しています：

![](<../../../.gitbook/assets/image (218).png>)

WPDNSEフォルダー内のファイルは元のファイルのコピーであり、PCの再起動では生き残らず、GUIDはシェルバッグから取得されます。

### レジストリ情報

[このページをチェックして](interesting-windows-registry-keys.md#usb-information) USB接続デバイスに関する興味深い情報を含むレジストリキーを学んでください。

### setupapi

USB接続が行われた時刻に関するタイムスタンプを取得するには、ファイル`C:\Windows\inf\setupapi.dev.log`を確認してください（`Section start`を検索）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)は、画像に接続されたUSBデバイスに関する情報を取得するために使用できます。

![](<../../../.gitbook/assets/image (452).png>)

### プラグアンドプレイのクリーンアップ

「プラグアンドプレイのクリーンアップ」として知られるスケジュールされたタスクは、主に古いドライバーバージョンの削除を目的としています。最新のドライバーパッケージバージョンを保持するという指定された目的とは対照的に、オンラインソースは、30日間非アクティブなドライバーも対象にしていることを示唆しています。したがって、過去30日間接続されていないリムーバブルデバイスのドライバーは削除される可能性があります。

タスクは次のパスにあります：`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

タスクの内容を示すスクリーンショットが提供されています： ![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主要コンポーネントと設定：**

* **pnpclean.dll**：このDLLは実際のクリーンアッププロセスを担当します。
* **UseUnifiedSchedulingEngine**：`TRUE`に設定されており、一般的なタスクスケジューリングエンジンの使用を示します。
* **MaintenanceSettings**：
* **Period ('P1M')**：タスクスケジューラに、定期的な自動メンテナンス中に毎月クリーンアップタスクを開始するよう指示します。
* **Deadline ('P2M')**：タスクスケジューラに、タスクが2か月連続で失敗した場合、緊急自動メンテナンス中にタスクを実行するよう指示します。

この構成により、ドライバーの定期的なメンテナンスとクリーンアップが確保され、連続して失敗した場合のタスクの再試行のための規定が設けられています。

**詳細については、次を確認してください：** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## メール

メールには**2つの興味深い部分があります：ヘッダーとメールの内容**。**ヘッダー**には次のような情報が含まれています：

* **誰が**メールを送信したか（メールアドレス、IP、メールをリダイレクトしたメールサーバー）
* **いつ**メールが送信されたか

また、`References`および`In-Reply-To`ヘッダー内にはメッセージのIDが含まれています：

![](<../../../.gitbook/assets/image (593).png>)

### Windowsメールアプリ

このアプリケーションは、メールをHTMLまたはテキストで保存します。メールは、`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`内のサブフォルダーにあります。メールは`.dat`拡張子で保存されます。

メールの**メタデータ**と**連絡先**は、**EDBデータベース**内にあります：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

ファイルの拡張子を`.vol`から`.edb`に変更すると、ツール[**ESEDatabaseView**](https://www.nirsoft.net/utils/ese_database_view.html)を使用して開くことができます。`Message`テーブル内でメールを見ることができます。

### Microsoft Outlook

ExchangeサーバーまたはOutlookクライアントが使用されると、いくつかのMAPIヘッダーが存在します：

* `Mapi-Client-Submit-Time`：メールが送信されたときのシステムの時間
* `Mapi-Conversation-Index`：スレッドの子メッセージの数と各メッセージのタイムスタンプ
* `Mapi-Entry-ID`：メッセージ識別子。
* `Mappi-Message-Flags`および`Pr_last_Verb-Executed`：MAPIクライアントに関する情報（メッセージは読まれたか？未読か？応答されたか？リダイレクトされたか？不在か？）

Microsoft Outlookクライアントでは、送信/受信されたすべてのメッセージ、連絡先データ、およびカレンダーデータは、次の場所にあるPSTファイルに保存されます：

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`は、使用されているファイルを示しています。

PSTファイルは、ツール[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)を使用して開くことができます。

![](<../../../.gitbook/assets/image (498).png>)

### Microsoft Outlook OSTファイル

**OSTファイル**は、Microsoft Outlookが**IMAP**または**Exchange**サーバーで構成されると生成され、PSTファイルと同様の情報を保存します。このファイルはサーバーと同期され、**過去12か月間**のデータを保持し、**最大サイズは50GB**で、PSTファイルと同じディレクトリにあります。OSTファイルを表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を利用できます。

### 添付ファイルの取得

失われた添付ファイルは、以下から回復可能かもしれません：

* **IE10**の場合：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
* **IE11以降**の場合：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOXファイル

**Thunderbird**は、データを保存するために**MBOXファイル**を使用し、` \Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`にあります。

### 画像サムネイル

* **Windows XPおよび8-8.1**：サムネイルを含むフォルダーにアクセスすると、削除後も画像プレビューを保存する`thumbs.db`ファイルが生成されます。
* **Windows 7/10**：UNCパス経由でネットワークにアクセスすると`thumbs.db`が作成されます。
* **Windows Vista以降**：サムネイルプレビューは`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`に集中し、**thumbcache_xxx.db**という名前のファイルが作成されます。[**Thumbsviewer**](https://thumbsviewer.github.io)および[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)は、これらのファイルを表示するためのツールです。

### Windowsレジストリ情報

Windowsレジストリは、広範なシステムおよびユーザー活動データを保存し、次のファイルに含まれています：

* `%windir%\System32\Config`は、さまざまな`HKEY_LOCAL_MACHINE`サブキー用です。
* `%UserProfile%{User}\NTUSER.DAT`は、`HKEY_CURRENT_USER`用です。
* Windows Vista以降のバージョンでは、`HKEY_LOCAL_MACHINE`レジストリファイルが`%Windir%\System32\Config\RegBack\`にバックアップされます。
* さらに、プログラム実行情報は、Windows VistaおよびWindows 2008 Server以降の`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`に保存されます。

### ツール

レジストリファイルを分析するために役立つツールがいくつかあります：

* **レジストリエディタ**：Windowsにインストールされています。現在のセッションのWindowsレジストリをナビゲートするためのGUIです。
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：レジストリファイルをロードし、GUIでナビゲートすることを可能にします。また、興味深い情報を持つキーをハイライトするブックマークも含まれています。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：再び、ロードされたレジストリをナビゲートするためのGUIを持ち、ロードされたレジストリ内の興味深い情報をハイライトするプラグインも含まれています。
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：レジストリから重要な情報を抽出できる別のGUIアプリケーションです。

### 削除された要素の回復

キーが削除されると、そのようにマークされますが、占有しているスペースが必要になるまで削除されません。したがって、**Registry Explorer**のようなツールを使用すると、これらの削除されたキーを回復することが可能です。

### 最終書き込み時間

各キー-値には、最後に変更された時間を示す**タイムスタンプ**が含まれています。

### SAM

ファイル/ハイブ**SAM**には、システムの**ユーザー、グループ、およびユーザーパスワード**のハッシュが含まれています。

`SAM\Domains\Account\Users`で、ユーザー名、RID、最終ログイン、最終失敗ログオン、ログインカウンター、パスワードポリシー、およびアカウントが作成された日時を取得できます。**ハッシュ**を取得するには、ファイル/ハイブ**SYSTEM**も**必要**です。

### Windowsレジストリの興味深いエントリ

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## 実行されたプログラム

### 基本的なWindowsプロセス

[この投稿](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)では、疑わしい動作を検出するための一般的なWindowsプロセスについて学ぶことができます。

### Windows Recent APPs

レジストリ`NTUSER.DAT`内のパス`Software\Microsoft\Current Version\Search\RecentApps`には、**実行されたアプリケーション**、**最後に実行された時間**、および**起動された回数**に関する情報を含むサブキーがあります。

### BAM（バックグラウンドアクティビティモデレーター）

レジストリエディタで`SYSTEM`ファイルを開き、パス`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`内で、**各ユーザーによって実行されたアプリケーション**に関する情報（パス内の`{SID}`に注意）と**実行された時間**を見つけることができます（時間はレジストリのデータ値内にあります）。

### Windowsプリフェッチ

プリフェッチは、コンピュータがユーザーが**近い将来にアクセスする可能性のあるコンテンツを表示するために必要なリソースを静かに**取得することを可能にする技術です。これにより、リソースに迅速にアクセスできるようになります。

Windowsプリフェッチは、**実行されたプログラムのキャッシュを作成**して、より迅速にロードできるようにします。これらのキャッシュは、`C:\Windows\Prefetch`内に`.pf`ファイルとして作成されます。XP/VISTA/WIN7では128ファイル、Win8/Win10では1024ファイルの制限があります。

ファイル名は`{program_name}-{hash}.pf`として作成されます（ハッシュは実行可能ファイルのパスと引数に基づいています）。W10では、これらのファイルは圧縮されています。ファイルの存在は、**プログラムが実行された**ことを示しています。

ファイル`C:\Windows\Prefetch\Layout.ini`には、**プリフェッチされたファイルのフォルダーの名前**が含まれています。このファイルには、**実行回数**、**実行日**、および**プログラムによって**開かれた**ファイルに関する情報が含まれています。

これらのファイルを検査するには、ツール[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)を使用できます。
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (315).png>)

### Superprefetch

**Superprefetch** は、次に読み込まれるものを予測することによって **プログラムをより速く読み込む** という同じ目的を持っています。しかし、これはプリフェッチサービスの代わりにはなりません。\
このサービスは `C:\Windows\Prefetch\Ag*.db` にデータベースファイルを生成します。

これらのデータベースには、**プログラムの名前**、**実行回数**、**開かれたファイル**、**アクセスされたボリューム**、**完全なパス**、**時間枠**、および **タイムスタンプ** が含まれています。

この情報には、ツール [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) を使用してアクセスできます。

### SRUM

**System Resource Usage Monitor** (SRUM) は、**プロセスによって消費されるリソース**を**監視**します。これはW8で登場し、`C:\Windows\System32\sru\SRUDB.dat` にESEデータベースとしてデータを保存します。

以下の情報を提供します：

* AppID とパス
* プロセスを実行したユーザー
* 送信バイト数
* 受信バイト数
* ネットワークインターフェース
* 接続の持続時間
* プロセスの持続時間

この情報は60分ごとに更新されます。

このファイルから日付を取得するには、ツール [**srum\_dump**](https://github.com/MarkBaggett/srum-dump) を使用できます。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**、または**ShimCache**は、**Microsoft**がアプリケーションの互換性の問題に対処するために開発した**Application Compatibility Database**の一部です。このシステムコンポーネントは、以下のファイルメタデータのさまざまな情報を記録します。

* ファイルのフルパス
* ファイルのサイズ
* **$Standard\_Information** (SI) の最終更新時刻
* ShimCacheの最終更新時刻
* プロセス実行フラグ

このデータは、オペレーティングシステムのバージョンに基づいて特定の場所にレジストリ内に保存されます。

* XPの場合、データは `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` に保存され、96エントリの容量があります。
* Server 2003およびWindowsのバージョン2008、2012、2016、7、8、10の場合、ストレージパスは `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache` で、512および1024エントリをそれぞれ収容します。

保存された情報を解析するには、[**AppCompatCacheParser**ツール](https://github.com/EricZimmerman/AppCompatCacheParser)の使用が推奨されます。

![](<../../../.gitbook/assets/image (75).png>)

### Amcache

**Amcache.hve**ファイルは、システム上で実行されたアプリケーションの詳細を記録するレジストリハイブです。通常、`C:\Windows\AppCompat\Programas\Amcache.hve`に見つかります。

このファイルは、実行されたプロセスの記録を保存することで注目されており、実行可能ファイルへのパスやそのSHA1ハッシュを含みます。この情報は、システム上のアプリケーションの活動を追跡するために非常に貴重です。

**Amcache.hve**からデータを抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)ツールを使用できます。以下のコマンドは、AmcacheParserを使用して**Amcache.hve**ファイルの内容を解析し、結果をCSV形式で出力する方法の例です。
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Among the generated CSV files, the `Amcache_Unassociated file entries` is particularly noteworthy due to the rich information it provides about unassociated file entries.

生成されたCSVファイルの中で、`Amcache_Unassociated file entries`は、関連付けられていないファイルエントリに関する豊富な情報を提供するため、特に注目に値します。

The most interesting CVS file generated is the `Amcache_Unassociated file entries`.

生成された最も興味深いCVSファイルは、`Amcache_Unassociated file entries`です。

### RecentFileCache

This artifact can only be found in W7 in `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` and it contains information about the recent execution of some binaries.

このアーティファクトはW7の`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`にのみ存在し、いくつかのバイナリの最近の実行に関する情報を含んでいます。

You can use the tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) to parse the file.

ファイルを解析するには、ツール[**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser)を使用できます。

### Scheduled tasks

You can extract them from `C:\Windows\Tasks` or `C:\Windows\System32\Tasks` and read them as XML.

それらは`C:\Windows\Tasks`または`C:\Windows\System32\Tasks`から抽出でき、XMLとして読むことができます。

### Services

You can find them in the registry under `SYSTEM\ControlSet001\Services`. You can see what is going to be executed and when.

それらはレジストリの`SYSTEM\ControlSet001\Services`に見つけることができます。何がいつ実行されるかを見ることができます。

### **Windows Store**

The installed applications can be found in `\ProgramData\Microsoft\Windows\AppRepository\`\
This repository has a **log** with **each application installed** in the system inside the database **`StateRepository-Machine.srd`**.

インストールされたアプリケーションは`\ProgramData\Microsoft\Windows\AppRepository\`に見つけることができます。\
このリポジトリには、データベース**`StateRepository-Machine.srd`**内にシステムにインストールされた**各アプリケーション**の**ログ**があります。

Inside the Application table of this database, it's possible to find the columns: "Application ID", "PackageNumber", and "Display Name". These columns have information about pre-installed and installed applications and it can be found if some applications were uninstalled because the IDs of installed applications should be sequential.

このデータベースのアプリケーションテーブル内には、「Application ID」、「PackageNumber」、「Display Name」という列があります。これらの列には、プリインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれており、インストールされたアプリケーションのIDは連続している必要があるため、いくつかのアプリケーションがアンインストールされたかどうかを確認できます。

It's also possible to **find installed application** inside the registry path: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
And **uninstalled** **applications** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

レジストリパス`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`内で**インストールされたアプリケーション**を見つけることも可能です。\
そして、`Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`に**アンインストールされた** **アプリケーション**があります。

## Windows Events

Information that appears inside Windows events are:

Windowsイベント内に表示される情報は次のとおりです。

* What happened
* Timestamp (UTC + 0)
* Users involved
* Hosts involved (hostname, IP)
* Assets accessed (files, folder, printer, services)

何が起こったか\
タイムスタンプ（UTC + 0）\
関与したユーザー\
関与したホスト（ホスト名、IP）\
アクセスされた資産（ファイル、フォルダー、プリンター、サービス）

The logs are located in `C:\Windows\System32\config` before Windows Vista and in `C:\Windows\System32\winevt\Logs` after Windows Vista. Before Windows Vista, the event logs were in binary format and after it, they are in **XML format** and use the **.evtx** extension.

ログは、Windows Vista以前は`C:\Windows\System32\config`に、Windows Vista以降は`C:\Windows\System32\winevt\Logs`にあります。Windows Vista以前はイベントログはバイナリ形式であり、その後は**XML形式**で**.evtx**拡張子を使用しています。

The location of the event files can be found in the SYSTEM registry in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

イベントファイルの場所は、SYSTEMレジストリの**`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**に見つけることができます。

They can be visualized from the Windows Event Viewer (**`eventvwr.msc`**) or with other tools like [**Event Log Explorer**](https://eventlogxp.com) **or** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

それらはWindowsイベントビューア（**`eventvwr.msc`**）から視覚化することができ、[**Event Log Explorer**](https://eventlogxp.com) **や** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**のような他のツールでも視覚化できます。**

## Understanding Windows Security Event Logging

Access events are recorded in the security configuration file located at `C:\Windows\System32\winevt\Security.evtx`. This file's size is adjustable, and when its capacity is reached, older events are overwritten. Recorded events include user logins and logoffs, user actions, and changes to security settings, as well as file, folder, and shared asset access.

アクセスイベントは、`C:\Windows\System32\winevt\Security.evtx`にあるセキュリティ構成ファイルに記録されます。このファイルのサイズは調整可能で、容量に達すると古いイベントが上書きされます。記録されたイベントには、ユーザーログインとログオフ、ユーザーアクション、セキュリティ設定の変更、ファイル、フォルダー、および共有資産へのアクセスが含まれます。

### Key Event IDs for User Authentication:

ユーザー認証のための主要なイベントID：

* **EventID 4624**: Indicates a user successfully authenticated.
* **EventID 4625**: Signals an authentication failure.
* **EventIDs 4634/4647**: Represent user logoff events.
* **EventID 4672**: Denotes login with administrative privileges.

* **EventID 4624**: ユーザーが正常に認証されたことを示します。\
* **EventID 4625**: 認証の失敗を示します。\
* **EventIDs 4634/4647**: ユーザーログオフイベントを表します。\
* **EventID 4672**: 管理者権限でのログインを示します。

#### Sub-types within EventID 4634/4647:

* **Interactive (2)**: Direct user login.
* **Network (3)**: Access to shared folders.
* **Batch (4)**: Execution of batch processes.
* **Service (5)**: Service launches.
* **Proxy (6)**: Proxy authentication.
* **Unlock (7)**: Screen unlocked with a password.
* **Network Cleartext (8)**: Clear text password transmission, often from IIS.
* **New Credentials (9)**: Usage of different credentials for access.
* **Remote Interactive (10)**: Remote desktop or terminal services login.
* **Cache Interactive (11)**: Login with cached credentials without domain controller contact.
* **Cache Remote Interactive (12)**: Remote login with cached credentials.
* **Cached Unlock (13)**: Unlocking with cached credentials.

#### EventID 4616:

* **Time Change**: Modification of the system time, could obscure the timeline of events.

#### EventID 6005 and 6006:

* **System Startup and Shutdown**: EventID 6005 indicates the system starting up, while EventID 6006 marks it shutting down.

#### EventID 1102:

* **Log Deletion**: Security logs being cleared, which is often a red flag for covering up illicit activities.

#### EventIDs for USB Device Tracking:

* **20001 / 20003 / 10000**: USB device first connection.
* **10100**: USB driver update.
* **EventID 112**: Time of USB device insertion.

USBデバイストラッキングのためのイベントID：

* **20001 / 20003 / 10000**: USBデバイスの最初の接続。\
* **10100**: USBドライバーの更新。\
* **EventID 112**: USBデバイス挿入の時間。

For practical examples on simulating these login types and credential dumping opportunities, refer to [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

これらのログインタイプや資格情報ダンプの機会をシミュレートする実用的な例については、[Altered Securityの詳細ガイド](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)を参照してください。

Event details, including status and sub-status codes, provide further insights into event causes, particularly notable in Event ID 4625.

イベントの詳細、ステータスおよびサブステータスコードを含む情報は、特にEvent ID 4625でのイベントの原因に関するさらなる洞察を提供します。

### Recovering Windows Events

To enhance the chances of recovering deleted Windows Events, it's advisable to power down the suspect computer by directly unplugging it. **Bulk\_extractor**, a recovery tool specifying the `.evtx` extension, is recommended for attempting to recover such events.

### Identifying Common Attacks via Windows Events

For a comprehensive guide on utilizing Windows Event IDs in identifying common cyber attacks, visit [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Identifiable by multiple EventID 4625 records, followed by an EventID 4624 if the attack succeeds.

#### Time Change

Recorded by EventID 4616, changes to system time can complicate forensic analysis.

#### USB Device Tracking

Useful System EventIDs for USB device tracking include 20001/20003/10000 for initial use, 10100 for driver updates, and EventID 112 from DeviceSetupManager for insertion timestamps.

#### System Power Events

EventID 6005 indicates system startup, while EventID 6006 marks shutdown.

#### Log Deletion

Security EventID 1102 signals the deletion of logs, a critical event for forensic analysis.

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
