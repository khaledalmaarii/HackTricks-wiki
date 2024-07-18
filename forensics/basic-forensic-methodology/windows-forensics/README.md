# Windows Artifacts

## Windows Artifacts

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 一般的なWindowsアーティファクト

### Windows 10通知

パス`\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`には、Windows Anniversaryより前の`appdb.dat`またはWindows Anniversary以降の`wpndatabase.db`というデータベースがあります。

このSQLiteデータベース内には、興味深いデータを含む可能性があるすべての通知（XML形式）を含む`Notification`テーブルがあります。

### タイムライン

タイムラインは、訪れたWebページ、編集されたドキュメント、実行されたアプリケーションの**時間順の履歴**を提供するWindowsの特性です。

データベースは、パス`\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`にあります。このデータベースはSQLiteツールで開くことも、[**WxTCmd**](https://github.com/EricZimmerman/WxTCmd)というツールで開くこともできます。**これにより、2つのファイルが生成され、[**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md)で開くことができます。**

### ADS（Alternate Data Streams）

ダウンロードされたファイルには、どのようにしてダウンロードされたかを示す**ADS Zone.Identifier**が含まれる場合があります。一部のソフトウェア（ブラウザなど）は、ファイルがダウンロードされたURLなどの**さらに多くの情報**を通常含めます。

## **ファイルのバックアップ**

### リサイクルビン

Vista/Win7/Win8/Win10では、**リサイクルビン**はドライブのルートにあるフォルダ**`$Recycle.bin`**にあります（`C:\$Recycle.bin`）。
このフォルダでファイルが削除されると、2つの特定のファイルが作成されます:

* `$I{id}`: ファイル情報（削除された日付）
* `$R{id}`: ファイルの内容

![](<../../../.gitbook/assets/image (486).png>)

これらのファイルを使用して、ツール[**Rifiuti**](https://github.com/abelcheung/rifiuti2)を使用して、削除されたファイルの元のアドレスと削除された日付を取得できます（Vista – Win10用に`rifiuti-vista.exe`を使用します）。
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### ボリュームシャドウコピー

シャドウコピーは、Microsoft Windowsに含まれる技術で、コンピュータファイルやボリュームの**バックアップコピー**やスナップショットを作成できます。それらが使用中であってもです。

これらのバックアップは通常、ファイルシステムのルートの`\System Volume Information`にあり、名前は以下の画像に示されている**UID**で構成されています:

![](<../../../.gitbook/assets/image (520).png>)

**ArsenalImageMounter**を使用してフォレンジックイメージをマウントすると、ツール[**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html)を使用してシャドウコピーを検査し、シャドウコピーのバックアップから**ファイルを抽出**することができます。

![](<../../../.gitbook/assets/image (521).png>)

レジストリエントリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`には、**バックアップしない**ファイルとキーが含まれています:

![](<../../../.gitbook/assets/image (522).png>)

レジストリ`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`には、`Volume Shadow Copies`に関する構成情報も含まれています。

### オフィスの自動保存ファイル

オフィスの自動保存ファイルは、`C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`にあります。

## シェルアイテム

シェルアイテムは、別のファイルにアクセスする方法に関する情報を含むアイテムです。

### 最近のドキュメント（LNK）

Windowsは、ユーザーがファイルを**開いたり使用したり作成したり**すると、これらの**ショートカット**を**自動的に作成**します:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

フォルダが作成されると、そのフォルダへのリンク、親フォルダへのリンク、祖父フォルダへのリンクも作成されます。

これら自動的に作成されたリンクファイルには、**ファイル**または**フォルダ**であるか、そのファイルの**MACタイム**、ファイルが保存されている場所の**ボリューム情報**、**ターゲットファイルのフォルダ**が含まれる情報があります。これらの情報は、削除された場合にこれらのファイルを回復するのに役立ちます。

また、リンクファイルの**作成日**は、元のファイルが**最初に使用された時間**であり、リンクファイルの**変更日**は、元のファイルが**最後に使用された時間**です。

これらのファイルを検査するには、[**LinkParser**](http://4discovery.com/our-tools/)を使用できます。

このツールでは、**2つのセット**のタイムスタンプが見つかります:

* **最初のセット:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
* **2番目のセット:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

最初のセットのタイムスタンプは、**ファイル自体のタイムスタンプ**を参照します。2番目のセットは、**リンクされたファイルのタイムスタンプ**を参照します。

同じ情報を取得するには、Windows CLIツール[**LECmd.exe**](https://github.com/EricZimmerman/LECmd)を実行できます。
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### ジャンプリスト

これらは、アプリケーションごとに示される最近使用されたファイルです。それぞれのアプリケーションでアクセスできる**最近使用されたファイルのリスト**です。これらは**自動的に作成されるか、カスタムで作成**されることがあります。

自動的に作成される**ジャンプリスト**は、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`に保存されます。ジャンプリストは、初期IDがアプリケーションのIDである`{id}.autmaticDestinations-ms`という形式に従って命名されます。

カスタムジャンプリストは、`C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`に保存され、通常はアプリケーションによって作成されます。これはファイルに何か**重要なこと**が起こったためかもしれません（お気に入りとしてマークされたかもしれません）。

どのジャンプリストの**作成時刻**は、**ファイルにアクセスされた最初の時間**を示し、**変更時刻**は最後の時間を示します。

[JumplistExplorer](https://ericzimmerman.github.io/#!index.md)を使用してジャンプリストを調査できます。

![](<../../../.gitbook/assets/image (474).png>)

（_JumplistExplorerによって提供されるタイムスタンプは、ジャンプリストファイル自体に関連しています_）

### シェルバッグ

[**こちらのリンク**](interesting-windows-registry-keys.md#shellbags)を参照して、シェルバッグとは何かを学びます。

## Windows USBの使用

USBデバイスが使用されたことを特定することが可能です。これは次のようなものの作成によって可能になります：

* Windows Recentフォルダ
* Microsoft Office Recentフォルダ
* ジャンプリスト

一部のLNKファイルは、元のパスを指す代わりにWPDNSEフォルダを指します：

![](<../../../.gitbook/assets/image (476).png>)

フォルダWPDNSE内のファイルは、元のファイルのコピーであり、したがってPCの再起動を行うと消えます。GUIDはシェルバッグから取得されます。

### レジストリ情報

USB接続されたデバイスに関する興味深い情報を含むレジストリキーについては、[このページを確認してください](interesting-windows-registry-keys.md#usb-information)。

### setupapi

USB接続が行われたタイムスタンプを取得するには、ファイル`C:\Windows\inf\setupapi.dev.log`を確認してください（`Section start`を検索）。

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)を使用して、イメージに接続されたUSBデバイスに関する情報を取得できます。

![](<../../../.gitbook/assets/image (483).png>)

### プラグアンドプレイのクリーンアップ

「プラグアンドプレイのクリーンアップ」として知られるスケジュールされたタスクは、古いドライバーバージョンを削除するために主に設計されています。最新のドライバーパッケージバージョンを保持することが明示されているにもかかわらず、オンラインソースによると、過去30日間非アクティブだったドライバーも対象となる可能性があります。その結果、過去30日間接続されていないリムーバブルデバイスのドライバーは削除の対象となる場合があります。

このタスクは次の場所にあります：
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`。

タスクの内容を示すスクリーンショットが提供されています：
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**タスクの主要なコンポーネントと設定:**
- **pnpclean.dll**: このDLLは実際のクリーンアッププロセスを担当しています。
- **UseUnifiedSchedulingEngine**: `TRUE`に設定されており、一般的なタスクスケジューリングエンジンの使用を示しています。
- **MaintenanceSettings**:
- **Period ('P1M')**: タスクスケジューラに、定期的な自動メンテナンス中に月次のクリーンアップタスクを開始するよう指示します。
- **Deadline ('P2M')**: タスクスケジューラに、2か月連続でタスクが失敗した場合、緊急時の自動メンテナンス中にタスクを実行するよう指示します。

この構成により、ドライバーの定期的なメンテナンスとクリーンアップが確保され、連続した失敗の場合にタスクを再試行するための規定がされています。

**詳細はこちらを参照:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## メール

メールには**2つの興味深い部分が含まれます: ヘッダーとコンテンツ**です。**ヘッダー**には次のような情報が含まれます：

* メールを送信した**誰**（メールアドレス、IP、メールをリダイレクトしたメールサーバー）
* メールがいつ送信されたか

また、`References`と`In-Reply-To`ヘッダー内にはメッセージのIDが含まれています：

![](<../../../.gitbook/assets/image (484).png>)

### Windowsメールアプリ

このアプリケーションは、メールをHTMLまたはテキストで保存します。メールは`\Users\<username>\AppData\Local\Comms\Unistore\data\3\`内のサブフォルダ内に保存されます。メールは`.dat`拡張子で保存されます。

メールの**メタデータ**と**連絡先**は**EDBデータベース**内に見つけることができます：`\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

ファイルの拡張子を`.vol`から`.edb`に変更し、[ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html)ツールを使用して開くことができます。`Message`テーブル内にメールが表示されます。

### Microsoft Outlook

ExchangeサーバーまたはOutlookクライアントが使用されている場合、いくつかのMAPIヘッダーが存在します：

* `Mapi-Client-Submit-Time`: メールが送信されたシステムの時間
* `Mapi-Conversation-Index`: スレッドの子メッセージ数とスレッドの各メッセージのタイムスタンプ
* `Mapi-Entry-ID`: メッセージ識別子
* `Mappi-Message-Flags`および`Pr_last_Verb-Executed`: MAPIクライアントに関する情報（メッセージは既読ですか？未読ですか？返信済みですか？リダイレクトされましたか？オフィスを外出中ですか？）

Microsoft Outlookクライアントでは、送受信したすべてのメッセージ、連絡先データ、およびカレンダーデータが次のPSTファイルに保存されます：

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook`（WinXP）
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

レジストリパス`HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`は使用されているファイルを示します。

PSTファイルは[**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html)ツールを使用して開くことができます。

![](<../../../.gitbook/assets/image (485).png>)
### Microsoft Outlook OST Files

**OSTファイル**は、Microsoft Outlookが**IMAP**または**Exchange**サーバーと構成されているときに生成され、PSTファイルと同様の情報を保存します。このファイルはサーバーと同期され、**過去12ヶ月**分のデータを**最大50GB**まで保持し、PSTファイルと同じディレクトリにあります。OSTファイルを表示するには、[**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)を利用できます。

### 添付ファイルの取得

失われた添付ファイルは次の場所から回復できる場合があります：

- **IE10**の場合：`%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11以降**の場合：`%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird**はデータを保存するために**MBOXファイル**を使用し、`\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`にあります。

### 画像サムネイル

- **Windows XPおよび8-8.1**：サムネイルが含まれるフォルダにアクセスすると、削除後も画像プレビューを保存する`thumbs.db`ファイルが生成されます。
- **Windows 7/10**：`thumbs.db`はUNCパス経由でネットワークにアクセスすると作成されます。
- **Windows Vista以降**：サムネイルプレビューは`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`に集約され、**thumbcache\_xxx.db**という名前のファイルがあります。[**Thumbsviewer**](https://thumbsviewer.github.io)と[**ThumbCache Viewer**](https://thumbcacheviewer.github.io)はこれらのファイルを表示するためのツールです。

### Windowsレジストリ情報

Windowsレジストリは、広範なシステムおよびユーザーのアクティビティデータを保存しており、次のファイルに含まれています：

- `HKEY_LOCAL_MACHINE`のさまざまなサブキーには、`%windir%\System32\Config`にファイルがあります。
- `HKEY_CURRENT_USER`には、`%UserProfile%{User}\NTUSER.DAT`にファイルがあります。
- Windows Vista以降のバージョンでは、`%Windir%\System32\Config\RegBack\`に`HKEY_LOCAL_MACHINE`レジストリファイルのバックアップがあります。
- さらに、プログラムの実行情報は、Windows VistaおよびWindows 2008 Server以降の`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`に保存されます。

### ツール

いくつかのツールがレジストリファイルを分析するのに役立ちます：

* **レジストリエディタ**：Windowsにインストールされています。現在のセッションのWindowsレジストリをナビゲートするためのGUIです。
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md)：レジストリファイルをロードし、GUIでそれらをナビゲートできます。興味深い情報を持つキーをハイライトするブックマークも含まれています。
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0)：再び、ロードされたレジストリをナビゲートし、ロードされたレジストリ内の興味深い情報をハイライトするプラグインも含まれています。
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html)：重要な情報を抽出できる別のGUIアプリケーションです。

### 削除された要素の回復

キーが削除されると、それが削除されたことがマークされますが、そのスペースが必要になるまで削除されません。したがって、**Registry Explorer**などのツールを使用すると、これらの削除されたキーを回復することが可能です。

### 最終更新時刻

各キー・値には、最後に変更された時刻を示す**タイムスタンプ**が含まれています。

### SAM

ファイル/ハイブ**SAM**には、システムの**ユーザー、グループ、ユーザーパスワード**のハッシュが含まれています。

`SAM\Domains\Account\Users`では、ユーザー名、RID、最終ログイン、最終失敗ログオン、ログインカウンター、パスワードポリシー、アカウント作成日などを取得できます。**ハッシュ**を取得するには、ファイル/ハイブ**SYSTEM**も必要です。

### Windowsレジストリの興味深いエントリ

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## 実行されたプログラム

### 基本的なWindowsプロセス

[この投稿](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)では、疑わしい動作を検出するための一般的なWindowsプロセスについて学ぶことができます。

### Windows最近のアプリ

レジストリ`NTUSER.DAT`内のパス`Software\Microsoft\Current Version\Search\RecentApps`には、**実行されたアプリケーション**、**最終実行時刻**、**実行回数**に関する情報が含まれるサブキーがあります。

### BAM（バックグラウンドアクティビティモデレーター）

レジストリエディタで`SYSTEM`ファイルを開き、パス`SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`内には、各ユーザーが実行した**アプリケーションに関する情報**（パス内の`{SID}`に注意）や**実行時刻**（レジストリのData値内に時刻が含まれています）が含まれています。

### Windows Prefetch

プリフェッチは、コンピューターが**ユーザーが近い将来にアクセスする可能性のあるコンテンツを表示するために必要なリソースを静かに取得**する技術です。

Windowsプリフェッチは、**実行されたプログラムのキャッシュ**を作成して、それらをより速くロードできるようにします。これらのキャッシュは、`C:\Windows\Prefetch`内に`.pf`ファイルとして作成されます。XP/VISTA/WIN7では128ファイルの制限があり、Win8/Win10では1024ファイルの制限があります。

ファイル名は`{program_name}-{hash}.pf`となります（ハッシュは実行可能ファイルのパスと引数に基づいています）。W10ではこれらのファイルが圧縮されています。ファイルが存在するだけで、そのプログラムがある時点で**実行された**ことを示しています。

ファイル`C:\Windows\Prefetch\Layout.ini`には、**プリフェッチされたファイルのフォルダ名**に関する情報が含まれています。このファイルには、**実行回数**、**実行日**、およびプログラムによって**開かれたファイル**に関する情報が含まれています。

これらのファイルを調査するには、[**PEcmd.exe**](https://github.com/EricZimmerman/PECmd)ツールを使用できます。
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch**は、prefetchと同じ目標を持ち、次に読み込まれるものを予測して**プログラムを高速に読み込む**ことです。ただし、prefetchサービスを置き換えるものではありません。\
このサービスは、`C:\Windows\Prefetch\Ag*.db`にデータベースファイルを生成します。

これらのデータベースには、**プログラムの名前**、**実行回数**、**開かれたファイル**、**アクセスしたボリューム**、**完全なパス**、**時間枠**、**タイムスタンプ**が含まれています。

この情報には、[**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/)ツールを使用してアクセスできます。

### SRUM

**System Resource Usage Monitor**（SRUM）は、**プロセスによって消費されるリソースを監視**します。W8に登場し、データは`C:\Windows\System32\sru\SRUDB.dat`にあるESEデータベースに保存されます。

次の情報が提供されます：

* AppIDとパス
* プロセスを実行したユーザー
* 送信バイト数
* 受信バイト数
* ネットワークインターフェース
* 接続期間
* プロセス期間

この情報は60分ごとに更新されます。

このファイルからデータを取得するには、[**srum_dump**](https://github.com/MarkBaggett/srum-dump)ツールを使用できます。
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache（ShimCache）

**AppCompatCache**、または**ShimCache**としても知られるものは、**Microsoft**が開発した**アプリケーション互換性データベース**の一部であり、アプリケーションの互換性の問題に対処するために使用されます。このシステムコンポーネントは、次のファイルメタデータを記録します：

- ファイルの完全なパス
- ファイルのサイズ
- **$Standard\_Information**（SI）の下の最終更新時刻
- ShimCacheの最終更新時刻
- プロセス実行フラグ

このようなデータは、オペレーティングシステムのバージョンに基づいてレジストリ内の特定の場所に保存されます：

- XPの場合、データは`SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`に保存され、96エントリを格納できます。
- Server 2003、およびWindowsバージョン2008、2012、2016、7、8、および10の場合、ストレージパスは`SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`で、それぞれ512および1024エントリを収容します。

保存された情報を解析するには、[**AppCompatCacheParser**ツール](https://github.com/EricZimmerman/AppCompatCacheParser)の使用をお勧めします。

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve**ファイルは、システムで実行されたアプリケーションに関する詳細を記録するレジストリハイブです。通常、`C:\Windows\AppCompat\Programas\Amcache.hve`にあります。

このファイルは、実行されたプロセスの記録、実行可能ファイルへのパス、およびそれらのSHA1ハッシュを保存するために注目されています。この情報は、システム上のアプリケーションの活動を追跡するために貴重です。

**Amcache.hve**からデータを抽出して分析するには、[**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)ツールを使用できます。次のコマンドは、**Amcache.hve**ファイルの内容を解析し、結果をCSV形式で出力するためのAmcacheParserの使用例です：
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
生成されたCSVファイルの中で、`Amcache_Unassociated file entries` は、関連付けられていないファイルエントリに関する豊富な情報を提供するため特に注目に値します。

最も興味深いCSVファイルは、`Amcache_Unassociated file entries` です。

### RecentFileCache

このアーティファクトは、`C:\Windows\AppCompat\Programs\RecentFileCache.bcf` にのみW7で見つけることができ、いくつかのバイナリの最近の実行に関する情報を含んでいます。

ファイルを解析するために [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) ツールを使用できます。

### スケジュールされたタスク

`C:\Windows\Tasks` または `C:\Windows\System32\Tasks` から抽出し、XMLとして読むことができます。

### サービス

レジストリ内の `SYSTEM\ControlSet001\Services` に見つけることができます。実行される内容と実行されるタイミングを確認できます。

### **Windows Store**

インストールされたアプリケーションは `\ProgramData\Microsoft\Windows\AppRepository\` にあります。\
このリポジトリには、システム内の各アプリケーションがデータベース **`StateRepository-Machine.srd`** 内にインストールされたログがあります。

このデータベースの Application テーブル内には、"Application ID"、"PackageNumber"、"Display Name" という列があります。これらの列には、事前にインストールされたアプリケーションとインストールされたアプリケーションに関する情報が含まれており、インストールされたアプリケーションのIDが連続しているかどうかを確認できます。

また、レジストリパス内にインストールされたアプリケーションを見つけることも可能です: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
そして、アンインストールされたアプリケーションはこちらにあります: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows イベント

Windows イベント内に表示される情報は以下の通りです:

* 何が起こったか
* タイムスタンプ (UTC + 0)
* 関与するユーザー
* 関与するホスト (ホスト名、IP)
* アクセスされたアセット (ファイル、フォルダ、プリンター、サービス)

ログは、Windows Vista より前の場合は `C:\Windows\System32\config` に、Windows Vista以降の場合は `C:\Windows\System32\winevt\Logs` にあります。Windows Vista より前では、イベントログはバイナリ形式であり、その後は **XML形式** であり、**.evtx** 拡張子が使用されます。

イベントファイルの場所は、SYSTEM レジストリ内の **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** にあります。

Windows イベントビューア (**`eventvwr.msc`**) や [**Event Log Explorer**](https://eventlogxp.com) **または** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** などの他のツールを使用して可視化できます。
#### システムの電源イベント

EventID 6005 はシステムの起動を示し、EventID 6006 はシャットダウンを示します。

#### ログの削除

セキュリティ EventID 1102 はログの削除を示し、これは法的解析において重要なイベントです。

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
