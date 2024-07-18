# ローカルクラウドストレージ

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって駆動される**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Windowsでは、OneDriveフォルダーは `\Users\<username>\AppData\Local\Microsoft\OneDrive` にあります。そして、`logs\Personal` 内には、同期されたファイルに関する興味深いデータを含む `SyncDiagnostics.log` ファイルがあります：

* バイト単位のサイズ
* 作成日
* 修正日
* クラウド内のファイル数
* フォルダー内のファイル数
* **CID**: OneDriveユーザーのユニークID
* レポート生成時間
* OSのHDのサイズ

CIDを見つけたら、このIDを含むファイルを**検索することをお勧めします**。_**\<CID>.ini**_ や _**\<CID>.dat**_ という名前のファイルが見つかるかもしれません。これらのファイルには、OneDriveと同期されたファイルの名前などの興味深い情報が含まれている可能性があります。

## Google Drive

Windowsでは、主要なGoogle Driveフォルダーは `\Users\<username>\AppData\Local\Google\Drive\user_default` にあります。\
このフォルダーには、アカウントのメールアドレス、ファイル名、タイムスタンプ、ファイルのMD5ハッシュなどの情報を含む `Sync_log.log` というファイルがあります。削除されたファイルも、そのログファイルに対応するMD5と共に表示されます。

ファイル **`Cloud_graph\Cloud_graph.db`** はsqliteデータベースで、**`cloud_graph_entry`** というテーブルが含まれています。このテーブルには、**同期された** **ファイルの名前**、修正時間、サイズ、ファイルのMD5チェックサムが含まれています。

データベース **`Sync_config.db`** のテーブルデータには、アカウントのメールアドレス、共有フォルダーのパス、Google Driveのバージョンが含まれています。

## Dropbox

Dropboxは**SQLiteデータベース**を使用してファイルを管理します。この\
データベースは以下のフォルダーにあります：

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

主要なデータベースは次のとおりです：

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

".dbx"拡張子は、**データベース**が**暗号化されている**ことを意味します。Dropboxは**DPAPI**を使用しています（[https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN)）

Dropboxが使用している暗号化をよりよく理解するには、[https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)を読むことができます。

しかし、主な情報は次のとおりです：

* **エントロピー**: d114a55212655f74bd772e37e64aee9b
* **ソルト**: 0D638C092E8B82FC452883F95F355B8E
* **アルゴリズム**: PBKDF2
* **反復回数**: 1066

それに加えて、データベースを復号化するには、次のものが必要です：

* **暗号化されたDPAPIキー**: `NTUSER.DAT\Software\Dropbox\ks\client` 内のレジストリで見つけることができます（このデータをバイナリとしてエクスポート）
* **`SYSTEM`** および **`SECURITY`** ハイブ
* **DPAPIマスタキー**: `\Users\<username>\AppData\Roaming\Microsoft\Protect` にあります
* Windowsユーザーの**ユーザー名**と**パスワード**

その後、[**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**ツールを使用できます：**

![](<../../../.gitbook/assets/image (448).png>)

すべてが期待通りに進めば、ツールは元のものを復元するために**使用する必要があるプライマリキー**を示します。元のものを復元するには、この[cyber\_chefレシピ](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\))を使用し、プライマリキーをレシピ内の「パスフレーズ」として設定します。

結果の16進数は、データベースを暗号化するために使用される最終キーであり、次のように復号化できます：
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** データベースには以下が含まれています：

* **Email**: ユーザーのメールアドレス
* **usernamedisplayname**: ユーザーの名前
* **dropbox\_path**: Dropboxフォルダがあるパス
* **Host\_id: Hash**: クラウドへの認証に使用されるハッシュ。このハッシュはウェブからのみ取り消すことができます。
* **Root\_ns**: ユーザー識別子

**`filecache.db`** データベースには、Dropboxと同期されたすべてのファイルとフォルダに関する情報が含まれています。`File_journal` テーブルが最も有用な情報を持っています：

* **Server\_path**: サーバー内のファイルがあるパス（このパスはクライアントの `host_id` によって前置されます）。
* **local\_sjid**: ファイルのバージョン
* **local\_mtime**: 修正日
* **local\_ctime**: 作成日

このデータベース内の他のテーブルには、さらに興味深い情報が含まれています：

* **block\_cache**: Dropboxのすべてのファイルとフォルダのハッシュ
* **block\_ref**: `block_cache` テーブルのハッシュIDと `file_journal` テーブルのファイルIDを関連付ける
* **mount\_table**: Dropboxの共有フォルダ
* **deleted\_fields**: Dropboxで削除されたファイル
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
