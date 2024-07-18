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


## smss.exe

**セッションマネージャ**.\
セッション0は**csrss.exe**と**wininit.exe**（**OSサービス**）を開始し、セッション1は**csrss.exe**と**winlogon.exe**（**ユーザーセッション**）を開始します。ただし、プロセスツリー内で**そのバイナリのプロセスが1つだけ**表示されるはずです。

また、セッション0と1以外のセッションがある場合、RDPセッションが発生している可能性があります。


## csrss.exe

**クライアント/サーバー実行サブシステムプロセス**.\
**プロセス**と**スレッド**を管理し、他のプロセスに**Windows API**を利用可能にし、**ドライブレターをマップ**し、**一時ファイルを作成**し、**シャットダウンプロセス**を処理します。

セッション0とセッション1でそれぞれ1つずつ実行されています（プロセスツリーには**2つのプロセス**があります）。新しいセッションごとに別のプロセスが作成されます。


## winlogon.exe

**Windowsログオンプロセス**.\
ユーザーの**ログオン**/**ログオフ**を担当します。ユーザー名とパスワードを求めるために**logonui.exe**を起動し、その後**lsass.exe**を呼び出して検証します。

その後、**`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`**にある**Userinit**というキーで指定された**userinit.exe**を起動します。

さらに、前述のレジストリには**Shellキー**に**explorer.exe**があるはずであり、それが**マルウェアの永続化手法**として悪用される可能性があります。


## wininit.exe

**Windows初期化プロセス**. \
セッション0で**services.exe**、**lsass.exe**、**lsm.exe**を起動します。1つのプロセスしか存在すべきです。


## userinit.exe

**Userinitログオンアプリケーション**.\
**HKCU**の**ntduser.dat**を読み込み、**ユーザー環境**を初期化し、**ログオンスクリプト**と**GPO**を実行します。

**explorer.exe**を起動します。


## lsm.exe

**ローカルセッションマネージャ**.\
smss.exeと協力してユーザーセッションを操作します：ログオン/ログオフ、シェルの開始、デスクトップのロック/アンロックなど。

W7以降、lsm.exeはサービス（lsm.dll）に変換されました。

W7では1つのプロセスしか存在せず、そのうち1つはDLLを実行するサービスです。


## services.exe

**サービス制御マネージャ**.\
**自動起動**および**ドライバ**として構成された**サービス**を**ロード**します。

**svchost.exe**、**dllhost.exe**、**taskhost.exe**、**spoolsv.exe**などの親プロセスです。

サービスは`HKLM\SYSTEM\CurrentControlSet\Services`で定義され、このプロセスはサービス情報のメモリ内DBを維持し、sc.exeによってクエリできます。

**一部のサービス**は**独自のプロセスで実行**され、他のサービスは**svchost.exeプロセスを共有**することになります。

1つのプロセスしか存在すべきです。


## lsass.exe

**ローカルセキュリティ機関サブシステム**.\
ユーザーの**認証**を担当し、**セキュリティトークン**を作成します。`HKLM\System\CurrentControlSet\Control\Lsa`にある認証パッケージを使用します。

**セキュリティイベントログ**に書き込み、1つのプロセスしか存在すべきです。

このプロセスはパスワードをダンプするために攻撃されやすいことに注意してください。


## svchost.exe

**汎用サービスホストプロセス**.\
複数のDLLサービスを1つの共有プロセスでホストします。

通常、**svchost.exe**は`-k`フラグを付けて起動されます。これにより、レジストリ**HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**にクエリが送信され、-kで言及された引数を含むキーがあり、同じプロセスで起動するサービスが含まれます。

たとえば：`-k UnistackSvcGroup`は、`PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`を起動します。

**-sフラグ**も引数とともに使用される場合、svchostに対してこの引数で指定されたサービスのみを起動するように要求されます。

`svchost.exe`の複数のプロセスが存在します。そのうちの1つでも**`-k`フラグを使用していない**場合、非常に疑わしいです。**親プロセスがservices.exeでない**場合も非常に疑わしいです。


## taskhost.exe

このプロセスは、DLLから実行されているプロセスのホストとして機能します。また、DLLから実行されているサービスをロードします。

W8ではtaskhostex.exeと呼ばれ、W10ではtaskhostw.exeと呼ばれます。


## explorer.exe

これは**ユーザーのデスクトップ**を担当し、ファイル拡張子を介してファイルを起動します。

**ログオンユーザーごとに1つの**プロセスが生成されるはずです。

これは**userinit.exe**から実行され、**このプロセスの親は表示されない**ため、**userinit.exe**が終了しているはずです。


# 悪意のあるプロセスの検知

* 期待されるパスから実行されていますか？（Windowsバイナリは一時的な場所から実行されません）
* 奇妙なIPと通信していますか？
* デジタル署名を確認してください（Microsoftの成果物は署名されているはずです）
* 正しくスペルされていますか？
* 期待されるSIDで実行されていますか？
* 親プロセスは期待されるものですか（あれば）？
* 子プロセスは期待されるものですか？（cmd.exe、wscript.exe、powershell.exeなどはありませんか？）


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
