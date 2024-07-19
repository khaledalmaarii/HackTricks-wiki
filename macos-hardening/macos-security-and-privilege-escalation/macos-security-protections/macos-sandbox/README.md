# macOS Sandbox

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

## 基本情報

MacOS Sandbox（最初はSeatbeltと呼ばれていました）は、**サンドボックス内で実行されるアプリケーション**を、アプリが実行されている**サンドボックスプロファイルで指定された許可されたアクション**に制限します。これにより、**アプリケーションが予期されるリソースのみをアクセスすることが保証されます**。

**`com.apple.security.app-sandbox`**という**権限**を持つアプリは、サンドボックス内で実行されます。**Appleのバイナリ**は通常サンドボックス内で実行され、**App Store**に公開するためには、**この権限が必須です**。したがって、ほとんどのアプリケーションはサンドボックス内で実行されます。

プロセスが何をできるか、またはできないかを制御するために、**サンドボックスはカーネル全体のすべての**syscall**にフックを持っています**。アプリの**権限**に応じて、サンドボックスは特定のアクションを**許可**します。

サンドボックスの重要なコンポーネントは以下の通りです：

* **カーネル拡張** `/System/Library/Extensions/Sandbox.kext`
* **プライベートフレームワーク** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* ユーザーランドで実行される**デーモン** `/usr/libexec/sandboxd`
* **コンテナ** `~/Library/Containers`

コンテナフォルダ内には、バンドルIDの名前を持つ**サンドボックスで実行される各アプリのフォルダ**を見つけることができます：
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
各バンドルIDフォルダー内には、アプリの**plist**と**データディレクトリ**を見つけることができます：
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
注意してください、シンボリックリンクがSandboxから「脱出」して他のフォルダにアクセスするために存在していても、アプリはそれらにアクセスするための**権限を持っている必要があります**。これらの権限は**`.plist`**の中にあります。
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Sandboxedアプリケーションによって作成/変更されたすべてのものには**隔離属性**が付与されます。これは、サンドボックスアプリが**`open`**を使用して何かを実行しようとした場合に、Gatekeeperをトリガーすることでサンドボックス空間を防ぎます。
{% endhint %}

### サンドボックスプロファイル

サンドボックスプロファイルは、その**サンドボックス**で何が**許可/禁止**されるかを示す設定ファイルです。これは、[**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\))プログラミング言語を使用する**サンドボックスプロファイル言語（SBPL）**を使用します。

ここに例があります：
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
この[**研究**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **を確認して、許可または拒否される可能性のある他のアクションを確認してください。**
{% endhint %}

重要な**システムサービス**も、`mdnsresponder`サービスのように独自のカスタム**サンドボックス**内で実行されます。これらのカスタム**サンドボックスプロファイル**は以下で確認できます：

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* 他のサンドボックスプロファイルは[https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)で確認できます。

**App Store**アプリは**プロファイル****`/System/Library/Sandbox/Profiles/application.sb`**を使用します。このプロファイルで、**`com.apple.security.network.server`**のような権限がプロセスにネットワークを使用することを許可する方法を確認できます。

SIPは、/System/Library/Sandbox/rootless.conf内のplatform\_profileというサンドボックスプロファイルです。

### サンドボックスプロファイルの例

特定のサンドボックスプロファイルでアプリケーションを起動するには、次のようにします：
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% endcode %}

{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Appleが作成した** **ソフトウェア**は、**Windows**上で**追加のセキュリティ対策**（アプリケーションサンドボックスなど）を持っていないことに注意してください。
{% endhint %}

バイパスの例:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)（彼らは`~$`で始まる名前のファイルをサンドボックスの外に書き込むことができます）。

### MacOS サンドボックスプロファイル

macOSはシステムサンドボックスプロファイルを2つの場所に保存します: **/usr/share/sandbox/** と **/System/Library/Sandbox/Profiles**。

サードパーティアプリケーションが _**com.apple.security.app-sandbox**_ 権限を持っている場合、システムはそのプロセスに **/System/Library/Sandbox/Profiles/application.sb** プロファイルを適用します。

### **iOS サンドボックスプロファイル**

デフォルトのプロファイルは **container** と呼ばれ、SBPLテキスト表現はありません。メモリ内では、このサンドボックスはサンドボックスからの各権限に対して許可/拒否のバイナリツリーとして表現されます。

### デバッグ & サンドボックスのバイパス

macOSでは、iOSとは異なり、プロセスはカーネルによって最初からサンドボックス化されるのではなく、**プロセス自身がサンドボックスに参加する必要があります**。これは、macOSではプロセスが積極的にサンドボックスに入ることを決定するまで、サンドボックスによって制限されないことを意味します。

プロセスは、権限 `com.apple.security.app-sandbox` を持っている場合、ユーザーランドから自動的にサンドボックス化されます。このプロセスの詳細な説明については、次を確認してください:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID権限の確認**

[**これによると**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s)、**`sandbox_check`**（これは `__mac_syscall` です）は、特定のPIDによってサンドボックスで**操作が許可されているかどうか**を確認できます。

[**ツール sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c)は、特定のアクションをPIDが実行できるかどうかを確認できます:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### App StoreアプリのカスタムSBPL

企業は、アプリを**カスタムサンドボックスプロファイル**で実行することが可能です（デフォルトのものではなく）。彼らは、Appleによって承認される必要がある権限**`com.apple.security.temporary-exception.sbpl`**を使用する必要があります。

この権限の定義は**`/System/Library/Sandbox/Profiles/application.sb:`**で確認できます。
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
この権限の後の文字列は、Sandboxプロファイルとして**eval**されます。

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
