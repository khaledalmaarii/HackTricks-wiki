# macOS Dangerous Entitlements & TCC perms

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

{% hint style="warning" %}
**`com.apple`** で始まる権限は第三者には利用できず、Appleのみが付与できますので注意してください。
{% endhint %}

## High

### `com.apple.rootless.install.heritable`

権限 **`com.apple.rootless.install.heritable`** は **SIPをバイパスする** ことを許可します。詳細は [こちらを確認してください](macos-sip.md#com.apple.rootless.install.heritable)。

### **`com.apple.rootless.install`**

権限 **`com.apple.rootless.install`** は **SIPをバイパスする** ことを許可します。詳細は [こちらを確認してください](macos-sip.md#com.apple.rootless.install)。

### **`com.apple.system-task-ports` (以前は `task_for_pid-allow` と呼ばれていました)**

この権限は、カーネルを除く **任意の** プロセスの **タスクポートを取得する** ことを許可します。詳細は [こちらを確認してください](../macos-proces-abuse/macos-ipc-inter-process-communication/)。

### `com.apple.security.get-task-allow`

この権限は、**`com.apple.security.cs.debugger`** 権限を持つ他のプロセスが、この権限を持つバイナリによって実行されるプロセスのタスクポートを取得し、**コードを注入する** ことを許可します。詳細は [こちらを確認してください](../macos-proces-abuse/macos-ipc-inter-process-communication/)。

### `com.apple.security.cs.debugger`

デバッグツール権限を持つアプリは、`task_for_pid()` を呼び出して、`Get Task Allow` 権限が `true` に設定された署名されていないおよびサードパーティのアプリの有効なタスクポートを取得できます。しかし、デバッグツール権限があっても、デバッガは **`Get Task Allow` 権限を持たない** プロセスのタスクポートを取得できず、それらはシステム整合性保護によって保護されています。詳細は [こちらを確認してください](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger)。

### `com.apple.security.cs.disable-library-validation`

この権限は、**Appleによって署名されていないか、メイン実行可能ファイルと同じチームIDで署名されていないフレームワーク、プラグイン、またはライブラリを読み込む** ことを許可します。これにより、攻撃者は任意のライブラリの読み込みを悪用してコードを注入することができます。詳細は [こちらを確認してください](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation)。

### `com.apple.private.security.clear-library-validation`

この権限は **`com.apple.security.cs.disable-library-validation`** と非常に似ていますが、**ライブラリ検証を直接無効にするのではなく、プロセスが **`csops`** システムコールを呼び出して無効にすることを許可します。**\
詳細は [こちらを確認してください](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)。

### `com.apple.security.cs.allow-dyld-environment-variables`

この権限は、**ライブラリやコードを注入するために使用される可能性のあるDYLD環境変数を使用する** ことを許可します。詳細は [こちらを確認してください](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)。

### `com.apple.private.tcc.manager` または `com.apple.rootless.storage`.`TCC`

[**このブログによると**](https://objective-see.org/blog/blog\_0x4C.html) **および** [**このブログによると**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)、これらの権限は **TCC** データベースを **変更する** ことを許可します。

### **`system.install.apple-software`** および **`system.install.apple-software.standar-user`**

これらの権限は、ユーザーに許可を求めることなく **ソフトウェアをインストールする** ことを許可します。これは **特権昇格** に役立つ可能性があります。

### `com.apple.private.security.kext-management`

カーネルにカーネル拡張を読み込むように要求するために必要な権限です。

### **`com.apple.private.icloud-account-access`**

権限 **`com.apple.private.icloud-account-access`** により、**`com.apple.iCloudHelper`** XPCサービスと通信することが可能になり、**iCloudトークンを提供します**。

**iMovie** と **Garageband** はこの権限を持っていました。

この権限から **iCloudトークンを取得する** ためのエクスプロイトに関する詳細は、トークを確認してください: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: これが何を許可するのかはわかりません。

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、再起動後にSSV保護されたコンテンツを更新するために使用できる可能性があると述べられています。方法がわかる方はPRを送ってください！

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**このレポート**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、再起動後にSSV保護されたコンテンツを更新するために使用できる可能性があると述べられています。方法がわかる方はPRを送ってください！

### `keychain-access-groups`

この権限は、アプリケーションがアクセスできる **キーチェーン** グループのリストです:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

**フルディスクアクセス** 権限を付与します。これは、TCCの中で最も高い権限の1つです。

### **`kTCCServiceAppleEvents`**

アプリが一般的に**タスクを自動化**するために他のアプリケーションにイベントを送信することを許可します。他のアプリを制御することで、これらの他のアプリに付与された権限を悪用することができます。

ユーザーにパスワードを要求させるようにすることができます：

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

また、**任意のアクション**を実行させることができます。

### **`kTCCServiceEndpointSecurityClient`**

ユーザーのTCCデータベースを**書き込む**ことを許可します。

### **`kTCCServiceSystemPolicySysAdminFiles`**

ユーザーの**`NFSHomeDirectory`**属性を**変更**することを許可し、これによりホームフォルダのパスを変更し、**TCCをバイパス**することができます。

### **`kTCCServiceSystemPolicyAppBundles`**

アプリバンドル内のファイルを変更することを許可します（app.app内）、これは**デフォルトでは禁止されています**。

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

このアクセス権を持つユーザーを確認するには、_システム設定_ > _プライバシーとセキュリティ_ > _アプリ管理_を確認してください。

### `kTCCServiceAccessibility`

プロセスは**macOSのアクセシビリティ機能を悪用**できるようになります。つまり、例えばキー入力を押すことができるようになります。したがって、Finderのようなアプリを制御するためのアクセスを要求し、この権限でダイアログを承認することができます。

## 中程度

### `com.apple.security.cs.allow-jit`

この権限は、`mmap()`システム関数に`MAP_JIT`フラグを渡すことで、**書き込み可能かつ実行可能なメモリを作成**することを許可します。詳細については[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit)。

### `com.apple.security.cs.allow-unsigned-executable-memory`

この権限は、**Cコードをオーバーライドまたはパッチ**することを許可し、長い間非推奨の**`NSCreateObjectFileImageFromMemory`**（根本的に安全ではありません）を使用するか、**DVDPlayback**フレームワークを使用することを許可します。詳細については[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory)。

{% hint style="danger" %}
この権限を含めると、アプリがメモリ安全でないコード言語の一般的な脆弱性にさらされます。アプリがこの例外を必要とするかどうかを慎重に検討してください。
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

この権限は、ディスク上の**自分の実行可能ファイルのセクションを変更**して強制終了することを許可します。詳細については[**こちらを確認してください**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection)。

{% hint style="danger" %}
実行可能メモリ保護を無効にする権限は、アプリから基本的なセキュリティ保護を取り除く極端な権限であり、攻撃者が検出されることなくアプリの実行可能コードを書き換えることを可能にします。可能であれば、より狭い権限を優先してください。
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

この権限は、nullfsファイルシステムをマウントすることを許可します（デフォルトでは禁止されています）。ツール: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master)。

### `kTCCServiceAll`

このブログ投稿によると、このTCC権限は通常次の形式で見つかります:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
プロセスに**すべてのTCC権限を要求させる**。

### **`kTCCServicePostEvent`**
{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
</details>
