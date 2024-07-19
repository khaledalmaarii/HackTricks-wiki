# Integrity Levels

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

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されているかどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます:

{% embed url="https://whiteintel.io" %}

***

## Integrity Levels

Windows Vista以降のバージョンでは、すべての保護されたアイテムには**整合性レベル**タグが付けられます。この設定では、特定のフォルダーやファイルを除いて、ファイルやレジストリキーに「中」整合性レベルが主に割り当てられます。標準ユーザーによって開始されたプロセスは中整合性レベルを持つのがデフォルトの動作であり、サービスは通常、システム整合性レベルで動作します。高整合性ラベルはルートディレクトリを保護します。

重要なルールは、オブジェクトのレベルよりも低い整合性レベルを持つプロセスによってオブジェクトが変更されることはできないということです。整合性レベルは次の通りです：

* **Untrusted**: このレベルは匿名ログインを持つプロセス用です。 %%%例: Chrome%%%
* **Low**: 主にインターネットとの相互作用のため、特にInternet Explorerの保護モードで、関連するファイルやプロセス、**一時インターネットフォルダー**のような特定のフォルダーに影響を与えます。低整合性プロセスは、レジストリ書き込みアクセスがないことや、ユーザープロファイル書き込みアクセスが制限されるなど、重大な制限に直面します。
* **Medium**: ほとんどの活動のデフォルトレベルで、標準ユーザーや特定の整合性レベルを持たないオブジェクトに割り当てられます。管理者グループのメンバーもデフォルトでこのレベルで動作します。
* **High**: 管理者専用で、低整合性レベルのオブジェクトを変更できるようにし、高整合性レベルのオブジェクトも含まれます。
* **System**: Windowsカーネルとコアサービスのための最高の操作レベルで、管理者でさえもアクセスできず、重要なシステム機能を保護します。
* **Installer**: 他のすべてのレベルの上に位置するユニークなレベルで、このレベルのオブジェクトは他のオブジェクトをアンインストールできます。

**Process Explorer**を使用してプロセスの整合性レベルを取得できます。**Sysinternals**からプロセスの**プロパティ**にアクセスし、"**Security**"タブを表示します：

![](<../../.gitbook/assets/image (824).png>)

`whoami /groups`を使用して**現在の整合性レベル**を取得することもできます。

![](<../../.gitbook/assets/image (325).png>)

### Integrity Levels in File-system

ファイルシステム内のオブジェクトは**最小整合性レベル要件**を必要とする場合があり、プロセスがこの整合性を持っていない場合、相互作用できません。\
例えば、**通常のユーザーコンソールから通常のファイルを作成し、権限を確認しましょう**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
今、ファイルに最低限の整合性レベルを**High**に設定しましょう。これは**管理者**として実行されている**コンソール**から行う必要があります。**通常のコンソール**は中程度の整合性レベルで実行されており、オブジェクトに高い整合性レベルを割り当てることは**許可されません**。
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
これは興味深いところです。ユーザー `DESKTOP-IDJHTKP\user` がファイルに対して **完全な権限** を持っていることがわかります（実際、このユーザーがファイルを作成したのです）。しかし、実装された最小の整合性レベルのため、彼は高い整合性レベル内で実行していない限り、ファイルを変更することができません（彼はそれを読むことができることに注意してください）：
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**したがって、ファイルに最低限の整合性レベルがある場合、それを変更するには、その整合性レベル以上で実行している必要があります。**
{% endhint %}

### バイナリの整合性レベル

私は `cmd.exe` のコピーを `C:\Windows\System32\cmd-low.exe` に作成し、**管理者コンソールから低い整合性レベルを設定しました：**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
今、`cmd-low.exe`を実行すると、**低い整合性レベル**で実行されます。中程度の整合性レベルではありません。

![](<../../.gitbook/assets/image (313).png>)

興味のある方のために、バイナリに高い整合性レベルを割り当てると（`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`）、自動的に高い整合性レベルで実行されるわけではありません（中程度の整合性レベルから呼び出すと、デフォルトで中程度の整合性レベルで実行されます）。

### プロセスの整合性レベル

すべてのファイルやフォルダーには最小整合性レベルがあるわけではありませんが、**すべてのプロセスは整合性レベルの下で実行されています**。ファイルシステムで起こったことと同様に、**プロセスが別のプロセス内に書き込むには、少なくとも同じ整合性レベルを持っている必要があります**。これは、低い整合性レベルのプロセスが中程度の整合性レベルのプロセスに対してフルアクセスのハンドルを開くことができないことを意味します。

このセクションと前のセクションで述べた制限により、セキュリティの観点からは、常に**可能な限り低い整合性レベルでプロセスを実行することが推奨されます**。

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**侵害された**かどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。**

</details>
{% endhint %}
