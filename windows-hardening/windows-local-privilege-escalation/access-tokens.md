# アクセストークン

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

[**WhiteIntel**](https://whiteintel.io) は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害された**かどうかを確認するための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトを確認し、**無料**でエンジンを試すことができます:

{% embed url="https://whiteintel.io" %}

***

## アクセストークン

システムに**ログインしている各ユーザーは、そのログオンセッションのセキュリティ情報を持つアクセストークンを保持しています**。ユーザーがログインすると、システムはアクセストークンを作成します。**ユーザーのために実行されるすべてのプロセスは、アクセストークンのコピーを持っています**。トークンはユーザー、ユーザーのグループ、およびユーザーの権限を識別します。トークンには、現在のログオンセッションを識別するログオンSID（セキュリティ識別子）も含まれています。

この情報は `whoami /all` を実行することで確認できます。
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![](<../../.gitbook/assets/image (772).png>)

### ローカル管理者

ローカル管理者がログインすると、**2つのアクセス トークンが作成されます**: 1つは管理者権限を持ち、もう1つは通常の権限を持ちます。**デフォルトでは**、このユーザーがプロセスを実行するとき、**通常の**（非管理者）**権限のトークンが使用されます**。このユーザーが**管理者として**何かを**実行**しようとすると（例えば「管理者として実行」）、**UAC**が許可を求めるために使用されます。\
[**UACについてもっと学びたい場合は、このページを読んでください**](../authentication-credentials-uac-and-efs/#uac)**。**

### 資格情報のユーザーなりすまし

他のユーザーの**有効な資格情報を持っている場合**、その資格情報を使用して**新しいログオン セッションを作成**できます:
```
runas /user:domain\username cmd.exe
```
**アクセス トークン**には、**LSASS**内のログオン セッションの**参照**も含まれています。これは、プロセスがネットワークのいくつかのオブジェクトにアクセスする必要がある場合に便利です。\
ネットワーク サービスにアクセスするために**異なる資格情報を使用するプロセス**を起動するには、次のようにします:
```
runas /user:domain\username /netonly cmd.exe
```
これは、ネットワーク内のオブジェクトにアクセスするための有用な資格情報を持っているが、その資格情報が現在のホスト内では無効である場合に役立ちます（現在のホストでは、現在のユーザー権限が使用されます）。

### トークンの種類

利用可能なトークンには2種類あります：

* **プライマリトークン**: プロセスのセキュリティ資格情報の表現として機能します。プライマリトークンの作成とプロセスとの関連付けは、特権の分離の原則を強調するために、昇格された権限を必要とするアクションです。通常、トークンの作成は認証サービスが担当し、ログオンサービスがユーザーのオペレーティングシステムシェルとの関連付けを処理します。プロセスは作成時に親プロセスのプライマリトークンを継承することに注意が必要です。
* **インパーソネーショントークン**: サーバーアプリケーションがクライアントのアイデンティティを一時的に採用して安全なオブジェクトにアクセスできるようにします。このメカニズムは、4つの操作レベルに階層化されています：
* **匿名**: 身元不明のユーザーと同様のサーバーアクセスを付与します。
* **識別**: サーバーがオブジェクトアクセスに利用せずにクライアントのアイデンティティを確認できるようにします。
* **インパーソネーション**: サーバーがクライアントのアイデンティティの下で操作できるようにします。
* **委任**: インパーソネーションに似ていますが、サーバーが相互作用するリモートシステムにこのアイデンティティの仮定を拡張する能力を含み、資格情報の保持を確保します。

#### インパーソネートトークン

metasploitの_**incognito**_モジュールを使用すると、十分な権限があれば、他の**トークン**を簡単に**リスト**および**インパーソネート**できます。これは、**他のユーザーのように行動するため**に役立つ可能性があります。この技術を使用して**権限を昇格**させることもできます。

### トークン権限

**権限を昇格させるために悪用できるトークン権限を学びましょう：**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

[**すべての可能なトークン権限といくつかの定義をこの外部ページで確認してください**](https://github.com/gtworek/Priv2Admin)。

## 参考文献

トークンについてさらに学ぶには、次のチュートリアルを参照してください：[https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) および [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を利用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害された**かどうかを確認するための**無料**機能を提供します。

WhiteIntelの主な目標は、情報を盗むマルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

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
