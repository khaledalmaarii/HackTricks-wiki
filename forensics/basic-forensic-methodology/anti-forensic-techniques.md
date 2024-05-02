<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 **Discord 그룹**에 **가입**하세요(https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **해킹 트릭을 공유**하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# 타임스탬프

공격자는 **파일의 타임스탬프를 변경**하여 감지를 피하려 할 수 있습니다.\
MFT 내부의 타임스탬프를 찾을 수 있습니다. 이는 `$STANDARD_INFORMATION` 및 `$FILE_NAME` 속성에 있습니다.

두 속성에는 **수정**, **액세스**, **생성**, **MFT 레지스트리 수정** (MACE 또는 MACB)의 4가지 타임스탬프가 있습니다.

**Windows 탐색기** 및 기타 도구는 **`$STANDARD_INFORMATION`**에서 정보를 표시합니다.

## TimeStomp - 안티 포렌식 도구

이 도구는 **`$STANDARD_INFORMATION`** 내부의 타임스탬프 정보를 **수정**하지만 **`$FILE_NAME`** 내부의 정보는 **수정하지 않습니다**. 따라서 **의심스러운 활동을 식별**할 수 있습니다.

## Usnjrnl

**USN Journal** (Update Sequence Number Journal)은 NTFS (Windows NT 파일 시스템)의 기능으로 볼륨 변경을 추적합니다. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 도구를 사용하여 이러한 변경 사항을 검사할 수 있습니다.

![](<../../.gitbook/assets/image (449).png>)

이전 이미지는 도구에서 표시된 **출력**으로 파일에 일부 **변경이 수행**된 것을 확인할 수 있습니다.

## $LogFile

파일 시스템의 모든 메타데이터 변경 사항은 [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)이라는 프로세스에서 **로그됩니다**. 로그된 메타데이터는 NTFS 파일 시스템의 루트 디렉토리에 위치한 `**$LogFile**`이라는 파일에 유지됩니다. [LogFileParser](https://github.com/jschicht/LogFileParser)와 같은 도구를 사용하여 이 파일을 구문 분석하고 변경 사항을 식별할 수 있습니다.

![](<../../.gitbook/assets/image (450).png>)

도구의 출력에서 다시 **일부 변경이 수행**된 것을 확인할 수 있습니다.

동일한 도구를 사용하여 **타임스탬프가 수정된 시간을 식별**할 수 있습니다:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: 파일 생성 시간
* ATIME: 파일 수정 시간
* MTIME: 파일의 MFT 레지스트리 수정
* RTIME: 파일 액세스 시간

## `$STANDARD_INFORMATION` 및 `$FILE_NAME` 비교

의심스러운 수정된 파일을 식별하는 또 다른 방법은 두 속성의 시간을 비교하여 **불일치**를 찾는 것입니다.

## 나노초

**NTFS** 타임스탬프는 **100 나노초의 정밀도**를 갖습니다. 따라서 2010-10-10 10:10:**00.000:0000과 같은 타임스탬프가있는 파일을 찾는 것은 매우 의심스러울 수 있습니다.

## SetMace - 안티 포렌식 도구

이 도구는 `$STARNDAR_INFORMATION` 및 `$FILE_NAME` 두 속성을 모두 수정할 수 있습니다. 그러나 Windows Vista부터는 이 정보를 수정하려면 라이브 OS가 필요합니다.

# 데이터 숨김

NFTS는 클러스터와 최소 정보 크기를 사용합니다. 즉, 파일이 클러스터와 반 개를 사용하는 경우 **파일이 삭제될 때까지 남은 반은 사용되지 않을 수 있습니다**. 그럼으로 이 "숨겨진" 공간에 데이터를 **숨길 수 있습니다**.

이러한 "숨겨진" 공간에 데이터를 숨기는 것을 허용하는 slacker와 같은 도구가 있습니다. 그러나 `$logfile` 및 `$usnjrnl`의 분석을 통해 일부 데이터가 추가되었음을 확인할 수 있습니다:

![](<../../.gitbook/assets/image (452).png>)

그런 다음 FTK Imager와 같은 도구를 사용하여 슬랙 공간을 검색할 수 있습니다. 이러한 유형의 도구는 콘텐츠를 난독화하거나 암호화 할 수 있습니다.

# UsbKill

이 도구는 USB 포트에 변경 사항이 감지되면 컴퓨터를 **끕니다**.\
이를 발견하는 방법은 실행 중인 프로세스를 검사하고 **실행 중인 각 파이썬 스크립트를 검토**하는 것입니다.

# 라이브 Linux 배포

이러한 배포판은 **RAM 메모리 내에서 실행**됩니다. NTFS 파일 시스템이 쓰기 권한으로 마운트된 경우에만 감지할 수 있습니다. 읽기 권한으로만 마운트되어 있으면 침입을 감지할 수 없습니다.

# 안전한 삭제

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows 구성

포렌식 조사를 훨씬 어렵게 만들기 위해 여러 Windows 로깅 방법을 비활성화할 수 있습니다.

## 타임스탬프 비활성화 - UserAssist

이는 사용자가 실행한 각 실행 파일의 날짜와 시간을 유지하는 레지스트리 키입니다.

UserAssist를 비활성화하려면 두 단계가 필요합니다:

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 및 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` 두 레지스트리 키를 0으로 설정하여 UserAssist를 비활성화하려는 신호를 보냅니다.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`와 같은 레지스트리 하위 트리를 지웁니다.

## 타임스탬프 비활성화 - Prefetch

이는 Windows 시스템의 성능을 향상시키기 위해 실행된 응용 프로그램에 대한 정보를 저장합니다. 그러나 이는 포렌식 실무에도 유용할 수 있습니다.

* `regedit`를 실행합니다
* 파일 경로 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`를 선택합니다
* `EnablePrefetcher` 및 `EnableSuperfetch`에서 마우스 오른쪽 버튼을 클릭합니다
* 각각을 수정하려면 1(또는 3)에서 0으로 값을 변경합니다
* 다시 시작합니다

## 타임스탬프 비활성화 - 마지막 액세스 시간

Windows NT 서버의 NTFS 볼륨에서 폴더가 열릴 때 시스템은 **각 목록된 폴더의 타임스탬프 필드를 업데이트**하는 시간을 취합니다. 이를 마지막 액세스 시간이라고합니다. 사용 빈도가 높은 NTFS 볼륨에서는 성능에 영향을 줄 수 있습니다.

1. 레지스트리 편집기(Regedit.exe)를 엽니다.
2. `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`로 이동합니다.
3. `NtfsDisableLastAccessUpdate`를 찾습니다. 존재하지 않으면이 DWORD를 추가하고 값을 1로 설정하여 프로세스를 비활성화합니다.
4. 레지스트리 편집기를 닫고 서버를 다시 시작합니다.
## USB 히스토리 삭제

모든 **USB 장치 항목**은 Windows 레지스트리에 **USBSTOR** 레지스트리 키 아래에 저장되어 있습니다. 이 키에는 PC나 노트북에 USB 장치를 연결할 때마다 생성되는 하위 키가 포함되어 있습니다. 이 키는 여기에서 찾을 수 있습니다: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **이를 삭제**하면 USB 히스토리가 삭제됩니다.\
또한 [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) 도구를 사용하여 삭제 여부를 확인하고 삭제할 수 있습니다.

USB에 대한 정보를 저장하는 또 다른 파일은 `C:\Windows\INF` 내부의 `setupapi.dev.log` 파일입니다. 이 파일도 삭제해야 합니다.

## 그림자 복사본 비활성화

`vssadmin list shadowstorage`로 그림자 복사본을 **목록**화합니다.\
`vssadmin delete shadow`를 실행하여 그림자 복사본을 **삭제**합니다.

또한 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)에서 제안된 단계를 따라 GUI를 통해 그림자 복사본을 삭제할 수도 있습니다.

그림자 복사본을 비활성화하려면 [여기에서 제안된 단계](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)를 따르세요:

1. Windows 시작 버튼을 클릭한 후 텍스트 검색 상자에 "services"를 입력하여 서비스 프로그램을 엽니다.
2. 목록에서 "Volume Shadow Copy"를 찾아 선택한 다음 마우스 오른쪽 버튼을 클릭하여 속성에 액세스합니다.
3. "시작 유형" 드롭다운 메뉴에서 "비활성화"를 선택한 다음 변경을 확인하기 위해 적용 및 확인을 클릭합니다.

그림자 복사본에서 복사할 파일의 구성을 수정하는 것도 가능합니다. 레지스트리 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`에서 이를 수행할 수 있습니다.

## 삭제된 파일 덮어쓰기

* **Windows 도구**인 `cipher /w:C`를 사용할 수 있습니다. 이를 통해 cipher에게 C 드라이브 내의 사용 가능한 미사용 디스크 공간에서 데이터를 제거하도록 지시할 수 있습니다.
* [**Eraser**](https://eraser.heidi.ie)와 같은 도구도 사용할 수 있습니다.

## Windows 이벤트 로그 삭제

* Windows + R --> eventvwr.msc --> "Windows Logs" 확장 --> 각 범주를 마우스 오른쪽 버튼으로 클릭하고 "로그 지우기"를 선택합니다.
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Windows 이벤트 로그 비활성화

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* 서비스 섹션 내에서 "Windows Event Log" 서비스를 비활성화합니다.
* `WEvtUtil.exec clear-log` 또는 `WEvtUtil.exe cl`

## $UsnJrnl 비활성화

* `fsutil usn deletejournal /d c:`

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **트위터** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 팔로우하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
