<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>AWS 해킹을 처음부터 전문가까지 배워보세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>


# 타임스탬프

공격자는 탐지를 피하기 위해 파일의 타임스탬프를 변경하는 것에 관심이 있을 수 있습니다.\
MFT 내부의 속성 `$STANDARD_INFORMATION` __ 및 __ `$FILE_NAME`에서 타임스탬프를 찾을 수 있습니다.

두 속성은 **수정**, **액세스**, **생성** 및 **MFT 레지스트리 수정** (MACE 또는 MACB)에 대한 4개의 타임스탬프를 가지고 있습니다.

**Windows 탐색기** 및 기타 도구는 **`$STANDARD_INFORMATION`**에서 정보를 표시합니다.

## TimeStomp - 안티 포렌식 도구

이 도구는 **`$STANDARD_INFORMATION`** 내부의 타임스탬프 정보를 **수정**하지만 **`$FILE_NAME`** 내부의 정보는 **수정하지 않습니다**. 따라서 **수상한 활동을 식별**할 수 있습니다.

## Usnjrnl

**USN Journal** (Update Sequence Number Journal)은 NTFS (Windows NT 파일 시스템)의 기능으로 볼륨 변경 내용을 추적합니다. [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 도구를 사용하여 이러한 변경 사항을 검사할 수 있습니다.

![](<../../.gitbook/assets/image (449).png>)

이전 이미지는 도구에서 표시된 **출력**입니다. 여기서 파일에 일부 **변경 사항이 수행**되었음을 확인할 수 있습니다.

## $LogFile

파일 시스템의 **모든 메타데이터 변경 사항은 로그에 기록**됩니다. 이 로그된 메타데이터는 NTFS 파일 시스템의 루트 디렉토리에 위치한 `**$LogFile**`라는 파일에 유지됩니다. [LogFileParser](https://github.com/jschicht/LogFileParser)와 같은 도구를 사용하여 이 파일을 구문 분석하고 변경 사항을 식별할 수 있습니다.

![](<../../.gitbook/assets/image (450).png>)

도구의 출력에서 다시 **일부 변경 사항이 수행**되었음을 볼 수 있습니다.

동일한 도구를 사용하여 **타임스탬프가 수정된 시간**을 식별할 수 있습니다:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: 파일의 생성 시간
* ATIME: 파일의 수정 시간
* MTIME: 파일의 MFT 레지스트리 수정
* RTIME: 파일의 액세스 시간

## `$STANDARD_INFORMATION` 및 `$FILE_NAME` 비교

수상한 수정된 파일을 식별하는 또 다른 방법은 두 속성의 시간을 비교하여 **불일치**를 찾는 것입니다.

## 나노초

**NTFS** 타임스탬프는 **100 나노초의 정밀도**를 가지고 있습니다. 따라서 2010-10-10 10:10:**00.000:0000과 같은 타임스탬프를 가진 파일은 매우 수상합니다**.

## SetMace - 안티 포렌식 도구

이 도구는 `$STARNDAR_INFORMATION` 및 `$FILE_NAME` 두 속성을 모두 수정할 수 있습니다. 그러나 Windows Vista부터는 이 정보를 수정하기 위해 라이브 OS가 필요합니다.

# 데이터 숨김

NFTS는 클러스터와 최소 정보 크기를 사용합니다. 즉, 파일이 클러스터와 반 개를 사용하는 경우 **남은 반 개는 파일이 삭제될 때까지 사용되지 않습니다**. 따라서 이 "숨겨진" 공간에 데이터를 **숨길 수 있습니다**.

슬래커와 같은 도구를 사용하여 이 "숨겨진" 공간에 데이터를 숨길 수 있습니다. 그러나 `$logfile` 및 `$usnjrnl`의 분석을 통해 일부 데이터가 추가되었음을 확인할 수 있습니다:

![](<../../.gitbook/assets/image (452).png>)

그런 다음 FTK Imager와 같은 도구를 사용하여 슬랙 공간을 검색할 수 있습니다. 이러한 도구는 콘텐츠를 난독화하거나 암호화하여 저장할 수 있습니다.

# UsbKill

이 도구는 USB 포트에 변경 사항이 감지되면 컴퓨터를 **종료**합니다.\
이를 발견하기 위해 실행 중인 프로세스를 검사하고 **실행 중인 각 Python 스크립트를 검토**하는 방법이 있습니다.

# 라이브 Linux 배포판

이러한 배포판은 **RAM 메모리 내에서 실행**됩니다. NTFS 파일 시스템이 쓰기 권한으로 마운트되었는지 여부에 따라 감지할 수 있습니다. 읽기 권한으로만 마운트되었다면 침입을 감지할 수 없습니다.

# 안전한 삭제

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows 구성

포렌식 조사를 훨씬 어렵게 만들기 위해 여러 Windows 로깅 방법을 비활성화할 수 있습니다.

## 타임스탬프 비활성화 - UserAssist

이는 사용자가 각 실행 파일을 실행한 날짜와 시간을 유지하는 레지스트리 키입니다.

UserAssist를 비활성화하려면 두 단계를 거쳐야 합니다:

1. `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 및 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` 두 개의 레지스트리 키를 0으로 설정하여 UserAssist를 비활성화하려는 것을 나타냅니다.
2. `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`와 같은 레지스트리 하위 트리를 지웁니다.

## 타임스탬프 비활성화 - Prefetch

이는 Windows 시스템의 성능을 향상시키기 위해 실행된 응용 프로그램에 대한 정보를 저장합니다. 그러나 이는 포렌식 작업에도 유용할 수 있습니다.

* `regedit`를 실행합니다.
* 파일 경로 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`를 선택합니다.
* `EnablePrefetcher` 및 `EnableSuperfetch`를 마우스 오른쪽 버튼으로 클릭합니다.
* 각각의 수정을 선택하여 값을 1 (또는 3)에서 0으로 변경합니다.
* 재부팅합니다.

## 타임스탬프 비활성화 - 마지막 액세스 시간

Windows NT 서버의 NTFS 볼륨에서
## USB 기록 삭제

**USB 장치 항목**은 PC나 노트북에 USB 장치를 연결할 때마다 생성되는 하위 키를 포함하는 **USBSTOR** 레지스트리 키 아래에 저장됩니다. 이 키는 H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`에서 찾을 수 있습니다. **이를 삭제**하면 USB 기록이 삭제됩니다.\
또한 `C:\Windows\INF` 폴더 내의 `setupapi.dev.log` 파일도 삭제해야 합니다.

## 그림자 복사 비활성화

`vssadmin list shadowstorage` 명령으로 **그림자 복사본**을 나열합니다.\
`vssadmin delete shadow` 명령으로 그림자 복사본을 삭제합니다.

또한 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)에서 제안하는 단계를 따라 GUI를 통해 삭제할 수도 있습니다.

그림자 복사본을 비활성화하려면 [여기의 단계](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)를 따릅니다:

1. 시작 버튼을 클릭한 후 텍스트 검색 상자에 "services"를 입력하여 서비스 프로그램을 엽니다.
2. 목록에서 "Volume Shadow Copy"를 찾아 선택한 다음 마우스 오른쪽 버튼을 클릭하여 속성에 액세스합니다.
3. "시작 유형" 드롭다운 메뉴에서 "비활성화"를 선택한 후, 변경 사항을 적용하고 확인을 클릭하여 변경을 확인합니다.

그림자 복사본에서 복사할 파일의 구성도 레지스트리 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`에서 수정할 수 있습니다.

## 삭제된 파일 덮어쓰기

* **Windows 도구**인 `cipher /w:C`를 사용할 수 있습니다. 이는 cipher에게 C 드라이브의 사용 가능한 미사용 디스크 공간에서 데이터를 제거하도록 지시합니다.
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


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>로부터 제로에서 영웅까지 AWS 해킹 배우기<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나 **Twitter**에서 **@hacktricks_live**를 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
