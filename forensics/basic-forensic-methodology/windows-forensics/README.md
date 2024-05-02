# Windows 아티팩트

## Windows 아티팩트

<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team 전문가)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 일반 Windows 아티팩트

### Windows 10 알림

경로 `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`에 `appdb.dat` (Windows Anniversary 이전) 또는 `wpndatabase.db` (Windows Anniversary 이후)라는 데이터베이스를 찾을 수 있습니다.

이 SQLite 데이터베이스 안에는 흥미로운 데이터를 포함할 수 있는 모든 알림(XML 형식)을 포함하는 `Notification` 테이블이 있습니다.

### 타임라인

타임라인은 방문한 웹 페이지, 편집된 문서 및 실행된 응용 프로그램의 **시간순 역사**를 제공하는 Windows의 특성입니다.

데이터베이스는 경로 `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`에 있습니다. 이 데이터베이스는 SQLite 도구나 [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) 도구로 열 수 있으며 **2개의 파일을 생성**하여 [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) 도구로 열 수 있습니다.

### ADS (대체 데이터 스트림)

다운로드된 파일에는 **어떻게** 인트라넷, 인터넷 등에서 **다운로드**되었는지를 나타내는 **ADS Zone.Identifier**가 포함될 수 있습니다. 일부 소프트웨어(브라우저와 같은)는 파일이 다운로드된 URL과 같은 **더 많은 정보**를 보통 포함합니다.

## **파일 백업**

### 휴지통

Vista/Win7/Win8/Win10에서 **휴지통**은 드라이브 루트(`C:\$Recycle.bin`)에 있는 폴더 **`$Recycle.bin`**에서 찾을 수 있습니다.\
이 폴더에서 파일이 삭제되면 2개의 특정 파일이 생성됩니다:

* `$I{id}`: 파일 정보(삭제된 날짜)
* `$R{id}`: 파일의 내용

![](<../../../.gitbook/assets/image (486).png>)

이러한 파일을 사용하여 삭제된 파일의 원래 주소와 삭제된 날짜를 얻을 수 있습니다([**Rifiuti**](https://github.com/abelcheung/rifiuti2) 도구를 사용하고 Vista - Win10용 `rifiuti-vista.exe`를 사용하세요).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### 볼륨 그림자 사본

그림자 사본은 사용 중인 파일 또는 볼륨의 **백업 사본** 또는 스냅숏을 만들 수 있는 Microsoft Windows에 포함된 기술입니다.

이러한 백업은 일반적으로 파일 시스템의 루트인 `\System Volume Information`에 위치하며 다음 이미지에 표시된 **UIDs**로 구성된 이름을 가지고 있습니다:

![](<../../../.gitbook/assets/image (520).png>)

**ArsenalImageMounter**를 사용하여 포렌식 이미지를 마운트하면 [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) 도구를 사용하여 그림자 사본을 검사하고 그림자 사본 백업에서 **파일을 추출**할 수 있습니다.

![](<../../../.gitbook/assets/image (521).png>)

레지스트리 항목 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`에는 **백업하지 않을 파일** 및 키가 포함되어 있습니다:

![](<../../../.gitbook/assets/image (522).png>)

레지스트리 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS`에는 `Volume Shadow Copies`에 대한 구성 정보도 포함되어 있습니다.

### 오피스 자동 저장 파일

오피스 자동 저장 파일은 다음 위치에 있습니다: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## 쉘 항목

쉘 항목은 다른 파일에 액세스하는 방법에 대한 정보를 포함하는 항목입니다.

### 최근 문서 (LNK)

Windows는 사용자가 파일을 **열거나 사용하거나 생성할 때** 다음 위치에 이러한 **바로 가기**를 **자동으로 생성**합니다:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

폴더가 생성되면 해당 폴더, 상위 폴더 및 상위 상위 폴더로의 링크도 생성됩니다.

이러한 자동으로 생성된 링크 파일에는 **원본에 대한 정보**가 포함되어 있으며 **파일**인지 **폴더**인지, 해당 파일의 **MAC 시간**, 파일이 저장된 위치의 **볼륨 정보** 및 **대상 파일의 폴더**가 있는 정보가 포함됩니다. 이 정보는 파일이 삭제된 경우 해당 파일을 복구하는 데 유용할 수 있습니다.

또한, 링크 파일의 **생성 날짜**는 원본 파일이 **처음 사용된 시간**이고 링크 파일의 **수정 날짜**는 원본 파일이 **마지막으로 사용된 시간**입니다.

이러한 파일을 검사하려면 [**LinkParser**](http://4discovery.com/our-tools/)를 사용할 수 있습니다.

이 도구에서는 **2 세트**의 타임스탬프를 찾을 수 있습니다:

* **첫 번째 세트:**
1. 파일 수정 날짜
2. 파일 액세스 날짜
3. 파일 생성 날짜
* **두 번째 세트:**
1. 링크 수정 날짜
2. 링크 액세스 날짜
3. 링크 생성 날짜.

첫 번째 세트의 타임스탬프는 **파일 자체의 타임스탬프**를 참조합니다. 두 번째 세트는 **연결된 파일의 타임스탬프**를 참조합니다.

Windows CLI 도구 [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)를 실행하여 동일한 정보를 얻을 수 있습니다.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
### 점프리스트

이것들은 각 응용 프로그램에서 표시된 최근 파일들입니다. **응용 프로그램에서 사용된 최근 파일 목록**으로, 각 응용 프로그램에서 액세스할 수 있는 목록입니다. 이들은 **자동으로 생성되거나 사용자 정의될 수 있습니다**.

자동으로 생성된 **점프리스트**는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`에 저장됩니다. 점프리스트는 초기 ID가 응용 프로그램의 ID인 `{id}.autmaticDestinations-ms` 형식을 따릅니다.

사용자 정의 점프리스트는 `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\`에 저장되며, 일반적으로 응용 프로그램에 의해 생성됩니다. 파일에 중요한 일이 발생했기 때문에 (즐겨 찾기로 표시된 경우일 수도 있음)

어떤 점프리스트의 **생성 시간**은 **파일에 처음 액세스한 시간을 나타내며**, **수정된 시간은 마지막 시간**을 나타냅니다.

[JumplistExplorer](https://ericzimmerman.github.io/#!index.md)를 사용하여 점프리스트를 검사할 수 있습니다.

![](<../../../.gitbook/assets/image (474).png>)

(_JumplistExplorer에서 제공하는 타임스탬프는 점프리스트 파일 자체와 관련이 있음을 유의하십시오_)

### 쉘백

[**쉘백이 무엇인지 알아보려면 이 링크를 따르세요.**](interesting-windows-registry-keys.md#shellbags)

## Windows USB 사용

USB 장치가 사용되었음을 식별하는 것이 가능합니다:

* Windows 최근 폴더
* Microsoft Office 최근 폴더
* 점프리스트

일부 LNK 파일은 원본 경로를 가리키는 대신 WPDNSE 폴더를 가리킵니다:

![](<../../../.gitbook/assets/image (476).png>)

WPDNSE 폴더의 파일은 원본 파일의 사본이므로 PC를 다시 시작하면 살아남지 않으며, GUID는 쉘백에서 가져옵니다.

### 레지스트리 정보

USB 연결된 장치에 대한 흥미로운 정보를 포함하는 레지스트리 키가 어디에 있는지 알아보려면 [이 페이지를 확인하세요](interesting-windows-registry-keys.md#usb-information).

### setupapi

USB 연결이 발생한 시간에 대한 타임스탬프를 얻으려면 파일 `C:\Windows\inf\setupapi.dev.log`를 확인하십시오 (`Section start`를 검색).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com)를 사용하여 이미지에 연결된 USB 장치에 대한 정보를 얻을 수 있습니다.

![](<../../../.gitbook/assets/image (483).png>)

### 플러그 앤 플레이 정리

'플러그 앤 플레이 정리'로 알려진 예약된 작업은 오래된 드라이버 버전을 제거하기 위해 주로 설계되었습니다. 최신 드라이버 패키지 버전을 유지하는 것이 명시된 목적과는 달리, 온라인 소스에 따르면 지난 30일간 비활성화된 드라이버도 대상으로 삼을 수 있다고 합니다. 따라서, 지난 30일간 연결되지 않은 제거 가능한 장치의 드라이버는 삭제 대상이 될 수 있습니다.

해당 작업은 다음 경로에 위치합니다:
`C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

작업 내용을 보여주는 스크린샷이 제공됩니다:
![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**작업의 주요 구성 요소 및 설정:**
- **pnpclean.dll**: 이 DLL은 실제 정리 프로세스를 담당합니다.
- **UseUnifiedSchedulingEngine**: `TRUE`로 설정되어 일반적인 작업 스케줄링 엔진을 사용함을 나타냅니다.
- **MaintenanceSettings**:
- **기간 ('P1M')**: 작업 스케줄러에게 정기적인 자동 유지 관리 중에 매월 정리 작업을 시작하도록 지시합니다.
- **마감 기한 ('P2M')**: 작업이 두 달 연속 실패하면 비상 자동 유지 관리 중에 작업을 실행하도록 작업 스케줄러에게 지시합니다.

이 구성은 드라이버의 정기적인 유지 관리와 정리를 보장하며, 연속적인 실패의 경우 작업을 재시도할 수 있는 조항을 제공합니다.

**자세한 정보는 여기를 확인하세요:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## 이메일

이메일에는 **헤더와 내용** 두 가지 흥미로운 부분이 포함되어 있습니다. **헤더**에서는 다음과 같은 정보를 찾을 수 있습니다:

* 이메일을 보낸 **사람** (이메일 주소, IP, 이메일을 리디렉션한 메일 서버)
* 이메일이 보내진 **시간**

또한, `References` 및 `In-Reply-To` 헤더 내에서 메시지의 ID를 찾을 수 있습니다:

![](<../../../.gitbook/assets/image (484).png>)

### Windows 메일 앱

이 응용 프로그램은 이메일을 HTML 또는 텍스트로 저장합니다. 이메일은 `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` 내의 하위 폴더에서 찾을 수 있습니다. 이메일은 `.dat` 확장자로 저장됩니다.

이메일의 **메타데이터** 및 **연락처**는 **EDB 데이터베이스** 내에서 찾을 수 있습니다: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

파일의 확장자를 `.vol`에서 `.edb`로 변경하고 [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) 도구를 사용하여 열 수 있습니다. `Message` 테이블 내에서 이메일을 볼 수 있습니다.

### Microsoft Outlook

Exchange 서버 또는 Outlook 클라이언트를 사용할 때 MAPI 헤더가 있습니다:

* `Mapi-Client-Submit-Time`: 이메일이 보내진 시스템 시간
* `Mapi-Conversation-Index`: 쓰레드의 자식 메시지 수 및 쓰레드의 각 메시지의 타임스탬프
* `Mapi-Entry-ID`: 메시지 식별자.
* `Mappi-Message-Flags` 및 `Pr_last_Verb-Executed`: MAPI 클라이언트에 대한 정보 (메시지 읽음? 읽지 않음? 응답함? 리디렉트됨? 사무실 외부?)

Microsoft Outlook 클라이언트에서 모든 보낸/받은 메시지, 연락처 데이터 및 캘린더 데이터는 다음 위치의 PST 파일에 저장됩니다:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

레지스트리 경로 `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook`은 사용 중인 파일을 나타냅니다.

PST 파일을 열려면 [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) 도구를 사용할 수 있습니다.

![](<../../../.gitbook/assets/image (485).png>)
### Microsoft Outlook OST 파일

**OST 파일**은 Microsoft Outlook이 **IMAP** 또는 **Exchange** 서버와 구성될 때 생성되며 PST 파일과 유사한 정보를 저장합니다. 이 파일은 서버와 동기화되어 **최대 50GB**까지의 데이터를 **지난 12개월 동안** 유지하며 PST 파일과 동일한 디렉토리에 위치합니다. OST 파일을 보려면 [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html)를 사용할 수 있습니다.

### 첨부 파일 검색

분실된 첨부 파일은 다음 위치에서 복구할 수 있습니다:

- **IE10**의 경우: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- **IE11 이상**의 경우: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX 파일

**Thunderbird**는 데이터를 저장하기 위해 **MBOX 파일**을 사용하며 이 파일은 `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`에 위치합니다.

### 이미지 썸네일

- **Windows XP 및 8-8.1**: 썸네일이 포함된 폴더에 액세스하면 이미지 미리보기를 저장하는 `thumbs.db` 파일이 생성되며 삭제 후에도 유지됩니다.
- **Windows 7/10**: `thumbs.db`는 UNC 경로를 통해 네트워크에서 액세스할 때 생성됩니다.
- **Windows Vista 및 이후**: 썸네일 미리보기는 `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`에 **thumbcache\_xxx.db**라는 파일로 중앙 집중화됩니다. [**Thumbsviewer**](https://thumbsviewer.github.io) 및 [**ThumbCache Viewer**](https://thumbcacheviewer.github.io)는 이러한 파일을 보는 데 사용할 수 있는 도구입니다.

### Windows 레지스트리 정보

Windows 레지스트리는 다음 위치에 포함된 파일에 포함되어 있으며 시스템 및 사용자 활동 데이터를 저장합니다:

- 다양한 `HKEY_LOCAL_MACHINE` 하위 키에 대한 `%windir%\System32\Config`.
- `HKEY_CURRENT_USER`에 대한 `%UserProfile%{User}\NTUSER.DAT`.
- Windows Vista 이상 버전은 `%Windir%\System32\Config\RegBack\`에 `HKEY_LOCAL_MACHINE` 레지스트리 파일을 백업합니다.
- 또한, 프로그램 실행 정보는 Windows Vista 및 Windows 2008 Server 이후에 `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`에 저장됩니다.

### 도구

레지스트리 파일을 분석하는 데 유용한 일부 도구는 다음과 같습니다:

* **레지스트리 편집기**: Windows에 설치되어 현재 세션의 Windows 레지스트리를 탐색하는 GUI 도구입니다.
* [**레지스트리 탐색기**](https://ericzimmerman.github.io/#!index.md): 레지스트리 파일을 로드하고 GUI를 통해 탐색할 수 있도록 해주는 도구입니다. 흥미로운 정보가 포함된 키를 강조하는 책갈피도 포함되어 있습니다.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): 로드된 레지스트리를 탐색하고 흥미로운 정보를 강조하는 플러그인도 포함된 GUI를 제공합니다.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): 로드된 레지스트리에서 중요한 정보를 추출할 수 있는 또 다른 GUI 응용 프로그램입니다.

### 삭제된 요소 복구

키가 삭제되면 해당 사실이 표시되지만 해당 공간이 필요할 때까지 제거되지 않습니다. 따라서 **Registry Explorer**와 같은 도구를 사용하여 이러한 삭제된 키를 복구할 수 있습니다.

### 마지막 수정 시간

각 키-값에는 마지막 수정된 시간을 나타내는 **타임스탬프**가 포함되어 있습니다.

### SAM

파일/하이브 **SAM**에는 시스템의 **사용자, 그룹 및 사용자 비밀번호** 해시가 포함되어 있습니다.

`SAM\Domains\Account\Users`에서는 사용자 이름, RID, 마지막 로그인, 마지막 로그인 실패, 로그인 횟수, 비밀번호 정책 및 계정 생성 시간을 얻을 수 있습니다. **해시**를 얻으려면 파일/하이브 **SYSTEM**도 필요합니다.
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch**는 prefetch와 동일한 목표를 가지고 있으며, **다음에 로드될 것을 예측하여 프로그램을 더 빨리 로드**합니다. 그러나 prefetch 서비스를 대체하지는 않습니다.\
이 서비스는 `C:\Windows\Prefetch\Ag*.db`에 데이터베이스 파일을 생성합니다.

이 데이터베이스에서는 **프로그램의 이름**, **실행 횟수**, **열린 파일**, **접근한 볼륨**, **전체 경로**, **시간대** 및 **타임스탬프**를 찾을 수 있습니다.

이 정보에는 [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) 도구를 사용하여 액세스할 수 있습니다.

### SRUM

**시스템 리소스 사용 모니터**(SRUM)는 **프로세스가 사용한 리소스를 모니터링**합니다. W8에 등장하며, 데이터를 `C:\Windows\System32\sru\SRUDB.dat`에 위치한 ESE 데이터베이스에 저장합니다.

다음 정보를 제공합니다:

* AppID 및 경로
* 프로세스를 실행한 사용자
* 보낸 바이트
* 받은 바이트
* 네트워크 인터페이스
* 연결 기간
* 프로세스 기간

이 정보는 60분마다 업데이트됩니다.

이 파일에서 날짜를 얻을 수 있는 도구인 [**srum\_dump**](https://github.com/MarkBaggett/srum-dump)를 사용할 수 있습니다.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**AppCompatCache**(ShimCache)은 **Microsoft**가 개발한 **Application Compatibility Database**의 일부로, 응용 프로그램 호환성 문제를 해결하기 위해 만들어졌습니다. 이 시스템 구성 요소는 다음과 같은 파일 메타데이터를 기록합니다:

- 파일의 전체 경로
- 파일의 크기
- **$Standard\_Information** (SI) 하위의 최종 수정 시간
- ShimCache의 최종 업데이트 시간
- 프로세스 실행 플래그

이러한 데이터는 운영 체제 버전에 따라 레지스트리의 특정 위치에 저장됩니다:

- XP의 경우, 데이터는 `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`에 저장되며 96개의 항목을 수용합니다.
- Server 2003 및 Windows 버전 2008, 2012, 2016, 7, 8 및 10의 경우, 저장 경로는 `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`이며 각각 512개 및 1024개의 항목을 수용합니다.

저장된 정보를 구문 분석하려면 [**AppCompatCacheParser** 도구](https://github.com/EricZimmerman/AppCompatCacheParser)를 사용하는 것이 좋습니다.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

**Amcache.hve** 파일은 시스템에서 실행된 응용 프로그램에 대한 세부 정보를 기록하는 레지스트리 하이브입니다. 일반적으로 `C:\Windows\AppCompat\Programas\Amcache.hve`에서 찾을 수 있습니다.

이 파일은 최근 실행된 프로세스의 기록뿐만 아니라 실행 파일의 경로와 SHA1 해시를 포함하여 중요한 정보를 저장합니다. 이 정보는 시스템에서 응용 프로그램의 활동을 추적하는 데 귀중합니다.

**Amcache.hve**에서 데이터를 추출하고 분석하려면 [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) 도구를 사용할 수 있습니다. 다음 명령은 **Amcache.hve** 파일의 내용을 구문 분석하고 결과를 CSV 형식으로 출력하는 방법의 예시입니다:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
생성된 CSV 파일 중 `Amcache_Unassociated file entries`는 연관되지 않은 파일 항목에 대한 풍부한 정보를 제공하기 때문에 특히 주목할 가치가 있습니다.

가장 흥미로운 CVS 파일은 `Amcache_Unassociated file entries`입니다.

### RecentFileCache

이 아티팩트는 `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`에서 W7에서만 찾을 수 있으며 일부 이진 파일의 최근 실행에 대한 정보를 포함합니다.

파일을 구문 분석하려면 [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) 도구를 사용할 수 있습니다.

### 예약된 작업

`C:\Windows\Tasks` 또는 `C:\Windows\System32\Tasks`에서 추출하여 XML로 읽을 수 있습니다.

### 서비스

레지스트리에서 `SYSTEM\ControlSet001\Services` 아래에서 찾을 수 있습니다. 무엇이 실행될지와 언제 실행될지 확인할 수 있습니다.

### **Windows Store**

설치된 애플리케이션은 `\ProgramData\Microsoft\Windows\AppRepository\`에서 찾을 수 있습니다.\
이 저장소에는 시스템에 설치된 각 애플리케이션에 대한 **로그**가 **`StateRepository-Machine.srd`** 데이터베이스 내부에 있습니다.

이 데이터베이스의 Application 테이블에서 "Application ID", "PackageNumber", "Display Name" 열을 찾을 수 있습니다. 이 열에는 사전 설치된 및 설치된 애플리케이션에 대한 정보가 있으며 설치된 애플리케이션의 ID가 연속적이어야 하는지 확인할 수 있습니다.

또한 레지스트리 경로에서 **설치된 애플리케이션**을 찾을 수 있습니다: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
그리고 **설치 해제된 애플리케이션**은 여기에서 찾을 수 있습니다: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows 이벤트

Windows 이벤트 내에서 나타나는 정보는 다음과 같습니다:

* 무슨 일이 있었는가
* 타임스탬프 (UTC + 0)
* 관련된 사용자
* 관련된 호스트 (호스트 이름, IP)
* 액세스된 에셋 (파일, 폴더, 프린터, 서비스)

로그는 Windows Vista 이전에는 `C:\Windows\System32\config`에 있었고, Windows Vista 이후에는 `C:\Windows\System32\winevt\Logs`에 있습니다. Windows Vista 이전에는 이벤트 로그가 이진 형식이었고, 그 이후에는 **XML 형식**이며 **.evtx** 확장자를 사용합니다.

이벤트 파일의 위치는 SYSTEM 레지스트리에서 **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**에서 찾을 수 있습니다.

Windows 이벤트 뷰어 (**`eventvwr.msc`**) 또는 [**Event Log Explorer**](https://eventlogxp.com) **또는** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**와 같은** 다른 도구로 시각화할 수 있습니다.

## Windows 보안 이벤트 로깅 이해

보안 구성 파일에 기록된 액세스 이벤트는 `C:\Windows\System32\winevt\Security.evtx`에 있습니다. 이 파일의 크기는 조정 가능하며, 용량이 가득 차면 이전 이벤트가 덮어씌워집니다. 기록된 이벤트에는 사용자 로그인 및 로그오프, 사용자 작업, 보안 설정 변경, 파일, 폴더 및 공유 자산 액세스가 포함됩니다.

### 사용자 인증을 위한 주요 이벤트 ID:

- **EventID 4624**: 사용자가 성공적으로 인증됨을 나타냅니다.
- **EventID 4625**: 인증 실패를 신호합니다.
- **EventIDs 4634/4647**: 사용자 로그오프 이벤트를 나타냅니다.
- **EventID 4672**: 관리 권한으로 로그인을 나타냅니다.

#### EventID 4634/4647 내의 하위 유형:

- **Interactive (2)**: 직접 사용자 로그인.
- **Network (3)**: 공유 폴더 액세스.
- **Batch (4)**: 일괄 프로세스 실행.
- **Service (5)**: 서비스 시작.
- **Proxy (6)**: 프록시 인증.
- **Unlock (7)**: 암호로 화면 잠금 해제.
- **Network Cleartext (8)**: IIS에서의 평문 암호 전송.
- **New Credentials (9)**: 액세스를 위한 다른 자격 증명 사용.
- **Remote Interactive (10)**: 원격 데스크톱 또는 터미널 서비스 로그인.
- **Cache Interactive (11)**: 도메인 컨트롤러 연락 없이 캐시된 자격 증명으로 로그인.
- **Cache Remote Interactive (12)**: 캐시된 자격 증명으로 원격 로그인.
- **Cached Unlock (13)**: 캐시된 자격 증명으로 잠금 해제.

#### EventID 4625의 상태 및 하위 상태 코드:

- **0xC0000064**: 사용자 이름이 존재하지 않음 - 사용자 이름 열거 공격을 나타낼 수 있습니다.
- **0xC000006A**: 올바른 사용자 이름이지만 잘못된 암호 - 암호 추측 또는 무차별 대입 시도가 있을 수 있습니다.
- **0xC0000234**: 사용자 계정 잠금 - 다수의 로그인 실패로 인한 무차별 대입 공격을 나타낼 수 있습니다.
- **0xC0000072**: 계정 비활성화 - 비활성화된 계정에 대한 무단 액세스 시도가 있을 수 있습니다.
- **0xC000006F**: 허용된 시간 외 로그인 - 설정된 로그인 시간 외에 액세스 시도가 있을 수 있으며, 무단 액세스의 가능성이 있습니다.
- **0xC0000070**: 워크스테이션 제한 위반 - 무단 위치에서 로그인 시도가 있을 수 있습니다.
- **0xC0000193**: 계정 만료 - 만료된 사용자 계정으로의 액세스 시도가 있을 수 있습니다.
- **0xC0000071**: 암호 만료 - 오래된 암호로의 로그인 시도가 있을 수 있습니다.
- **0xC0000133**: 시간 동기화 문제 - 클라이언트와 서버 간의 큰 시간 차이는 패스더티켓과 같은 고급 공격의 징후일 수 있습니다.
- **0xC0000224**: 필수 암호 변경 필요 - 빈번한 필수 변경은 계정 보안을 불안정하게 만들려는 시도일 수 있습니다.
- **0xC0000225**: 보안 문제가 아닌 시스템 버그를 나타냅니다.
- **0xC000015b**: 거부된 로그온 유형 - 사용자가 서비스 로그온을 실행하려고 시도하는 등의 무단 로그온 유형으로의 액세스 시도가 있을 수 있습니다.

#### EventID 4616:
- **시간 변경**: 시스템 시간 변경, 사건 타임라인을 혼란스럽게 할 수 있습니다.

#### EventID 6005 및 6006:
- **시스템 시작 및 종료**: EventID 6005는 시스템 시작을 나타내고, EventID 6006은 시스템 종료를 나타냅니다.

#### EventID 1102:
- **로그 삭제**: 불법 활동을 숨기기 위한 보안 로그 삭제.

#### USB 장치 추적을 위한 EventID:
- **20001 / 20003 / 10000**: USB 장치 최초 연결.
- **10100**: USB 드라이버 업데이트.
- **EventID 112**: USB 장치 삽입 시간.
#### 시스템 전원 이벤트

EventID 6005은 시스템 시작을 나타내며, EventID 6006은 종료를 표시합니다.

#### 로그 삭제

보안 EventID 1102는 로그 삭제를 신호하는데, 이는 포렌식 분석에 중요한 이벤트입니다.

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>제로부터 영웅이 될 때까지 AWS 해킹 배우기</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를 팔로우하세요.**
* **HackTricks 및 HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유하세요.**

</details>
