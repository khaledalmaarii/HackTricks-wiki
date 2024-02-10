# 흥미로운 Windows 레지스트리 키

### 흥미로운 Windows 레지스트리 키

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>


### **Windows 버전 및 소유자 정보**
- **`Software\Microsoft\Windows NT\CurrentVersion`**에 위치한 Windows 버전, 서비스 팩, 설치 시간 및 등록된 소유자 이름을 간단하게 찾을 수 있습니다.

### **컴퓨터 이름**
- 호스트 이름은 **`System\ControlSet001\Control\ComputerName\ComputerName`** 아래에서 찾을 수 있습니다.

### **시간대 설정**
- 시스템의 시간대는 **`System\ControlSet001\Control\TimeZoneInformation`**에 저장됩니다.

### **접근 시간 추적**
- 기본적으로 마지막 접근 시간 추적은 꺼져 있습니다 (**`NtfsDisableLastAccessUpdate=1`**). 활성화하려면 다음을 사용하세요:
`fsutil behavior set disablelastaccess 0`

### Windows 버전 및 서비스 팩
- **Windows 버전**은 에디션 (예: Home, Pro) 및 릴리스 (예: Windows 10, Windows 11)를 나타내며, **서비스 팩**은 수정 사항과 때로는 새로운 기능을 포함한 업데이트입니다.

### 마지막 접근 시간 활성화
- 마지막 접근 시간 추적을 활성화하면 파일이 마지막으로 열린 시간을 확인할 수 있으며, 이는 포렌식 분석이나 시스템 모니터링에 중요할 수 있습니다.

### 네트워크 정보 세부 사항
- 레지스트리에는 네트워크 구성에 대한 포괄적인 데이터가 저장되어 있으며, 이는 네트워크 보안 설정 및 권한 이해에 중요합니다. 이 데이터에는 **네트워크 유형 (무선, 케이블, 3G)** 및 **네트워크 범주 (공용, 개인/홈, 도메인/작업)**가 포함됩니다.

### 클라이언트 측 캐싱 (CSC)
- **CSC**는 공유 파일의 복사본을 캐싱하여 오프라인 파일 액세스를 향상시킵니다. 다양한 **CSCFlags** 설정은 어떤 파일이 어떻게 캐시되는지를 제어하며, 연결이 불안정한 환경에서는 성능과 사용자 경험에 영향을 줄 수 있습니다.

### 자동 시작 프로그램
- 다양한 `Run` 및 `RunOnce` 레지스트리 키에 나열된 프로그램은 자동으로 시작되어 시스템 부팅 시간에 영향을 주며, 악성 코드 또는 원치 않는 소프트웨어를 식별하는 데 중요한 지점이 될 수 있습니다.

### Shellbags
- **Shellbags**는 폴더 보기에 대한 환경 설정뿐만 아니라 폴더가 더 이상 존재하지 않더라도 폴더 접근에 대한 포렌식 증거를 제공합니다. 다른 수단으로는 명확하지 않은 사용자 활동을 밝혀내는 데 귀중합니다.

### USB 정보 및 포렌식
- 레지스트리에 저장된 USB 장치에 대한 세부 정보는 컴퓨터에 연결된 장치를 추적하는 데 도움이 될 수 있으며, 민감한 파일 전송이나 무단 액세스 사건과 장치를 연결할 수 있습니다.

### 볼륨 일련 번호
- **볼륨 일련 번호**는 파일 시스템의 특정 인스턴스를 추적하는 데 중요할 수 있으며, 파일의 원본을 다른 장치에서 확인해야 하는 포렌식 시나리오에 유용합니다.

### **종료 세부 정보**
- 종료 시간 및 횟수 (XP의 경우에만 해당)는 **`System\ControlSet001\Control\Windows`** 및 **`System\ControlSet001\Control\Watchdog\Display`**에 저장됩니다.

### **네트워크 구성**
- 자세한 네트워크 인터페이스 정보는 **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**를 참조하세요.
- VPN 연결을 포함한 첫 번째 및 마지막 네트워크 연결 시간은 **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**의 다양한 경로에 기록됩니다.

### **공유 폴더**
- 공유 폴더 및 설정은 **`System\ControlSet001\Services\lanmanserver\Shares`**에 있습니다. 클라이언트 측 캐싱 (CSC) 설정은 오프라인 파일의 가용성을 결정합니다.

### **자동으로 시작되는 프로그램**
- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** 및 `Software\Microsoft\Windows\CurrentVersion`의 유사한 항목과 같은 경로에 나열된 프로그램은 시작 시 자동으로 실행됩니다.

### **검색 및 입력된 경로**
- 탐색기 검색 및 입력된 경로는 레지스트리의 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`**에 WordwheelQuery 및 TypedPaths로 추적됩니다.

### **최근 문서 및 Office 파일**
- 최근에 액세스한 문서 및 Office 파일은 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` 및 특정 Office 버전 경로에 기록됩니다.

### **가장 최근에 사용된 (MRU) 항목**
- 최근 파일 경로 및 명령을 나타내는 MRU 목록은 `NTUSER.DAT`의 다양한 `ComDlg32` 및 `Explorer` 하위 키에 저장됩니다.

### **사용자 활동 추적**
- User Assist 기능은 애플리케이션 사용 횟수 및 마지막 실행 시간을 포함한 자세한 사용 통계를 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**에 기록합니다.

### **Shell
