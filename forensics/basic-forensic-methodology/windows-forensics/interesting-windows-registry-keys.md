# 흥미로운 Windows 레지스트리 키

### 흥미로운 Windows 레지스트리 키

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요**.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}

### **Windows 버전 및 소유자 정보**
- **`Software\Microsoft\Windows NT\CurrentVersion`**에 위치한 이곳에서 Windows 버전, 서비스 팩, 설치 시간 및 등록된 소유자 이름을 간단하게 찾을 수 있습니다.

### **컴퓨터 이름**
- 호스트 이름은 **`System\ControlSet001\Control\ComputerName\ComputerName`** 아래에서 찾을 수 있습니다.

### **시간대 설정**
- 시스템의 시간대는 **`System\ControlSet001\Control\TimeZoneInformation`**에 저장됩니다.

### **접근 시간 추적**
- 기본적으로 마지막 접근 시간 추적은 꺼져 있습니다 (**`NtfsDisableLastAccessUpdate=1`**). 이를 활성화하려면 다음을 사용하세요:
`fsutil behavior set disablelastaccess 0`

### Windows 버전 및 서비스 팩
- **Windows 버전**은 에디션 (예: 홈, 프로) 및 릴리스 (예: Windows 10, Windows 11)을 나타내며, **서비스 팩**은 수정 사항과 때로는 새로운 기능을 포함하는 업데이트입니다.

### 마지막 접근 시간 활성화
- 마지막 접근 시간 추적을 활성화하면 파일이 마지막으로 열린 시간을 확인할 수 있어서 포렌식 분석이나 시스템 모니터링에 중요할 수 있습니다.

### 네트워크 정보 세부사항
- 레지스트리에는 네트워크 구성에 대한 포괄적인 데이터가 저장되어 있으며, **네트워크 유형(무선, 케이블, 3G)** 및 **네트워크 범주(공용, 개인/홈, 도메인/작업)**를 포함하고 있어 네트워크 보안 설정 및 권한을 이해하는 데 중요합니다.

### 클라이언트 측 캐싱 (CSC)
- **CSC**는 공유 파일의 복사본을 캐싱하여 오프라인 파일 액세스를 향상시킵니다. 다양한 **CSCFlags** 설정은 어떤 파일이 어떻게 캐싱되는지를 제어하며, 일시적인 연결이 있는 환경에서는 성능 및 사용자 경험에 영향을 줄 수 있습니다.

### 자동 시작 프로그램
- 다양한 `Run` 및 `RunOnce` 레지스트리 키에 나열된 프로그램들은 자동으로 시작되어 시스템 부팅 시간에 영향을 주며, 악성 코드나 원치 않는 소프트웨어를 식별하는 데 중요할 수 있습니다.

### 쉘백
- **쉘백**은 폴더 보기에 대한 환경 설정 뿐만 아니라 폴더 액세스에 대한 포렌식 증거를 제공합니다. 다른 방법으로는 명확하지 않은 사용자 활동을 드러내는 조사에 귀중합니다.

### USB 정보 및 포렌식
- USB 장치에 대한 레지스트리에 저장된 세부 정보는 컴퓨터에 연결된 장치를 추적하는 데 도움이 될 수 있으며, 민감한 파일 전송이나 무단 액세스 사건과 연결될 수 있습니다.

### 볼륨 일련 번호
- **볼륨 일련 번호**는 파일 시스템의 특정 인스턴스를 추적하는 데 중요할 수 있으며, 파일 원본을 다른 장치 간에 확립해야 하는 포렌식 시나리오에서 유용합니다.

### **종료 세부 정보**
- 종료 시간 및 횟수 (XP의 경우에만)는 **`System\ControlSet001\Control\Windows`** 및 **`System\ControlSet001\Control\Watchdog\Display`**에 저장됩니다.

### **네트워크 구성**
- 자세한 네트워크 인터페이스 정보는 **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**를 참조하세요.
- VPN 연결을 포함한 첫 번째 및 마지막 네트워크 연결 시간은 **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**의 다양한 경로에 로깅됩니다.

### **공유 폴더**
- 공유 폴더 및 설정은 **`System\ControlSet001\Services\lanmanserver\Shares`**에 있습니다. 클라이언트 측 캐싱 (CSC) 설정은 오프라인 파일 가용성을 결정합니다.

### **자동으로 시작하는 프로그램**
- **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`**과 `Software\Microsoft\Windows\CurrentVersion` 하위 항목과 같은 경로는 시작 시 실행되는 프로그램을 자세히 설명합니다.

### **검색 및 입력된 경로**
- 탐색기 검색 및 입력된 경로는 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`**의 WordwheelQuery 및 TypedPaths 아래에서 레지스트리에 추적됩니다.

### **최근 문서 및 Office 파일**
- 액세스한 최근 문서 및 Office 파일은 `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` 및 특정 Office 버전 경로에 기록됩니다.

### **가장 최근에 사용된 (MRU) 항목**
- 최근 파일 경로 및 명령을 나타내는 MRU 목록은 `NTUSER.DAT`의 다양한 `ComDlg32` 및 `Explorer` 하위 키에 저장됩니다.

### **사용자 활동 추적**
- 사용자 어시스트 기능은 **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**에서 실행 횟수 및 마지막 실행 시간을 포함한 자세한 응용 프로그램 사용 통계를 기록합니다.

### **쉘백 분석**
- 폴더 액세스 세부 정보를 나타내는 쉘백은 `USRCLASS.DAT` 및 `NTUSER.DAT`의 `Software\Microsoft\Windows\Shell`에 저장됩니다. 분석을 위해 **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)**를 사용하세요.

### **USB 장치 이력**
- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** 및 **`HKLM\SYSTEM\ControlSet001\Enum\USB`**에는 제조사, 제품 이름 및 연결 타임스탬프를 포함한 연결된 USB 장치에 대한 상세 정보가 포함되어 있습니다.
- 특정 USB 장치와 연결된 사용자는 장치의 **{GUID}**를 검색하여 파악할 수 있습니다.
- 마지막으로 마운트된 장치 및 해당 볼륨 일련 번호는 각각 `System\MountedDevices` 및 `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`를 통해 추적할 수 있습니다.

이 안내서는 Windows 시스템에서 상세한 시스템, 네트워크 및 사용자 활동 정보에 액세스하기 위한 중요한 경로와 방법을 명확하고 사용하기 쉽게 요약합니다.



{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요**.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
