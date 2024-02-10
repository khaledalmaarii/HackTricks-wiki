# WmicExec

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로에서 영웅까지 AWS 해킹을 배워보세요</strong>!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 작동 방식 설명

WMI를 사용하여 사용자 이름과 비밀번호 또는 해시가 알려진 호스트에서 프로세스를 열 수 있습니다. Wmiexec을 사용하여 WMI를 통해 명령을 실행하면 반-대화식 셸 환경이 제공됩니다.

**dcomexec.py:** 다양한 DCOM 엔드포인트를 활용하여 이 스크립트는 wmiexec.py와 유사한 반-대화식 셸을 제공하며, 특히 ShellBrowserWindow DCOM 객체를 활용합니다. 현재 MMC20. Application, Shell Windows 및 Shell Browser Window 객체를 지원합니다. (출처: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## WMI 기본 사항

### 네임스페이스

디렉토리 스타일의 계층 구조로 구성된 WMI의 최상위 컨테이너는 \root이며, 이 하위에는 네임스페이스라고 하는 추가 디렉토리가 구성됩니다.
네임스페이스를 나열하는 명령어:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
네임스페이스 내의 클래스는 다음을 사용하여 나열할 수 있습니다:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **클래스**

WMI 작업에 있어서 win32\_process와 같은 WMI 클래스 이름과 해당 클래스가 속한 네임스페이스를 알아야 합니다.
`win32`로 시작하는 클래스를 나열하는 명령어:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
클래스의 호출:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### 메서드

메서드는 WMI 클래스의 하나 이상의 실행 가능한 함수입니다. 이러한 메서드는 실행될 수 있습니다.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI 열거

### WMI 서비스 상태

WMI 서비스가 정상적으로 작동하는지 확인하는 명령어:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### 시스템 및 프로세스 정보

WMI를 통해 시스템 및 프로세스 정보 수집하기:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
공격자에게 WMI는 시스템이나 도메인에 대한 민감한 데이터를 열거하는 강력한 도구입니다.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
### **수동 원격 WMI 쿼리**

원격 컴퓨터에서 로컬 관리자 또는 로그인한 사용자와 같은 특정 정보를 신중한 명령 구성을 통해 식별할 수 있습니다. `wmic`은 또한 여러 노드에서 동시에 명령을 실행하기 위해 텍스트 파일에서 읽는 것을 지원합니다.

Empire 에이전트를 배포하는 것과 같이 WMI를 통해 프로세스를 원격으로 실행하기 위해 다음 명령 구조를 사용하며, "0"의 반환 값으로 성공적인 실행을 나타냅니다:
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
이 과정은 원격 실행 및 시스템 열거에 대한 WMI의 기능을 보여주며, 시스템 관리 및 펜테스팅에 대한 유용성을 강조합니다.


## 참고 자료
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## 자동화 도구

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
