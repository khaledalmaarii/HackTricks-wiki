# 무결성 수준

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 코드**에 의해 **침해**당했는지 무료로 확인할 수 있는 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 탈취 악성 코드로 인한 계정 탈취 및 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료로** 시도해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

***

## 무결성 수준

Windows Vista 이상 버전에서 모든 보호된 항목에는 **무결성 수준** 태그가 있습니다. 이 설정은 대부분 파일과 레지스트리 키에 "중간" 무결성 수준을 할당하며, 특정 폴더 및 파일은 인터넷 익스플로러 7이 낮은 무결성 수준에서 쓸 수 있는 예외입니다. 표준 사용자에 의해 시작된 프로세스는 일반적으로 중간 무결성 수준을 갖지만, 서비스는 일반적으로 시스템 무결성 수준에서 작동합니다. 고 무결성 레이블은 루트 디렉토리를 보호합니다.

중요한 규칙은 객체가 해당 객체의 수준보다 낮은 무결성 수준을 갖는 프로세스에 의해 수정될 수 없다는 것입니다. 무결성 수준은 다음과 같습니다:

* **신뢰되지 않는**: 익명 로그인을 사용하는 프로세스를 위한 수준입니다. %%%예시: Chrome%%%
* **낮음**: 주로 인터넷 상호작용을 위한 수준으로, 특히 인터넷 익스플로러의 보호 모드에서 관련 파일 및 프로세스에 영향을 미치며, **임시 인터넷 폴더**와 같은 특정 폴더에 영향을 줍니다. 낮은 무결성 프로세스는 레지스트리 쓰기 액세스가 없으며 사용자 프로필 쓰기 액세스가 제한됩니다.
* **중간**: 대부분의 활동에 대한 기본 수준으로, 표준 사용자 및 특정 무결성 수준이 없는 객체에 할당됩니다. 관리자 그룹의 구성원조차 기본적으로 이 수준에서 작동합니다.
* **높음**: 관리자 전용으로, 높은 무결성 수준을 포함하여 낮은 무결성 수준의 객체를 수정할 수 있습니다.
* **시스템**: Windows 커널 및 핵심 서비스를 위한 최고 운영 수준으로, 심각한 시스템 기능을 보호하기 위해 관리자조차 접근할 수 없습니다.
* **설치 프로그램**: 다른 모든 수준보다 높은 고유한 수준으로, 이 수준의 객체는 다른 모든 객체를 제거할 수 있습니다.

프로세스의 무결성 수준은 **Sysinternals**의 **Process Explorer**를 사용하여 프로세스의 **속성**에 액세스하고 "**보안**" 탭을 확인하여 얻을 수 있습니다:

![](<../../.gitbook/assets/image (824).png>)

또한 `whoami /groups`를 사용하여 **현재 무결성 수준**을 확인할 수 있습니다.

![](<../../.gitbook/assets/image (325).png>)

### 파일 시스템의 무결성 수준

파일 시스템 내의 객체는 **최소 무결성 수준 요구 사항**이 있을 수 있으며, 프로세스가 이 무결성 프로세스를 갖지 않으면 상호작용할 수 없습니다.\
예를 들어, **일반 사용자 콘솔에서 일반 파일을 만들고 권한을 확인**해 보겠습니다:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
이제 파일에 **높은** 최소 무결성 수준을 할당합시다. 이 작업은 **관리자 권한으로 실행되는 콘솔**에서 수행되어야 합니다. 일반 콘솔은 중간 무결성 수준에서 실행되므로 객체에 **높은** 무결성 수준을 할당할 수 없습니다:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
이 부분이 흥미로운 부분입니다. 사용자 `DESKTOP-IDJHTKP\user`가 파일에 대해 **전체 권한**을 가지고 있음을 알 수 있습니다 (실제로 이 파일을 생성한 사용자입니다). 그러나 최소 무결성 수준이 적용되어 있기 때문에 더 이상 파일을 수정할 수 없을 것이며 높은 무결성 수준에서 실행 중이 아닌 이상 파일을 수정할 수 없습니다 (참고로 파일을 읽을 수는 있습니다):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**따라서 파일이 최소 무결성 수준을 갖고 있을 때 해당 파일을 수정하려면 적어도 해당 무결성 수준에서 실행 중이어야 합니다.**
{% endhint %}

### 이진 파일의 무결성 수준

나는 `cmd.exe`의 사본을 `C:\Windows\System32\cmd-low.exe`로 만들었고 **관리자 콘솔에서 낮은 무결성 수준으로 설정했습니다:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
이제 `cmd-low.exe`를 실행하면 **낮은 무결성 수준**에서 실행됩니다. 대신에 중간 수준에서 실행되지 않습니다:

![](<../../.gitbook/assets/image (313).png>)

궁금한 사람들을 위해, 이진 파일에 높은 무결성 수준을 할당하면 (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), 자동으로 높은 무결성 수준에서 실행되지 않습니다 (기본적으로 중간 무결성 수준에서 호출하면 중간 무결성 수준에서 실행됩니다).

### 프로세스의 무결성 수준

모든 파일과 폴더가 최소 무결성 수준을 갖지는 않지만, **모든 프로세스는 무결성 수준 하에서 실행됩니다**. 파일 시스템에서 발생한 것과 유사하게, **다른 프로세스 내부에 쓰기를 원하는 프로세스는 적어도 동일한 무결성 수준을 가져야 합니다**. 이는 낮은 무결성 수준을 갖는 프로세스가 중간 무결성 수준을 갖는 프로세스에게 전체 액세스 권한을 갖는 핸들을 열 수 없음을 의미합니다.

이전 섹션과 이 섹션에서 설명된 제한 사항으로 인해 보안적인 측면에서 항상 **가능한 한 낮은 무결성 수준에서 프로세스를 실행하는 것이 권장**됩니다.

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 기반으로 한 검색 엔진으로, 회사나 그 고객이 **스틸러 악성 소프트웨어**에 의해 **침해**당했는지 확인하는 **무료** 기능을 제공합니다.

WhiteIntel의 주요 목표는 정보 탈취 악성 소프트웨어로 인한 계정 탈취와 랜섬웨어 공격을 막는 것입니다.

그들의 웹사이트를 방문하여 **무료**로 엔진을 시험해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>와 함께 **제로**부터 **히어로**까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks 및 HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
