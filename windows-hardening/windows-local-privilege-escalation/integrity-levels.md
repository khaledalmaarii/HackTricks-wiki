<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 PR을 제출**하세요.

</details>


# 무결성 수준

Windows Vista 및 이후 버전에서 모든 보호된 항목은 **무결성 수준** 태그와 함께 제공됩니다. 이 설정은 대부분 파일 및 레지스트리 키에 "중간" 무결성 수준을 할당합니다. 단, Internet Explorer 7이 낮은 무결성 수준에서 쓸 수 있는 특정 폴더 및 파일을 제외하고는 말입니다. 기본 동작은 표준 사용자에 의해 시작된 프로세스가 중간 무결성 수준을 갖도록 하는 것이고, 서비스는 일반적으로 시스템 무결성 수준에서 작동합니다. 루트 디렉토리는 높은 무결성 레이블로 보호됩니다.

중요한 규칙 중 하나는 객체를 해당 객체의 수준보다 낮은 무결성 수준을 가진 프로세스가 수정할 수 없다는 것입니다. 무결성 수준은 다음과 같습니다:

- **Untrusted**: 이 수준은 익명 로그인을 가진 프로세스를 위한 것입니다. %%%예시: Chrome%%%
- **Low**: 주로 인터넷 상호 작용에 사용되며, 특히 Internet Explorer의 보호 모드에서 관련 파일 및 프로세스, 그리고 **임시 인터넷 폴더**와 같은 특정 폴더에 영향을 줍니다. 낮은 무결성 프로세스는 레지스트리 쓰기 액세스 및 제한된 사용자 프로필 쓰기 액세스를 포함한 중요한 제한 사항을 겪습니다.
- **Medium**: 대부분의 활동에 대한 기본 수준으로, 표준 사용자와 특정 무결성 수준이 없는 객체에 할당됩니다. 관리자 그룹의 구성원도 기본적으로 이 수준에서 작동합니다.
- **High**: 관리자를 위해 예약된 수준으로, 높은 수준 자체를 포함하여 낮은 무결성 수준의 객체를 수정할 수 있게 합니다.
- **System**: Windows 커널 및 핵심 서비스를 위한 가장 높은 작동 수준으로, 심지어 관리자도 접근할 수 없어 중요한 시스템 기능을 보호합니다.
- **Installer**: 다른 모든 객체를 제거할 수 있도록 하는 독특한 수준입니다.

프로세스의 무결성 수준은 **Sysinternals**의 **Process Explorer**를 사용하여 프로세스의 **속성**에 액세스하고 "**보안**" 탭을 확인하여 얻을 수 있습니다:

![](<../../.gitbook/assets/image (318).png>)

`whoami /groups`를 사용하여 **현재 무결성 수준**을 확인할 수도 있습니다.

![](<../../.gitbook/assets/image (319).png>)

## 파일 시스템의 무결성 수준

파일 시스템 내부의 객체는 **최소 무결성 수준 요구 사항**을 필요로 할 수 있으며, 프로세스가 이 무결성 프로세스를 갖지 않으면 해당 객체와 상호 작용할 수 없습니다.\
예를 들어, 일반 사용자 콘솔에서 **일반 파일을 생성하고 권한을 확인**해 보겠습니다:
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
이제 파일에 최소 **높은** 무결성 수준을 할당해 보겠습니다. 이 작업은 **관리자 권한으로 실행되는 콘솔**에서 수행되어야 합니다. 일반 콘솔은 중간 무결성 수준에서 실행되므로 객체에 높은 무결성 수준을 할당할 수 없습니다.
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
여기서 흥미로운 점이 나타납니다. 사용자 `DESKTOP-IDJHTKP\user`가 파일에 대해 **전체 권한**을 가지고 있음을 알 수 있습니다 (실제로 이 파일을 생성한 사용자입니다). 그러나 최소 무결성 수준이 구현되어 있기 때문에 그는 더 이상 파일을 수정할 수 없습니다. 단, 높은 무결성 수준에서 실행 중인 경우에만 파일을 읽을 수 있습니다.
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**따라서 파일이 최소 무결성 수준을 가질 때 해당 파일을 수정하려면 해당 무결성 수준 이상으로 실행해야 합니다.**
{% endhint %}

## 이진 파일의 무결성 수준

나는 `cmd.exe`를 `C:\Windows\System32\cmd-low.exe`로 복사하고 **관리자 콘솔에서 낮은 무결성 수준으로 설정했습니다:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
이제 `cmd-low.exe`를 실행하면 **중간 수준 대신 낮은 무결성 수준에서 실행**됩니다:

![](<../../.gitbook/assets/image (320).png>)

궁금한 사람들을 위해, 이진 파일에 높은 무결성 수준을 할당하면 (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), 자동으로 높은 무결성 수준에서 실행되지 않습니다 (기본적으로 중간 무결성 수준에서 호출하는 경우 중간 무결성 수준에서 실행됩니다).

## 프로세스의 무결성 수준

모든 파일과 폴더가 최소한의 무결성 수준을 갖지는 않지만, **모든 프로세스는 무결성 수준에서 실행**됩니다. 파일 시스템에서 발생한 것과 유사하게, **프로세스가 다른 프로세스 내부에 쓰기를 하려면 적어도 동일한 무결성 수준을 가져야 합니다**. 즉, 낮은 무결성 수준을 갖는 프로세스는 중간 무결성 수준을 갖는 프로세스에 대한 전체 액세스를 가진 핸들을 열 수 없습니다.

이와 이전 섹션에서 언급한 제한 사항으로 인해, 보안적인 측면에서는 항상 **가능한 한 낮은 무결성 수준에서 프로세스를 실행하는 것이 권장**됩니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 여러분의 해킹 기술을 공유하세요.

</details>
