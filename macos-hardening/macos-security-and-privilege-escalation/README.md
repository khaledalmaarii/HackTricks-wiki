# macOS 보안 및 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* **경험있는 해커 및 버그 바운티 헌터와 소통하기 위해** [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**해킹 통찰력**\
해킹의 스릴과 도전을 다루는 콘텐츠와 상호 작용하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대한 정보를 받아보세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)에 참여하여 최고의 해커들과 협업을 시작하세요!**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험있는 해커와 버그 바운티 헌터와 소통하기 위해 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 참여하세요!

**맥OS 기본 사항**

맥OS에 익숙하지 않은 경우 맥OS의 기본 사항을 배우는 것이 좋습니다:

* 특수한 맥OS **파일 및 권한:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 일반적인 맥OS **사용자**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **커널의 아키텍처**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 일반적인 맥OS **네트워크 서비스 및 프로토콜**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **오픈소스** 맥OS: [https://opensource.apple.com/](https://opensource.apple.com/)
* `tar.gz`를 다운로드하려면 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)와 같은 URL을 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)로 변경하십시오.

### 맥OS MDM

회사에서는 **맥OS 시스템을 MDM으로 관리**하는 경우가 많습니다. 따라서 공격자의 관점에서는 **그 작동 방식을 알아야**합니다:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### 맥OS - 검사, 디버깅 및 퍼징

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## 맥OS 보안 보호

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 공격 대상

### 파일 권한

**루트로 실행되는 프로세스가** 사용자가 제어할 수 있는 파일을 작성하는 경우 사용자는 이를 악용하여 **권한을 상승**할 수 있습니다.\
다음과 같은 상황에서 발생할 수 있습니다:

* 사용자가 이미 생성한 파일을 사용했습니다 (사용자 소유)
* 그룹으로 인해 사용자가 쓸 수 있는 파일을 사용했습니다.
* 사용자가 소유한 디렉토리 안에 파일이 있습니다 (사용자가 파일을 생성할 수 있음)
* 루트가 소유한 디렉토리 안에 파일이 있지만 그룹으로 인해 사용자가 쓰기 권한을 가지고 있습니다 (사용자가 파일을 생성할 수 있음)

루트가 사용할 **파일을 생성**할 수 있다면 사용자는 해당 파일의 내용을 **이용**하거나 다른 위치로 **심볼릭 링크/하드 링크**를 만들 수 있습니다.

이러한 취약점을 확인하기 위해 **취약한 `.pkg` 설치 프로그램**을 확인하는 것을 잊지 마세요:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}



### 파일 확장자 및 URL 스키마 앱 핸들러

파일 확장자로 등록된 이상한 앱은 남용될 수 있으며 다른 애플리케이션이 특정 프로토콜을 열도록 등록할 수 있습니다.

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## 맥OS TCC / SIP 권한 상승

맥OS에서는 **응용 프로그램 및 이진 파일이** 다른 것보다 더 권한을 가질 수 있습니다.

따라서 맥OS 시스템을 성공적으로 침해하려는 공격자는 일반적으로 **TCC 권한을 상승**해야 합니다 (또는 필요에 따라 **SIP를 우회**해야 할 수도 있음).

이러한 권한은 일반적으로 응용 프로그램이 **서명된 권한**으로 제공되거나 응용 프로그램이 일부 액세스를 요청하고 **사용자가 승인한 후** TCC 데이터베이스에서 찾을 수 있습니다. 프로세스가 이러한 권한을 얻는 다른 방법은 일반적으로 **상속**되는 권한을 가진 프로세스의 **자식 프로세스**가 되는 것입니다.

[TCC에서 권한 상승](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)을 위한 다른 방법, [TCC 우회](macos-security-protections/macos-tcc/macos-tcc-bypasses/) 및 과거에 [SIP가 우회된](macos-security-protections/macos-sip.md#sip-bypasses) 방법을 찾으려면 이 링크를 따르세요.

## 맥OS 전통적인 권한 상승

물론 레드 팀의 관점에서는 루트로 권한을 상승하는 것도 중요합니다. 몇 가지 힌트를 위해 다음 게시물을 확인하세요:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## 참고 자료

* [**OS X 사고 대응: 스크립팅 및 분석**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

경험 많은 해커와 버그 바운티 헌터와 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하세요!

**해킹 통찰력**\
해킹의 스릴과 도전에 대해 깊이 파고드는 콘텐츠에 참여하세요.

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰력을 통해 빠르게 변화하는 해킹 세계를 따라가세요.

**최신 공지사항**\
새로운 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대해 최신 정보를 받아보세요.

**[Discord](https://discord.com/invite/N3FrSbmwdy)**에 가입하여 최고의 해커들과 협업을 시작하세요!

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**로 AWS 해킹을 처음부터 전문가까지 배워보세요!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기법을 공유하세요.

</details>
