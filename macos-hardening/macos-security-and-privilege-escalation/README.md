# macOS 보안 및 권한 상승

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks를 광고하거나 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **우리와 함께** 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 귀하의 해킹 기술을 공유하세요.

</details>

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

경험 많은 해커 및 버그 바운티 헌터와 소통하려면 [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하세요!

**해킹 통찰력**\
해킹의 스릴과 도전에 대해 탐구하는 콘텐츠와 상호 작용하세요

**실시간 해킹 뉴스**\
빠르게 변화하는 해킹 세계의 최신 뉴스와 통찰력을 유지하세요

**최신 공지**\
출시되는 최신 버그 바운티 및 중요한 플랫폼 업데이트에 대해 알아두세요

**우리와 함께** [**Discord**](https://discord.com/invite/N3FrSbmwdy)에 가입하여 최고의 해커들과 협업을 시작하세요!

## 기본 MacOS

macOS에 익숙하지 않다면 macOS의 기본을 배우는 것이 좋습니다:

* 특수 macOS **파일 및 권한:**

{% content-ref url="macos-files-folders-and-binaries/" %}
[macos-files-folders-and-binaries](macos-files-folders-and-binaries/)
{% endcontent-ref %}

* 일반 macOS **사용자**

{% content-ref url="macos-users.md" %}
[macos-users.md](macos-users.md)
{% endcontent-ref %}

* **AppleFS**

{% content-ref url="macos-applefs.md" %}
[macos-applefs.md](macos-applefs.md)
{% endcontent-ref %}

* **커널의** **아키텍처**

{% content-ref url="mac-os-architecture/" %}
[mac-os-architecture](mac-os-architecture/)
{% endcontent-ref %}

* 일반 macOS **네트워크 서비스 및 프로토콜**

{% content-ref url="macos-protocols.md" %}
[macos-protocols.md](macos-protocols.md)
{% endcontent-ref %}

* **오픈소스** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
* `tar.gz`를 다운로드하려면 [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)와 같은 URL을 [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)로 변경하세요

### MacOS MDM

회사에서는 **macOS 시스템이 MDM으로 관리**될 가능성이 매우 높습니다. 따라서 공격자의 관점에서는 **그 작동 방식을** 알아야 합니다:

{% content-ref url="../macos-red-teaming/macos-mdm/" %}
[macos-mdm](../macos-red-teaming/macos-mdm/)
{% endcontent-ref %}

### MacOS - 검사, 디버깅 및 퍼징

{% content-ref url="macos-apps-inspecting-debugging-and-fuzzing/" %}
[macos-apps-inspecting-debugging-and-fuzzing](macos-apps-inspecting-debugging-and-fuzzing/)
{% endcontent-ref %}

## MacOS 보안 보호

{% content-ref url="macos-security-protections/" %}
[macos-security-protections](macos-security-protections/)
{% endcontent-ref %}

## 공격 표면

### 파일 권한

**루트로 실행 중인 프로세스가** 사용자가 제어할 수 있는 파일을 작성하면 사용자가 이를 악용하여 **권한을 상승**할 수 있습니다.\
다음 상황에서 발생할 수 있습니다:

* 사용된 파일이 이미 사용자에 의해 생성되었습니다 (사용자 소유)
* 사용된 파일이 그룹으로 인해 사용자에게 쓰기 가능합니다
* 사용된 파일이 사용자가 소유한 디렉토리 안에 있습니다 (사용자가 파일을 생성할 수 있음)
* 사용된 파일이 루트가 소유한 디렉토리 안에 있지만 사용자가 그룹으로 인해 쓰기 액세스 권한을 가지고 있습니다 (사용자가 파일을 생성할 수 있음)

**루트가 사용할 파일을 생성**할 수 있는 경우, 사용자는 해당 내용을 **이용**하거나 다른 위치로 **심볼릭 링크/하드 링크**를 만들 수 있습니다.

이러한 취약점의 경우 **취약한 `.pkg` 설치 프로그램을** 확인하는 것을 잊지 마세요:

{% content-ref url="macos-files-folders-and-binaries/macos-installers-abuse.md" %}
[macos-installers-abuse.md](macos-files-folders-and-binaries/macos-installers-abuse.md)
{% endcontent-ref %}

### 파일 확장자 및 URL 스킴 앱 핸들러

파일 확장자로 등록된 이상한 앱은 악용될 수 있으며 다른 애플리케이션이 특정 프로토콜을 열도록 등록할 수 있습니다

{% content-ref url="macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](macos-file-extension-apps.md)
{% endcontent-ref %}

## macOS TCC / SIP 권한 상승

macOS에서 **응용 프로그램 및 이진 파일은** 다른 것보다 더 권한이 있는 폴더 또는 설정에 액세스할 수 있는 권한을 가질 수 있습니다.

따라서 macOS 기계를 성공적으로 침해하려는 공격자는 macOS TCC 권한을 **상승**해야 할 것입니다 (또는 **SIP 우회**, 그에 따라 필요에 따라).

이러한 권한은 일반적으로 응용 프로그램이 **사인된 권한** 또는 응용 프로그램이 일부 액세스를 요청하고 **사용자가 승인한 후** TCC 데이터베이스에서 찾을 수 있습니다. 프로세스가 이러한 권한을 얻는 다른 방법은 일반적으로 **상속**되므로 해당 **권한을 가진 프로세스의 자식**이 되는 것입니다.

다음 링크를 따라 이러한 권한을 [**TCC에서 상승**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)하는 다양한 방법, [**TCC 우회**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) 및 과거에 **SIP가 우회**된 방법을 찾아보세요.

## macOS 전통적인 권한 상승

물론 레드팀의 관점에서는 루트로 상승하는 것도 중요합니다. 몇 가지 힌트를 확인하려면 다음 게시물을 확인하세요:

{% content-ref url="macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](macos-privilege-escalation.md)
{% endcontent-ref %}
## 참고 자료

* [**OS X 사건 대응: 스크립팅 및 분석**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
* [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
* [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

<figure><img src="../../.gitbook/assets/image (380).png" alt=""><figcaption></figcaption></figure>

[**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) 서버에 가입하여 경험 많은 해커 및 버그 바운티 헌터들과 소통하세요!

**해킹 통찰**\
해킹의 즐거움과 도전에 대해 탐구하는 콘텐츠에 참여하세요

**실시간 해킹 뉴스**\
실시간 뉴스와 통찰을 통해 빠르게 변화하는 해킹 세계를 파악하세요

**최신 공지**\
최신 버그 바운티 출시 및 중요한 플랫폼 업데이트에 대해 알아두세요

**우리와 함께** [**Discord**](https://discord.com/invite/N3FrSbmwdy) 에 가입하여 최고의 해커들과 협업을 시작하세요!

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)로부터 AWS 해킹을 제로부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 가입하거나**트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하세요.

</details>
