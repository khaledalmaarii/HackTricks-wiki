# macOS Apple Events

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF로 HackTricks 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를** **팔로우**하세요.
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **깃허브 저장소에 제출하세요.**

</details>

## 기본 정보

**Apple Events**는 Apple의 macOS에서 애플리케이션이 서로 통신할 수 있게 하는 기능입니다. 이는 macOS 운영 체제의 일부인 **Apple Event Manager**의 일부로, 프로세스 간 통신을 처리하는 역할을 담당합니다. 이 시스템을 통해 한 애플리케이션이 다른 애플리케이션에게 특정 작업을 수행하도록 요청하는 메시지를 보낼 수 있습니다. 예를 들어 파일을 열거나 데이터를 검색하거나 명령을 실행하는 것과 같은 작업을 수행할 수 있습니다.

mina 데몬은 `/System/Library/CoreServices/appleeventsd`이며 서비스 `com.apple.coreservices.appleevents`를 등록합니다.

이 데몬은 Apple Event Mach Port를 제공하여 이벤트를 수신할 수 있는 모든 애플리케이션을 확인합니다. 그리고 앱이 이벤트를 보내려면 데몬으로부터 이 포트를 요청해야 합니다.

샌드박스화된 애플리케이션은 이벤트를 보낼 수 있도록 `allow appleevent-send` 및 `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`와 같은 권한이 필요합니다. `com.apple.security.temporary-exception.apple-events`와 같은 권한은 `com.apple.private.appleevents`와 같은 권한이 필요한 이벤트를 보낼 수 있는 사용자를 제한할 수 있습니다.

{% hint style="success" %}
메시지를 보낸 정보를 로그로 기록하려면 환경 변수 **`AEDebugSends`**를 사용할 수 있습니다.
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>와 함께 제로부터 영웅이 되는 AWS 해킹 배우기</summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)을 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
