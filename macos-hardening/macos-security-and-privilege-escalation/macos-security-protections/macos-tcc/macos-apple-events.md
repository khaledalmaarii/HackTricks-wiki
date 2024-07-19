# macOS Apple Events

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

## Basic Information

**Apple Events**는 애플의 macOS에서 애플리케이션 간의 통신을 가능하게 하는 기능입니다. 이는 macOS 운영 체제의 구성 요소인 **Apple Event Manager**의 일부로, 프로세스 간 통신을 처리하는 역할을 합니다. 이 시스템은 한 애플리케이션이 다른 애플리케이션에 메시지를 보내 특정 작업을 수행하도록 요청할 수 있게 합니다. 예를 들어 파일 열기, 데이터 검색 또는 명령 실행 등이 있습니다.

mina 데몬은 `/System/Library/CoreServices/appleeventsd`로, 서비스 `com.apple.coreservices.appleevents`를 등록합니다.

이벤트를 수신할 수 있는 모든 애플리케이션은 이 데몬과 확인하여 자신의 Apple Event Mach Port를 제공합니다. 그리고 애플리케이션이 이벤트를 보내고자 할 때, 해당 애플리케이션은 데몬으로부터 이 포트를 요청합니다.

샌드박스 애플리케이션은 이벤트를 보낼 수 있도록 `allow appleevent-send` 및 `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))`와 같은 권한이 필요합니다. `com.apple.security.temporary-exception.apple-events`와 같은 권한은 이벤트를 보낼 수 있는 접근을 제한할 수 있으며, 이는 `com.apple.private.appleevents`와 같은 권한이 필요합니다.

{% hint style="success" %}
It's possible to use the env variable **`AEDebugSends`** in order to log informtion about the message sent:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **해킹 트릭을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하세요.**

</details>
{% endhint %}
