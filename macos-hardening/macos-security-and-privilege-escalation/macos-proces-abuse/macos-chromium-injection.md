# macOS Chromium Injection

{% hint style="success" %}
AWS 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

## 기본 정보

Google Chrome, Microsoft Edge, Brave 등과 같은 Chromium 기반 브라우저들은 Chromium 오픈 소스 프로젝트를 기반으로 구축되었습니다. 이는 공통된 기반을 공유하고 있어 유사한 기능과 개발자 옵션을 갖추고 있음을 의미합니다.

#### `--load-extension` 플래그

`--load-extension` 플래그는 Chromium 기반 브라우저를 명령줄이나 스크립트에서 시작할 때 사용됩니다. 이 플래그는 브라우저가 시작될 때 **하나 이상의 확장 프로그램을 자동으로 로드**할 수 있도록 합니다.

#### `--use-fake-ui-for-media-stream` 플래그

`--use-fake-ui-for-media-stream` 플래그는 Chromium 기반 브라우저를 시작하는 데 사용할 수 있는 또 다른 명령줄 옵션입니다. 이 플래그는 카메라와 마이크의 미디어 스트림에 대한 액세스 권한을 요청하는 일반 사용자 프롬프트를 **우회**하기 위해 설계되었습니다. 이 플래그를 사용하면 브라우저가 카메라 또는 마이크 액세스를 요청하는 모든 웹사이트나 애플리케이션에 자동으로 권한을 부여합니다.

### 도구

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### 예제
```bash
# Intercept traffic
voodoo intercept -b chrome
```
## 참고 자료

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 **Discord 그룹**에 **가입**하세요(https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦에서 **팔로우**하세요 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 해킹 트릭을 공유하고 싶다면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 레포지토리에 PR을 제출하세요.

</details>
{% endhint %}
