# macOS Chromium Injection

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 제로부터 전문가까지 배우세요!</strong></summary>

다른 HackTricks 지원 방법:

- **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>

## 기본 정보

Google Chrome, Microsoft Edge, Brave 등과 같은 Chromium 기반 브라우저는 Chromium 오픈 소스 프로젝트를 기반으로 구축되었습니다. 이는 공통 기반을 공유하고 있으므로 유사한 기능과 개발자 옵션을 갖추고 있습니다.

#### `--load-extension` 플래그

`--load-extension` 플래그는 명령줄이나 스크립트에서 Chromium 기반 브라우저를 시작할 때 사용됩니다. 이 플래그를 사용하면 브라우저가 시작될 때 **하나 이상의 확장 프로그램을 자동으로 로드**할 수 있습니다.

#### `--use-fake-ui-for-media-stream` 플래그

`--use-fake-ui-for-media-stream` 플래그는 Chromium 기반 브라우저를 시작하는 데 사용할 수 있는 또 다른 명령줄 옵션입니다. 이 플래그는 카메라와 마이크의 미디어 스트림에 액세스할 권한을 요청하는 일반 사용자 프롬프트를 **우회**하기 위해 설계되었습니다. 이 플래그를 사용하면 브라우저가 카메라 또는 마이크 액세스를 요청하는 모든 웹사이트나 애플리케이션에 자동으로 권한을 부여합니다.

### 도구

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### 예제
```bash
# Intercept traffic
voodoo intercept -b chrome
```
## 참고 자료

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 되는 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 PDF로 HackTricks를 다운로드하길 원한다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>
