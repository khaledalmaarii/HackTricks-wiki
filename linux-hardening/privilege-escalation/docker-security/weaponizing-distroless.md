# Distroless 무기화

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>

## Distroless란?

Distroless 컨테이너는 **특정 애플리케이션을 실행하는 데 필요한 종속성만 포함**하는 컨테이너 유형입니다. 추가적인 소프트웨어나 필요하지 않은 도구는 포함되지 않으며, 이러한 컨테이너는 **가볍고 안전**하며, 불필요한 구성 요소를 제거하여 **공격 표면을 최소화**하는 것을 목표로 합니다.

Distroless 컨테이너는 **보안과 신뢰성이 중요한 프로덕션 환경**에서 자주 사용됩니다.

일부 **distroless 컨테이너**의 **예시**는 다음과 같습니다:

* **Google에서 제공하는 것**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard에서 제공하는 것**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Distroless 무기화

Distroless 컨테이너를 무기화하는 목표는 **distroless의 제한 사항** (시스템에서 일반적인 이진 파일의 부재)과 `/dev/shm`의 **읽기 전용** 또는 **실행 금지**와 같은 컨테이너에서 일반적으로 발견되는 보호 기능을 고려하여 **임의의 이진 파일과 페이로드를 실행**할 수 있도록 하는 것입니다.

### 메모리를 통해

2023년 어느 시점에 추가될 예정입니다...

### 기존 이진 파일을 통해

#### openssl

****[**이 게시물에서**](https://www.form3.tech/engineering/content/exploiting-distroless-images)는 이러한 컨테이너에서 자주 **`openssl`** 이진 파일이 발견된다는 것을 설명하고 있습니다. 이는 컨테이너 내에서 실행될 소프트웨어에 **필요**하기 때문일 수 있습니다.

**`openssl`** 이진 파일을 남용하여 **임의의 작업을 실행**할 수 있습니다.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
