# iButton

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 소개

iButton은 **동전 모양의 금속 컨테이너**에 포장된 전자 식별 키의 일반적인 이름입니다. 또한 **Dallas Touch** Memory 또는 접촉 메모리라고도 불립니다. 실제로는 내부에 **디지털 프로토콜로 작동하는 완전한 마이크로칩**이 숨겨져 있기 때문에 종종 "자석" 키로 잘못 착각됩니다.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### iButton이란 무엇인가? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

일반적으로 iButton은 키와 리더의 물리적 형태를 의미합니다 - 두 개의 접점이 있는 원형 동전입니다. 그 주변에는 가장 흔한 플라스틱 홀더부터 링, 펜던트 등 다양한 변형이 있습니다.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

키가 리더에 도달하면 **접촉이 이루어지고** 키는 ID를 **전송**하기 위해 전원을 공급받습니다. 때로는 키가 **즉시 읽히지 않을 수도 있습니다**. 이는 인터콤의 **접촉 PSD가 예상보다 큰** 경우입니다. 따라서 키와 리더의 외곽선이 접촉하지 못할 수 있습니다. 그럴 경우 키를 리더의 벽 중 하나 위에 눌러야 합니다.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 프로토콜** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallas 키는 1-Wire 프로토콜을 사용하여 데이터를 교환합니다. 데이터 전송을 위한 단 하나의 연락처(!!)만 있으며, 마스터에서 슬레이브로, 그리고 그 반대 방향으로 작동합니다. 1-Wire 프로토콜은 마스터-슬레이브 모델에 따라 작동합니다. 이 토폴로지에서 마스터는 항상 통신을 시작하고 슬레이브는 그 명령을 따릅니다.

키(슬레이브)가 인터콤(마스터)에 접촉하면 키 내부의 칩이 인터콤에 의해 전원이 공급되고 키가 초기화됩니다. 그 후 인터콤은 키 ID를 요청합니다. 이 과정을 더 자세히 살펴보겠습니다.

Flipper는 마스터 및 슬레이브 모드에서 모두 작동할 수 있습니다. 키 읽기 모드에서 Flipper는 리더로 작동하여 마스터로 작동합니다. 그리고 키 에뮬레이션 모드에서 Flipper는 키인 척하며 슬레이브 모드에 있습니다.

### Dallas, Cyfral 및 Metakom 키

이러한 키의 작동 방식에 대한 정보는 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) 페이지를 확인하세요.

### 공격

iButton은 Flipper Zero를 사용하여 공격할 수 있습니다:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 참고 자료

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
