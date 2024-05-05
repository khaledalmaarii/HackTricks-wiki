# iButton

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로부터 영웅이 될 때까지 AWS 해킹을 배우세요!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

## 소개

iButton은 **동전 모양의 금속 컨테이너**에 포장된 전자 식별 키에 대한 일반적인 이름입니다. 또한 **Dallas Touch** Memory 또는 접촉 메모리라고도 합니다. 종종 "자석" 키로 잘못 지칭되지만 내부에는 **자석이 전혀 없습니다**. 사실, 디지털 프로토콜에서 작동하는 완전한 **마이크로칩**이 숨어 있습니다.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### iButton이란 무엇인가? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

일반적으로 iButton은 키와 리더의 물리적 형태를 의미합니다 - 두 개의 접촉이 있는 원형 동전. 주변 프레임에 대해서는 가장 일반적인 플라스틱 홀더부터 링, 펜던트 등 다양한 변형이 있습니다.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

키가 리더에 도달하면 **접촉이 발생**하고 키는 **ID를 전송**하기 위해 전원이 공급됩니다. 때로는 키가 **즉시 읽히지 않을 수 있습니다**. 왜냐하면 **인터콤의 접촉 PSD가** 예상보다 크기 때문일 수 있습니다. 그런 경우에는 키를 리더의 벽 중 하나 위에 눌러야 합니다.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 프로토콜** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas 키는 1-Wire 프로토콜을 사용하여 데이터를 교환합니다. 데이터 전송을 위한 데이터 전송을 위한 단 하나의 접촉 (!!)으로, 마스터에서 슬레이브로, 그리고 그 반대 방향으로 작동합니다. 1-Wire 프로토콜은 마스터-슬레이브 모델에 따라 작동합니다. 이 토폴로지에서 마스터는 항상 통신을 시작하고 슬레이브는 그 명령을 따릅니다.

키(슬레이브)가 인터콤(마스터)에 접촉하면 키 내부의 칩이 켜지고 인터콤에 의해 전원이 공급되어 키가 초기화됩니다. 그 후 인터콤은 키 ID를 요청합니다. 이후에는 이 프로세스를 더 자세히 살펴볼 것입니다.

플리퍼는 마스터 및 슬레이브 모드에서 모두 작동할 수 있습니다. 키 읽기 모드에서 플리퍼는 리더로 작동하며 이는 마스터로 작동한다는 것을 의미합니다. 그리고 키 에뮬레이션 모드에서 플리퍼는 키인 척하며 슬레이브 모드에 있습니다.

### Dallas, Cyfral 및 Metakom 키

이러한 키들이 어떻게 작동하는지에 대한 정보는 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) 페이지를 확인하세요.

### 공격

iButton은 Flipper Zero로 공격당할 수 있습니다:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## 참고 자료

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)
