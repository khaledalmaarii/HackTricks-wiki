# Sub-GHz RF

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 차고 문

차고 문 오프너는 일반적으로 300-190 MHz 범위의 주파수에서 작동하며, 가장 일반적인 주파수는 300 MHz, 310 MHz, 315 MHz 및 390 MHz입니다. 이 주파수 범위는 다른 주파수 대역보다 혼잡하지 않으며 다른 장치로부터의 간섭을 경험할 가능성이 적기 때문에 차고 문 오프너에 일반적으로 사용됩니다.

## 차 문

대부분의 자동차 키 키보드는 **315 MHz 또는 433 MHz**에서 작동합니다. 이 두 주파수는 라디오 주파수이며 다양한 응용 프로그램에서 사용됩니다. 두 주파수의 주요 차이점은 433 MHz가 315 MHz보다 더 긴 범위를 가지고 있다는 것입니다. 이는 원격 키없는 진입과 같이 더 긴 범위가 필요한 응용 프로그램에는 433 MHz가 더 적합하다는 것을 의미합니다.\
유럽에서는 433.92MHz가 일반적으로 사용되고 미국과 일본에서는 315MHz입니다.

## **무차별 대입 공격**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

각 코드를 5번씩 보내는 대신에 한 번만 보내면 시간이 6분으로 줄어듭니다:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

그리고 신호 간의 2ms 대기 기간을 제거하면 시간을 3분으로 줄일 수 있습니다.

또한, De Bruijn Sequence를 사용하여 모든 잠재적인 이진 숫자를 보내기 위해 필요한 비트 수를 줄이면 이 시간은 단지 8초로 줄어듭니다:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

이 공격의 예는 [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)에서 구현되었습니다.

**전조를 요구하면 De Bruijn Sequence** 최적화를 피하고 **롤링 코드는 이 공격을 방지**합니다(코드가 무차별 대입 공격을 할 수 없을 정도로 충분히 길다고 가정합니다).

## Sub-GHz 공격

Flipper Zero를 사용하여 이러한 신호를 공격하려면 확인하세요:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## 롤링 코드 보호

자동 차고 문 오프너는 일반적으로 무선 원격 제어를 사용하여 차고 문을 열고 닫습니다. 원격 제어는 차고 문 오프너에 라디오 주파수(RF) 신호를 보내어 모터를 작동하여 문을 열거나 닫습니다.

누군가는 코드 그래버라고 하는 장치를 사용하여 RF 신호를 가로채고 나중에 사용하기 위해 기록할 수 있습니다. 이를 **재생 공격**이라고 합니다. 이러한 유형의 공격을 방지하기 위해 현대의 대부분의 차고 문 오프너는 **롤링 코드** 시스템이라고 하는 보다 안전한 암호화 방법을 사용합니다.

**RF 신호는 일반적으로 롤링 코드를 사용하여 전송**됩니다. 이는 코드가 각 사용마다 변경된다는 것을 의미합니다. 이로 인해 신호를 가로채고 코드를 사용하여 차고에 무단으로 접근하는 것이 어려워집니다.

롤링 코드 시스템에서 원격 제어와 차고 문 오프너는 각각 사용될 때마다 새로운 코드를 생성하는 **공유 알고리즘**을 가지고 있습니다. 차고 문 오프너는 **올바른 코드에만 응답**하여 코드를 가로채고 무단으로 차고에 접근하는 것을 훨씬 어렵게 만듭니다.

### **Missing Link 공격**

기본적으로, 당신은 버튼을 듣고 **원격 제어가 장치(예: 차량 또는 차고)의 범위 밖에 있을 때 신호를 캡처**합니다. 그런 다음 장치로 이동하여 **캡처한 코드를 사용하여 열 수** 있습니다.

### 전체 링크 방해 공격

공격자는 차량이나 수신기 근처에서 신호를 **방해**하여 **수신기가 실제로 코드를 '들을' 수 없게** 할 수 있으며, 그런 다음 방해를 중단한 후에는 간단히 코드를 **캡처하고 재생**할 수 있습니다.

피해자는 어느 시점에서 **차를 잠그기 위해 키를 사용**할 것이지만, 그때 공격은 **"문을 닫음" 코드를 충분히 기록**할 것입니다. 이 코드를 다시 보내서 문을 열 수 있습니다(다른 주파수로의 **변경이 필요**할 수 있습니다. 왜냐하면 동일한 코드를 열고 닫기 위해 사용하지만 서로 다른 주파수에서 두 명령을 수신하는 차량이 있기 때문입니다).

{% hint style="warning" %}
**방해**는 작동하지만, 차를 잠그기 위해 **사람이 문을 테스트**하여 잠겼는지 확인하면 차가 잠기지 않았다는 사실을 알 수 있습니다. 게다가 이러한 공격에 대해 알고 있다면 '잠금' 버튼을 누를 때 차가 잠금 **소리**가 나지 않거나 차의 **라이트**가 깜박이지 않는 것을 들을 수도 있습니다.
{% endhint %
### 알람 소리 방해 공격

차량에 설치된 애프터마켓 롤링 코드 시스템을 대상으로 테스트를 진행할 때, **동일한 코드를 두 번 보내면** 즉시 **알람이 작동**하고 차량을 동력으로부터 차단하여 **서비스 거부(Denial of Service)** 기회를 제공합니다. 아이러니하게도 알람과 차량 동력 차단을 해제하는 방법은 **리모컨을 누르는 것**이었으며, 이로 인해 공격자는 **지속적으로 DoS 공격을 수행**할 수 있었습니다. 또는 피해자가 공격을 가능한 빨리 중단하고 싶어하기 때문에 **이전 공격과 이 공격을 혼합하여 더 많은 코드를 얻을 수**도 있습니다.

## 참고 자료

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* HackTricks에서 **회사 광고를 보거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 여러분의 해킹 기교를 공유하세요.

</details>
