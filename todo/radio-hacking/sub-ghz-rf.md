# 서브-GHz RF

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 **제로부터 영웅까지 AWS 해킹 배우기**!</summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드**하고 싶다면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 제출하세요.

</details>

## 차고 문

차고 문 오프너는 일반적으로 300-190 MHz 범위의 주파수에서 작동하며, 가장 일반적인 주파수는 300 MHz, 310 MHz, 315 MHz 및 390 MHz입니다. 이 주파수 범위는 다른 주파수 대역보다 혼잡하지 않고 다른 장치로부터 간섭을 받을 가능성이 적기 때문에 차고 문 오프너에 일반적으로 사용됩니다.

## 자동차 문

대부분의 자동차 키 FOB는 **315 MHz 또는 433 MHz**에서 작동합니다. 이 두 라디오 주파수는 다양한 응용 프로그램에서 사용됩니다. 두 주파수의 주요 차이점은 433 MHz가 315 MHz보다 더 긴 범위를 가지고 있다는 것입니다. 이는 433 MHz가 원격 무선 열쇠 입력과 같이 더 긴 범위가 필요한 응용 프로그램에 더 적합하다는 것을 의미합니다.\
유럽에서는 433.92MHz가 일반적이며 미국과 일본에서는 315MHz입니다.

## **무차별 대입 공격**

<figure><img src="../../.gitbook/assets/image (1084).png" alt=""><figcaption></figcaption></figure>

각 코드를 5번씩 보내는 대신 한 번만 보내면 시간이 6분으로 줄어듭니다:

<figure><img src="../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

그리고 신호 간의 2ms 대기 기간을 제거하면 시간을 3분으로 줄일 수 있습니다.

또한 De Bruijn Sequence를 사용하여 모든 잠재적인 이진 숫자를 보내기 위해 필요한 비트 수를 줄이면 **이 시간이 8초로 줄어듭니다**:

<figure><img src="../../.gitbook/assets/image (583).png" alt=""><figcaption></figcaption></figure>

이 공격의 예는 [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)에서 구현되었습니다.

**전조 부호**를 요구하면 De Bruijn Sequence 최적화를 피하고 **롤링 코드**는 이 공격을 방지합니다(코드가 무차별 대입 공격으로부터 충분히 길지 않은 경우).

## 서브-GHz 공격

Flipper Zero로 이러한 신호를 공격하려면 다음을 확인하세요:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## 롤링 코드 보호

자동 차고 문 오프너는 일반적으로 무선 원격 제어를 사용하여 차고 문을 열고 닫습니다. 원격 제어는 무선 주파수(RF) 신호를 차고 문 오프너에 보내어 모터를 활성화하여 문을 열거나 닫습니다.

누군가가 코드 그랩버라는 장치를 사용하여 RF 신호를 가로채서 기록하여 나중에 사용할 수 있습니다. 이를 **재생 공격**이라고 합니다. 이러한 유형의 공격을 방지하기 위해 현대의 많은 차고 문 오프너는 **롤링 코드** 시스템이라고 하는 더 안전한 암호화 방법을 사용합니다.

**RF 신호는 일반적으로 롤링 코드를 사용하여** 전송되며, 이는 코드가 사용될 때마다 변경됨을 의미합니다. 이는 누군가가 신호를 가로채고 차고에 무단으로 접근하는 것을 훨씬 어렵게 만듭니다.

롤링 코드 시스템에서 원격 제어와 차고 문 오프너는 **새로운 코드를 생성하는 공유 알고리즘**을 가지고 있습니다. 차고 문 오프너는 **올바른 코드에만 응답**하여 누군가가 코드를 가로챌 수 없게 만듭니다.

### **Missing Link 공격**

기본적으로 당신은 버튼을 듣고 **원격이 장치(예: 자동차 또는 차고)에서 벗어난 상태에서 신호를 캡처**합니다. 그런 다음 장치로 이동하여 **캡처한 코드를 사용하여 엽니다**.

### 전체 링크 방해 공격

공격자는 **차량이나 수신기 근처에서 신호를 방해**할 수 있으므로 **수신기가 실제로 코드를 '들을' 수 없게**하고 그런 다음 방해를 멈춘 후에는 단순히 **캡처하고 재생**할 수 있습니다.

피해자는 어느 시점에서 **차를 잠그기 위해 키를 사용**할 것이지만, 그때 공격은 아마도 문을 열기 위해 **충분한 "문을 닫는" 코드를 기록**했을 것입니다 (다른 주파수를 사용해야 할 수 있음을 염두에 두세요. 동일한 코드를 사용하여 열고 닫는 차량이 있지만 서로 다른 주파수에서 두 명령을 수신합니다).

{% hint style="warning" %}
**방해는 작동**하지만, 만약 **차를 잠그는 사람이 단순히 문을 잠그는지 확인**하기 위해 문을 테스트하면 차가 잠기지 않았음을 알 수 있습니다. 또한 이러한 공격에 대해 인식하고 있다면 차가 잠기지 않았다는 사실을 듣거나 차가 '잠금' 버튼을 누를 때 차의 **등이 깜박이지 않는 소리**를 듣을 수도 있습니다.
{% endhint %}

### **코드 그랩 공격 (aka ‘RollJam’)**

이것은 더 **은밀한 방해 기술**입니다. 공격자는 신호를 방해하여 피해자가 문을 잠그려고 할 때 작동하지 않게 만들지만, 공격자는 이 코드를 **기록**할 것입니다. 그런 다음 피해자는 버튼을 눌러 차를 다시 잠그려고 할 것이고 차는 **두 번째 코드를 기록**할 것입니다.\
즉시 이후 **공격자는 첫 번째 코드를 보낼 수** 있고 **차가 잠길 것**입니다 (피해자는 두 번째 누름이 닫혔다고 생각할 것입니다). 그런 다음 공격자는 차를 **열기 위해 두 번째 훔친 코드를 보낼 수** 있을 것입니다 (일반적으로 "차를 닫는" 코드도 열기 위해 사용될 수 있음을 가정합니다). 주파수 변경이 필요할 수 있습니다 (차량이 동일한 코드를 열고 닫기 위해 사용하지만 서로 다른 주파수에서 두 명령을 수신하는 경우).

공격자는 **자신의 수신기가 아닌 차 수신기를 방해**할 수 있습니다. 왜냐하면 차 수신기가 예를 들어 1MHz 대역폭에서 수신 중인 경우, 공격자는 원격 신호를 듣기 위해 정확한 주파수를 방해하지 않고 **그 스펙트럼에서 가까운 주파수를 방해**할 것이기 때문입니다. 반면 공격자의 수신기는 원격 신호를 **방해 없이** 듣을 수 있는 작은 범위에서 수신합니다.

{% hint style="warning" %}
다른 사양에서 본 구현은 **롤링 코드가 전체 코드의 일부**라는 것을 보여줍니다. 즉, 전송된 코드는 **24비트 키**이며 첫 **12비트는 롤링 코드**, 두 번째 8비트는 명령(잠금 또는 잠금 해제)이며 마지막 4비트는 **체크섬**입니다. 이 유형을 구현하는 차량은 공격자가 단순히 롤링 코드 세그먼트를 교체하여 **두 주파수에서 모든 롤링 코드를 사용**할 수 있도록 만들기 때문에 자연스럽게 취약합니다.
{% endhint %}

{% hint style="danger" %}
피해자가 공격자가 첫 번째 코드를 보내는 동안 세 번째 코드를 보내면 첫 번째와 두 번째 코드가 무효화됩니다.
{% endhint %}
### 경보음 발생 방해 공격

자동차에 설치된 시장 판매용 롤링 코드 시스템에 대한 테스트에서 **동일한 코드를 두 번 보내면 즉시 경보음과 시동 잠금장치가 활성화**되어 공격자에게 **서비스 거부** 기회를 제공합니다. 아이러니하게도 **경보음과 시동 잠금장치를 비활성화**하는 방법은 **리모컨을 누르는 것**이며, 이는 공격자에게 **지속적으로 DoS 공격을 수행**할 수 있는 능력을 제공합니다. 또는 피해자가 공격을 가능한 빨리 중단하고 싶어할 것이므로 **이전 공격과 이 공격을 혼합하여 더 많은 코드를 획득**할 수 있습니다.

## 참고 자료

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><strong>제로부터 AWS 해킹을 전문가로 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 홍보하거나 HackTricks를 PDF로 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)에 가입하거나 [텔레그램 그룹](https://t.me/peass)에 참여**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks 및 HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 요령을 공유**하세요.

</details>
