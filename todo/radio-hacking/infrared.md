# 적외선

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 AWS 해킹을 제로부터 전문가까지 배우세요</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **HackTricks를 PDF로 다운로드하려면** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [telegram 그룹](https://t.me/peass)에 **가입**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** github 저장소로 **PR 제출**을 통해 **해킹 트릭을 공유**하세요.

</details>

## 적외선 작동 방식 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**적외선 빛은 사람에게는 보이지 않습니다**. IR 파장은 **0.7에서 1000 마이크론**입니다. 가정용 리모컨은 데이터 전송을 위해 IR 신호를 사용하며 파장 범위는 0.75에서 1.4 마이크론입니다. 리모컨의 마이크로컨트롤러는 특정 주파수로 적외선 LED를 깜박이게하여 디지털 신호를 IR 신호로 변환합니다.

IR 신호를 수신하기 위해 **광수신기(photoreceiver)**가 사용됩니다. 이는 IR 빛을 전압 펄스로 변환하여 이미 **디지털 신호**로 만듭니다. 일반적으로 수신기 내부에는 **원하는 파장만 통과시키고 잡음을 제거하는 어두운 빛 필터**가 있습니다.

### 다양한 IR 프로토콜 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR 프로토콜은 3가지 요소에서 다릅니다:

* 비트 인코딩
* 데이터 구조
* 캐리어 주파수 — 주로 36에서 38 kHz 범위

#### 비트 인코딩 방법 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 펄스 거리 인코딩**

비트는 펄스 사이의 간격의 지속 시간을 변조함으로써 인코딩됩니다. 펄스 자체의 폭은 일정합니다.

<figure><img src="../../.gitbook/assets/image (295).png" alt=""><figcaption></figcaption></figure>

**2. 펄스 폭 인코딩**

비트는 펄스 폭의 변조에 의해 인코딩됩니다. 펄스 버스트 후 공간의 폭은 일정합니다.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 위상 인코딩**

맨체스터 인코딩으로도 알려져 있습니다. 논리 값은 펄스 버스트와 공간 사이의 전환의 극성에 의해 정의됩니다. "공간에서 펄스 버스트"는 논리 "0"을 나타내고, "펄스 버스트에서 공간"은 논리 "1"을 나타냅니다.

<figure><img src="../../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 이전 방법들과 다른 독특한 방법들의 조합**

{% hint style="info" %}
일부 IR 프로토콜은 **여러 유형의 장치에 대해 범용적이 되려고 합니다**. 가장 유명한 것은 RC5와 NEC입니다. 유명하다고 해서 **가장 흔한 것은 아닙니다**. 제 환경에서는 NEC 리모컨을 두 개만 만나봤고 RC5 리모컨은 만나보지 못했습니다.

제조업체들은 동일한 장치 범위 내에서도 자사 고유의 IR 프로토콜을 사용하는 것을 좋아합니다 (예: TV 박스). 따라서 서로 다른 회사의 리모컨 및 때로는 동일 회사의 다른 모델에서도 동일한 유형의 다른 장치와 작동할 수 없습니다.
{% endhint %}

### IR 신호 탐색

리모컨 IR 신호가 어떻게 보이는지 확인하는 가장 신뢰할 수 있는 방법은 오실로스코프를 사용하는 것입니다. 이는 수신된 신호를 복조하거나 반전시키지 않고 그대로 표시합니다. 이는 테스트 및 디버깅에 유용합니다. NEC IR 프로토콜 예제를 통해 예상 신호를 보여줄 것입니다.

<figure><img src="../../.gitbook/assets/image (235).png" alt=""><figcaption></figcaption></figure>

일반적으로 인코딩된 패킷의 시작 부분에 프리앰블이 있습니다. 이를 통해 수신기는 이득 및 배경의 수준을 결정할 수 있습니다. 또한 Sharp와 같이 프리앰블이 없는 프로토콜도 있습니다.

그런 다음 데이터가 전송됩니다. 구조, 프리앰블 및 비트 인코딩 방법은 특정 프로토콜에 의해 결정됩니다.

**NEC IR 프로토콜**은 짧은 명령과 버튼이 눌릴 때 전송되는 반복 코드를 포함합니다. 명령과 반복 코드는 시작 부분에 동일한 프리앰블을 가지고 있습니다.

NEC **명령**은 프리앰블 외에 주소 바이트와 명령 번호 바이트로 구성되어 있으며, 장치가 수행해야 할 작업을 이해합니다. 주소 및 명령 번호 바이트는 전송의 무결성을 확인하기 위해 반대 값으로 복제됩니다. 명령의 끝에 추가적인 스톱 비트가 있습니다.

**반복 코드**는 프리앰블 뒤에 "1"이 있으며, 이는 스톱 비트입니다.

**논리 "0" 및 "1"**을 위해 NEC는 펄스 거리 인코딩을 사용합니다: 먼저 펄스 버스트가 전송되고 그 후에는 일시 중지가 있으며, 그 길이가 비트의 값을 설정합니다.

### 에어컨

다른 리모컨과 달리 **에어컨은 눌린 버튼의 코드만을 전송하는 것이 아닙니다**. 눌린 버튼으로 모든 정보를 **전송하여 에어컨 기계와 리모컨이 동기화되도록**합니다.\
이렇게 함으로써 한 리모컨으로 20ºC로 설정된 기계가 21ºC로 증가되는 것을 피하고, 그 후에 온도가 여전히 20ºC인 다른 리모컨을 사용하여 온도를 더 높이면 21ºC로 "증가"되고, 21ºC에 있다고 생각하여 22ºC로 증가되지 않습니다.

### 공격

Flipper Zero로 적외선을 공격할 수 있습니다:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## 참고 자료

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
