# 적외선

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 탐색하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 적외선 작동 방식 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**적외선은 인간에게 보이지 않습니다**. 적외선 파장은 **0.7에서 1000 마이크론**입니다. 가정용 리모컨은 데이터 전송을 위해 적외선 신호를 사용하며, 파장 범위는 0.75에서 1.4 마이크론입니다. 리모컨의 마이크로컨트롤러는 특정 주파수로 적외선 LED를 깜빡이게하여 디지털 신호를 적외선 신호로 변환합니다.

적외선 신호를 수신하기 위해 **광수신기**가 사용됩니다. 이 광수신기는 적외선 빛을 전압 펄스로 변환합니다. 일반적으로 수신기 내부에는 **원하는 파장만 통과시키고 잡음을 제거하는 어두운 빛 필터**가 있습니다.

### 다양한 적외선 프로토콜 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

적외선 프로토콜은 다음과 같은 3가지 요소로 다릅니다:

* 비트 인코딩
* 데이터 구조
* 캐리어 주파수 - 주로 36에서 38 kHz 범위

#### 비트 인코딩 방식 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 펄스 거리 인코딩**

비트는 펄스 사이의 간격의 지속 시간을 변조하여 인코딩됩니다. 펄스 자체의 폭은 일정합니다.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. 펄스 폭 인코딩**

비트는 펄스 폭의 변조에 의해 인코딩됩니다. 펄스 버스트 후 공간의 폭은 일정합니다.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. 위상 인코딩**

이는 맨체스터 인코딩이라고도 알려져 있습니다. 논리 값은 펄스 버스트와 공간 사이의 극성에 의해 정의됩니다. "공간에서 펄스 버스트"는 논리 "0"을 나타내고, "펄스 버스트에서 공간"은 논리 "1"을 나타냅니다.

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. 이전 방식의 조합 및 기타 독특한 방식**

{% hint style="info" %}
일부 적외선 프로토콜은 여러 종류의 장치에 **범용적으로 사용**되기 위해 노력하고 있습니다. 가장 유명한 것은 RC5와 NEC입니다. 유명하다고 해서 가장 흔한 것은 아닙니다. 제 환경에서는 NEC 리모컨을 두 개만 만나봤고 RC5 리모컨은 없었습니다.

제조업체들은 종종 동일한 종류의 장치(예: TV 박스) 내에서도 고유한 적외선 프로토콜을 사용합니다. 따라서 서로 다른 회사의 리모컨 및 때로는 동일한 회사의 다른 모델에서도 동일한 유형의 장치와 작동할 수 없습니다.
{% endhint %}

### 적외선 신호 탐색

리모컨의 적외선 신호가 어떻게 보이는지 가장 신뢰할 수 있는 방법은 오실로스코프를 사용하는 것입니다. 이는 수신된 신호를 복조하거나 반전시키지 않고 "그대로" 표시합니다. 이는 테스트 및 디버깅에 유용합니다. NEC 적외선 프로토콜의 예를 통해 예상되는 신호를 보여줄 것입니다.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

일반적으로 인코딩된 패킷의 시작 부분에는 프리앰블이 있습니다. 이를 통해 수신기는 이득과 배경의 수준을 결정할 수 있습니다. 또한 Sharp와 같은 프리앰블이 없는 프로토콜도 있습니다.

그런 다음 데이터가 전송됩니다. 구조, 프리앰블 및 비트 인코딩 방법은 특정 프로토콜에 의해 결정됩니다.

**NEC 적외선 프로토콜**은 버튼이 눌린 동안 전송되는 짧은 명령과 반복 코드를 포함합니다. 명령과 반복 코드는 모두 시작 부분에 동일한 프리앰블을 가지고 있습니다.

NEC **명령**은 프리앰블 외에도 주소 바이트와 명령 번호 바이트로 구성되어 있으며, 이를 통해 장치가 수행해야 할 작업을 이해합니다. 주소와 명령 번호 바이트는 전송의 무결성을 확인하기 위해 반전된 값으로 복제됩니다. 명령의 끝에는 추가적인 스톱 비트가 있습니다.

**반복 코드**는 프리앰블 뒤에 "1"이 있는 스톱 비트를 가지고 있습니다.

NEC는 **논리 "0"과 "1"**에 대해 펄스 거리 인코딩을 사용합니다. 먼저 펄스 버스트가 전송되고 그 후에 일시 중지가 있으며, 그 길이가 비트의 값을 설정합니다.

### 에어컨

다른 리모컨과 달리 **에어컨은 눌린 버튼의 코드만 전송하지 않습니다**. 버튼이 눌릴 때 **에어컨 기계와 리모컨이 동기화되도록 모든 정보를 전송**합니다.\
이렇게 함으로써 한 리모컨으로 20ºC로 설정된 기계가 21ºC로 증가되고, 그런 다음 여전히 온도
