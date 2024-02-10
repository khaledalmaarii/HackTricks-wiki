# 라디오

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)는 GNU/Linux와 macOS용 무료 디지털 신호 분석기로, 알려지지 않은 라디오 신호의 정보를 추출하는 데 사용됩니다. SoapySDR을 통해 다양한 SDR 장치를 지원하며, FSK, PSK 및 ASK 신호의 조정이 가능하며, 아날로그 비디오를 디코딩하고, 버스트 신호를 분석하고, 아날로그 음성 채널을 듣는 등의 기능을 실시간으로 제공합니다.

### 기본 설정

설치 후 구성할 수 있는 몇 가지 사항이 있습니다.\
설정(두 번째 탭 버튼)에서 **SDR 장치**를 선택하거나 읽을 **파일을 선택**하고, 신호를 동조화할 주파수와 샘플 속도(컴퓨터가 지원하는 경우 최대 2.56Msps까지 권장)를 선택할 수 있습니다.\\

![](<../../.gitbook/assets/image (655) (1).png>)

GUI 동작에서 컴퓨터가 지원하는 경우 몇 가지 기능을 활성화하는 것이 좋습니다:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
컴퓨터가 캡처하지 못하는 것을 알게 되면 OpenGL을 비활성화하고 샘플 속도를 낮추는 것을 시도해보세요.
{% endhint %}

### 사용법

* 신호를 **캡처하고 분석하기 위해** "Push to capture" 버튼을 필요한 만큼 누르면 됩니다.

![](<../../.gitbook/assets/image (631).png>)

* SigDigger의 **튜너**는 신호를 **더 잘 캡처**하는 데 도움이 됩니다(하지만 신호를 저하시킬 수도 있습니다). 이상적으로는 0부터 시작하여 **노이즈**가 **필요한 신호의 개선보다 큰 경우**까지 **크게 만들어**보세요.

![](<../../.gitbook/assets/image (658).png>)

### 라디오 채널과 동기화

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)를 사용하여 듣고 싶은 채널과 동기화하려면 "Baseband audio preview" 옵션을 구성하고, 전송되는 모든 정보를 얻기 위해 대역폭을 구성한 다음, 노이즈가 실제로 증가하기 시작하기 전의 수준으로 튜너를 설정하세요:

![](<../../.gitbook/assets/image (389).png>)

## 흥미로운 트릭

* 장치가 정보의 버스트를 보내는 경우, 일반적으로 **첫 번째 부분은 프리앰블**이므로 거기에서 정보를 찾지 못하거나 오류가 있는 경우 **걱정할 필요가 없습니다**.
* 정보의 프레임에서는 일반적으로 **서로 정렬된 다른 프레임을 찾아야 합니다**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **비트를 복구한 후에는 어떻게 처리해야 할 수도 있습니다**. 예를 들어, Manchester 부호화에서 up+down은 1 또는 0이 되고, down+up은 다른 하나가 됩니다. 따라서 1과 0의 쌍(ups와 downs)은 실제 1 또는 실제 0이 됩니다.
* 신호가 Manchester 부호화를 사용하더라도(연속으로 두 개 이상의 0 또는 1을 찾을 수 없음), 프리앰블에서 여러 개의 1 또는 0을 찾을 수도 있습니다!

### IQ를 사용하여 변조 유형 파악

신호에 정보를 저장하는 방법은 3가지가 있습니다: **진폭**, **주파수** 또는 **위상**을 변조합니다.\
신호를 확인하는 경우 정보를 저장하는 데 사용되는 방법을 알아보기 위해 다양한 방법이 있지만, 좋은 방법 중 하나는 IQ 그래프를 확인하는 것입니다.

![](<../../.gitbook/assets/image (630).png>)

* **AM 감지**: IQ 그래프에 예를 들어 **2개의 원**이 나타나면(아마도 하나는 0이고 다른 하나는 다른 진폭일 것입니다), 이것은 AM 신호일 수 있습니다. 이는 IQ 그래프에서 0과 원 사이의 거리가 신호의 진폭이기 때문에 다른 진폭이 사용되는 것을 쉽게 시각화할 수 있기 때문입니다.
* **PM 감지**: 이전 이미지와 마찬가지로, 상호 관련이 없는 작은 원을 찾으면 이는 아마도 위상 변조가 사용된 것입니다. 이는 IQ 그래프에서 점과 0,0 사이의 각도가 신호의 위상이기 때문입니다. 따라서 4개의 다른 위상이 사용된다는 것을 의미합니다.
* 정보가 위상 자체가 아닌 위상이 변경되는 사실에 숨겨져 있는 경우, 서로 다른 위상이 명확하게 구별되지 않을 수 있습니다.
* **FM 감지**: IQ에는 주파수를 식별하기 위한 필드가 없습니다(중심까지의 거리는 진폭이고 각도는 위상입니다).\
따라서 FM을 식별하려면 이 그래프에서 **기본적으로 원만 보여야 합니다**.\
또한, 다른 주파수는 원을 따라 **속도 가속도로 "표현"**됩니다(SysDigger에서 신호를 선택하면 IQ 그래프가 생성되며, 생성된 원에서 가속도나 방향 변경을 찾으면 이는 FM일 수 있습니다):

## AM 예제

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### AM 해독

#### Envelope 확인

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)를 사용하여 AM 정보를 확인하고 **envelope**만 확인하면 다른 진폭 수준을 명확하게 볼 수 있습니다. 사용된 신호는 AM으로 정보가 포함된 펄스를 보내고 있으며,
#### IQ와 함께

이 예제에서는 **큰 원**과 **많은 점들이 중앙에** 있는 것을 볼 수 있습니다.

![](<../../.gitbook/assets/image (640).png>)

### 심볼 속도 얻기

#### 하나의 심볼로

가장 작은 심볼을 선택하고 "Selection freq"를 확인하세요. 이 경우 1.013kHz (1kHz)입니다.

![](<../../.gitbook/assets/image (638) (1).png>)

#### 여러 심볼로

선택할 심볼의 수를 지정할 수도 있으며, SigDigger가 1개의 심볼의 주파수를 계산합니다 (선택한 심볼이 많을수록 좋습니다). 이 시나리오에서는 10개의 심볼을 선택하고 "Selection freq"는 1.004 Khz입니다.

![](<../../.gitbook/assets/image (635).png>)

### 비트 얻기

이 신호가 **AM 변조** 신호임을 발견했고 **심볼 속도**를 알았다면 (이 경우에는 위로 올라가는 것이 1을 의미하고 아래로 내려가는 것이 0을 의미한다는 것을 알고 있다면), 신호에 인코딩된 비트를 얻는 것은 매우 쉽습니다. 따라서 정보가 있는 신호를 선택하고 샘플링과 결정을 구성하고 샘플을 누르세요 (확인하세요 **Amplitude**이 선택되어 있고, 발견된 **심볼 속도**가 구성되어 있으며, **Gadner clock recovery**가 선택되어 있는지):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sync to selection intervals**는 심볼 속도를 찾기 위해 이전에 선택한 간격을 사용한다는 것을 의미합니다.
* **Manual**은 지정된 심볼 속도를 사용할 것이라는 것을 의미합니다.
* **Fixed interval selection**에서는 선택해야 할 간격의 수를 지정하고, 이를 통해 심볼 속도를 계산합니다.
* **Gadner clock recovery**는 일반적으로 가장 좋은 옵션입니다. 그러나 약간의 근사한 심볼 속도를 지정해야 합니다.

샘플을 누르면 다음이 나타납니다:

![](<../../.gitbook/assets/image (659).png>)

이제 SigDigger가 정보를 전달하는 레벨의 범위를 이해하도록 하기 위해 **낮은 레벨**을 클릭하고 가장 큰 레벨까지 클릭을 유지하세요:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

예를 들어 **4개의 다른 진폭 레벨**이 있다면 **Bits per symbol을 2로 구성**하고 가장 작은 것부터 가장 큰 것까지 선택해야 합니다.

마지막으로 **확대**를 늘리고 **행 크기를 변경**하여 비트를 볼 수 있습니다 (모두 선택하고 복사하여 모든 비트를 얻을 수 있습니다):

![](<../../.gitbook/assets/image (649) (1).png>)

신호가 심볼 당 1보다 많은 비트를 가지고 있는 경우 (예: 2), SigDigger는 어떤 심볼이 00, 01, 10, 11인지 알 수 없으므로 각각을 나타내기 위해 다른 **회색 스케일**을 사용합니다 (비트를 복사하면 0부터 3까지의 숫자를 사용하므로 이를 처리해야 합니다).

또한, **Manchester**와 같은 **코딩**을 사용할 수 있으며, **위로+아래로**는 **1 또는 0**일 수 있으며, 아래로+위로는 1 또는 0일 수 있습니다. 이러한 경우에는 얻은 위로 (1)와 아래로 (0)를 처리하여 01 또는 10의 쌍을 0 또는 1로 대체해야 합니다.

## FM 예제

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### FM 해제하기

#### 주파수와 파형 확인

FM으로 변조된 정보를 전송하는 신호 예제:

![](<../../.gitbook/assets/image (661) (1).png>)

이전 이미지에서 **2개의 주파수가 사용**되는 것을 잘 볼 수 있지만, **파형**을 **관찰**해도 **정확히 2개의 다른 주파수를 올바르게 식별**할 수 없을 수도 있습니다:

![](<../../.gitbook/assets/image (653).png>)

이는 신호를 양 주파수에서 캡처했기 때문에 한 주파수가 다른 주파수에 대해 음수에 근접합니다:

![](<../../.gitbook/assets/image (656).png>)

동기화된 주파수가 **한 주파수에 다른 주파수보다 가까울 경우** 2개의 다른 주파수를 쉽게 볼 수 있습니다:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### 히스토그램 확인

정보가 있는 신호의 주파수 히스토그램을 확인하면 쉽게 2개의 다른 신호를 볼 수 있습니다:

![](<../../.gitbook/assets/image (657).png>)

이 경우 **진폭 히스토그램**을 확인하면 **하나의 진폭만** 찾을 수 있으므로 AM일 수 없습니다 (많은 진폭을 찾는 경우 신호가 채널을 따라서 전력을 잃은 것일 수 있습니다):

![](<../../.gitbook/assets/image (646).png>)

이것은 위상 히스토그램일 것입니다 (이것은 신호가 위상으로 변조되지 않았음을 명확히 보여줍니다):

![](<../../.gitbook/assets/image (201) (2).png>)

#### IQ와 함께

IQ에는 주파수를 식별할 수 있는 필드가 없습니다 (중심으로부터의 거리는 진폭이고 각도는 위상입니다).\
따라서 FM을 식별하려면 이 그래프에서 **기본적으로 원만 보여야** 합니다.\
또한, 다른 주파수는 IQ 그래프에서 **원을 따라 가속도가 변화**함으로써 "표현"됩니다 (따라서 SysDigger에서 신호를 선택하면 IQ 그래프가 생성되고, 생성된 원에서 가속도나 방향 변경을 찾으면 이것이 FM일 수 있습니다):

![](<../../.gitbook/assets/image (643) (1).png>)

### 심볼 속도 얻기

주파수를 찾은 후에는 AM 예제에서 사용한 **동일한 기술**을 사용하여 심볼 속도를 얻을 수 있습니다.

### 비트 얻기

주파수가 변조된 신호를 찾은 후에는 AM 예제에서 사용한 **동일한 기술**을 사용하여 비트를 얻을 수 있습니다. 그리고 **신호가 주파수로 변조**되고 **심볼 속도**를 알았다면.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요!</summary>

HackTricks를 지원하는 다른 방법:

* 회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 구매하세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family)인 [**The PEASS Family**](https://opensea.io
