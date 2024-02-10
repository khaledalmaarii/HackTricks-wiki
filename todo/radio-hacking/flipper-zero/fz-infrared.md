# FZ - 적외선

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출**하세요.

</details>

## 소개 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

적외선이 작동하는 방식에 대한 자세한 정보는 다음을 참조하세요:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero의 적외선 신호 수신기 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper는 적외선 리모컨의 신호를 가로챌 수 있는 디지털 적외선 신호 수신기 TSOP를 사용합니다. Xiaomi와 같은 일부 스마트폰에는 적외선 포트도 있지만, 대부분의 스마트폰은 신호를 전송할 수만 있고 수신할 수는 없다는 점을 염두에 두세요.

Flipper의 적외선 수신기는 꽤 민감합니다. TV 리모컨과 Flipper 사이의 어딘가에 있으면서도 신호를 잡을 수 있습니다. Flipper의 IR 포트에 리모컨을 직접 향하게 할 필요는 없습니다. 이는 누군가가 TV 근처에서 채널을 변경하는 동안에도 유용합니다. 당신과 Flipper가 멀리 떨어져 있는 경우입니다.

적외선 신호의 디코딩은 소프트웨어 측면에서 발생하기 때문에 Flipper Zero는 잠재적으로 모든 적외선 리모컨 코드의 수신과 전송을 지원할 수 있습니다. 인식할 수 없는 프로토콜의 경우, Flipper는 수신한 대로 원시 신호를 기록하고 재생합니다.

## 작업

### 유니버설 리모컨

Flipper Zero는 **TV, 에어컨 또는 미디어 센터를 제어하는 유니버설 리모컨**으로 사용할 수 있습니다. 이 모드에서 Flipper는 SD 카드의 사전에 따라 모든 지원되는 제조업체의 모든 알려진 코드를 **브루트포스**합니다. 특정 리모컨을 선택하여 레스토랑 TV를 끄는 것은 필요하지 않습니다.

유니버설 리모컨 모드에서 전원 버튼을 누르면 Flipper는 알고 있는 모든 TV(Sony, Samsung, Panasonic 등)에 대한 "전원 끄기" 명령을 순차적으로 보냅니다. TV가 신호를 받으면 반응하여 전원이 꺼집니다.

이러한 브루트포스는 시간이 소요됩니다. 사전이 클수록 완료하는 데 더 오래 걸립니다. TV가 정확히 어떤 신호를 인식했는지 알 수 없으므로 TV로부터 피드백이 없습니다.

### 새로운 리모컨 학습

Flipper Zero로 적외선 신호를 **캡처**할 수 있습니다. Flipper가 데이터베이스에서 신호를 **찾으면** Flipper는 자동으로 **이 장치가 어떤 장치인지 알고** 상호작용할 수 있게 해줍니다.\
찾을 수 없는 경우, Flipper는 신호를 **저장**하고 재생할 수 있게 해줍니다.

## 참고 자료

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 제로에서 영웅까지 AWS 해킹을 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 HackTricks를 **PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 저를 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면 PR을** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 제출**하세요.

</details>
