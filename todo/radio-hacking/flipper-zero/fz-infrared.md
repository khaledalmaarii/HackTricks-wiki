# FZ - 적외선

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅까지 AWS 해킹을 배우세요</strong></a><strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사가 HackTricks에 광고되길 원하시나요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 얻으세요
* **💬** [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 **가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하시거나 **트위터**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하고 PR을 제출하여** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 기여하세요.

</details>

## 소개 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

더 많은 정보를 원하시면 적외선이 작동하는 방법을 확인하세요:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Flipper Zero의 IR 신호 수신기 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper는 **IR 리모컨에서 신호를 가로챌 수 있는** 디지털 IR 신호 수신기 TSOP를 사용합니다. Xiaomi와 같은 **일부 스마트폰**도 IR 포트를 가지고 있지만, **대부분은 신호를 전송만** 할 뿐 **수신할 수 없습니다**.

Flipper 적외선 **수신기는 상당히 민감**합니다. TV와 리모컨 사이의 **어딘가에 있으면서도 신호를 잡을 수** 있습니다. Flipper의 IR 포트를 리모컨에 직접 향하게 할 필요는 없습니다. 누군가가 TV 근처에서 채널을 변경하는 동안에도 Flipper와 당신이 멀리 떨어져 있는 경우 유용합니다.

**적외선의 디코딩**은 **소프트웨어** 측면에서 발생하기 때문에 Flipper Zero는 잠재적으로 **어떤 IR 리모컨 코드의 수신 및 송신**을 지원합니다. **인식할 수 없는** 프로토콜의 경우 - **수신된 대로 원시 신호를 기록하고 재생**합니다.

## 동작

### 유니버설 리모컨

Flipper Zero는 **모든 TV, 에어컨 또는 미디어 센터를 제어하는 유니버설 리모컨**으로 사용할 수 있습니다. 이 모드에서 Flipper는 SD 카드의 사전에 따라 모든 지원 제조업체의 모든 알려진 코드를 **브루트포스**합니다. 레스토랑 TV를 끄기 위해 특정 리모컨을 선택할 필요가 없습니다.

유니버설 리모컨 모드에서 전원 버튼을 누르면 Flipper는 알고 있는 모든 TV(Sony, Samsung, Panasonic 등)의 "전원 끄기" 명령을 **순차적으로 보냅니다**. TV가 신호를 받으면 반응하여 꺼집니다.

이러한 브루트 포스는 시간이 소요됩니다. 사전이 클수록 완료하는 데 더 오랜 시간이 걸립니다. TV가 정확히 어떤 신호를 인식했는지 알 수 없으므로 TV로부터 피드백이 없습니다.

### 새로운 리모컨 배우기

Flipper Zero로 **적외선 신호를 캡처**하는 것이 가능합니다. Flipper가 데이터베이스에서 **신호를 찾으면** 자동으로 **이 장치가 무엇인지 알게** 되고 상호 작용할 수 있게 해줍니다.\
찾을 수 없는 경우, Flipper는 **신호를 저장**하고 **재생**할 수 있게 해줍니다.

## 참고 자료

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
