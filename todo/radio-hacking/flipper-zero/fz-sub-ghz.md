# FZ - Sub-GHz

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}


## 소개 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero는 **내장 모듈을 통해 300-928 MHz 범위의 라디오 주파수를 수신하고 전송할 수 있으며**, 원격 제어를 읽고 저장하고 에뮬레이트할 수 있습니다. 이러한 제어 장치는 게이트, 장벽, 라디오 잠금 장치, 원격 제어 스위치, 무선 초인종, 스마트 조명 등과의 상호작용에 사용됩니다. Flipper Zero는 보안이 손상되었는지 여부를 배우는 데 도움을 줄 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 하드웨어 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero는 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 칩](https://www.ti.com/lit/ds/symlink/cc1101.pdf)을 기반으로 한 내장 서브 1 GHz 모듈과 라디오 안테나를 가지고 있으며 (최대 범위는 50미터입니다). CC1101 칩과 안테나는 300-348 MHz, 387-464 MHz 및 779-928 MHz 대역의 주파수에서 작동하도록 설계되었습니다.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## 작업

### 주파수 분석기

{% hint style="info" %}
리모컨이 사용하는 주파수를 찾는 방법
{% endhint %}

분석할 때 Flipper Zero는 주파수 구성에서 사용 가능한 모든 주파수에서 신호 강도(RSSI)를 스캔합니다. Flipper Zero는 -90 [dBm](https://en.wikipedia.org/wiki/DBm)보다 높은 신호 강도를 가진 주파수 중 가장 높은 RSSI 값을 표시합니다.

리모컨의 주파수를 확인하려면 다음을 수행하십시오:

1. 리모컨을 Flipper Zero의 왼쪽에 매우 가깝게 놓습니다.
2. **메인 메뉴** **→ Sub-GHz**로 이동합니다.
3. **주파수 분석기**를 선택한 후 분석할 리모컨의 버튼을 누르고 유지합니다.
4. 화면에서 주파수 값을 확인합니다.

### 읽기

{% hint style="info" %}
사용되는 주파수에 대한 정보 찾기 (사용되는 주파수를 찾는 또 다른 방법)
{% endhint %}

**읽기** 옵션은 **지정된 변조에서 구성된 주파수를 청취합니다**: 기본값은 433.92 AM입니다. 읽기 중 **무언가가 발견되면**, **정보가 화면에 표시됩니다**. 이 정보는 미래에 신호를 복제하는 데 사용할 수 있습니다.

읽기 중에는 **왼쪽 버튼**을 눌러 **구성할 수 있습니다**.\
현재 **4개의 변조**(AM270, AM650, FM328 및 FM476)와 **여러 관련 주파수**가 저장되어 있습니다:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

**관심 있는 주파수를 설정할 수 있지만**, 리모컨이 사용하는 주파수가 **확실하지 않은 경우**, **호핑을 켜세요** (기본값은 꺼짐) 및 Flipper가 이를 캡처하고 주파수를 설정하는 데 필요한 정보를 제공할 때까지 버튼을 여러 번 누르십시오.

{% hint style="danger" %}
주파수 간 전환에는 시간이 걸리므로 전환 시 전송된 신호가 누락될 수 있습니다. 더 나은 신호 수신을 위해 주파수 분석기에 의해 결정된 고정 주파수를 설정하십시오.
{% endhint %}

### **원시 읽기**

{% hint style="info" %}
구성된 주파수에서 신호를 훔치고 (재생)하기
{% endhint %}

**원시 읽기** 옵션은 **청취 주파수에서 전송된 신호를 기록합니다**. 이는 신호를 **훔치고** **반복하는 데** 사용할 수 있습니다.

기본적으로 **원시 읽기는 AM650에서 433.92로 설정되어 있지만**, 읽기 옵션에서 관심 있는 신호가 **다른 주파수/변조에 있는 경우**, 원시 읽기 옵션 내에서 왼쪽 버튼을 눌러 수정할 수 있습니다.

### 무차별 대입

예를 들어 차고 문에 사용되는 프로토콜을 알고 있다면 **모든 코드를 생성하고 Flipper Zero로 전송할 수 있습니다.** 이는 일반적인 차고 유형을 지원하는 예입니다: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 수동 추가

{% hint style="info" %}
구성된 프로토콜 목록에서 신호 추가하기
{% endhint %}

#### [지원되는 프로토콜 목록](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (대부분의 정적 코드 시스템에서 작동) | 433.92 | 정적  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | 정적  |
| Nice Flo 24bit\_433                                             | 433.92 | 정적  |
| CAME 12bit\_433                                                 | 433.92 | 정적  |
| CAME 24bit\_433                                                 | 433.92 | 정적  |
| Linear\_300                                                     | 300.00 | 정적  |
| CAME TWEE                                                       | 433.92 | 정적  |
| Gate TX\_433                                                    | 433.92 | 정적  |
| DoorHan\_315                                                    | 315.00 | 동적 |
| DoorHan\_433                                                    | 433.92 | 동적 |
| LiftMaster\_315                                                 | 315.00 | 동적 |
| LiftMaster\_390                                                 | 390.00 | 동적 |
| Security+2.0\_310                                               | 310.00 | 동적 |
| Security+2.0\_315                                               | 315.00 | 동적 |
| Security+2.0\_390                                               | 390.00 | 동적 |

### 지원되는 Sub-GHz 공급업체

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)에서 목록 확인하기

### 지역별 지원되는 주파수

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)에서 목록 확인하기

### 테스트

{% hint style="info" %}
저장된 주파수의 dBms 가져오기
{% endhint %}

## 참고

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
