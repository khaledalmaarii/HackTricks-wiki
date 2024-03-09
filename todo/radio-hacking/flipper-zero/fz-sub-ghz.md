# FZ - Sub-GHz

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 AWS 해킹을 처음부터 전문가까지 배우세요</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나 HackTricks를 PDF로 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [Discord 그룹](https://discord.gg/hRep4RUj7f)** 또는 [텔레그램 그룹](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 소개 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero는 **300-928 MHz 범위의 라디오 주파수를 수신하고 송신**할 수 있는 내장 모듈을 갖추고 있습니다. 이 모듈은 원격 제어 장치를 읽고 저장하며 흉내를 낼 수 있어 게이트, 장애물, 라디오 잠금, 원격 제어 스위치, 무선 도어벨, 스마트 조명 등과 상호 작용하기 위해 사용됩니다. Flipper Zero를 사용하여 보안이 침해되었는지 알아볼 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 하드웨어 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero에는 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 칩](https://www.ti.com/lit/ds/symlink/cc1101.pdf)을 기반으로 한 내장 서브-1 GHz 모듈과 라디오 안테나(최대 범위는 50m)가 탑재되어 있습니다. CC1101 칩과 안테나는 300-348 MHz, 387-464 MHz 및 779-928 MHz 대역에서 작동하도록 설계되었습니다.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## 작업

### 주파수 분석기

{% hint style="info" %}
원격 제어가 사용하는 주파수를 찾는 방법
{% endhint %}

분석 시, Flipper Zero는 주파수 구성에서 사용 가능한 모든 주파수에서 신호 강도(RSSI)를 스캔합니다. Flipper Zero는 -90 [dBm](https://en.wikipedia.org/wiki/DBm)보다 높은 신호 강도를 가진 주파수를 화면에 표시합니다.

원격 제어의 주파수를 결정하려면 다음을 수행하세요:

1. 원격 제어를 Flipper Zero의 왼쪽에 매우 가까이 놓습니다.
2. **Main Menu** **→ Sub-GHz**로 이동합니다.
3. **Frequency Analyzer**를 선택한 다음 분석하려는 원격 제어의 버튼을 누릅니다.
4. 화면에서 주파수 값을 확인합니다.

### 읽기

{% hint style="info" %}
사용된 주파수에 대한 정보 찾기(또 다른 주파수를 찾는 또 다른 방법)
{% endhint %}

**Read** 옵션은 기본적으로 433.92 AM에서 구성된 주파수에서 수신합니다. 읽기 중에 **무언가를 찾으면** 화면에 정보가 제공됩니다. 이 정보는 나중에 신호를 복제하는 데 사용될 수 있습니다.

Read를 사용하는 동안 **왼쪽 버튼을 누르고 구성**할 수 있습니다.\
현재 **4가지 변조**(AM270, AM650, FM328 및 FM476)가 있으며 **여러 가지 관련 주파수**가 저장되어 있습니다:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

**관심 있는 주파수**를 설정할 수 있지만, 사용 중인 원격 제어에 사용된 주파수가 **정확히 어떤 것인지 확신이 없다면 Hopping을 ON**으로 설정하고 Flipper가 캡처하고 필요한 정보를 제공할 때까지 버튼을 여러 번 누르세요.

{% hint style="danger" %}
주파수 간 전환에는 시간이 소요되므로 전환 시간에 전송된 신호가 누락될 수 있습니다. 신호 수신을 개선하려면 주파수 분석기에서 결정된 고정 주파수를 설정하세요.
{% endhint %}

### **Raw 읽기**

{% hint style="info" %}
구성된 주파수에서 신호를 도용(및 재생)합니다
{% endhint %}

**Raw 읽기** 옵션은 수신 주파수에서 보낸 신호를 기록합니다. 이를 사용하여 신호를 도용하고 반복할 수 있습니다.

기본적으로 **Raw 읽기도 433.92에서 AM650으로 설정**되어 있지만, 읽기 옵션으로 관심 있는 신호가 **다른 주파수/변조에 있다는 것을 발견했다면 해당 주파수를 수정**할 수도 있습니다(Read Raw 옵션 내에서 왼쪽을 누릅니다).

### 브루트 포스

예를 들어 차고 문에서 사용되는 프로토콜을 알고 있다면 **Flipper Zero로 모든 코드를 생성하고 전송**할 수 있습니다. 이는 일반적인 차고의 일반적인 유형을 지원하는 예시입니다: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 수동 추가

{% hint style="info" %}
구성된 프로토콜 목록에서 신호 추가
{% endhint %}

#### [지원되는 프로토콜 목록](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (대부분의 정적 코드 시스템과 호환됨) | 433.92 | 정적  |
| --------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                 | 433.92 | 정적  |
| Nice Flo 24bit\_433                                 | 433.92 | 정적  |
| CAME 12bit\_433                                     | 433.92 | 정적  |
| CAME 24bit\_433                                     | 433.92 | 정적  |
| Linear\_300                                         | 300.00 | 정적  |
| CAME TWEE                                           | 433.92 | 정적  |
| Gate TX\_433                                        | 433.92 | 정적  |
| DoorHan\_315                                        | 315.00 | 동적 |
| DoorHan\_433                                        | 433.92 | 동적 |
| LiftMaster\_315                                     | 315.00 | 동적 |
| LiftMaster\_390                                     | 390.00 | 동적 |
| Security+2.0\_310                                   | 310.00 | 동적 |
| Security+2.0\_315                                   | 315.00 | 동적 |
| Security+2.0\_390                                   | 390.00 | 동적 |
### 지원되는 Sub-GHz 공급업체

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)에서 목록을 확인하십시오.

### 지역별 지원되는 주파수

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)에서 목록을 확인하십시오.

### 테스트

{% hint style="info" %}
저장된 주파수의 dBm 가져오기
{% endhint %}

## 참고

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)
