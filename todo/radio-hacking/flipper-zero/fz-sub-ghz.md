# FZ - Sub-GHz

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks)와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 표면을 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm_source=referral&utm_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 소개 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero는 내장 모듈을 통해 **300-928 MHz 범위의 무선 주파수를 수신 및 송신**할 수 있으며, 원격 제어를 읽고 저장하고 에뮬레이션할 수 있습니다. 이러한 제어는 문, 장벽, 무선 잠금장치, 원격 제어 스위치, 무선 초인종, 스마트 조명 등과의 상호 작용에 사용됩니다. Flipper Zero를 사용하여 보안이 침해되었는지 확인할 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 하드웨어 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero에는 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 칩](https://www.ti.com/lit/ds/symlink/cc1101.pdf)과 무선 안테나(최대 범위는 50m)를 기반으로 한 내장형 sub-1 GHz 모듈이 있습니다. CC1101 칩과 안테나는 300-348 MHz, 387-464 MHz 및 779-928 MHz 대역에서 작동하도록 설계되었습니다.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## 작업

### 주파수 분석기

{% hint style="info" %}
원격 제어가 사용하는 주파수를 찾는 방법
{% endhint %}

Flipper Zero는 주파수 구성에서 사용 가능한 모든 주파수에서 신호 강도(RSSI)를 스캔합니다. Flipper Zero는 RSSI 값이 가장 높은 주파수를 화면에 표시하며, 신호 강도가 -90 [dBm](https://en.wikipedia.org/wiki/DBm)보다 높은 경우입니다.

원격 제어의 주파수를 확인하려면 다음을 수행하세요:

1. 원격 제어를 Flipper Zero의 왼쪽에 매우 가까이 놓으세요.
2. **Main Menu** **→ Sub-GHz**로 이동하세요.
3. **Frequency Analyzer**를 선택한 다음, 분석하려는 원격 제어의 버튼을 누르고 누르고 있습니다.
4. 화면에 표시된 주파수 값을 확인하세요.

### 읽기

{% hint style="info" %}
사용된 주파수에 대한 정보 찾기(사용된 주파수를 찾는 또 다른 방법)
{% endhint %}

**Read** 옵션은 지정된 주파수에서 지정된 변조 방식(기본값은 433.92 AM)으로 **리스닝**합니다. 읽기 중에 **무언가를 찾으면** 화면에 **정보가 표시**됩니다. 이 정보는 나중에 신호를 복제하는 데 사용될 수 있습니다.

Read를 사용하는 동안 **왼쪽 버튼**을 눌러 **구성**할 수 있습니다.\
현재 **4개의 변조 방식**(AM270, AM650, FM328 및 FM476)과 **여러 가지 중요한 주파수**가 저장되어 있습니다:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

**관심 있는 주파수**를 설정할 수 있지만, 원격 제어에 사용되는 **어떤 주파수**인지 확실하지 않은 경우에는 (기본값은 꺼져 있음) **Hopping을 ON**으로 설정하고 Flipper가 캡처하고 주파수를 설정하는 데 필요한 정보를 제공할 때까지 버튼을 여러 번 누르세요.

{% hint style="danger" %}
주파수 간 전환에는 시간이 소요되므로, 전환 시간에 전송된 신호가 누락될 수 있습니다. 신호 수신을 개선하기 위해 주파수 분석기에서 결정된 고정 주파수를 설정하세요.
{% endhint %}

### **Raw 읽기**

{% hint style="info" %}
구성된 주파수에서 신호를 훔쳐보고(재생)합니다.
{% endhint %}

**Raw Read** 옵션은 청취 주파수에서 보낸 신호를 기록합니다. 이를 사용하여 신호를 훔쳐보고 반복할 수 있습니다.

기본적으로 **Raw Read**는 433.92에서 AM650으로 설정되어 있지만, Read 옵션을 사용하여 관심 있는 신호가 다른 주파수/변조 방식에 있는 경우 왼쪽 버튼을 눌러 해당 설정을 수정할 수도 있습니다.

### 브루트 포스

예를 들어 차고 문에서 사용되는 프로토콜을 알고 있다면 Flipper Zero로 모든 코드를 생성하고 보낼 수 있습니다. 이는 일반적인 차고의 일반적인 유형을 지원하는 예입니다: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### 수동으로 추가

{% hint style="info" %}
구성된 프로토콜 목록에서 신호를 추가합니다.
{% endhint %}

#### [지원되는 프로토콜 목록](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (대부분의 정적 코드 시스템과 호환됨) | 433.92 | 정적   |
| ------------------------------------------------ | ------ | ------ |
| Nice Flo 12bit\_433                              | 433.92 | 정적   |
| Nice Flo 24bit\_433                              | 433.92 | 정적   |
| CAME 12bit
### 지원되는 Sub-GHz 공급업체

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)에서 목록을 확인하세요.

### 지역별 지원 주파수

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)에서 목록을 확인하세요.

### 테스트

{% hint style="info" %}
저장된 주파수의 dBm 가져오기
{% endhint %}

## 참고

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 빠르게 수정할 수 있도록 하세요. Intruder는 공격 표면을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**를** 팔로우하세요.
* **HackTricks**와 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
