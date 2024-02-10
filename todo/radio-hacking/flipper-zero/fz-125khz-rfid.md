# FZ - 125kHz RFID

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT 컬렉션인 The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 기교를 공유**하세요.

</details>

## 소개

125kHz 태그가 작동하는 방법에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## 작업

이러한 유형의 태그에 대한 자세한 정보는 [**이 소개**](../../../radio-hacking/pentesting-rfid.md#low-frequency-rfid-tags-125khz)를 읽으세요.

### 읽기

카드 정보를 **읽으려고 시도**합니다. 그런 다음 그것을 **에뮬레이션**할 수 있습니다.

{% hint style="warning" %}
일부 인터콤은 키 복제를 방지하기 위해 읽기 전에 쓰기 명령을 보내려고 합니다. 쓰기가 성공하면 해당 태그는 가짜로 간주됩니다. Flipper가 RFID를 에뮬레이션할 때 리더가 원본과 구별할 수 있는 방법이 없으므로 이러한 문제가 발생하지 않습니다.
{% endhint %}

### 수동으로 추가

Flipper Zero에서 **수동으로 데이터를 지정하여 가짜 카드를 생성**한 다음 에뮬레이션할 수 있습니다.

#### 카드의 ID

카드를 받을 때 때로는 카드에 기록된 ID(또는 일부)를 확인할 수 있습니다.

* **EM Marin**

예를 들어 EM-Marin 카드에서 물리적 카드에는 **마지막 5바이트 중 3바이트를 알아볼 수 있습니다**.\
카드에서 읽을 수 없는 경우 브루트 포스로 찾을 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

동일한 일이 HID 카드에서 발생하며 카드에 인쇄된 3바이트 중 2바이트만 찾을 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### 에뮬레이션/쓰기

카드를 **복사**하거나 ID를 **수동으로 입력**한 후 Flipper Zero에서 에뮬레이션하거나 실제 카드에 **쓸** 수 있습니다.

## 참고 자료

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 상품**](https://peass.creator-spring.com)을 구매하세요.
* 독점적인 [**NFT 컬렉션인 The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 기교를 공유**하세요.

</details>
