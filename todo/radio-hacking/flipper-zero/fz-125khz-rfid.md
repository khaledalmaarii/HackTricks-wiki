# FZ - 125kHz RFID

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 소개

125kHz 태그 작동 방식에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## 작업

이러한 유형의 태그에 대한 자세한 정보는 [**이 소개**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)를 읽으세요.

### 읽기

카드 정보를 **읽으려고 시도**합니다. 그런 다음 **모방**할 수 있습니다.

{% hint style="warning" %}
일부 인터콤은 키 복제를 방지하기 위해 읽기 전에 쓰기 명령을 보내려고 합니다. 쓰기가 성공하면 해당 태그는 가짜로 간주됩니다. Flipper가 RFID를 모방할 때 리더가 원본과 구별할 방법이 없기 때문에 이러한 문제가 발생하지 않습니다.
{% endhint %}

### 수동 추가

Flipper Zero에서 **수동으로 데이터를 지정**하여 **가짜 카드를 생성**한 다음 모방할 수 있습니다.

#### 카드의 ID

카드를 받을 때 때로는 카드에 표시된 ID(또는 일부)를 찾을 수 있습니다.

- **EM Marin**

예를 들어 EM-Marin 카드의 경우 물리적 카드에서 **마지막 5바이트 중 마지막 3바이트를 명확히 읽을 수 있습니다**.\
카드에서 읽을 수 없는 경우 브루트 포스할 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

- **HID**

HID 카드의 경우 카드에 인쇄된 3바이트 중 2바이트만 찾을 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### 모방/쓰기

카드를 **복사**하거나 **수동으로 ID를 입력한 후** Flipper Zero에서 모방하거나 **실제 카드에 쓸 수** 있습니다.

## 참고 자료

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드하고 싶다면** [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 스왜그**](https://peass.creator-spring.com)를 구입하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
