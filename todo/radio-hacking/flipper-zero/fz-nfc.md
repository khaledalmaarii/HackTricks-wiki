# FZ - NFC

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로부터 영웅이 되는 AWS 해킹을 배우세요</strong></a><strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **HackTricks에 귀사를 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 얻으세요
* **💬** [**Discord 그룹**](https://discord.gg/hRep4RUj7f)에 **가입**하거나 [**텔레그램 그룹**](https://t.me/peass)에 가입하시거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **해킹 요령을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>

## 소개 <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID 및 NFC에 대한 정보는 다음 페이지를 확인하세요:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## 지원되는 NFC 카드 <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
NFC 카드 외에도 Flipper Zero는 여러 **Mifare** Classic 및 Ultralight 및 **NTAG**와 같은 **고주파 카드 유형**을 지원합니다.
{% endhint %}

새로운 종류의 NFC 카드가 지원되는 카드 목록에 추가될 것입니다. Flipper Zero는 다음 **NFC 카드 유형 A** (ISO 14443A)를 지원합니다:

* ﻿**은행 카드 (EMV)** — UID, SAK 및 ATQA만 읽고 저장하지 않음.
* ﻿**알 수 없는 카드** — (UID, SAK, ATQA)를 읽고 UID를 에뮬레이트할 수 있음.

**NFC 카드 유형 B, 유형 F 및 유형 V**의 경우, Flipper Zero는 UID를 저장하지 않고 읽을 수 있습니다.

### NFC 카드 유형 A <a href="#uvusf" id="uvusf"></a>

#### 은행 카드 (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero는 UID, SAK, ATQA 및 은행 카드에 저장된 데이터를 **저장하지 않고** 읽을 수 있습니다.

은행 카드 읽기 화면은 은행 카드의 데이터를 **저장하거나 에뮬레이트하지 않고** 읽을 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 알 수 없는 카드 <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero가 **NFC 카드 유형을 결정할 수 없는 경우**, UID, SAK 및 ATQA만 **읽고 저장**할 수 있습니다.

알 수 없는 카드 읽기 화면은 알 수 없는 NFC 카드에 대해 Flipper Zero가 UID만 에뮬레이트할 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC 카드 유형 B, F 및 V <a href="#wyg51" id="wyg51"></a>

**NFC 카드 유형 B, F 및 V**의 경우, Flipper Zero는 UID를 저장하지 않고 읽을 수 있습니다.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## 작업

NFC에 대한 소개는 [**이 페이지**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)를 읽으세요.

### 읽기

Flipper Zero는 **NFC 카드를 읽을 수 있지만**, ISO 14443을 기반으로 하는 **모든 프로토콜을 이해하지는 못합니다**. 그러나 **UID는 저수준 속성**이므로 **UID가 이미 읽혔지만 고수준 데이터 전송 프로토콜이 아직 알려지지 않은 상황**에 처할 수 있습니다. Flipper를 사용하여 UID를 읽고, 에뮬레이트하고, 수동으로 입력하여 UID를 사용하여 권한 부여에 UID를 사용하는 원시 리더를 위해 데이터를 읽을 수 있습니다.

#### UID 읽기 대 데이터 내부 읽기 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper에서 13.56 MHz 태그를 읽는 것은 두 부분으로 나뉩니다:

* **저수준 읽기** — UID, SAK 및 ATQA만 읽습니다. Flipper는 이 카드에서 읽은 데이터를 기반으로 고수준 프로토콜을 추측하려고 합니다. 이것은 특정 요소를 기반으로 한 가정에 불과하므로 100% 확신할 수 없습니다.
* **고수준 읽기** — 특정 고수준 프로토콜을 사용하여 카드 메모리에서 데이터를 읽습니다. 이는 Mifare Ultralight의 데이터를 읽거나, Mifare Classic의 섹터를 읽거나, PayPass/Apple Pay의 카드 속성을 읽는 것입니다.

### 특정 읽기

Flipper Zero가 저수준 데이터에서 카드 유형을 찾지 못하는 경우, `추가 작업`에서 `특정 카드 유형 읽기`를 선택하여 **수동으로** **읽고자 하는 카드 유형을 지정**할 수 있습니다.

#### EMV 은행 카드 (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UID를 단순히 읽는 것 외에도 은행 카드에서 많은 데이터를 추출할 수 있습니다. **전체 카드 번호**(카드 앞면의 16자리), **유효 날짜**, 경우에 따라 **소유자의 이름**과 **가장 최근 거래 목록**을 얻을 수 있습니다.\
그러나 이 방법으로 **CVV를 읽을 수는 없습니다**(카드 뒷면의 3자리). 또한 **은행 카드는 재생 공격으로부터 보호**되므로 Flipper로 복사한 후 결제를 위해 에뮬레이트하려고 시도해도 작동하지 않습니다.
## 참고 자료

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)를 통해 제로부터 영웅이 되는 AWS 해킹을 배우세요</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고하고 싶으신가요**? 혹은 **PEASS의 최신 버전에 액세스하거나 HackTricks를 PDF로 다운로드하고 싶으신가요**? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 저희의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* [**공식 PEASS & HackTricks 스왹**](https://peass.creator-spring.com)을 얻으세요
* **💬** [**Discord 그룹**](https://discord.gg/hRep4RUj7f)이나 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**을 팔로우하세요**.
* **해킹 트릭을 공유하고 싶으시다면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **에 PR을 제출하세요**.

</details>
