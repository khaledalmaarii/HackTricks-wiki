# FZ - NFC

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전 또는 HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **해킹 트릭을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정하세요. Intruder는 공격 대상 범위를 추적하고 적극적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## 소개 <a href="#9wrzi" id="9wrzi"></a>

RFID 및 NFC에 대한 정보는 다음 페이지를 참조하세요:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## 지원되는 NFC 카드 <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
NFC 카드 외에도 Flipper Zero는 **기타 유형의 고주파 카드**인 **Mifare** Classic 및 Ultralight 및 **NTAG**를 지원합니다.
{% endhint %}

지원되는 카드 목록에 새로운 유형의 NFC 카드가 추가될 예정입니다. Flipper Zero는 다음과 같은 **NFC 카드 유형 A** (ISO 14443A)를 지원합니다:

* ﻿**은행 카드 (EMV)** — UID, SAK 및 ATQA만 읽고 저장하지 않습니다.
* ﻿**알 수 없는 카드** — (UID, SAK, ATQA)를 읽고 UID를 에뮬레이션할 수 있습니다.

**NFC 카드 유형 B, 유형 F 및 유형 V**의 경우, Flipper Zero는 UID를 읽을 수 있지만 저장하지는 않습니다.

### NFC 카드 유형 A <a href="#uvusf" id="uvusf"></a>

#### 은행 카드 (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero는 은행 카드의 데이터를 **저장하지 않고** UID, SAK, ATQA 및 저장된 데이터만 읽을 수 있습니다.

은행 카드 읽기 화면Flipper Zero는 은행 카드의 데이터를 **저장하거나 에뮬레이션하지 않고** 읽을 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 알 수 없는 카드 <a href="#37eo8" id="37eo8"></a>

Flipper Zero가 **NFC 카드의 유형을 판별할 수 없는 경우**, UID, SAK 및 ATQA만 **읽고 저장**할 수 있습니다.

알 수 없는 카드 읽기 화면알 수 없는 NFC 카드의 경우, Flipper Zero는 UID만 에뮬레이션할 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC 카드 유형 B, F 및 V <a href="#wyg51" id="wyg51"></a>

**NFC 카드 유형 B, F 및 V**의 경우, Flipper Zero는 UID를 읽을 수 있지만 저장하지는 않습니다.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## 작업

NFC에 대한 소개는 [**이 페이지**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)를 읽어보세요.

### 읽기

Flipper Zero는 **NFC 카드를 읽을 수 있지만**, ISO 14443을 기반으로 하는 **모든 프로토콜을 이해하지는 않습니다**. 그러나 **UID는 저수준 속성**이므로 **UID가 이미 읽혔지만 고수준 데이터 전송 프로토콜은 여전히 알 수 없는 상황**에 처할 수 있습니다. Flipper를 사용하여 UID를 사용하여 인가를 위한 원시 리더에 대해 데이터를 읽고 에뮬레이션하고 수동으로 입력할 수 있습니다.

#### UID 읽기 대 데이터 내부 읽기 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Flipper에서 13.56 MHz 태그를 읽는 것은 두 부분으로 나눌 수 있습니다:

* **저수준 읽기** — UID, SAK 및 ATQA만 읽습니다. Flipper는 이 카드에서 읽은 데이터를 기반으로 고수준 프로토콜을 추측하려고 합니다. 이는 특정 요소를 기반으로 한 가정에 불과하므로 100% 확신할 수는 없습니다.
* **고수준 읽기** — 특정 고수준 프로토콜을 사용하여 카드의 메모리에서 데이터를 읽습니다. Mifare Ultralight의 데이터를 읽거나 Mifare Classic의 섹터를 읽거나 PayPass/Apple Pay의 카드 속성을 읽는 것이 해당됩니다.

### 특정 읽기

Flipper Zero가 저수준 데이터에서 카드 유형을 찾지 못하는 경우, `추가 작업`에서 `특정 카드 유형 읽기`를 선택하고 **읽고자 하는 카드 유형을 수동으로 지정**할 수 있습니다.
#### EMV 은행 카드 (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UID를 읽는 것 외에도 은행 카드에서 더 많은 데이터를 추출할 수 있습니다. 은행 카드의 **전체 카드 번호** (카드 앞면의 16자리 숫자), **유효 기간**, 그리고 경우에 따라 **소유자의 이름**과 **가장 최근 거래 목록**을 얻을 수 있습니다.\
그러나 이 방법으로 CVV (카드 뒷면의 3자리 숫자)를 읽을 수는 없습니다. 또한 은행 카드는 **재생 공격으로부터 보호**되므로 Flipper로 복사한 후에 이를 에뮬레이션하여 결제하는 것은 작동하지 않습니다.

## 참고 자료

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

가장 중요한 취약점을 찾아서 더 빠르게 수정할 수 있습니다. Intruder는 공격 표면을 추적하고 예방적인 위협 스캔을 실행하여 API부터 웹 앱 및 클라우드 시스템까지 전체 기술 스택에서 문제를 찾습니다. [**무료로 시도해보세요**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) 오늘.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>로 AWS 해킹을 처음부터 전문가까지 배워보세요</strong></a><strong>!</strong></summary>

* **사이버 보안 회사**에서 일하시나요? **회사를 HackTricks에서 광고**하거나 **PEASS의 최신 버전에 액세스**하거나 **HackTricks를 PDF로 다운로드**하고 싶으신가요? [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인해보세요!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견해보세요. 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter**에서 **팔로우**하세요 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **자신의 해킹 기법을 공유하려면** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **및** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)에 PR을 제출하세요.

</details>
