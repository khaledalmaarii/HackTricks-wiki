# FZ - iButton

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 소개

iButton이 무엇인지에 대한 자세한 정보는 다음을 참조하세요:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## 디자인

다음 이미지의 **파란색** 부분은 Flipper가 **실제 iButton을 읽을 수 있도록**해야하는 위치입니다. **녹색** 부분은 Flipper zero가 **iButton을 올바르게 에뮬레이션하기 위해 리더에 접촉해야하는 위치입니다**.

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

## 동작

### 읽기

읽기 모드에서 Flipper는 iButton 키가 터치되기를 기다리며 **Dallas, Cyfral 및 Metakom**의 세 가지 유형의 키를 처리할 수 있습니다. Flipper는 **키의 유형을 자동으로 식별**합니다. 키 프로토콜의 이름은 ID 번호 위에 화면에 표시됩니다.

### 수동으로 추가

**Dallas, Cyfral 및 Metakom** 유형의 iButton을 **수동으로 추가**할 수 있습니다.

### 에뮬레이션

읽거나 수동으로 추가된 iButton을 **에뮬레이션**할 수 있습니다.

{% hint style="info" %}
Flipper Zero의 예상되는 연락처를 리더에 접촉시킬 수 없는 경우 **외부 GPIO를 사용**할 수 있습니다.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (24) (1).png" alt=""><figcaption></figcaption></figure>

## 참고 자료

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
