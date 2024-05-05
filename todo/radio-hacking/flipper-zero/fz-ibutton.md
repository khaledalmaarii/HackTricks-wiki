# FZ - iButton

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

## 소개

iButton이 무엇인지에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## 디자인

다음 이미지의 **파란** 부분은 **실제 iButton을 놓아야 하는 위치**를 나타냅니다. **녹색** 부분은 Flipper zero가 **iButton을 올바르게 에뮬레이트**하기 위해 리더에 **접촉해야 하는 방법**을 보여줍니다.

<figure><img src="../../../.gitbook/assets/image (565).png" alt=""><figcaption></figcaption></figure>

## 작업

### 읽기

읽기 모드에서 Flipper는 iButton 키가 터치되기를 기다리며 **Dallas, Cyfral 및 Metakom** 세 가지 유형의 키 중 어느 것이든 처리할 수 있습니다. Flipper는 **키의 유형을 자동으로 식별**합니다. 키 프로토콜의 이름은 ID 번호 위에 화면에 표시됩니다.

### 수동으로 추가

**Dallas, Cyfral 및 Metakom** 유형의 iButton을 **수동으로 추가**할 수 있습니다.

### **에뮬레이트**

저장된 iButton(읽기 또는 수동으로 추가된)을 **에뮬레이트**할 수 있습니다.

{% hint style="info" %}
Flipper Zero의 예상된 접촉을 리더에 터치할 수 없는 경우 **외부 GPIO를 사용**할 수 있습니다:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

## 참고 자료

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

- **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks를 다운로드**하려면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
- [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
- 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)를 **팔로우**하세요.
- **HackTricks** 및 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
