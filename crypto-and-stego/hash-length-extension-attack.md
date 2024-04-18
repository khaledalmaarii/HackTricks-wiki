<details>

<summary><strong>htARTE (HackTricks AWS Red Team 전문가)로부터 제로에서 영웅까지 AWS 해킹 배우기</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사가 HackTricks에 광고되길 원하거나** **PDF 형식의 HackTricks 다운로드**를 원하면 [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 굿즈**](https://peass.creator-spring.com)를 구매하세요
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요, 당사의 독점 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션
* **💬 [디스코드 그룹](https://discord.gg/hRep4RUj7f)** 또는 [**텔레그램 그룹**](https://t.me/peass)에 **가입**하거나 **트위터** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **해킹 트릭을 공유하고 싶다면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소로 PR을 제출하세요.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, **무료** 기능을 제공하여 회사나 고객이 **도난당한 악성 소프트웨어**에 의해 **침해**당했는지 확인할 수 있습니다.

WhiteIntel의 주요 목표는 정보 도난 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 방지하는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

---

# 공격 요약

일부 **알려진 평문 데이터에 비밀을 추가**하고 해당 데이터를 해싱하는 서버를 상상해보십시오. 다음을 알고 있다면:

* **비밀의 길이** (주어진 길이 범위에서도 브루트포스 가능)
* **평문 데이터**
* **알고리즘 (이 공격에 취약함)**
* **패딩이 알려져 있음**
* 일반적으로 기본값이 사용되므로 다른 3가지 요구 사항이 충족되면 이것도 해당됨
* 패딩은 비밀+데이터의 길이에 따라 달라지므로 비밀의 길이가 필요함

그러면 **공격자**가 **데이터를 추가**하고 **이전 데이터 + 추가된 데이터에 대한 유효한 서명을 생성**할 수 있습니다.

## 어떻게?

기본적으로 취약한 알고리즘은 먼저 **데이터 블록을 해싱**하고, 그런 다음 **이전에 생성된 해시**(상태)에서 **다음 데이터 블록을 추가**하고 **해싱**합니다.

그런 다음, 비밀이 "비밀"이고 데이터가 "데이터"인 경우, "secretdata"의 MD5는 6036708eba0d11f6ef52ad44e8b74d5b입니다.\
공격자가 "append" 문자열을 추가하려면:

* 64개의 "A"의 MD5를 생성
* 이전에 초기화된 해시의 상태를 6036708eba0d11f6ef52ad44e8b74d5b로 변경
* 문자열 "append"를 추가
* 해시를 완료하면 결과 해시는 **"비밀" + "데이터" + "패딩" + "append"에 대한 유효한 것**이 될 것입니다.

## **도구**

{% embed url="https://github.com/iagox86/hash_extender" %}

## 참고 자료

이 공격에 대한 자세한 설명은 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)에서 찾을 수 있습니다.

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)은 **다크 웹**을 활용한 검색 엔진으로, **무료** 기능을 제공하여 회사나 고객이 **도난당한 악성 소프트웨어**에 의해 **침해**당했는지 확인할 수 있습니다.

WhiteIntel의 주요 목표는 정보 도난 악성 소프트웨어로 인한 계정 탈취 및 랜섬웨어 공격을 방지하는 것입니다.

그들의 웹사이트를 방문하여 엔진을 **무료**로 사용해 볼 수 있습니다:

{% embed url="https://whiteintel.io" %}

</details>
