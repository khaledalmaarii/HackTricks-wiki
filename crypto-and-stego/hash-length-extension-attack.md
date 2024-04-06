<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>


# 공격 요약

알려진 일부 평문 데이터에 **비밀**을 **추가**하고 해당 데이터를 해싱하여 **서명**하는 서버를 상상해보세요. 다음을 알고 있다면:

* **비밀의 길이** (주어진 길이 범위에서 브루트포스로 찾을 수도 있음)
* **평문 데이터**
* **알고리즘 (이 공격에 취약한)**
* **패딩이 알려져 있는**
* 일반적으로 기본 패딩이 사용되므로 다른 3가지 요구 사항을 충족하면 이 역시 그렇습니다.
* 패딩은 비밀+데이터의 길이에 따라 다르므로 비밀의 길이가 필요합니다.

그렇다면, **공격자**는 **데이터**를 **추가**하고 **이전 데이터 + 추가된 데이터**에 대한 유효한 **서명**을 **생성**할 수 있습니다.

## 어떻게?

기본적으로 취약한 알고리즘은 먼저 **데이터 블록을 해싱**한 다음, **이전에** 생성된 **해시**(상태)에서 **다음 데이터 블록을 추가**하고 **해싱**합니다.

그러면, 비밀이 "비밀"이고 데이터가 "데이터"인 경우, "비밀데이터"의 MD5는 6036708eba0d11f6ef52ad44e8b74d5b입니다.\
공격자가 문자열 "추가"를 추가하려면:

* 64개의 "A"의 MD5를 생성합니다.
* 이전에 초기화된 해시의 상태를 6036708eba0d11f6ef52ad44e8b74d5b로 변경합니다.
* 문자열 "추가"를 추가합니다.
* 해시를 완료하면 결과 해시는 **"비밀" + "데이터" + "패딩" + "추가"**에 대한 **유효한 해시**가 됩니다.

## **도구**

{% embed url="https://github.com/iagox86/hash_extender" %}

## 참고 자료

이 공격에 대한 자세한 설명은 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)에서 찾을 수 있습니다.


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFT**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
