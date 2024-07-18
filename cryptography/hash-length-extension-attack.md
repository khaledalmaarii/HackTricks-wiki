{% hint style="success" %}
**AWS 해킹 학습 및 실습:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP 해킹 학습 및 실습:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}


# 공격 요약

일부 **데이터**에 **비밀**을 **추가**하고 해당 데이터를 해싱하는 서버를 상상해보세요. 다음을 알고 있다면:

* **비밀의 길이** (주어진 길이 범위에서 브루트포스할 수도 있음)
* **명확한 텍스트 데이터**
* **알고리즘 (이 공격에 취약한)**
* **패딩이 알려져 있다**
* 일반적으로 기본값이 사용되므로 다른 3가지 요구 사항이 충족되면 이것도 사용됨
* 패딩은 비밀 + 데이터의 길이에 따라 달라지므로 비밀의 길이가 필요함

그럼, **공격자**는 **데이터**를 **추가**하고 **이전 데이터 + 추가된 데이터**에 대한 유효한 **서명**을 **생성**할 수 있습니다.

## 어떻게?

기본적으로 취약한 알고리즘은 먼저 **데이터 블록을 해싱**하고, 그런 다음 **이전에** 생성된 **해시**(상태)에서 **다음 데이터 블록을 추가**하고 **해싱**합니다.

그럼, 비밀이 "비밀"이고 데이터가 "데이터"인 경우, "비밀데이터"의 MD5는 6036708eba0d11f6ef52ad44e8b74d5b입니다.\
공격자가 "추가" 문자열을 추가하려면:

* 64개의 "A"의 MD5를 생성
* 이전에 초기화된 해시의 상태를 6036708eba0d11f6ef52ad44e8b74d5b로 변경
* 문자열 "추가"를 추가
* 해시를 완료하면 결과 해시는 **"비밀" + "데이터" + "패딩" + "추가"**에 대한 유효한 것이 될 것입니다

## **도구**

{% embed url="https://github.com/iagox86/hash_extender" %}

## 참고 자료

이 공격에 대한 자세한 설명은 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)에서 찾을 수 있습니다.


{% hint style="success" %}
**AWS 해킹 학습 및 실습:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP 해킹 학습 및 실습:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}
