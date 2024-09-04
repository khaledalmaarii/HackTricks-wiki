# 해시 길이 확장 공격

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}


## 공격 요약

서버가 **데이터**에 **비밀**을 **추가**하여 **서명**하고 그 데이터를 해시한다고 상상해 보세요. 다음을 알고 있다면:

* **비밀의 길이** (주어진 길이 범위에서 무차별 대입으로도 알 수 있음)
* **명확한 텍스트 데이터**
* **알고리즘 (이 공격에 취약함)**
* **패딩이 알려져 있음**
* 일반적으로 기본값이 사용되므로 다른 3가지 요구 사항이 충족되면 이것도 해당됨
* 패딩은 비밀+데이터의 길이에 따라 달라지므로 비밀의 길이가 필요함

그렇다면 **공격자**가 **데이터를 추가**하고 **이전 데이터 + 추가된 데이터**에 대한 유효한 **서명**을 **생성**하는 것이 가능합니다.

### 어떻게?

기본적으로 취약한 알고리즘은 먼저 **데이터 블록을 해시**한 다음, **이전에** 생성된 **해시**(상태)에서 **다음 데이터 블록을 추가**하고 **해시**합니다.

그런 다음 비밀이 "secret"이고 데이터가 "data"라고 가정해 보세요. "secretdata"의 MD5는 6036708eba0d11f6ef52ad44e8b74d5b입니다.\
공격자가 "append" 문자열을 추가하고 싶다면 다음과 같이 할 수 있습니다:

* 64개의 "A"로 MD5 생성
* 이전에 초기화된 해시의 상태를 6036708eba0d11f6ef52ad44e8b74d5b로 변경
* "append" 문자열 추가
* 해시를 완료하면 결과 해시는 **"secret" + "data" + "padding" + "append"**에 대한 유효한 해시가 됩니다.

### **도구**

{% embed url="https://github.com/iagox86/hash_extender" %}

### 참고 문헌

이 공격에 대한 좋은 설명은 [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)에서 찾을 수 있습니다.



{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 트릭을 공유하세요.**

</details>
{% endhint %}
