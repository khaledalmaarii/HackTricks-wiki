# 웹에서 민감한 정보 노출 도용

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

만약 **세션에 기반한 민감한 정보를 제공하는 웹 페이지를 발견**하면: 쿠키를 반사하거나 인쇄하거나 CC 세부 정보 또는 기타 민감한 정보를 표시할 수 있습니다. 그것을 도용해 볼 수 있습니다.\
여기서 주요한 방법을 제시합니다:

* [**CORS 우회**](pentesting-web/cors-bypass.md): CORS 헤더를 우회할 수 있다면 악의적인 페이지에 대한 Ajax 요청을 수행하여 정보를 도용할 수 있습니다.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): 페이지에서 XSS 취약점을 찾으면 해당 취약점을 악용하여 정보를 도용할 수 있습니다.
* [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): XSS 태그를 삽입할 수 없는 경우에도 다른 일반적인 HTML 태그를 사용하여 정보를 도용할 수 있습니다.
* [**Clickjaking**](pentesting-web/clickjacking.md): 이 공격에 대한 보호가 없는 경우 사용자를 속여 민감한 데이터를 보내도록 유도할 수 있습니다 (예: [여기](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}
