# 웹에서 민감한 정보 유출 도용하기

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

어떤 시점에 **세션에 따라 민감한 정보를 표시하는 웹 페이지**를 발견하면: 쿠키를 반영하거나, CC 세부정보를 인쇄하거나, 기타 민감한 정보를 표시할 수 있습니다. 이를 도용해 보세요.\
여기서 이를 달성하기 위해 시도할 수 있는 주요 방법을 소개합니다:

* [**CORS 우회**](../pentesting-web/cors-bypass.md): CORS 헤더를 우회할 수 있다면 악성 페이지에 대한 Ajax 요청을 수행하여 정보를 도용할 수 있습니다.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): 페이지에서 XSS 취약점을 발견하면 이를 악용하여 정보를 도용할 수 있습니다.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): XSS 태그를 주입할 수 없다면 다른 일반 HTML 태그를 사용하여 정보를 도용할 수 있습니다.
* [**Clickjaking**](../pentesting-web/clickjacking.md): 이 공격에 대한 보호가 없다면 사용자를 속여 민감한 데이터를 보내도록 할 수 있습니다 (예시 [여기](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)). 

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃허브 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
