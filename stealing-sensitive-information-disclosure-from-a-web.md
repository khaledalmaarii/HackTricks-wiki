# 웹에서 민감한 정보 유출하기

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>

만약 **세션에 기반한 민감한 정보를 제공하는 웹 페이지**를 발견한다면: 아마도 쿠키를 반영하거나 인쇄하거나 신용카드 세부 정보 또는 다른 민감한 정보를 제공할 수 있습니다. 이를 도용해볼 수 있습니다.\
여기에서는 이를 달성하기 위한 주요 방법을 소개합니다:

* [**CORS 우회**](pentesting-web/cors-bypass.md): CORS 헤더를 우회할 수 있다면 악성 페이지에 대한 Ajax 요청을 수행하여 정보를 도용할 수 있습니다.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): 페이지에서 XSS 취약점을 발견한다면 이를 악용하여 정보를 도용할 수 있습니다.
* [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): XSS 태그를 삽입할 수 없는 경우에도 다른 일반적인 HTML 태그를 사용하여 정보를 도용할 수 있습니다.
* [**Clickjaking**](pentesting-web/clickjacking.md): 이 공격에 대한 보호가 없다면 사용자를 속여 민감한 데이터를 보내도록 유도할 수 있습니다 (예시 [여기](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* 회사를 **HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션인 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **HackTricks**와 **HackTricks Cloud** github 저장소에 PR을 제출하여 **해킹 트릭을 공유**하세요.

</details>
