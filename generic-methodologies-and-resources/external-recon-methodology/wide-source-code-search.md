# 넓은 소스 코드 검색

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

이 페이지의 목표는 **수천만 개/수백만 개의 저장소에서 코드(문자 또는 정규식)를 검색할 수 있는 플랫폼을 열거**하는 것입니다.

이는 **유출된 정보를 검색**하거나 **취약점** 패턴을 찾는 데 도움이 됩니다.

* [**SourceGraph**](https://sourcegraph.com/search): 수백만 개의 저장소에서 검색. 무료 버전과 엔터프라이즈 버전(15일 무료)이 있습니다. 정규식을 지원합니다.
* [**Github Search**](https://github.com/search): Github 전체에서 검색. 정규식을 지원합니다.
* 아마도 [**Github Code Search**](https://cs.github.com/)도 확인하는 것이 유용할 수 있습니다.
* [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Gitlab 프로젝트 전체에서 검색. 정규식을 지원합니다.
* [**SearchCode**](https://searchcode.com/): 수백만 개의 프로젝트에서 코드를 검색합니다.

{% hint style="warning" %}
저장소에서 유출물을 찾을 때 `git log -p`와 같은 명령을 실행할 때 **다른 커밋을 포함하는 다른 브랜치**에 비밀 정보가 포함될 수 있음을 잊지 마세요!
{% endhint %}

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) 깃헙 저장소에 PR을 제출하여 해킹 요령을 공유하세요.

</details>
{% endhint %}
