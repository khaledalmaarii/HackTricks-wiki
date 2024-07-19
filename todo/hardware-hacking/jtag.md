# JTAG

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)은 Raspberry PI 또는 Arduino와 함께 사용하여 알 수 없는 칩의 JTAG 핀을 찾는 도구입니다.\
**Arduino**에서는 **핀 2에서 11까지를 JTAG에 속할 가능성이 있는 10핀에 연결**합니다. Arduino에 프로그램을 로드하면 모든 핀을 브루트포스하여 JTAG에 속하는 핀과 각 핀을 찾으려고 시도합니다.\
**Raspberry PI**에서는 **핀 1에서 6**만 사용할 수 있습니다(6핀, 따라서 각 잠재적 JTAG 핀을 테스트하는 데 더 느리게 진행됩니다).

### Arduino

Arduino에서 케이블을 연결한 후(핀 2에서 11까지를 JTAG 핀에 연결하고 Arduino GND를 기본 보드 GND에 연결), **Arduino에 JTAGenum 프로그램을 로드**하고 Serial Monitor에서 **`h`**(도움 요청 명령)를 보내면 도움말을 볼 수 있습니다:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

**"No line ending" 및 115200baud**로 설정합니다.\
스캔을 시작하려면 s 명령을 보냅니다:

![](<../../.gitbook/assets/image (774).png>)

JTAG에 연결하고 있다면 **FOUND!**로 시작하는 하나 이상의 **라인을 찾을 수 있습니다**. 이는 JTAG의 핀을 나타냅니다.

{% hint style="success" %}
AWS 해킹 배우기 및 연습하기:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP 해킹 배우기 및 연습하기: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks 지원하기</summary>

* [**구독 계획**](https://github.com/sponsors/carlospolop) 확인하기!
* **💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 참여하거나 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**를 팔로우하세요.**
* **[**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 리포지토리에 PR을 제출하여 해킹 팁을 공유하세요.**

</details>
{% endhint %}
