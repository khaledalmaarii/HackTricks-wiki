# FZ - 125kHz RFID

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 소개

125kHz 태그 작동 방식에 대한 자세한 정보는 다음을 확인하세요:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## 작업

이러한 유형의 태그에 대한 자세한 정보는 [**이 소개를 읽어보세요**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### 읽기

카드 정보를 **읽으려고** 시도합니다. 그런 다음 이를 **에뮬레이트**할 수 있습니다.

{% hint style="warning" %}
일부 인터콤은 읽기 전에 쓰기 명령을 보내어 키 복제를 방지하려고 합니다. 쓰기가 성공하면 해당 태그는 가짜로 간주됩니다. Flipper가 RFID를 에뮬레이트할 때 리더가 원본과 구별할 방법이 없으므로 이러한 문제는 발생하지 않습니다.
{% endhint %}

### 수동 추가

Flipper Zero에서 **수동으로 데이터를 입력하여 가짜 카드를 생성**한 다음 이를 에뮬레이트할 수 있습니다.

#### 카드의 ID

카드를 받을 때 카드에 ID(또는 일부)가 보이도록 쓰여 있는 경우가 있습니다.

* **EM Marin**

예를 들어 이 EM-Marin 카드에서는 물리적 카드에서 **마지막 3개의 5바이트를 명확하게 읽을 수 있습니다**.\
나머지 2개는 카드를 통해 읽을 수 없는 경우 무차별 대입으로 찾을 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* **HID**

이 HID 카드에서도 카드에 인쇄된 3바이트 중 2바이트만 찾을 수 있습니다.

<figure><img src="../../../.gitbook/assets/image (1014).png" alt=""><figcaption></figcaption></figure>

### 에뮬레이트/쓰기

카드를 **복사**하거나 **ID를 수동으로 입력**한 후 Flipper Zero로 이를 **에뮬레이트**하거나 실제 카드에 **쓰기**할 수 있습니다.

## 참고자료

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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
