# iButton

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Intro

iButton은 **동전 모양의 금속 용기**에 포장된 전자 식별 키의 일반적인 이름입니다. **Dallas Touch** Memory 또는 접촉 메모리라고도 불립니다. 종종 “자기” 키로 잘못 언급되지만, 그 안에는 **자기적인 것**이 전혀 없습니다. 사실, **디지털 프로토콜**로 작동하는 완전한 **마이크로칩**이 내부에 숨겨져 있습니다.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

일반적으로 iButton은 키와 리더의 물리적 형태를 의미하며, 두 개의 접점이 있는 둥근 동전입니다. 이를 둘러싼 프레임에는 구멍이 있는 가장 일반적인 플라스틱 홀더부터 링, 펜던트 등 다양한 변형이 있습니다.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

키가 리더에 도달하면 **접점이 접촉**하고 키가 **전원 공급**을 받아 ID를 **전송**합니다. 때때로 키가 **즉시 읽히지 않는** 경우가 있는데, 이는 **인터콤의 접촉 PSD가 너무 크기** 때문입니다. 그래서 키와 리더의 외곽이 접촉하지 못할 수 있습니다. 그런 경우에는 리더의 벽 중 하나에 키를 눌러야 합니다.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas 키는 1-wire 프로토콜을 사용하여 데이터를 교환합니다. 데이터 전송을 위한 접점이 하나만 있으며 (!!) 양방향으로, 마스터에서 슬레이브로, 그리고 그 반대 방향으로 작동합니다. 1-wire 프로토콜은 마스터-슬레이브 모델에 따라 작동합니다. 이 토폴로지에서 마스터는 항상 통신을 시작하고 슬레이브는 그 지침을 따릅니다.

키(슬레이브)가 인터콤(마스터)과 접촉하면, 키 내부의 칩이 켜지고 인터콤에 의해 전원이 공급되어 키가 초기화됩니다. 그 후 인터콤이 키 ID를 요청합니다. 다음으로 이 과정을 더 자세히 살펴보겠습니다.

Flipper는 마스터 및 슬레이브 모드 모두에서 작동할 수 있습니다. 키 읽기 모드에서 Flipper는 리더로 작동하며, 즉 마스터로 작동합니다. 그리고 키 에뮬레이션 모드에서는 Flipper가 키인 척하며 슬레이브 모드에 있습니다.

### Dallas, Cyfral & Metakom keys

이 키들이 어떻게 작동하는지에 대한 정보는 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/) 페이지를 확인하세요.

### Attacks

iButtons는 Flipper Zero로 공격할 수 있습니다:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
