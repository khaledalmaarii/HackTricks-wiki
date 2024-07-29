# Weaponizing Distroless

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

## What is Distroless

Distroless 컨테이너는 **특정 애플리케이션을 실행하는 데 필요한 종속성만 포함된** 컨테이너의 일종으로, 필요하지 않은 추가 소프트웨어나 도구는 포함되지 않습니다. 이러한 컨테이너는 **가볍고** **안전**하게 설계되었으며, 불필요한 구성 요소를 제거하여 **공격 표면을 최소화**하는 것을 목표로 합니다.

Distroless 컨테이너는 **보안과 신뢰성이 가장 중요한** **생산 환경**에서 자주 사용됩니다.

**Distroless 컨테이너의 몇 가지 예**는 다음과 같습니다:

* **Google**에서 제공: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard**에서 제공: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Distroless 컨테이너를 무기화하는 목표는 **distroless**에 의해 암시된 **제한에도 불구하고 임의의 바이너리와 페이로드를 실행할 수 있는** 것입니다(시스템에 일반적인 바이너리가 부족함) 그리고 **읽기 전용** 또는 **실행 금지**와 같은 컨테이너에서 일반적으로 발견되는 보호 기능도 포함됩니다.

### Through memory

2023년의 어느 시점에...

### Via Existing binaries

#### openssl

****[**이 게시물에서는,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) 바이너리 **`openssl`**이 이러한 컨테이너에서 자주 발견된다고 설명하고 있으며, 이는 **컨테이너 내에서 실행될 소프트웨어에 필요하기 때문일 수 있습니다.**


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
