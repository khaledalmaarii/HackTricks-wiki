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

Konteina isiyo na mfumo wa uendeshaji ni aina ya kontena ambayo **ina viambatisho muhimu tu kuendesha programu maalum**, bila programu au zana za ziada ambazo hazihitajiki. Kontena hizi zimeundwa kuwa **nyepesi** na **salama** kadri iwezekanavyo, na zina lengo la **kupunguza uso wa shambulio** kwa kuondoa vipengele visivyohitajika.

Konteina zisizo na mfumo wa uendeshaji mara nyingi hutumiwa katika **mazingira ya uzalishaji ambapo usalama na uaminifu ni muhimu**.

Baadhi ya **mfano** wa **konteina zisizo na mfumo wa uendeshaji** ni:

* Iliyotolewa na **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Iliyotolewa na **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Lengo la kuunda silaha kutoka kwa kontena isiyo na mfumo wa uendeshaji ni kuwa na uwezo wa **kutekeleza binaries na payloads bila mipaka** inayohusishwa na **distroless** (ukosefu wa binaries za kawaida katika mfumo) na pia ulinzi unaopatikana mara nyingi katika kontena kama **kusoma tu** au **hakuna utekelezaji** katika `/dev/shm`.

### Through memory

Kuja katika wakati fulani wa 2023...

### Via Existing binaries

#### openssl

****[**Katika chapisho hili,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) inafafanuliwa kuwa binary **`openssl`** mara nyingi hupatikana katika kontena hizi, labda kwa sababu inahitajika na programu ambayo itakuwa ikikimbia ndani ya kontena.
