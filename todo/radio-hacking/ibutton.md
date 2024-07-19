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

iButton - це загальна назва для електронного ідентифікаційного ключа, упакованого в **металевий контейнер у формі монети**. Його також називають **Dallas Touch** Memory або контактною пам'яттю. Хоча його часто неправильно називають "магнітним" ключем, у ньому **немає нічого магнітного**. Насправді всередині прихований повноцінний **мікросхема**, що працює на цифровому протоколі.

<figure><img src="../../.gitbook/assets/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Зазвичай iButton означає фізичну форму ключа та зчитувача - кругла монета з двома контактами. Для рамки, що оточує його, існує безліч варіацій, від найпоширенішого пластикового тримача з отвором до кілець, підвісок тощо.

<figure><img src="../../.gitbook/assets/image (1078).png" alt=""><figcaption></figcaption></figure>

Коли ключ досягає зчитувача, **контакти торкаються** і ключ отримує живлення для **передачі** свого ID. Іноді ключ **не зчитується** відразу, оскільки **контакт PSD домофона більший**, ніж повинен бути. Тому зовнішні контури ключа та зчитувача не можуть торкатися. Якщо це так, вам доведеться натиснути ключ на одну з стінок зчитувача.

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Ключі Dallas обмінюються даними, використовуючи протокол 1-wire. З лише одним контактом для передачі даних (!!) в обох напрямках, від майстра до раба і навпаки. Протокол 1-wire працює за моделлю Master-Slave. У цій топології Master завжди ініціює зв'язок, а Slave виконує його інструкції.

Коли ключ (Slave) контактує з домофоном (Master), мікросхема всередині ключа вмикається, живиться від домофона, і ключ ініціалізується. Після цього домофон запитує ID ключа. Далі ми розглянемо цей процес більш детально.

Flipper може працювати як у режимі Master, так і в режимі Slave. У режимі зчитування ключа Flipper діє як зчитувач, тобто працює як Master. А в режимі емуляції ключа Flipper вдає з себе ключ, він у режимі Slave.

### Dallas, Cyfral & Metakom keys

Для отримання інформації про те, як працюють ці ключі, перегляньте сторінку [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

iButtons можуть бути атаковані за допомогою Flipper Zero:

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
