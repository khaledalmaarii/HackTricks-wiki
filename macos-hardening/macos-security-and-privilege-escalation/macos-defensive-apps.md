# macOS Defensive Apps

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Firewalls

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Він буде моніторити кожне з'єднання, яке здійснює кожен процес. Залежно від режиму (тихе дозволення з'єднань, тихе відмовлення з'єднання та сповіщення) він **показуватиме вам сповіщення** щоразу, коли встановлюється нове з'єднання. Він також має дуже зручний графічний інтерфейс для перегляду всієї цієї інформації.
* [**LuLu**](https://objective-see.org/products/lulu.html): Брандмауер Objective-See. Це базовий брандмауер, який сповіщатиме вас про підозрілі з'єднання (він має графічний інтерфейс, але не такий вишуканий, як у Little Snitch).

## Persistence detection

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Додаток Objective-See, який шукатиме в кількох місцях, де **шкідливе ПЗ може зберігатися** (це одноразовий інструмент, а не сервіс моніторингу).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Як KnockKnock, моніторячи процеси, які генерують збереження.

## Keyloggers detection

* [**ReiKey**](https://objective-see.org/products/reikey.html): Додаток Objective-See для виявлення **кейлогерів**, які встановлюють "event taps" клавіатури.
