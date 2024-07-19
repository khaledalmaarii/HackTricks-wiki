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

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html) : Il surveillera chaque connexion effectuée par chaque processus. Selon le mode (autoriser silencieusement les connexions, refuser silencieusement la connexion et alerter), il **vous montrera une alerte** chaque fois qu'une nouvelle connexion est établie. Il dispose également d'une très belle interface graphique pour voir toutes ces informations.
* [**LuLu**](https://objective-see.org/products/lulu.html) : Pare-feu d'Objective-See. C'est un pare-feu de base qui vous alertera pour des connexions suspectes (il a une interface graphique mais elle n'est pas aussi sophistiquée que celle de Little Snitch).

## Persistence detection

* [**KnockKnock**](https://objective-see.org/products/knockknock.html) : Application d'Objective-See qui recherchera à plusieurs endroits où **le malware pourrait persister** (c'est un outil à usage unique, pas un service de surveillance).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html) : Comme KnockKnock, en surveillant les processus qui génèrent de la persistance.

## Keyloggers detection

* [**ReiKey**](https://objective-see.org/products/reikey.html) : Application d'Objective-See pour trouver des **keyloggers** qui installent des "taps" d'événements clavier.
