# macOS Defensive Apps

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

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

* [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Pratiće svaku vezu koju uspostavi svaki proces. U zavisnosti od režima (tiho dozvoliti veze, tiho odbiti vezu i upozoriti) **pokazaće vam upozorenje** svaki put kada se uspostavi nova veza. Takođe ima veoma lepu GUI za pregled svih ovih informacija.
* [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See vatrozid. Ovo je osnovni vatrozid koji će vas upozoriti na sumnjive veze (ima GUI, ali nije tako sofisticiran kao onaj kod Little Snitch).

## Detekcija postojanosti

* [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See aplikacija koja će pretraživati na nekoliko lokacija gde **malver može biti postojan** (to je alat za jednokratnu upotrebu, nije servis za praćenje).
* [**BlockBlock**](https://objective-see.org/products/blockblock.html): Kao KnockKnock, prati procese koji generišu postojanost.

## Detekcija keylogger-a

* [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See aplikacija za pronalaženje **keylogger-a** koji instaliraju "event taps" za tastaturu.
