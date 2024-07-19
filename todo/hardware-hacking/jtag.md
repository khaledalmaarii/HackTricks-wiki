# JTAG

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)is 'n hulpmiddel wat gebruik kan word met 'n Raspberry PI of 'n Arduino om te probeer om JTAG-pinne van 'n onbekende chip te vind.\
In die **Arduino**, koppel die **pinnes van 2 tot 11 aan 10pinnes wat moontlik aan 'n JTAG behoort**. Laai die program in die Arduino en dit sal probeer om al die pinnes te bruteforce om te vind of enige pinnes aan JTAG behoort en watter een elkeen is.\
In die **Raspberry PI** kan jy slegs **pinnes van 1 tot 6** gebruik (6pinnes, so jy sal stadiger gaan om elke potensiële JTAG-pin te toets).

### Arduino

In Arduino, nadat jy die kabels gekoppel het (pin 2 tot 11 aan JTAG-pinne en Arduino GND aan die basisbord GND), **laai die JTAGenum program in Arduino** en in die Serial Monitor stuur 'n **`h`** (opdrag vir hulp) en jy behoort die hulp te sien:

![](<../../.gitbook/assets/image (939).png>)

![](<../../.gitbook/assets/image (578).png>)

Konfigureer **"Geen lyn einde" en 115200baud**.\
Stuur die opdrag s om te begin skandeer:

![](<../../.gitbook/assets/image (774).png>)

As jy 'n JTAG kontak, sal jy een of verskeie **lyne vind wat begin met FOUND!** wat die pinnes van JTAG aandui.

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
