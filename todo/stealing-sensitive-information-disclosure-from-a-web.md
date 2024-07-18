# Stealing Sensitive Information Disclosure from a Web

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

As jy op 'n stadium 'n **webbladsy vind wat jou sensitiewe inligting op grond van jou sessie aanbied**: Miskien reflekteer dit koekies, of druk of CC besonderhede of enige ander sensitiewe inligting, kan jy probeer om dit te steel.\
Hier is die hoofmaniere wat jy kan probeer om dit te bereik:

* [**CORS omseiling**](../pentesting-web/cors-bypass.md): As jy CORS koptekste kan omseil, sal jy in staat wees om die inligting te steel deur 'n Ajax versoek vir 'n kwaadwillige bladsy uit te voer.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): As jy 'n XSS kwesbaarheid op die bladsy vind, mag jy dit kan misbruik om die inligting te steel.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): As jy nie XSS merke kan inspuit nie, mag jy steeds in staat wees om die inligting te steel deur ander gewone HTML merke te gebruik.
* [**Clickjaking**](../pentesting-web/clickjacking.md): As daar geen beskerming teen hierdie aanval is nie, mag jy die gebruiker kan mislei om jou die sensitiewe data te stuur (een voorbeeld [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

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
