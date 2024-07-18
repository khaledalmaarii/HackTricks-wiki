# Steel van Gevoelige Inligting Openbaarmaking van 'n Web

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

Indien jy op 'n **webbladsy kom wat jou gevoelige inligting toon gebaseer op jou sessie**: Dalk reflekteer dit koekies, of druk kredietkaartbesonderhede of enige ander gevoelige inligting, kan jy probeer om dit te steel.\
Hier bied ek jou die hoofmaniere aan om dit te probeer bereik:

* [**CORS omseiling**](pentesting-web/cors-bypass.md): As jy CORS-koppe kan omseil, sal jy in staat wees om die inligting te steel deur 'n Ajax-aanvraag vir 'n skadelike bladsy uit te voer.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): As jy 'n XSS-gebrek op die bladsy vind, kan jy dit moontlik misbruik om die inligting te steel.
* [**Dangling Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): As jy nie XSS-etikette kan inspuit nie, kan jy steeds die inligting steel deur ander gewone HTML-etikette te gebruik.
* [**Clickjaking**](pentesting-web/clickjacking.md): As daar geen beskerming teen hierdie aanval is nie, kan jy die gebruiker moontlik mislei om jou die gevoelige data te stuur ( 'n voorbeeld [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
