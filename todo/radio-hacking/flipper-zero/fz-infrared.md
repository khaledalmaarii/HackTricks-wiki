# FZ - Infrarooi

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Inleiding <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Vir meer inligting oor hoe Infrarooi werk, kyk:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR Seinontvanger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper gebruik 'n digitale IR seinontvanger TSOP, wat **toelaat om seine van IR afstandbeheerders te onderskep**. Daar is 'n paar **smartphones** soos Xiaomi, wat ook 'n IR-poort het, maar hou in gedagte dat **meeste van hulle net kan oordra** seine en **nie kan ontvang** nie.

Die Flipper infrarooi **ontvanger is redelik sensitief**. Jy kan selfs die **sein vang** terwyl jy **ergens tussen** die afstandbeheerder en die TV bly. Dit is nie nodig om die afstandbeheerder direk na Flipper se IR-poort te wys nie. Dit is handig wanneer iemand kanale verander terwyl hy naby die TV staan, en jy en Flipper is 'n entjie weg.

Aangesien die **ontleding van die infrarooi** sein aan die **programmatuur** kant gebeur, ondersteun Flipper Zero potensieel die **ontvangs en oordrag van enige IR afstandbeheerkodes**. In die geval van **onbekende** protokolle wat nie herken kon word nie - dit **registreer en speel die** ruwe sein presies soos ontvang.

## Aksies

### Universele Afstandbeheerders

Flipper Zero kan gebruik word as 'n **universele afstandbeheerder om enige TV, lugversorger of mediacentrum te beheer**. In hierdie modus, Flipper **bruteforces** al die **bekende kodes** van al die ondersteunde vervaardigers **volgens die woordeboek van die SD-kaart**. Jy hoef nie 'n spesifieke afstandbeheerder te kies om 'n restaurant TV af te skakel nie.

Dit is genoeg om die aan/af-knoppie in die Universele Afstandbeheerder-modus te druk, en Flipper sal **gevolglik "Power Off"** opdragte van al die TV's wat hy ken stuur: Sony, Samsung, Panasonic... ensovoorts. Wanneer die TV sy sein ontvang, sal dit reageer en afskakel.

So 'n brute-force neem tyd. Hoe groter die woordeboek, hoe langer sal dit neem om te voltooi. Dit is onmoontlik om uit te vind watter sein presies die TV herken het, aangesien daar geen terugvoer van die TV is nie.

### Leer Nuwe Afstandbeheerder

Dit is moontlik om 'n **infrarooi sein** met Flipper Zero te **vang**. As dit **die sein in die databasis vind**, sal Flipper outomaties **weet watter toestel dit is** en jou toelaat om daarmee te interaksie.\
As dit nie, kan Flipper die **sein** **stoor** en sal dit jou toelaat om dit te **herhaal**.

## Verwysings

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
