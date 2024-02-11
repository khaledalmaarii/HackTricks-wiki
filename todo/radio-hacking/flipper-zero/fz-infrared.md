# FZ - Infrarooi

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Inleiding <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Vir meer inligting oor hoe infrarooi werk, kyk:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Infrarooi Seinontvanger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper gebruik 'n digitale infrarooi seinontvanger TSOP, wat **sein vanaf infrarooi afstandbeheerders onderskep**. Daar is sommige **slimfone** soos Xiaomi, wat ook 'n infrarooi-poort het, maar onthou dat **die meeste van hulle slegs seine kan stuur** en **nie kan ontvang** nie.

Die Flipper infrarooi **ontvanger is baie sensitief**. Jy kan selfs die sein **vang terwyl jy êrens tussen** die afstandbeheerder en die TV is. Dit is nie nodig om die afstandbeheerder direk op Flipper se infrarooi-poort te rig nie. Dit is handig wanneer iemand kanale skakel terwyl hy naby die TV staan, en jy en Flipper is albei 'n afstand weg.

Aangesien die **dekodering van die infrarooi** sein aan die **sagtewarekant plaasvind**, ondersteun Flipper Zero moontlik die **ontvangs en uitsending van enige infrarooi afstandbeheerder-kodes**. In die geval van **onbekende** protokolle wat nie herken kon word nie - dit **neem op en speel terug** die rou sein presies soos ontvang.

## Aksies

### Universele Afstandbeheerders

Flipper Zero kan gebruik word as 'n **universele afstandbeheerder om enige TV, lugversorger of media-sentrum** te beheer. In hierdie modus **bruteforce** Flipper al die **bekende kodes** van alle ondersteunde vervaardigers **volgens die woordeboek van die SD-kaart**. Jy hoef nie 'n spesifieke afstandbeheerder te kies om 'n restaurant-TV af te skakel nie.

Dit is genoeg om die kragknoppie in die Universele Afstandbeheerder-modus te druk, en Flipper sal **opeenvolgend "Krag Af"**-opdragte van al die TV's wat dit ken, stuur: Sony, Samsung, Panasonic... en so aan. Wanneer die TV sy sein ontvang, sal dit reageer en afskakel.

So 'n bruteforce neem tyd. Hoe groter die woordeboek, hoe langer sal dit neem om klaar te maak. Dit is onmoontlik om uit te vind watter sein presies die TV herken het, aangesien daar geen terugvoer van die TV is nie.

### Leer Nuwe Afstandbeheerder

Dit is moontlik om 'n infrarooi sein met Flipper Zero **vas te vang**. As dit die sein in die databasis **vind**, sal Flipper outomaties **weet watter toestel dit is** en sal dit jou in staat stel om daarmee te interaksieer.\
As dit nie die sein vind nie, kan Flipper die sein **stoor** en jou toelaat om dit **terug te speel**.

## Verwysings

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
