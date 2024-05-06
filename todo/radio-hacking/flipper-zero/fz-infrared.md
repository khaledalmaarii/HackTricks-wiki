# FZ - Infrarooi

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Inleiding <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Vir meer inligting oor hoe Infrarooi werk, kyk:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR-Signaalontvanger in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper gebruik 'n digitale IR-signaalontvanger TSOP, wat **seinne van IR-afstandbeheerders onderskep**. Daar is **slimfone** soos Xiaomi, wat ook 'n IR-poort het, maar onthou dat **die meeste van hulle slegs kan uitsaai** seine en **nie kan ontvang** nie.

Die Flipper infrarooi-ontvanger is redelik sensitief. Jy kan selfs **die sein opvang** terwyl jy **iewers tussen** die afstandbeheerder en die TV bly. Dit is onnodig om die afstandbeheerder direk op Flipper se IR-poort te rig. Dit kom van pas wanneer iemand kanale skakel terwyl hulle naby die TV staan, en jy en Flipper is albei 'n afstand weg.

Aangesien die **ontsleuteling van die infrarooi-sein** aan die **sagtewarekant plaasvind**, ondersteun Flipper Zero moontlik die **ontvangs en uitsaai van enige IR-afstandbeheerkodes**. In die geval van **onbekende** protokolle wat nie herken kon word nie - dit **neem op en speel terug** die rou sein presies soos ontvang.

## Aksies

### Universele Afstandbeheerders

Flipper Zero kan gebruik word as 'n **universele afstandbeheerder om enige TV, lugversorger, of media-sentrum te beheer**. In hierdie modus **brute force** Flipper al die **bekende kodes** van alle ondersteunde vervaardigers **volgens die woordeboek van die SD-kaart**. Jy hoef nie 'n spesifieke afstandbeheerder te kies om 'n restaurant-TV af te skakel nie.

Dit is genoeg om die kragknoppie in die Universele Afstandbeheerder-modus te druk, en Flipper sal **opeenvolgend "Krag Af"** bevele van al die TV's wat dit ken, stuur: Sony, Samsung, Panasonic... ensovoorts. Wanneer die TV sy sein ontvang, sal dit reageer en afskakel.

So 'n brute force neem tyd. Hoe groter die woordeboek, hoe langer dit sal neem om klaar te maak. Dit is onmoontlik om uit te vind watter sein presies die TV herken het aangesien daar geen terugvoer van die TV is nie.

### Leer Nuwe Afstandbeheerder

Dit is moontlik om 'n infrarooi-sein te **vang** met Flipper Zero. As dit **die sein in die databasis vind**, sal Flipper outomaties **weet watter toestel dit is** en sal dit jou toelaat om daarmee te interaksieer.\
As dit nie doen nie, kan Flipper die **sein stoor** en sal dit jou toelaat om dit **af te speel**.

## Verwysings

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
