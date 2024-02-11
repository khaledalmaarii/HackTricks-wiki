<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n lopende spel gestoor word en om dit te verander.\
Wanneer jy dit aflaai en uitvoer, word jy **voorgestel** aan 'n **opleiding** oor hoe om die instrument te gebruik. As jy wil leer hoe om die instrument te gebruik, word dit sterk aanbeveel om dit te voltooi.

# Wat soek jy?

![](<../../.gitbook/assets/image (580).png>)

Hierdie instrument is baie nuttig om te vind **waar 'n sekere waarde** (gewoonlik 'n getal) **in die geheue van 'n program gestoor word**.\
**Gewoonlik word getalle** in **4byte**-vorm gestoor, maar jy kan hulle ook in **double** of **float**-formate vind, of jy wil dalk iets **anders as 'n getal** soek. Daarom moet jy seker maak dat jy kies wat jy wil **soek vir**:

![](<../../.gitbook/assets/image (581).png>)

Jy kan ook **verskillende tipes soektogte** aandui:

![](<../../.gitbook/assets/image (582).png>)

Jy kan ook die blokkie merk om die spel te **stop terwyl jy die geheue deursoek**:

![](<../../.gitbook/assets/image (584).png>)

## Hotkeys

In _**Edit --> Settings --> Hotkeys**_ kan jy verskillende **hotkeys** instel vir verskillende doeleindes, soos die **stop van die spel** (wat baie nuttig is as jy op 'n punt die geheue wil deursoek). Ander opsies is beskikbaar:

![](<../../.gitbook/assets/image (583).png>)

# Die waarde wysig

Sodra jy **gevind** het waar die **waarde** wat jy **soek** (meer hieroor in die volgende stappe) gestoor word, kan jy dit wysig deur dit dubbel te kliek, en dan dubbel te kliek op die waarde daarvan:

![](<../../.gitbook/assets/image (585).png>)

En uiteindelik die blokkie merk om die wysiging in die geheue te laat plaasvind:

![](<../../.gitbook/assets/image (586).png>)

Die **verandering** aan die **geheue** sal onmiddellik **toegepas** word (let daarop dat die waarde **nie in die spel opgedateer sal word nie** totdat die spel hierdie waarde weer gebruik).

# Die waarde soek

So, ons gaan aanneem dat daar 'n belangrike waarde is (soos die lewe van jou gebruiker) wat jy wil verbeter, en jy is op soek na hierdie waarde in die geheue)

## Deur 'n bekende verandering

As jy op soek is na die waarde 100, doen jy 'n soektog deur te soek na daardie waarde en jy vind baie ooreenkomste:

![](<../../.gitbook/assets/image (587).png>)

Dan doen jy iets sodat die **waarde verander**, en jy **stop** die spel en doen 'n **volgende soektog**:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine sal soek na die **waardes** wat **van 100 na die nuwe waarde** gegaan het. Geluk, jy het die **adres** van die waarde wat jy gesoek het, gevind, en jy kan dit nou wysig.\
_As jy nog verskeie waardes het, doen iets om daardie waarde weer te wysig, en doen nog 'n "volgende soektog" om die adresse te filter._

## Onbekende waarde, bekende verandering

In die scenario waar jy **nie die waarde weet nie**, maar jy weet **hoe om dit te verander** (en selfs die waarde van die verandering), kan jy na jou getal soek.

Begin dus deur 'n soektog van die tipe "**Onbekende aanvanklike waarde**" uit te voer:

![](<../../.gitbook/assets/image (589).png>)

Maak dan die waarde verander, dui aan **hoe** die **waarde verander** het (in my geval is dit met 1 verminder) en doen 'n **volgende soektog**:

![](<../../.gitbook/assets/image (590).png>)

Jy sal **alle waardes wat op die gekose manier gewysig is**, te sien kry:

![](<../../.gitbook/assets/image (591).png>)

Sodra jy jou waarde gevind het, kan jy dit wysig.

Let daarop dat daar 'n **baie moontlike veranderinge** is en jy hierdie stappe soveel as jy wil kan doen om die resultate te filter:

![](<../../.gitbook/assets/image (592).png>)

## Willekeurige geheue-adres - Die kode vind

Tot dusver het ons geleer hoe om 'n adres te vind wat 'n waarde stoor, maar dit is baie waarskynlik dat in **verskillende uitvoerings van die spel daardie adres op verskillende plekke in die geheue** is. Kom ons vind uit hoe om altyd daardie adres te vind.

Gebruik van een van die genoemde truuks, vind die adres waar jou huidige spel die belangrike waarde stoor. Doen dan (as jy wil, stop die spel) 'n **regs-klik** op die gevonde **adres** en kies "**Find out what accesses this address**" of "**Find out what writes to this address**":

![](<../../.gitbook/assets/image (593).png>)

Die **eerste opsie** is nuttig om te weet watter **dele** van die **kode** hierdie **adres gebruik** (wat nuttig is vir ander dinge soos **weet waar jy die kode van die spel kan wysig**).\
Die **tweede opsie** is meer **spesifiek**, en sal meer nuttig wees in hierdie geval aangesien ons belangstel om te weet **van waar hierdie waarde geskryf word**.

Sodra jy een van daardie opsies gekies het, sal die **debugger** aan die program **geheg** word en 'n nuwe **leë venster** sal verskyn. Speel nou die spel en wysig daardie waarde (sonder om die spel te herlaai). Die **venster** behoort gevul te word met die **adresses** wat die **waarde wysig**:

![](<../../.gitbook/assets/image (594).png>)

Nou dat jy die adres gevind het wat die waarde wysig, kan jy die kode **na willekeur wysig** (Cheat Engine stel jou in staat om dit vinnig vir NOPs te wysig):

![](<../../.gitbook/assets/image (595).png>)

Jy kan dit nou wysig sodat die kode nie jou getal beïnvloed nie, of altyd op 'n positiewe manier beïnvloed.
## Willekeurige Geheugenadres - Vind die wysiger

Volg die vorige stappe om te vind waar die waarde waarin jy belangstel, is. Gebruik dan "**Vind uit wat na hierdie adres skryf**" om uit te vind watter adres hierdie waarde skryf en dubbelklik daarop om die disassemblage-aansig te kry:

![](<../../.gitbook/assets/image (596).png>)

Voer dan 'n nuwe soektog uit **deur te soek na die hekswaarde tussen "\[]"** (die waarde van $edx in hierdie geval):

![](<../../.gitbook/assets/image (597).png>)

(_As daar verskeie verskyn, het jy gewoonlik die kleinste adres een nodig_)\
Nou het ons die **wysiger gevind wat die waarde wat ons belangstel, sal wysig**.

Klik op "**Voeg adres handmatig by**":

![](<../../.gitbook/assets/image (598).png>)

Klik nou op die "Wysiger" keuseblokkie en voeg die gevonde adres by in die teksblokkie (in hierdie scenario was die gevonde adres in die vorige prentjie "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Merk op hoe die eerste "Adres" outomaties gevul word vanuit die wysigeradres wat jy intik)

Klik OK en 'n nuwe wysiger sal geskep word:

![](<../../.gitbook/assets/image (600).png>)

Nou, elke keer as jy daardie waarde wysig, wysig jy die belangrike waarde, selfs al is die geheueadres waar die waarde is, verskillend.

## Kode-inspuiting

Kode-inspuiting is 'n tegniek waar jy 'n stukkie kode in die teikenproses inspuit en dan die uitvoering van die kode omlei om deur jou eie geskrewe kode te gaan (soos om jou punte te gee in plaas daarvan om dit af te trek).

Stel jou voor jy het die adres gevind wat 1 van die lewe van jou speler aftrek:

![](<../../.gitbook/assets/image (601).png>)

Klik op "Wys disassembler" om die **ontsamelingskode** te kry.\
Klik dan **CTRL+a** om die Auto assemble-venster te roep en kies _**Template --> Kode-inspuiting**_

![](<../../.gitbook/assets/image (602).png>)

Vul die **adres van die instruksie wat jy wil wysig** in (dit word gewoonlik outomaties ingevul):

![](<../../.gitbook/assets/image (603).png>)

'n Templaat sal gegenereer word:

![](<../../.gitbook/assets/image (604).png>)

Voeg jou nuwe saamgestelde kode in die "**newmem**" afdeling in en verwyder die oorspronklike kode uit die "**originalcode**" as jy nie wil hê dat dit uitgevoer moet word nie. In hierdie voorbeeld sal die ingespuite kode 2 punte byvoeg in plaas van 1 af te trek:

![](<../../.gitbook/assets/image (605).png>)

**Klik op uitvoer en so aan en jou kode behoort in die program ingespuit te word en die gedrag van die funksionaliteit te verander!**

# **Verwysings**

* **Cheat Engine-tutoriaal, voltooi dit om te leer hoe om met Cheat Engine te begin**



<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
