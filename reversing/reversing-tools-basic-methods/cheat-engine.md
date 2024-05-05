# Bedrogsmasjien

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

[**Bedrogsmasjien**](https://www.cheatengine.org/downloads.php) is 'n nuttige program om te vind waar belangrike waardes binne die geheue van 'n hardlopende spel gestoor word en om hulle te verander.\
Wanneer jy dit aflaai en hardloop, word jy **voorgelê** met 'n **handleiding** oor hoe om die instrument te gebruik. As jy wil leer hoe om die instrument te gebruik, word dit sterk aanbeveel om dit te voltooi.

## Wat soek jy?

![](<../../.gitbook/assets/image (762).png>)

Hierdie instrument is baie nuttig om **te vind waar 'n sekere waarde** (gewoonlik 'n nommer) **gestoor word in die geheue** van 'n program.\
**Gewoonlik word getalle** in **4 byte**-vorm gestoor, maar jy kan hulle ook in **dubbel** of **float**-formate vind, of jy wil dalk vir iets **anders as 'n nommer** soek. Om daardie rede moet jy seker maak jy **kies** wat jy wil **soek vir**:

![](<../../.gitbook/assets/image (324).png>)

Jy kan ook **verskillende** tipes **soektogte** aandui:

![](<../../.gitbook/assets/image (311).png>)

Jy kan ook die blokkie aankruis om die spel te **stop terwyl jy die geheue skandeer**:

![](<../../.gitbook/assets/image (1052).png>)

### Snelsleutels

In _**Edit --> Settings --> Hotkeys**_ kan jy verskillende **snelsleutels** instel vir verskillende doeleindes soos **stopmaak** van die **spel** (wat baie nuttig is as jy op 'n stadium die geheue wil skandeer). Ander opsies is beskikbaar:

![](<../../.gitbook/assets/image (864).png>)

## Waarde wysig

Sodra jy **gevind** het waar die **waarde** wat jy **soek** (meer hieroor in die volgende stappe) is, kan jy dit **verander** deur daarop te dubbelklik, en dan die waarde daarvan dubbelklik:

![](<../../.gitbook/assets/image (563).png>)

En uiteindelik die blokkie **merk** om die wysiging in die geheue te laat plaasvind:

![](<../../.gitbook/assets/image (385).png>)

Die **verandering** aan die **geheue** sal onmiddellik **toegepas** word (let daarop dat totdat die spel hierdie waarde nie weer gebruik nie, sal die waarde **nie in die spel opgedateer word** nie).

## Soek die waarde

Dus, ons gaan aanneem dat daar 'n belangrike waarde is (soos die lewe van jou gebruiker) wat jy wil verbeter, en jy is op soek na hierdie waarde in die geheue)

### Deur 'n bekende verandering

As jy op soek is na die waarde 100, **voer 'n skandering** uit op soek na daardie waarde en jy vind baie ooreenkomste:

![](<../../.gitbook/assets/image (108).png>)

Dan doen jy iets sodat die **waarde verander**, en jy **stop** die spel en **voer** 'n **volgende skandering** uit:

![](<../../.gitbook/assets/image (684).png>)

Bedrogsmasjien sal soek na die **waardes** wat **van 100 na die nuwe waarde** gegaan het. Geluk, jy het die **adres** van die waarde wat jy gesoek het, gevind, jy kan dit nou wysig.\
_As jy nog verskeie waardes het, doen iets om daardie waarde weer te wysig, en voer nog 'n "volgende skandering" uit om die adresse te filter._

### Onbekende Waarde, bekende verandering

In die scenario weet jy nie die waarde nie, maar jy weet **hoe om dit te verander** (en selfs die waarde van die verandering) jy kan na jou nommer soek.

Begin dus deur 'n skandering van die tipe "**Onbekende aanvanklike waarde**" uit te voer:

![](<../../.gitbook/assets/image (890).png>)

Maak dan die waarde verander, dui **aan** hoe die **waarde verander** het (in my geval is dit met 1 verminder) en voer 'n **volgende skandering** uit:

![](<../../.gitbook/assets/image (371).png>)

Jy sal al die waardes te sien kry wat op die gekose manier gewysig is:

![](<../../.gitbook/assets/image (569).png>)

Sodra jy jou waarde gevind het, kan jy dit wysig.

Let daarop dat daar 'n **baie moontlike veranderinge** is en jy kan hierdie **stappe soveel as jy wil** doen om die resultate te filter:

![](<../../.gitbook/assets/image (574).png>)

### Lukrake Geheue-adres - Vind die kode

Tot dusver het ons geleer hoe om 'n adres te vind wat 'n waarde stoor, maar dit is baie waarskynlik dat in **verskillende uitvoerings van die spel daardie adres in verskillende plekke van die geheue** is. Laat ons uitsorteer hoe om altyd daardie adres te vind.

Deur van een van die genoemde truuks gebruik te maak, vind die adres waar jou huidige spel die belangrike waarde stoor. Dan (stop die spel as jy wil) doen 'n **regterklik** op die gevonde **adres** en kies "**Vind uit wat hierdie adres aanspreek**" of "**Vind uit wat na hierdie adres skryf**":

![](<../../.gitbook/assets/image (1067).png>)

Die **eerste opsie** is nuttig om te weet watter **dele** van die **kode** hierdie **adres** gebruik (wat nuttig is vir meer dinge soos **weet waar jy die kode kan wysig** van die spel).\
Die **tweede opsie** is meer **spesifiek**, en sal meer nuttig wees in hierdie geval aangesien ons belangstel om te weet **van waar hierdie waarde geskryf word**.

Sodra jy een van daardie opsies gekies het, sal die **foutvinder** aan die program geheg word en 'n nuwe **leë venster** sal verskyn. Speel nou die spel en **verander** daardie **waarde** (sonder om die spel te herlaai). Die **venster** behoort gevul te word met die **adres wat die waarde wysig**:

![](<../../.gitbook/assets/image (91).png>)

Nou dat jy die adres gevind het wat die waarde wysig, kan jy die kode **na willekeur wysig** (Bedrogsmasjien laat jou toe om dit vinnig vir NOPs te wysig):

![](<../../.gitbook/assets/image (1057).png>)

Sodoende kan jy dit nou wysig sodat die kode nie jou nommer beïnvloed nie, of altyd op 'n positiewe manier beïnvloed.
### Lukraak Geheue-Adres - Vind die wyser

Volg die vorige stappe om te vind waar die waarde wat jy belangstel is. Gebruik dan "**Vind uit wat na hierdie adres skryf**" om uit te vind watter adres hierdie waarde skryf en dubbelklik daarop om die disassemblage-aansig te kry:

![](<../../.gitbook/assets/image (1039).png>)

Voer dan 'n nuwe skandering uit **op soek na die hekswaarde tussen "\[]"** (die waarde van $edx in hierdie geval):

![](<../../.gitbook/assets/image (994).png>)

(_As verskeie verskyn, het jy gewoonlik die een met die kleinste adres nodig_)\
Nou het ons die **wysers gevind wat die waarde wat ons belangstel, sal wysig**.

Klik op "**Voeg Adres Handmatig By**":

![](<../../.gitbook/assets/image (990).png>)

Klik nou op die "Wysers" aanvinkblokkie en voeg die gevonde adres by in die teksblokkie (in hierdie scenario was die gevonde adres in die vorige beeld "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (392).png>)

(Merk op hoe die eerste "Adres" outomaties ingevul word vanaf die wyseradres wat jy invoer)

Klik OK en 'n nuwe wyser sal geskep word:

![](<../../.gitbook/assets/image (308).png>)

Nou, elke keer as jy daardie waarde wysig, is jy **die belangrike waarde aan die wysig, selfs al is die geheue-adres waar die waarde is, anders.**

### Kode-inspuiting

Kode-inspuiting is 'n tegniek waar jy 'n stuk kode in die teikenproses inspuit, en dan die uitvoering van die kode omlei om deur jou eie geskrewe kode te gaan (soos om jou punte te gee in plaas daarvan om dit af te trek).

Stel jou het byvoorbeeld die adres gevind wat 1 van die lewe van jou speler aftrek:

![](<../../.gitbook/assets/image (203).png>)

Klik op Wys disassembler om die **ontsamelingskode** te kry.\
Klik dan **CTRL+a** om die Auto assembleer-venster aan te roep en kies _**Sjabloon --> Kode-inspuiting**_

![](<../../.gitbook/assets/image (902).png>)

Vul die **adres van die instruksie wat jy wil wysig** in (dit word gewoonlik outomaties ingevul):

![](<../../.gitbook/assets/image (744).png>)

'n Sjabloon sal gegenereer word:

![](<../../.gitbook/assets/image (944).png>)

Voeg dus jou nuwe samestellingskode in die "**newmem**" afdeling in en verwyder die oorspronklike kode uit die "**originalcode**" as jy nie wil hê dat dit uitgevoer word\*\*.\*\* In hierdie voorbeeld sal die ingespuite kode 2 punte byvoeg in plaas van 1 af te trek:

![](<../../.gitbook/assets/image (521).png>)

**Klik op uitvoer ensovoorts en jou kode behoort in die program ingespuit te word wat die gedrag van die funksionaliteit verander!**

## **Verwysings**

* **Cheat Engine handleiding, voltooi dit om te leer hoe om met Cheat Engine te begin**
