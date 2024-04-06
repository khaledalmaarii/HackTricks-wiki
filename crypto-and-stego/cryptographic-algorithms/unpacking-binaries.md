<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>


# Identifisering van gepakte binaêre lêers

* **Gebrek aan strings**: Dit is algemeen om te vind dat gepakte binaêre lêers amper geen strings het nie.
* Baie **ongebruikte strings**: Wanneer 'n kwaadwillige program van 'n soort kommersiële pakkingsprogram gebruik maak, is dit algemeen om baie strings sonder kruisverwysings te vind. Selfs as hierdie strings bestaan, beteken dit nie noodwendig dat die binaêre lêer nie gepak is nie.
* Jy kan ook van sommige hulpmiddels gebruik maak om te probeer uitvind watter pakkingsprogram gebruik is om 'n binaêre lêer te pak:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Basiese Aanbevelings

* **Begin** deur die gepakte binaêre lêer **van onder af in IDA te analiseer en beweeg opwaarts**. Ontpakkingsprogramme eindig wanneer die ontpakte kode eindig, so dit is onwaarskynlik dat die ontpakker die uitvoering aan die ontpakte kode oordra aan die begin.
* Soek na **JMP's** of **CALLs** na **registers** of **geheuegebiede**. Soek ook na **funksies wat argumente druk en 'n adresrigting en dan `retn` oproep**, omdat die terugkeer van die funksie in daardie geval die adres kan oproep wat net voor dit op die stapel gedruk is.
* Plaas 'n **afbreking** op `VirtualAlloc`, omdat dit spasie in die geheue toewys waar die program ontpakte kode kan skryf. Voer die "run to user code" uit of gebruik F8 om **waarde binne EAX te kry** na die uitvoering van die funksie en "**volg daardie adres in die dump**". Jy weet nooit of dit die gebied is waar die ontpakte kode gestoor gaan word nie.
* **`VirtualAlloc`** met die waarde "**40**" as 'n argument beteken Lees+Skryf+Uitvoer (daar gaan 'n kode gekopieer word wat uitgevoer moet word).
* Terwyl jy kode ontpak, is dit normaal om **verskeie oproepe** na **aritmetiese bewerkings** en funksies soos **`memcopy`** of **`Virtual`**`Alloc` te vind. As jy jouself in 'n funksie bevind wat blykbaar slegs aritmetiese bewerkings uitvoer en miskien 'n `memcopy`, is die aanbeveling om te probeer **die einde van die funksie te vind** (miskien 'n JMP of oproep na 'n register) **of ten minste die oproep na die laaste funksie** en hardloop dan daarna, aangesien die kode nie interessant is nie.
* Terwyl jy kode ontpak, **merk** jy elke keer as jy 'n **geheuegebied verander**, aangesien 'n verandering in geheuegebied die **begin van die ontpakkingkode** kan aandui. Jy kan maklik 'n geheuegebied aflaai deur gebruik te maak van Process Hacker (proses --> eienskappe --> geheue).
* Terwyl jy probeer kode ontpak, is 'n goeie manier om **te weet of jy al met die ontpakte kode werk** (sodat jy dit net kan aflaai) om **die strings van die binaêre lêer te ondersoek**. As jy op 'n punt 'n sprong uitvoer (dalk deur die geheuegebied te verander) en jy besef dat **baie meer strings bygevoeg is**, kan jy weet **jy werk met die ontpakte kode**.\
As die pakkingsprogram egter al baie strings bevat, kan jy sien hoeveel strings die woord "http" bevat en sien of hierdie getal toeneem.
* Wanneer jy 'n uitvoerbare lêer aflaai van 'n geheuegebied, kan jy sommige koppele aanpas deur [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) te gebruik.


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
