<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


# Identifiseer gepakte binêre lêers

* **Gebrek aan strings**: Dit is algemeen om te vind dat gepakte binêre lêers amper geen string het nie.
* Baie **ongebruikte strings**: Ook, wanneer 'n kwaadwillige program 'n soort kommersiële pakker gebruik, is dit algemeen om baie strings sonder kruisverwysings te vind. Selfs as hierdie strings bestaan, beteken dit nie dat die binêre lêer nie gepak is nie.
* Jy kan ook van hulpmiddels gebruik maak om te probeer vind watter pakker gebruik is om 'n binêre lêer te pak:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Basiese Aanbevelings

* **Begin** deur die gepakte binêre lêer **van onder af in IDA te analiseer en beweeg opwaarts**. Ontpakkers verlaat sodra die ontspande kode verlaat word, dus is dit onwaarskynlik dat die ontspakker uitvoering aan die ontspande kode gee aan die begin.
* Soek na **JMP's** of **CALLs** na **registers** of **geheue-areas**. Soek ook na **funksies wat argumente druk en 'n adresrigting en dan `retn` aanroep**, omdat die terugkeer van die funksie in daardie geval die adres kan aanroep wat net na dit op die stok gedruk is.
* Plaas 'n **afkap-punt** op `VirtualAlloc` aangesien dit spasie in geheue toewys waar die program ontspanne kode kan skryf. Hardloop na gebruikerskode of gebruik F8 om **die waarde binne EAX te kry** na die uitvoering van die funksie en "**volg daardie adres in die dump**". Jy weet nooit of dit die area is waar die ontspanne kode gestoor gaan word.
* **`VirtualAlloc`** met die waarde "**40**" as 'n argument beteken Lees+Skryf+Uitvoer (sekere kode wat uitvoering benodig, gaan hier gekopieer word).
* Terwyl jy kode ontspan, is dit normaal om **verskeie oproepe** na **rekenkundige bewerkings** en funksies soos **`memcopy`** of **`Virtual`**`Alloc` te vind. As jy jouself in 'n funksie bevind wat blykbaar net rekenkundige bewerkings uitvoer en miskien 'n paar `memcopy` , is die aanbeveling om te probeer die einde van die funksie te vind (miskien 'n JMP of oproep na 'n register) **of** ten minste die **oproep na die laaste funksie** en hardloop dan daarna aangesien die kode nie interessant is nie.
* Terwyl jy kode ontspan, **merk** jy elke keer wanneer jy **geheue-areas verander** aangesien 'n verandering in geheue-area die **begin van die ontspanne kode** kan aandui. Jy kan maklik 'n geheue-area dump deur Process Hacker (proses --> eienskappe --> geheue) te gebruik.
* Terwyl jy probeer kode ontspan, is 'n goeie manier om **te weet of jy reeds met die ontspanne kode werk** (sodat jy dit net kan dump) om **die strings van die binêre lêer te ondersoek**. As jy op 'n punt 'n sprong maak (miskien deur die geheue-area te verander) en jy besef dat **baie meer strings bygevoeg is**, kan jy weet **jy werk met die ontspanne kode**.\
Maar as die pakker reeds baie strings bevat, kan jy sien hoeveel strings die woord "http" bevat en sien of hierdie getal toeneem.
* Wanneer jy 'n uitvoerbare lêer van 'n geheue-area dump, kan jy sommige koppe regmaak deur [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) te gebruik.


<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
