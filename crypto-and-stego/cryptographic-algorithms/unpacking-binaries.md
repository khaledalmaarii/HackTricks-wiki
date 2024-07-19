{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}


# Identifisering van gepakte binêre

* **gebrek aan strings**: Dit is algemeen om te vind dat gepakte binêre amper geen string het nie
* 'n Baie **onbenutte strings**: Ook, wanneer 'n malware 'n soort kommersiële pakker gebruik, is dit algemeen om baie strings sonder kruisverwysings te vind. Selfs al bestaan hierdie strings beteken dit nie dat die binêre nie gepak is nie.
* Jy kan ook 'n paar gereedskap gebruik om te probeer uitvind watter pakker gebruik is om 'n binêre te pak:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Basiese Aanbevelings

* **Begin** om die gepakte binêre **van onder in IDA te analiseer en beweeg op**. Unpackers verlaat wanneer die uitgepakte kode verlaat, so dit is onwaarskynlik dat die unpacker uitvoering aan die uitgepakte kode aan die begin oorgee.
* Soek na **JMP's** of **CALLs** na **registers** of **gebiede** van **geheue**. Soek ook na **funksies wat argumente en 'n adresrigting druk en dan `retn` aanroep**, want die terugkeer van die funksie in daardie geval kan die adres wat net na die stapel gedruk is, aanroep voordat dit dit aanroep.
* Plaas 'n **breekpunt** op `VirtualAlloc` aangesien dit ruimte in geheue toewys waar die program uitgepakte kode kan skryf. Die "loop na gebruikerskode" of gebruik F8 om **na waarde binne EAX te kom** nadat die funksie uitgevoer is en "**volg daardie adres in dump**". Jy weet nooit of dit die gebied is waar die uitgepakte kode gestoor gaan word.
* **`VirtualAlloc`** met die waarde "**40**" as 'n argument beteken Lees+Skryf+Voer uit (sommige kode wat uitvoering benodig gaan hier gekopieer word).
* **Terwyl jy kode unpack**, is dit normaal om **verskeie oproepe** na **aritmetiese operasies** en funksies soos **`memcopy`** of **`Virtual`**`Alloc` te vind. As jy in 'n funksie is wat blykbaar net aritmetiese operasies uitvoer en dalk 'n `memcopy`, is die aanbeveling om te probeer **die einde van die funksie te vind** (miskien 'n JMP of oproep na 'n register) **of** ten minste die **oproep na die laaste funksie** en loop dan na dit, aangesien die kode nie interessant is nie.
* Terwyl jy kode unpack, **let op** wanneer jy **geheuegebied verander** aangesien 'n verandering in geheuegebied die **begin van die unpacking kode** kan aandui. Jy kan maklik 'n geheuegebied dump met Process Hacker (proses --> eienskappe --> geheue).
* Terwyl jy probeer om kode te unpack, is 'n goeie manier om **te weet of jy reeds met die uitgepakte kode werk** (sodat jy dit net kan dump) om die **strings van die binêre te kontroleer**. As jy op 'n sekere punt 'n sprong maak (miskien die geheuegebied verander) en jy opmerk dat **baie meer strings bygevoeg is**, dan kan jy weet **jy werk met die uitgepakte kode**.\
As die pakker egter reeds baie strings bevat, kan jy kyk hoeveel strings die woord "http" bevat en sien of hierdie getal toeneem.
* Wanneer jy 'n uitvoerbare lêer van 'n geheuegebied dump, kan jy sommige koptekste regstel met [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
