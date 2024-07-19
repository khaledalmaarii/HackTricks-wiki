# SPI

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

## Basiese Inligting

SPI (Serial Peripheral Interface) is 'n Sinchroniese Seriële Kommunikasieprotokol wat in ingebedde stelsels gebruik word vir kortafstandkommunikasie tussen IC's (Geïntegreerde Stroombane). SPI Kommunikasieprotokol maak gebruik van die meester-slaaf argitektuur wat georkestreer word deur die Klok en Chip Kies Sein. 'n Meester-slaaf argitektuur bestaan uit 'n meester (gewoonlik 'n mikroverwerker) wat eksterne periferies soos EEPROM, sensors, beheertoestelle, ens. bestuur wat as die slawes beskou word.

Meerdere slawes kan aan 'n meester gekoppel word, maar slawes kan nie met mekaar kommunikeer nie. Slawes word bestuur deur twee penne, klok en chip kies. Aangesien SPI 'n sinchroniese kommunikasieprotokol is, volg die invoer- en uitvoerpenne die klokseine. Die chip kies word deur die meester gebruik om 'n slaaf te kies en met hom te kommunikeer. Wanneer die chip kies hoog is, is die slaaf toestel nie gekies nie, terwyl wanneer dit laag is, die chip gekies is en die meester met die slaaf sal kommunikeer.

Die MOSI (Master Out, Slave In) en MISO (Master In, Slave Out) is verantwoordelik vir die stuur en ontvang van data. Data word na die slaaf toestel gestuur deur die MOSI pen terwyl die chip kies laag gehou word. Die invoerdata bevat instruksies, geheue adresse of data volgens die datasheet van die slaaf toestel verskaffer. Na 'n geldige invoer is die MISO pen verantwoordelik vir die oordrag van data na die meester. Die uitvoerdata word presies by die volgende klok siklus gestuur nadat die invoer eindig. Die MISO penne stuur data tot die data volledig oorgedra is of die meester die chip kies pen hoog stel (in daardie geval sal die slaaf stop om te stuur en die meester sal nie daarna luister nie).

## Dumping Firmware van EEPROMs

Dumping firmware kan nuttig wees om die firmware te analiseer en kwesbaarhede daarin te vind. Dikwels is die firmware nie op die internet beskikbaar nie of is dit irrelevant weens variasies van faktore soos modelnommer, weergawe, ens. Daarom kan dit nuttig wees om die firmware direk van die fisiese toestel te onttrek om spesifiek te wees terwyl jy op soek is na bedreigings.

Om Serial Console te verkry kan nuttig wees, maar dikwels gebeur dit dat die lêers slegs leesbaar is. Dit beperk die analise weens verskeie redes. Byvoorbeeld, 'n hulpmiddel wat benodig word om pakkette te stuur en te ontvang, sal nie in die firmware wees nie. Dus is dit nie haalbaar om die binêre lêers te onttrek om hulle om te keer nie. Daarom kan dit baie nuttig wees om die hele firmware op die stelsel te dump en die binêre lêers vir analise te onttrek.

Ook, tydens rooi spanwerk en om fisiese toegang tot toestelle te verkry, kan die dumping van die firmware help om die lêers te wysig of kwaadwillige lêers in te spuit en dan weer in die geheue te flits wat nuttig kan wees om 'n agterdeur in die toestel te implanteer. Daarom is daar talle moontlikhede wat ontsluit kan word met firmware dumping.

### CH341A EEPROM Programmer en Leser

Hierdie toestel is 'n goedkoop hulpmiddel om firmwares van EEPROMs te dump en ook om hulle weer te flits met firmware lêers. Dit was 'n gewilde keuse om met rekenaar BIOS skywe (wat net EEPROMs is) te werk. Hierdie toestel sluit oor USB aan en benodig minimale hulpmiddels om te begin. Ook, dit voltooi gewoonlik die taak vinnig, so dit kan nuttig wees in fisiese toestel toegang ook.

![drawing](../../.gitbook/assets/board\_image\_ch341a.jpg)

Koppel die EEPROM geheue met die CH341a Programmer en steek die toestel in die rekenaar. Indien die toestel nie gedetecteer word nie, probeer om bestuurders in die rekenaar te installeer. Maak ook seker dat die EEPROM in die regte oriëntasie gekoppel is (gewoonlik, plaas die VCC Pen in omgekeerde oriëntasie teen die USB-konnektor) anders sal die sagteware nie in staat wees om die chip te detecteer nie. Verwys na die diagram indien nodig:

![drawing](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![drawing](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Laastens, gebruik sagteware soos flashrom, G-Flash (GUI), ens. om die firmware te dump. G-Flash is 'n minimale GUI hulpmiddel wat vinnig is en die EEPROM outomaties detecteer. Dit kan nuttig wees as die firmware vinnig onttrek moet word, sonder om veel met die dokumentasie te knoei.

![drawing](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Na die dumping van die firmware, kan die analise op die binêre lêers gedoen word. Hulpmiddels soos strings, hexdump, xxd, binwalk, ens. kan gebruik word om baie inligting oor die firmware sowel as die hele lêerstelsel te onttrek.

Om die inhoud van die firmware te onttrek, kan binwalk gebruik word. Binwalk analiseer vir hex handtekeninge en identifiseer die lêers in die binêre lêer en is in staat om hulle te onttrek.
```
binwalk -e <filename>
```
Die kan .bin of .rom wees volgens die gereedskap en konfigurasies wat gebruik word.

{% hint style="danger" %}
Let daarop dat firmware-ekstraksie 'n delikate proses is en baie geduld vereis. Enige verkeerde hantering kan moontlik die firmware korrupteer of selfs heeltemal uitvee en die toestel onbruikbaar maak. Dit word aanbeveel om die spesifieke toestel te bestudeer voordat jy probeer om die firmware te ekstrak.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Let daarop dat selfs al dui die PINOUT van die Pirate Bus pinde aan vir **MOSI** en **MISO** om aan SPI te koppel, kan sommige SPIs pinde as DI en DO aandui. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flitsgeheue te dump deur iets soos te loop:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
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
