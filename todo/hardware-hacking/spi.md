# SPI

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

SPI (Serial Peripheral Interface) is 'n Synchronous Serial Kommunikasieprotokol wat in ingebedde stelsels gebruik word vir kortafstandskommunikasie tussen IC's (Geïntegreerde stroombrekers). SPI Kommunikasieprotokol maak gebruik van die meester-slaaf argitektuur wat georkestreer word deur die Klok- en Chip Select-sein. 'n Meester-slaaf argitektuur bestaan uit 'n meester (gewoonlik 'n mikroprosessor) wat eksterne randtoestelle soos EEPROM, sensors, beheerstelsels, ens. bestuur, wat as die slawe beskou word.

Meervoudige slawe kan aan 'n meester gekoppel word, maar slawe kan nie met mekaar kommunikeer nie. Slawe word geadministreer deur twee pine, klok en chip select. Aangesien SPI 'n synchrone kommunikasieprotokol is, volg die inset- en uitsetpunte die kloksignale. Die chip select word deur die meester gebruik om 'n slaaf te kies en daarmee te kommunikeer. Wanneer die chip select hoog is, is die slaaftoestel nie gekies nie, terwyl wanneer dit laag is, die skyf gekies is en die meester met die slaaf sou interaksie hê.

Die MOSI (Meester Uit, Slaaf In) en MISO (Meester In, Slaaf Uit) is verantwoordelik vir die stuur en ontvang van data. Data word na die slaaftoestel gestuur deur die MOSI-pen terwyl die chip select laag gehou word. Die insetdata bevat instruksies, geheue-adresse of data soos per die datablad van die slaaftoestellewer. Met 'n geldige inset is die MISO-pen verantwoordelik vir die oordrag van data na die meester. Die uitsetdata word presies met die volgende klok-siklus na die einde van die inset gestuur. Die MISO-penne stuur data oor totdat die data heeltemal oorgedra is of die meester die chip select-pen hoog stel (in daardie geval sal die slaaf ophou om oor te dra en die meester sal nie daarna luister nie).

## Dumping Firmware van EEPROMs

Die aflaai van firmware kan nuttig wees vir die analise van die firmware en die vind van kwesbaarhede daarin. Baie kere is die firmware nie beskikbaar op die internet of is irrelevant as gevolg van faktore soos modelnommer, weergawe, ens. Daarom kan dit nuttig wees om die firmware direk van die fisiese toestel te onttrek om spesifiek te wees tydens die soeke na bedreigings.

Die verkryging van 'n Seriële Konsole kan nuttig wees, maar baie kere gebeur dit dat die lêers slegs lees is. Dit beperk die analise as gevolg van verskeie redes. Byvoorbeeld, gereedskap wat benodig word om pakkies te stuur en te ontvang, sal nie in die firmware wees nie. Dus is dit nie haalbaar om die binêre lêers te onttrek vir omgekeerde ingenieurswese nie. Daarom kan dit baie nuttig wees om die hele firmware op die stelsel te dump en die binêre lêers vir analise te onttrek.

Ook, tydens rooi lees en die verkryging van fisiese toegang tot toestelle, kan die aflaai van die firmware help om die lêers te wysig of skadelike lêers in te spuit en dit dan weer in die geheue te flits wat kan help om 'n agterdeur in die toestel te implanteer. Daarom is daar tal moontlikhede wat met firmware-aflaai ontsluit kan word.

### CH341A EEPROM-programmeerder en -leser

Hierdie toestel is 'n goedkoop instrument vir die aflaai van firmware van EEPROMs en ook vir die herflitsing daarvan met firmware-lêers. Dit is 'n gewilde keuse vir die werk met rekenaar BIOS-stroombrekers (wat net EEPROMs is). Hierdie toestel verbind oor USB en benodig minimale gereedskap om te begin. Dit kry ook gewoonlik die taak vinnig gedoen, sodat dit ook nuttig kan wees vir fisiese toegang tot toestelle.

![tekening](../../.gitbook/assets/board\_image\_ch341a.jpg)

Koppel die EEPROM-geheue aan die CH341a-programmeerder en steek die toestel in die rekenaar. Indien die toestel nie opgespoor word nie, probeer om bestuurders in die rekenaar te installeer. Maak ook seker dat die EEPROM in die regte oriëntasie gekoppel is (gewoonlik, plaas die VCC-pen in omgekeerde oriëntasie tot die USB-konnektor) anders sal die sagteware nie in staat wees om die skyf op te spoor nie. Raadpleeg die diagram indien nodig:

![tekening](../../.gitbook/assets/connect\_wires\_ch341a.jpg) ![tekening](../../.gitbook/assets/eeprom\_plugged\_ch341a.jpg)

Gebruik ten slotte sagteware soos flashrom, G-Flash (GUI), ens. vir die aflaai van die firmware. G-Flash is 'n minimale GUI-gereedskap wat vinnig is en die EEPROM outomaties opspoor. Dit kan nuttig wees as die firmware vinnig onttrek moet word, sonder om baie met die dokumentasie te speel.

![tekening](../../.gitbook/assets/connected\_status\_ch341a.jpg)

Na die aflaai van die firmware kan die analise op die binêre lêers gedoen word. Gereedskap soos strings, hexdump, xxd, binwalk, ens. kan gebruik word om baie inligting oor die firmware sowel as die hele lêersisteem ook te onttrek.

Om die inhoud uit die firmware te onttrek, kan binwalk gebruik word. Binwalk analiseer vir heks-handtekeninge en identifiseer die lêers in die binêre lêer en is in staat om hulle te onttrek.
```
binwalk -e <filename>
```
Die kan .bin of .rom wees volgens die gereedskap en konfigurasies wat gebruik word.

{% hint style="danger" %}
Let daarop dat die uithaal van firmware 'n delikate proses is en baie geduld vereis. Enige verkeerde hantering kan potensieel die firmware beskadig of selfs heeltemal uitvee en die toestel onbruikbaar maak. Dit word aanbeveel om die spesifieke toestel te bestudeer voordat 'n poging aangewend word om die firmware uit te haal.
{% endhint %}

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (910).png>)

Let daarop dat selfs al dui die PINOUT van die Pirate Bus op pine vir **MOSI** en **MISO** om aan SPI te koppel, sommige SPI's kan pine aandui as DI en DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (360).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flash-geheue te dump deur iets soos die volgende uit te voer:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
