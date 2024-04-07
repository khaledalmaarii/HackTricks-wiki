# SPI

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

SPI (Serial Peripheral Interface) is 'n Synchronous Serial Kommunikasieprotokol wat in ingebedde stelsels gebruik word vir kortafstandskommunikasie tussen IC's (Geïntegreerde stroombrekers). SPI Kommunikasieprotokol maak gebruik van die meester-slaaf argitektuur wat georkestreer word deur die Klok- en Chip Select-sein. 'n Meester-slaaf argitektuur bestaan uit 'n meester (gewoonlik 'n mikroprosessor) wat eksterne randtoestelle soos EEPROM, sensors, beheerstelsels, ens. bestuur wat as die slawe beskou word.

Meer as een slaaf kan aan 'n meester gekoppel word, maar slawe kan nie met mekaar kommunikeer nie. Slawe word geadministreer deur twee stifte, klok en chip select. Aangesien SPI 'n synchrone kommunikasieprotokol is, volg die inset- en uitsetstifte die kloksignale. Die chip select word deur die meester gebruik om 'n slaaf te kies en daarmee te kommunikeer. Wanneer die chip select hoog is, is die slaaftoestel nie gekies nie, terwyl wanneer dit laag is, die skyf gekies is en die meester met die slaaf sal interaksie hê.

Die MOSI (Meester Uit, Slaaf In) en MISO (Meester In, Slaaf Uit) is verantwoordelik vir die stuur en ontvang van data. Data word na die slaaftoestel gestuur deur die MOSI-stift terwyl die chip select laag gehou word. Die insetdata bevat instruksies, geheue-adresse of data soos per die datablad van die slaaftoestelvervaardiger. Met 'n geldige inset is die MISO-stift verantwoordelik vir die oordrag van data na die meester. Die uitsetdata word presies by die volgende klok-siklus na die einde van die inset gestuur. Die MISO-stifte stuur data oor totdat die data heeltemal oorgedra is of die meester die chip select-stift hoog stel (in daardie geval sal die slaaf ophou om oor te dra en die meester sal nie daarna luister nie).

## Dump Flash

### Bus Pirate + flashrom

![](<../../.gitbook/assets/image (907).png>)

Let daarop dat selfs al dui die PINOUT van die Pirate Bus stifte vir **MOSI** en **MISO** aan om aan SPI te koppel, sommige SPI's kan stifte aandui as DI en DO. **MOSI -> DI, MISO -> DO**

![](<../../.gitbook/assets/image (357).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flitsgeheue te dump deur iets soos die volgende uit te voer:
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

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
