<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>


# Uitsnygereedskap

## Autopsy

Die mees algemene gereedskap wat in forensika gebruik word om lêers uit beelde te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer inneem om "verborge" lêers te vind. Let daarop dat Autopsy gebou is om skyfbeelds en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

## Binwalk <a id="binwalk"></a>

**Binwalk** is 'n gereedskap om binêre lêers soos beelde en klanklêers te soek vir ingebedde lêers en data.
Dit kan geïnstalleer word met `apt`, maar die [bron](https://github.com/ReFirmLabs/binwalk) kan op GitHub gevind word.
**Nuttige opdragte**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

'n Ander algemene instrument om verskuilde lêers te vind is **foremost**. Jy kan die opsetlêer van foremost in `/etc/foremost.conf` vind. As jy net wil soek na sekere spesifieke lêers, verwyder die kommentaarmerke. As jy niks verwyder nie, sal foremost soek na sy verstek geconfigureerde lêertipes.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** is nog 'n instrument wat gebruik kan word om **lêers wat in 'n lêer ingebed is** te vind en te onttrek. In hierdie geval moet jy die lêertipes wat jy wil onttrek, ontkommentarieer uit die konfigurasie-lêer (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Hierdie instrument kom binne kali, maar jy kan dit hier vind: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Hierdie instrument kan 'n beeld skandeer en sal **pcaps onttrek** binne dit, **netwerkinligting\(URL's, domeine, IP's, MAC's, e-posse\)** en meer **lêers**. Jy hoef net die volgende te doen:
```text
bulk_extractor memory.img -o out_folder
```
Navigeer deur **alle inligting** wat die instrument ingesamel het \(wagwoorde?\), **analiseer** die **pakkies** \(lees [**Pcaps-analise**](../pcap-inspection/)\), soek na **vreemde domeine** \(domeine wat verband hou met **kwaadwillige sagteware** of **nie-bestaande**\).

## PhotoRec

Jy kan dit vind by [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dit kom met 'n GUI- en CLI-weergawe. Jy kan die **lêertipes** kies wat PhotoRec moet soek.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Spesifieke Data Carving-instrumente

## FindAES

Soek na AES-sleutels deur te soek na hul sleutelskedules. In staat om 128, 192 en 256 bit sleutels te vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai [hier af](https://sourceforge.net/projects/findaes/).

# Aanvullende instrumente

Jy kan [**viu** ](https://github.com/atanunq/viu)gebruik om beelde vanuit die terminaal te sien.
Jy kan die Linux-opdraglyn-instrument **pdftotext** gebruik om 'n pdf in te omskep na teks en dit te lees.



<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
