<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy hulle vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Carving & Herstelgereedskap

Meer gereedskap in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

Die mees algemene gereedskap wat in forensika gebruik word om lêers uit beelde te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer insluk om "verborge" lêers te vind. Let daarop dat Autopsy gebou is om skyfbeelders en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is 'n gereedskap vir die analise van binêre lêers om ingebedde inhoud te vind. Dit kan geïnstalleer word via `apt` en die bronkode is op [GitHub](https://github.com/ReFirmLabs/binwalk).

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

Hierdie instrument kom binne kali, maar jy kan dit hier vind: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Hierdie instrument kan 'n beeld skandeer en sal **pcaps onttrek** binne dit, **netwerkinligting (URL's, domeine, IP's, MAC's, e-posse)** en meer **lêers**. Jy hoef net te doen:
```
bulk_extractor memory.img -o out_folder
```
Navigeer deur **alle inligting** wat die instrument ingesamel het (wagwoorde?), **analiseer** die **pakkies** (lees [**Pcaps-analise**](../pcap-inspection/)), soek na **vreemde domeine** (domeine wat verband hou met **kwaadwillige sagteware** of **nie-bestaande** domeine).

## PhotoRec

Jy kan dit vind by [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Dit kom met GUI- en CLI-weergawes. Jy kan die **lêertipes** kies wat PhotoRec moet soek.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Kyk na die [kode](https://code.google.com/archive/p/binvis/) en die [webwerf-instrument](https://binvis.io/#/).

### Kenmerke van BinVis

* Visuele en aktiewe **struktuurkyker**
* Verskeie grafieke vir verskillende fokuspunte
* Fokus op dele van 'n monster
* **Sien reekse en hulpbronne**, in PE- of ELF-uitvoerbare lêers, byvoorbeeld
* Kry **patrone** vir kripto-analise van lêers
* **Opmerk** verpakker- of enkodeeralgoritmes
* **Identifiseer** steganografie deur patrone
* **Visuele** binêre verskil

BinVis is 'n goeie **beginpunt om bekend te raak met 'n onbekende teiken** in 'n swart-boks scenario.

# Spesifieke Data Carving-instrumente

## FindAES

Soek na AES-sleutels deur te soek na hul sleutelskedules. In staat om 128, 192 en 256 bit sleutels te vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai dit hier af: [here](https://sourceforge.net/projects/findaes/).

# Aanvullende instrumente

Jy kan [**viu** ](https://github.com/atanunq/viu)gebruik om beelde vanuit die terminaal te sien.\
Jy kan die Linux-opdraglyn-instrument **pdftotext** gebruik om 'n pdf in te skakel na teks en dit te lees.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Vind kwesbaarhede wat die belangrikste is sodat jy dit vinniger kan regstel. Intruder volg jou aanvalsoppervlak, voer proaktiewe dreigingsskanderings uit, vind probleme regoor jou hele tegnologie-stapel, van API's tot webtoepassings en wolkstelsels. [**Probeer dit vandag nog gratis**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks).

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
