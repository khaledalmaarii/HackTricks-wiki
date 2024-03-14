# Lêer/Data Uithol & Herstelgereedskap

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

**Probeer Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Uithol & Herstelgereedskap

Meer gereedskap in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die mees algemene gereedskap wat in forensika gebruik word om lêers uit beelde te onttrek is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer inneem om "verborge" lêers te vind. Let daarop dat Autopsy gebou is om skyfbeeld en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is 'n gereedskap vir die analise van binêre lêers om ingeslote inhoud te vind. Dit is installeerbaar via `apt` en die bron is op [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nuttige bevele**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

'n Ander algemene instrument om verskuilde lêers te vind is **foremost**. Jy kan die opsetlêer van foremost vind in `/etc/foremost.conf`. As jy net wil soek na spesifieke lêers, ontkommentarieer hulle. As jy niks ontkommentarieer nie, sal foremost soek na sy verstek geconfigureerde lêertipes.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is nog 'n instrument wat gebruik kan word om **lêers wat in 'n lêer ingebed is** te vind en te onttrek. In hierdie geval sal jy nodig wees om uit die konfigurasie lêer (_/etc/scalpel/scalpel.conf_) die lêertipes wat jy wil onttrek, te ontkommentarieer.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Hierdie gereedskap kom binne Kali maar jy kan dit hier vind: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Hierdie gereedskap kan 'n beeld skandeer en sal **pcaps onttrek** binne dit, **netwerk inligting (URL's, domeine, IP's, MAC's, e-posse)** en meer **lêers**. Jy hoef net te doen:
```
bulk_extractor memory.img -o out_folder
```
Navigeer deur **alle inligting** wat die instrument ingesamel het (wagwoorde?), **analiseer** die **pakette** (lees[ **Pcaps-analise**](../pcap-inspection/)), soek na **vreemde domeine** (domeine verwant aan **malware** of **nie-bestaande**).

### PhotoRec

Jy kan dit vind op [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Dit kom met GUI- en CLI-weergawes. Jy kan die **lêertipes** kies wat PhotoRec moet soek.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Kyk na die [kode](https://code.google.com/archive/p/binvis/) en die [webwerf-instrument](https://binvis.io/#/).

#### Kenmerke van BinVis

* Visuele en aktiewe **struktuurkyker**
* Verskeie grafieke vir verskillende fokuspunte
* Fokus op dele van 'n monster
* **Sien van reekse en bronne**, in PE of ELF uitvoerbare lêers bv.
* Kry **patrone** vir kriptontleding van lêers
* **Opmerk** pakker- of enkodeeralgoritmes
* **Identifiseer** Steganografie deur patrone
* **Visuele** binêre-verskil

BinVis is 'n goeie **beginpunt om vertroud te raak met 'n onbekende teiken** in 'n swartboks-situasie.

## Spesifieke Data Carving-instrumente

### FindAES

Soek na AES-sleutels deur te soek na hul sleutelskedules. In staat om 128, 192 en 256 bit sleutels te vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai af [hier](https://sourceforge.net/projects/findaes/).

## Aanvullende instrumente

Jy kan [**viu** ](https://github.com/atanunq/viu)gebruik om beelde vanuit die terminaal te sien.\
Jy kan die Linux-opdraglyn-instrument **pdftotext** gebruik om 'n pdf na teks te omskep en dit te lees.

**Probeer Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
