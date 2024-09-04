# File/Data Carving & Recovery Tools

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Die mees algemene hulpmiddel wat in forensiese ondersoeke gebruik word om lêers uit beelde te onttrek, is [**Autopsy**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer verwerk om "versteekte" lêers te vind. Let daarop dat Autopsy gebou is om skyfbeelde en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** is 'n hulpmiddel om binêre lêers te analiseer om ingebedde inhoud te vind. Dit kan geïnstalleer word via `apt` en sy bron is op [GitHub](https://github.com/ReFirmLabs/binwalk).

**Nuttige opdragte**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Nog 'n algemene hulpmiddel om verborge lêers te vind, is **foremost**. Jy kan die konfigurasielêer van foremost in `/etc/foremost.conf` vind. As jy net vir 'n paar spesifieke lêers wil soek, ontkommentarieer hulle. As jy niks ontkommentarieer nie, sal foremost vir sy standaard geconfigureerde lêertipes soek.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** is 'n ander hulpmiddel wat gebruik kan word om **lêers wat in 'n lêer ingebed is** te vind en te onttrek. In hierdie geval sal jy die lêertipes wat jy wil hê dit moet onttrek, uit die konfigurasie-lêer (_/etc/scalpel/scalpel.conf_) moet ontkommentarieer.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Hierdie hulpmiddel kom binne kali, maar jy kan dit hier vind: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Hierdie hulpmiddel kan 'n beeld skandeer en sal **pcaps** daarin **onttrek**, **netwerk inligting (URL's, domeine, IP's, MAC's, e-posse)** en meer **lêers**. Jy hoef net te doen:
```
bulk_extractor memory.img -o out_folder
```
Navigate through **alle die inligting** that the tool has gathered (wagwoorde?), **analiseer** the **pakkette** (lees[ **Pcaps analise**](../pcap-inspection/)), search for **vreemde domeine** (domeine verwant aan **malware** of **nie-bestaande**).

### PhotoRec

You can find it in [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

It comes with GUI and CLI versions. You can select the **lêer-tipes** you want PhotoRec to search for.

![](<../../../.gitbook/assets/image (242).png>)

### binvis

Check the [kode](https://code.google.com/archive/p/binvis/) and the [web blad gereedskap](https://binvis.io/#/).

#### Features of BinVis

* Visuele en aktiewe **struktuurkyker**
* Meerdere plotte vir verskillende fokuspunte
* Fokusering op gedeeltes van 'n monster
* **Sien stings en hulpbronne**, in PE of ELF uitvoerbare e. g.
* Kry **patrone** vir kriptoanalise op lêers
* **Identifiseer** pakker of kodering algoritmes
* **Identifiseer** Steganografie deur patrone
* **Visuele** binêre-diffing

BinVis is a great **beginpunt om bekend te raak met 'n onbekende teiken** in 'n swart-doos scenario.

## Spesifieke Data Carving Gereedskap

### FindAES

Searches for AES sleutels by searching for their key schedules. Able to find 128. 192, and 256 bit sleutels, such as those used by TrueCrypt and BitLocker.

Download [hier](https://sourceforge.net/projects/findaes/).

## Aanvullende gereedskap

You can use [**viu** ](https://github.com/atanunq/viu)to see images from the terminal.\
You can use the linux command line tool **pdftotext** to transform a pdf into text and read it.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
