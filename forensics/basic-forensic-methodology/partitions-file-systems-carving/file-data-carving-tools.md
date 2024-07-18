{% hint style="success" %}
Leer en oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}


# Uitsnygereedskap

## Autopsie

Die mees algemene gereedskap wat in forensika gebruik word om lêers uit beelde te onttrek, is [**Autopsie**](https://www.autopsy.com/download/). Laai dit af, installeer dit en laat dit die lêer inneem om "verborge" lêers te vind. Let daarop dat Autopsie gebou is om skyfbeeld en ander soorte beelde te ondersteun, maar nie eenvoudige lêers nie.

## Binwalk <a id="binwalk"></a>

**Binwalk** is 'n gereedskap om binêre lêers soos beelde en klanklêers te soek vir ingeslote lêers en data.
Dit kan met `apt` geïnstalleer word, maar die [bron](https://github.com/ReFirmLabs/binwalk) kan op github gevind word.
**Nuttige bevele**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

'n Ander algemene instrument om verskuilde lêers te vind is **foremost**. Jy kan die opsetlêer van foremost vind in `/etc/foremost.conf`. As jy net wil soek na spesifieke lêers, moet jy hulle uitkommenteer. As jy niks uitkommenteer nie, sal foremost soek na sy verstek geconfigureerde lêertipes.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** is nog 'n instrument wat gebruik kan word om **lêers wat in 'n lêer ingebed is** te vind en te onttrek. In hierdie geval sal jy nodig wees om die lêertipes wat jy wil onttrek, te ontsluit vanaf die konfigurasie lêer \(_/etc/scalpel/scalpel.conf_\).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Hierdie gereedskap kom binne kali maar jy kan dit hier vind: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Hierdie gereedskap kan 'n beeld skandeer en sal **pcaps onttrek** binne dit, **netwerk inligting\(URL's, domeine, IP's, MAC's, e-posse\)** en meer **lêers**. Jy hoef net te doen:
```text
bulk_extractor memory.img -o out_folder
```
Navigeer deur **alle inligting** wat die instrument ingesamel het \(wagwoorde?\), **analiseer** die **pakkies** \(lees[ **Pcaps-analise**](../pcap-inspection/)\), soek na **vreemde domeine** \(domeine verwant aan **malware** of **nie-bestaande**\).

## PhotoRec

Jy kan dit vind op [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dit kom met 'n GUI en CLI weergawe. Jy kan die **lêer-tipes** kies wat jy wil hê dat PhotoRec moet soek.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Spesifieke Data Carving Gereedskap

## FindAES

Soek na AES-sleutels deur te soek na hul sleutelskedules. In staat om 128, 192, en 256 bit sleutels te vind, soos dié wat deur TrueCrypt en BitLocker gebruik word.

Laai af [hier](https://sourceforge.net/projects/findaes/).

# Aanvullende gereedskap

Jy kan [**viu** ](https://github.com/atanunq/viu)gebruik om afbeeldings van die terminaal te sien.
Jy kan die linux-opdraglyn-gereedskap **pdftotext** gebruik om 'n pdf in te skakel na teks en dit te lees.



{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
