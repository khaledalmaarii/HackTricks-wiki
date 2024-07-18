{% hint style="success" %}
Jifunze na zoea AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoea GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


# Vyombo vya Carving

## Autopsy

Zana ya kawaida sana inayotumiwa katika uchunguzi wa kiforensiki kutoa faili kutoka kwa picha ni [**Autopsy**](https://www.autopsy.com/download/). Pakua, iweke na ifanye iingize faili ili kupata faili "zilizofichwa". Kumbuka kwamba Autopsy imejengwa kusaidia picha za diski na aina nyingine za picha, lakini sio faili za kawaida.

## Binwalk <a id="binwalk"></a>

**Binwalk** ni zana ya kutafuta faili za binary kama picha na faili za sauti kwa faili zilizojumuishwa na data.
Inaweza kusakinishwa na `apt` hata hivyo [chanzo](https://github.com/ReFirmLabs/binwalk) kinaweza kupatikana kwenye github.
**Amri muhimu**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Chombo kingine cha kawaida cha kutafuta faili zilizofichwa ni **foremost**. Unaweza kupata faili ya usanidi wa foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta baadhi ya faili maalum, toa alama ya maoni kwao. Ikiwa hutotoa alama ya maoni kwa kitu chochote, foremost itatafuta aina zilizowekwa kwa msingi.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** ni chombo kingine kinachoweza kutumika kutafuta na kutoa **faili zilizojumuishwa katika faili**. Katika kesi hii utahitaji kufuta maoni kutoka kwenye faili ya usanidi \(_/etc/scalpel/scalpel.conf_\) aina za faili unazotaka izitoa.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Zana hii iko ndani ya kali lakini unaweza kuipata hapa: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Zana hii inaweza skani picha na **kutoa pcaps** ndani yake, **taarifa za mtandao\(URLs, uwanja, IPs, MACs, barua pepe\)** na **faili zaidi**. Unachohitaji kufanya ni:
```text
bulk_extractor memory.img -o out_folder
```
Pitia **maelezo yote** ambayo chombo kimekusanya \(nywila?\), **chambua** **pakiti** \(soma [**Uchambuzi wa Pcaps**](../uchunguzi-wa-pcap/)\), tafuta **vikoa vya ajabu** \(vikoa vinavyohusiana na **programu hasidi** au **visivyokuwepo**\).

## PhotoRec

Unaweza kuipata kwenye [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Inakuja na toleo la GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec iitafute.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Vyombo vya Kuchonga Data Maalum

## FindAES

Inatafuta funguo za AES kwa kutafuta ratiba zao za funguo. Inaweza kupata funguo za biti 128, 192, na 256, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

# Vyombo vya Kuboresha

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminal.
Unaweza kutumia chombo cha mstari wa amri cha linux **pdftotext** kubadilisha pdf kuwa maandishi na kusoma.
