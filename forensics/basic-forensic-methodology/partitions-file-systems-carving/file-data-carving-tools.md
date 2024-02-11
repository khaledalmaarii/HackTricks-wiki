<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>


# Zana za Carving

## Autopsy

Zana maarufu zaidi inayotumiwa katika uchunguzi wa kisayansi wa kuchimbua faili kutoka kwa picha ni [**Autopsy**](https://www.autopsy.com/download/). Pakua, iweke na ifanye kazi ya kuchunguza faili ili kupata faili "zilizofichwa". Kumbuka kuwa Autopsy imejengwa ili kusaidia picha za diski na aina nyingine za picha, lakini sio faili rahisi.

## Binwalk <a id="binwalk"></a>

**Binwalk** ni zana ya kutafuta faili za binary kama picha na faili za sauti kwa faili na data iliyowekwa ndani yake.
Inaweza kusakinishwa na `apt` hata hivyo [chanzo](https://github.com/ReFirmLabs/binwalk) kinaweza kupatikana kwenye github.
**Amri muhimu**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Chombo kingine cha kawaida cha kupata faili zilizofichwa ni **foremost**. Unaweza kupata faili ya usanidi ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta faili fulani maalum, toa maoni kwenye faili hizo. Ikiwa haujatoa maoni yoyote, foremost itatafuta aina za faili zilizowekwa kwa usanidi wake wa chaguo-msingi.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** ni chombo kingine kinachoweza kutumika kupata na kuchimbua **faili zilizojumuishwa katika faili**. Katika kesi hii, utahitaji kuondoa maoni kutoka kwenye faili ya usanidi \(_/etc/scalpel/scalpel.conf_\) aina za faili unazotaka izichimbue.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Herramienta hii iko ndani ya kali lakini unaweza kuipata hapa: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Herramienta hii inaweza kuchunguza picha na **kuchimbua pcaps** ndani yake, **taarifa za mtandao (URLs, domains, IPs, MACs, mails)** na **faili zaidi**. Unachotakiwa kufanya ni:
```text
bulk_extractor memory.img -o out_folder
```
Pitia **habari zote** ambazo zimekusanywa na zana \(maneno ya siri?\), **chambua** pakiti \(soma [**uchambuzi wa Pcaps**](../pcap-inspection/)\), tafuta **anwani za kushangaza** \(anwani zinazohusiana na **programu hasidi** au **zisizokuwepo**\).

## PhotoRec

Unaweza kuipata kwenye [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Inakuja na toleo la GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec ifanye utafutaji.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Zana za Kuchimba Data Maalum

## FindAES

Inatafuta funguo za AES kwa kutafuta ratiba zao za funguo. Inaweza kupata funguo za biti 128, 192, na 256, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

# Zana Zingine za Kuboresha

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminal.
Unaweza kutumia zana ya mstari wa amri ya linux **pdftotext** kubadilisha pdf kuwa maandishi na kuyasoma.



<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
