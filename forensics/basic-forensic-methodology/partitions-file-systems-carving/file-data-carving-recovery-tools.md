<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inayotangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Zana za Kuchimba na Kurejesha

Zana zaidi katika [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

Zana inayotumiwa sana katika uchunguzi wa kisayansi kuchambua faili kutoka kwa picha ni [**Autopsy**](https://www.autopsy.com/download/). Pakua, sakinisha na ingiza faili ili kupata faili "zilizofichwa". Kumbuka kuwa Autopsy imejengwa ili kusaidia picha za diski na aina zingine za picha, lakini sio faili rahisi.

## Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni zana ya kuchambua faili za binary ili kupata yaliyomo yaliyofichwa. Inaweza kusakinishwa kupitia `apt` na chanzo chake kiko kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

**Amri muhimu**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Chombo kingine cha kawaida cha kupata faili zilizofichwa ni **foremost**. Unaweza kupata faili ya usanidi ya foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta faili fulani maalum, toa maoni kwenye faili hizo. Ikiwa haujatoa maoni yoyote, foremost itatafuta aina za faili zilizowekwa kwa usanidi wake wa msingi.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** ni chombo kingine kinachoweza kutumika kupata na kuchimbua **faili zilizojumuishwa katika faili**. Katika kesi hii, utahitaji kuondoa alama kutoka kwenye faili ya usanidi (_/etc/scalpel/scalpel.conf_) aina za faili unazotaka izichimbue.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Herramienta hii iko ndani ya kali lakini unaweza kuipata hapa: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Herramienta hii inaweza kuchunguza picha na **kuchimbua pcaps** ndani yake, **taarifa za mtandao (URLs, domains, IPs, MACs, mails)** na **faili zaidi**. Unachotakiwa kufanya ni:
```
bulk_extractor memory.img -o out_folder
```
Pitapita kupitia **habari zote** ambazo zana imekusanya (nywila?), **chambua** **pakiti** (soma [**Uchambuzi wa Pcaps**](../pcap-inspection/)), tafuta **anwani za ajabu** (anwani zinazohusiana na **programu hasidi** au **zisizokuwepo**).

## PhotoRec

Unaweza kuipata kwenye [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Inakuja na toleo la GUI na CLI. Unaweza kuchagua **aina za faili** unayotaka PhotoRec iweze kutafuta.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Angalia [msimbo](https://code.google.com/archive/p/binvis/) na [zana ya ukurasa wa wavuti](https://binvis.io/#/).

### Vipengele vya BinVis

* Mwonekano na mtazamaji wa **muundo**
* Grafu nyingi kwa vituo tofauti vya umakini
* Kuzingatia sehemu ya sampuli
* **Kuona herufi na rasilimali**, katika faili za utekelezaji za PE au ELF kwa mfano
* Kupata **mifano** kwa ajili ya kuchambua faili za siri
* **Kugundua** pakiti au algorithm za kufunga
* **Tambua** Steganografia kwa mifano
* **Tazama** tofauti za binary

BinVis ni **mwanzo mzuri wa kujifunza kuhusu lengo lisilojulikana** katika hali ya black-boxing.

# Zana za Kuchimba Data Maalum

## FindAES

Inatafuta funguo za AES kwa kutafuta ratiba zao za funguo. Inaweza kupata funguo za biti 128, 192, na 256, kama vile zinavyotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

# Zana Zingine za Kuboresha

Unaweza kutumia [**viu**](https://github.com/atanunq/viu) kuona picha kutoka kwenye terminal.\
Unaweza kutumia zana ya mstari wa amri ya linux **pdftotext** kubadilisha pdf kuwa maandishi na kuyasoma.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaowajali zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho wa kujitokeza, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa API hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia zingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
