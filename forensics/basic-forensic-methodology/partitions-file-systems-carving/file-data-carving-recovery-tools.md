# Zana za Kuchonga na Kurejesha Data

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kikundi cha Usalama cha Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Zana za Kuchonga na Kurejesha

Zana zaidi kwenye [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Zana ya kawaida sana kutumika katika uchunguzi wa kiforensiki kutoa faili kutoka kwa picha ni [**Autopsy**](https://www.autopsy.com/download/). Pakua, isakinishe na ifanye iingize faili ili kupata faili "zilizofichwa". Kumbuka kwamba Autopsy imejengwa kusaidia picha za diski na aina zingine za picha, lakini sio faili za kawaida.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** ni zana ya kuchambua faili za binary ili kupata yaliyomo yaliyofichwa. Inaweza kusakinishwa kupitia `apt` na chanzo chake kiko kwenye [GitHub](https://github.com/ReFirmLabs/binwalk).

**Amri muhimu**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Chombo kingine cha kawaida cha kutafuta faili zilizofichwa ni **foremost**. Unaweza kupata faili ya usanidi wa foremost katika `/etc/foremost.conf`. Ikiwa unataka tu kutafuta baadhi ya faili maalum, toa alama ya maoni kwao. Ikiwa hutotoa alama ya maoni kwa kitu chochote, foremost itatafuta aina zake za faili zilizosanidiwa kwa msingi.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** ni chombo kingine kinachoweza kutumika kutafuta na kutoa **faili zilizojumuishwa katika faili**. Katika kesi hii, utahitaji kufuta maoni kutoka kwenye faili ya usanidi (_/etc/scalpel/scalpel.conf_) aina za faili unazotaka izitoa.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Herramienta hii iko ndani ya kali lakini unaweza kuipata hapa: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Herramienta hii inaweza kutafuta picha na **kutoa pcaps** ndani yake, **taarifa za mtandao (URLs, domains, IPs, MACs, barua pepe)** na **faili zaidi**. Unachohitaji kufanya ni:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

Unaweza kuipata kwenye [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Inakuja na toleo la GUI na CLI. Unaweza kuchagua **aina za faili** unazotaka PhotoRec iweze kutafuta.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Angalia [mimba](https://code.google.com/archive/p/binvis/) na [zana ya ukurasa wa wavuti](https://binvis.io/#/).

#### Sifa za BinVis

* Mwangaza wa **muundo na mtazamaji** wa vitendo
* Grafu nyingi kwa pointi tofauti za kuzingatia
* Kuzingatia sehemu za sampuli
* **Kuona maneno na rasilimali**, katika utekelezaji wa PE au ELF kwa mfano
* Kupata **mifumo** kwa cryptanalysis kwenye faili
* **Kugundua** packer au algorithms za encoder
* **Kutambua** Steganography kwa mifumo
* **Visual** binary-diffing

BinVis ni **mahali pazuri pa kuanzia ili kuzoea lengo lisilojulikana** katika hali ya black-boxing.

## Zana Maalum za Ukarabati wa Data

### FindAES

Inatafuta funguo za AES kwa kutafuta ratiba zao za funguo. Inaweza kupata funguo za biti 128, 192, na 256, kama zile zinazotumiwa na TrueCrypt na BitLocker.

Pakua [hapa](https://sourceforge.net/projects/findaes/).

## Zana Zingine za Kufanana

Unaweza kutumia [**viu** ](https://github.com/atanunq/viu)kuona picha kutoka kwenye terminal.\
Unaweza kutumia zana ya mstari wa amri ya linux **pdftotext** kubadilisha pdf kuwa maandishi na kusoma.

**Jaribu Kikundi cha Usalama cha Kujitahidi**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia zingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
