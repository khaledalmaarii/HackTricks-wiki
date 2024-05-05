# Sehemu/Ufumo wa Faili/Carving

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Sehemu

Kifaa cha diski ngumu au **diski ya SSD inaweza kuwa na sehemu tofauti** kwa lengo la kutenganisha data kimwili.\
**Kitengo cha chini kabisa** cha diski ni **sektori** (kawaida ina 512B). Kwa hivyo, kila ukubwa wa sehemu unahitaji kuwa maradufu ya ukubwa huo.

### MBR (Rekodi ya Mwanzo ya Boot)

Imetengwa katika **sektori ya kwanza ya diski baada ya 446B ya msimbo wa boot**. Sekta hii ni muhimu kwa kuelekeza PC ni nini na kutoka wapi sehemu inapaswa kufungwa.\
Inaruhusu hadi **sehemu 4** (angalau **1 tu** inaweza kuwa **inayoweza kuanzishwa**). Walakini, ikiwa unahitaji sehemu zaidi unaweza kutumia **sehemu zilizopanuliwa**. **Bayt ya mwisho** ya sektori hii ya kwanza ni saini ya rekodi ya boot **0x55AA**. Sehemu moja tu inaweza kuwa imeorodheshwa kama inayoweza kuanzishwa.\
MBR inaruhusu **max 2.2TB**.

![](<../../../.gitbook/assets/image (350).png>)

![](<../../../.gitbook/assets/image (304).png>)

Kutoka kwa **bayt 440 hadi 443** ya MBR unaweza kupata **Sahihi ya Diski ya Windows** (ikiwa Windows inatumika). Barua ya kigeni ya anwani ya diski ngumu inategemea Saini ya Diski ya Windows. Kubadilisha saini hii inaweza kuzuia Windows kuanza (zana: [**Mhariri wa Diski ya Aktiviti**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (310).png>)

**Muundo**

| Offset      | Urefu      | Kitu                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Msimbo wa Boot      |
| 446 (0x1BE) | 16 (0x10)  | Sehemu ya Kwanza    |
| 462 (0x1CE) | 16 (0x10)  | Sehemu ya Pili      |
| 478 (0x1DE) | 16 (0x10)  | Sehemu ya Tatu      |
| 494 (0x1EE) | 16 (0x10)  | Sehemu ya Nne       |
| 510 (0x1FE) | 2 (0x2)    | Saini 0x55 0xAA     |

**Muundo wa Rekodi ya Sehemu**

| Offset    | Urefu     | Kitu                                                   |
| --------- | --------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01)  | Bendera ya Kazi (0x80 = inayoweza kuanzishwa)          |
| 1 (0x01)  | 1 (0x01)  | Kichwa cha Kuanza                                      |
| 2 (0x02)  | 1 (0x01)  | Sekta ya Kuanza (bits 0-5); sehemu za juu za silinda (6- 7) |
| 3 (0x03)  | 1 (0x01)  | Silinda ya Kuanza sehemu ya chini                      |
| 4 (0x04)  | 1 (0x01)  | Nambari ya Aina ya Sehemu (0x83 = Linux)               |
| 5 (0x05)  | 1 (0x01)  | Kichwa cha Mwisho                                      |
| 6 (0x06)  | 1 (0x01)  | Sekta ya Mwisho (bits 0-5); sehemu za juu za silinda (6- 7) |
| 7 (0x07)  | 1 (0x01)  | Silinda ya Mwisho sehemu ya chini                      |
| 8 (0x08)  | 4 (0x04)  | Sekta zilizotangulia sehemu (kidogo mwisho)             |
| 12 (0x0C) | 4 (0x04)  | Sekta katika sehemu                                    |

Ili kufunga MBR kwenye Linux kwanza unahitaji kupata kianzishaji wa kuanza (unaweza kutumia `fdisk` na amri ya `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Na kisha tumia msimbo ufuatao
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Ukarabati wa kibao cha mantiki** (**LBA**) ni mpango wa kawaida unaotumiwa kwa **kutaja mahali pa vitalu** vya data vilivyohifadhiwa kwenye vifaa vya kuhifadhi vya kompyuta, kwa ujumla mifumo ya kuhifadhi ya sekondari kama vile diski ngumu. LBA ni mpango wa kutaja wa moja kwa moja wa mstari; **vitalu hupatikana kwa nambari ya kipekee**, na kibao cha kwanza kikiwa LBA 0, kibao cha pili LBA 1, na kadhalika.

### GPT (Jedwali la Sehemu la GUID)

Jedwali la Sehemu la GUID, linalojulikana kama GPT, linapendelewa kwa uwezo wake ulioboreshwa ikilinganishwa na MBR (Rekodi ya Kuanza Mwalimu). Kipekee kwa **kitambulisho cha kipekee duniani** kwa sehemu, GPT inaonekana kwa njia kadhaa:

* **Mahali na Ukubwa**: GPT na MBR zinaanza kwenye **sehemu 0**. Walakini, GPT inafanya kazi kwa **bits 64**, ikilinganishwa na bits 32 za MBR.
* **Vikwazo vya Sehemu**: GPT inasaidia hadi **sehemu 128** kwenye mifumo ya Windows na inaweza kuhifadhi hadi **9.4ZB** ya data.
* **Majina ya Sehemu**: Inatoa uwezo wa kutaja sehemu kwa hadi wahusika wa Unicode 36.

**Uimara na Uokoaji wa Data**:

* **Udhibitishaji**: Tofauti na MBR, GPT haifungi upangaji wa sehemu na data ya kuanza kwenye sehemu moja. Inarejesha data hii kote kwenye diski, ikiboresha uadilifu na uimara wa data.
* **Uchunguzi wa Redundancy ya Mzunguko (CRC)**: GPT inatumia CRC kuhakikisha uadilifu wa data. Inachunguza kwa uangalifu uharibifu wa data, na ikigundulika, GPT inajaribu kurejesha data iliyoharibika kutoka kwenye eneo lingine la diski.

**MBR ya Kinga (LBA0)**:

* GPT inaendeleza ufuatiliaji wa nyuma kupitia MBR ya kinga. Kipengele hiki kinaishi katika nafasi ya MBR ya zamani lakini imeundwa kuzuia programu za zamani zinazotegemea MBR kwa makosa kufuta diski zilizo na GPT, hivyo kulinda uadilifu wa data kwenye diski zilizo na GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (1062).png>)

**MBR ya Kihybridi (LBA 0 + GPT)**

[Kutoka Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Katika mifumo ya uendeshaji inayounga mkono **kuanza kwa msingi wa GPT kupitia huduma za BIOS** badala ya EFI, sehemu ya kwanza inaweza pia kutumika kuhifadhi hatua ya kwanza ya msimbo wa **kuanza** wa **bootloader**, lakini **imebadilishwa** kutambua **sehemu za GPT**. Bootloader kwenye MBR haitakiwi kudhani ukubwa wa sehemu wa bytes 512.

**Kichwa cha Jedwali la Sehemu (LBA 1)**

[Kutoka Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Kichwa cha jedwali la sehemu hufafanua vitalu vinavyoweza kutumika kwenye diski. Pia hufafanua idadi na ukubwa wa viingilio vya sehemu vinavyounda jedwali la sehemu (offsets 80 na 84 kwenye jedwali).

| Offset    | Urefu    | Yaliyomo                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Saini ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h au 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)kwenye mashine za little-endian) |
| 8 (0x08)  | 4 bytes  | Mapitio 1.0 (00h 00h 01h 00h) kwa UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bytes  | Ukubwa wa kichwa kwa little endian (kwa bytes, kawaida 5Ch 00h 00h 00h au 92 bytes)                                                                                             |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) ya kichwa (offset +0 hadi ukubwa wa kichwa) kwa little endian, na uga huu ukiwekwa sifuri wakati wa kuhesabu                                |
| 20 (0x14) | 4 bytes  | Imehifadhiwa; lazima iwe sifuri                                                                                                                                                 |
| 24 (0x18) | 8 bytes  | LBA ya Sasa (eneo la nakala hii ya kichwa)                                                                                                                                      |
| 32 (0x20) | 8 bytes  | LBA ya Kurejesha (eneo la nakala nyingine ya kichwa)                                                                                                                             |
| 40 (0x28) | 8 bytes  | LBA ya kwanza inayoweza kutumika kwa sehemu (jedwali la sehemu la msingi la mwisho LBA + 1)                                                                                     |
| 48 (0x30) | 8 bytes  | LBA ya mwisho inayoweza kutumika (jedwali la sehemu la sekondari la kwanza LBA − 1)                                                                                               |
| 56 (0x38) | 16 bytes | GUID ya Diski kwa mchanganyiko wa endian                                                                                                                                         |
| 72 (0x48) | 8 bytes  | Kuanza LBA ya safu ya viingilio vya sehemu (daima 2 kwenye nakala ya msingi)                                                                                                    |
| 80 (0x50) | 4 bytes  | Idadi ya viingilio vya sehemu kwenye safu                                                                                                                                       |
| 84 (0x54) | 4 bytes  | Ukubwa wa kila kuingilio cha sehemu (kawaida 80h au 128)                                                                                                                         |
| 88 (0x58) | 4 bytes  | CRC32 ya safu ya viingilio vya sehemu kwa little endian                                                                                                                         |
| 92 (0x5C) | \*       | Imehifadhiwa; lazima iwe sifuri kwa sehemu iliyobaki (bytes 420 kwa ukubwa wa sehemu wa 512; lakini inaweza kuwa zaidi na ukubwa mkubwa wa sehemu)                               |

**Viingilio vya Sehemu (LBA 2–33)**

| Muundo wa Viingilio vya Sehemu ya GUID |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Urefu    | Yaliyomo                                                                                                          |
| 0 (0x00)                    | 16 bytes | [GUID ya aina ya sehemu](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mchanganyiko wa endian) |
| 16 (0x10)                   | 16 bytes | GUID ya sehemu ya kipekee (mchanganyiko wa endian)                                                                |
| 32 (0x20)                   | 8 bytes  | LBA ya Kwanza ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                     |
| 40 (0x28)                   | 8 bytes  | LBA ya Mwisho (pamoja, kawaida ni namba ya kipekee)                                                               |
| 48 (0x30)                   | 8 bytes  | Alama za sifa (k.m. biti 60 inaonyesha kusoma tu)                                                                 |
| 56 (0x38)                   | 72 bytes | Jina la sehemu (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE vitengo vya nambari)                           |

**Aina za Sehemu**

![](<../../../.gitbook/assets/image (83).png>)

Aina zaidi za sehemu katika [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Ukaguzi

Baada ya kufunga picha ya uchunguzi na [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), unaweza kukagua sehemu ya kwanza ukitumia zana ya Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Katika picha ifuatayo, **MBR** iligunduliwa kwenye **sehemu 0** na kufafanuliwa:

![](<../../../.gitbook/assets/image (354).png>)

Ikiwa ilikuwa **jedwali la GPT badala ya MBR** inapaswa kuonekana saini _EFI PART_ kwenye **sehemu 1** (ambayo kwenye picha iliyotangulia iko wazi).
## Mfumo wa Faili

### Orodha ya mifumo ya faili ya Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**Mfumo wa faili wa FAT (File Allocation Table)** umebuniwa karibu na sehemu yake kuu, jedwali la kugawanya faili, lililowekwa mwanzoni mwa kiasi. Mfumo huu unalinda data kwa kudumisha **nakala mbili** za jedwali, ikihakikisha usalama wa data hata kama moja imeharibika. Jedwali, pamoja na folda ya msingi, lazima iwe katika **eneo lililofungwa**, muhimu kwa mchakato wa kuanza kwa mfumo.

Kitengo msingi cha kuhifadhi cha mfumo wa FAT ni **kluster, kawaida 512B**, ikijumuisha sehemu nyingi. FAT imeendelea kupitia toleo:

* **FAT12**, ikiunga mkono anwani za kluster zenye biti 12 na kushughulikia hadi kluster 4078 (4084 na UNIX).
* **FAT16**, ikiboresha hadi anwani zenye biti 16, hivyo kuhifadhi hadi kluster 65,517.
* **FAT32**, ikisonga mbele zaidi na anwani zenye biti 32, ikiruhusu kluster 268,435,456 za kuvutia kwa kiasi.

Kizuizi kikubwa kote kwenye toleo za FAT ni **ukubwa wa faili wa kiwango cha 4GB**, uliowekwa na uga wa biti 32 uliotumika kuhifadhi ukubwa wa faili.

Vipengele muhimu vya saraka ya msingi, hasa kwa FAT12 na FAT16, ni pamoja na:

* **Jina la Faili/Folda** (hadi wahusika 8)
* **Sifa**
* **Tarehe za Uundaji, Kubadilisha, na Kupata Mwisho**
* **Anwani ya Jedwali la FAT** (inayoonyesha kluster ya kuanza ya faili)
* **Ukubwa wa Faili**

### EXT

**Ext2** ndio mfumo wa faili wa kawaida zaidi kwa **partisheni zisizo na journaling** (**partisheni ambazo hazibadiliki sana**) kama vile partisheni ya boot. **Ext3/4** ni **journaling** na hutumiwa kawaida kwa **partisheni zilizobaki**.

## **Metadata**

Baadhi ya faili zina metadata. Taarifa hii ni kuhusu maudhui ya faili ambayo mara nyingine inaweza kuwa ya kuvutia kwa mchambuzi kulingana na aina ya faili, inaweza kuwa na taarifa kama:

* Kichwa
* Toleo la MS Office lililotumika
* Mwandishi
* Tarehe za uundaji na ubadilishaji wa mwisho
* Mfano wa kamera
* Vielezo vya GPS
* Taarifa ya Picha

Unaweza kutumia zana kama [**exiftool**](https://exiftool.org) na [**Metadiver**](https://www.easymetadata.com/metadiver-2/) kupata metadata ya faili.

## **Uokoaji wa Faili Zilizofutwa**

### Faili Zilizofutwa Zilizosajiliwa

Kama ilivyoonekana hapo awali kuna sehemu kadhaa ambapo faili bado imehifadhiwa baada ya kufutwa. Hii ni kwa sababu kawaida kufuta faili kutoka kwa mfumo wa faili kunaiweka kama imefutwa lakini data haijaguswa. Kisha, inawezekana kukagua usajili wa faili (kama MFT) na kupata faili zilizofutwa.

Pia, OS kawaida huihifadhi habari nyingi kuhusu mabadiliko ya mfumo wa faili na nakala rudufu, hivyo inawezekana kujaribu kuzitumia kurejesha faili au habari nyingi iwezekanavyo.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Uchongaji wa Faili**

**Uchongaji wa faili** ni mbinu inayojaribu **kupata faili katika data nyingi**. Kuna njia 3 kuu ambazo zana kama hizi hufanya kazi: **Kulingana na vichwa na miguu ya aina za faili**, kulingana na **miundo ya aina za faili** na kulingana na **maudhui** yenyewe.

Tafadhali kumbuka kuwa mbinu hii **haitafaulu kuokoa faili zilizovunjika**. Ikiwa faili **haipo katika sehemu za kluster zilizounganishwa**, basi mbinu hii haitaweza kuipata au angalau sehemu yake.

Kuna zana kadhaa unazoweza kutumia kwa Uchongaji wa Faili ikionyesha aina za faili unazotaka kutafuta

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Uchongaji wa **M**aflaka ya Data

Uchongaji wa Maflaka ya Data ni sawa na Uchongaji wa Faili lakini **badala ya kutafuta faili kamili, inatafuta vipande vya kuvutia** vya habari.\
Kwa mfano, badala ya kutafuta faili kamili inayohifadhi URL zilizosajiliwa, mbinu hii itatafuta URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Kufuta kwa Usalama

Kwa dhahiri, kuna njia za **kufuta faili kwa usalama na sehemu za kumbukumbu kuhusu hizo**. Kwa mfano, inawezekana **kubadilisha maudhui** ya faili na data zisizo na maana mara kadhaa, kisha **iondoe** **kumbukumbu** kutoka kwa **$MFT** na **$LOGFILE** kuhusu faili, na **iondoe Nakala za Kivuli za Kiasi**.\
Unaweza kugundua kuwa hata ukifanya hatua hiyo kunaweza kuwa na **sehemu zingine ambapo uwepo wa faili bado unarekodiwa**, na hiyo ni kweli na sehemu ya kazi ya mtaalamu wa uchunguzi wa kielelezo.

## Marejeo

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**
