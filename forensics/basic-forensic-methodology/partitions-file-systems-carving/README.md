# Sehemu za Diski/Mfumo wa Faili/Uchongaji

## Sehemu za Diski/Mfumo wa Faili/Uchongaji

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Sehemu za Diski

Diski ngumu au diski ya **SSD inaweza kuwa na sehemu tofauti** kwa lengo la kutenganisha data kimwili.\
**Kiwango cha chini** cha diski ni **sekta** (kawaida ina 512B). Kwa hivyo, ukubwa wa kila sehemu unahitaji kuwa mara nyingi ya ukubwa huo.

### MBR (Master Boot Record)

Imetengwa katika **sehemu ya kwanza ya diski baada ya 446B ya msimbo wa kuanza**. Sekta hii ni muhimu kuonyesha PC ni nini na kutoka wapi sehemu inapaswa kufungwa.\
Inaruhusu hadi **sehemu 4** (kwa kiwango cha juu **1 tu** inaweza kuwa **inayofanya kazi**/**inayoweza kufungwa**). Walakini, ikiwa unahitaji sehemu zaidi unaweza kutumia **sehemu zilizopanuliwa**. **Bayt ya mwisho** ya sehemu hii ya kwanza ni saini ya rekodi ya kuanza **0x55AA**. Sehemu moja tu inaweza kuwa imeandikwa kama inayofanya kazi.\
MBR inaruhusu **max 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Kutoka kwa **bayt 440 hadi 443** ya MBR unaweza kupata **Windows Disk Signature** (ikiwa Windows inatumika). Barua ya anwani ya anatokea kwa saini ya Diski ya Windows. Kubadilisha saini hii kunaweza kuzuia Windows kuanza (zana: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Muundo**

| Offset      | Urefu      | Kitu                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Msimbo wa kuanza    |
| 446 (0x1BE) | 16 (0x10)  | Sehemu ya Kwanza    |
| 462 (0x1CE) | 16 (0x10)  | Sehemu ya Pili      |
| 478 (0x1DE) | 16 (0x10)  | Sehemu ya Tatu      |
| 494 (0x1EE) | 16 (0x10)  | Sehemu ya Nne       |
| 510 (0x1FE) | 2 (0x2)    | Saini 0x55 0xAA     |

**Muundo wa Rekodi ya Sehemu**

| Offset    | Urefu     | Kitu                                                   |
| --------- | --------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01)  | Bendera ya kazi (0x80 = inayoweza kufungwa)             |
| 1 (0x01)  | 1 (0x01)  | Kichwa cha kuanza                                      |
| 2 (0x02)  | 1 (0x01)  | Sekta ya kuanza (bits 0-5); bits za juu za silinda (6-7) |
| 3 (0x03)  | 1 (0x01)  | Silinda ya kuanza ya chini 8 bits                       |
| 4 (0x04)  | 1 (0x01)  | Nambari ya aina ya sehemu (0x83 = Linux)                 |
| 5 (0x05)  | 1 (0x01)  | Kichwa cha mwisho                                      |
| 6 (0x06)  | 1 (0x01)  | Sekta ya mwisho (bits 0-5); bits za juu za silinda (6-7) |
| 7 (0x07)  | 1 (0x01)  | Silinda ya mwisho ya chini 8 bits                       |
| 8 (0x08)  | 4 (0x04)  | Sekta zilizotangulia sehemu (little endian)             |
| 12 (0x0C) | 4 (0x04)  | Sekta katika sehemu                                    |

Ili kufunga MBR kwenye Linux, kwanza unahitaji kupata kianzio cha kuanza (unaweza kutumia `fdisk` na amri ya `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

Kisha tumia nambari ifuatayo
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ni mfumo wa kawaida unaotumiwa kwa **kutaja eneo la vitalu** vya data vilivyohifadhiwa kwenye vifaa vya uhifadhi wa kompyuta, kwa ujumla mfumo wa uhifadhi wa sekondari kama vile diski ngumu. LBA ni mfumo rahisi sana wa kutaja eneo; **vitalu hupatikana kwa kutumia nambari ya kiashiria**, na kwa kuanzia vitalu vya kwanza ni LBA 0, vitalu vya pili ni LBA 1, na kadhalika.

### GPT (GUID Partition Table)

Mwongozo wa Sehemu ya Kitambulisho, unaojulikana kama GPT, unapendelewa kwa uwezo wake ulioboreshwa ikilinganishwa na MBR (Master Boot Record). Kipekee kwa kitambulisho chake cha kipekee cha kimataifa kwa sehemu, GPT ina sifa kadhaa:

- **Mahali na Ukubwa**: GPT na MBR zote zinaanza kwenye **sekta 0**. Walakini, GPT inafanya kazi kwa kutumia **bits 64**, tofauti na bits 32 za MBR.
- **Vikwazo vya Sehemu**: GPT inasaidia hadi **sehemu 128** kwenye mifumo ya Windows na inaweza kuhifadhi hadi **9.4ZB** ya data.
- **Majina ya Sehemu**: Inatoa uwezo wa kutoa majina kwa sehemu kwa kutumia wahusika wa Unicode hadi 36.

**Uimara na Uokoaji wa Data**:

- **Udhibiti**: Tofauti na MBR, GPT haizuizi upangaji wa sehemu na data ya upakiaji kwenye eneo moja. Inarejesha data hii kwenye diski nzima, ikiboresha uadilifu na uimara wa data.
- **Cyclic Redundancy Check (CRC)**: GPT inatumia CRC kuhakikisha uadilifu wa data. Inachunguza kwa uangalifu uharibifu wa data, na ikigundulika, GPT inajaribu kurejesha data iliyoharibika kutoka eneo lingine la diski.

**Protective MBR (LBA0)**:

- GPT inaendeleza utangamano wa nyuma kupitia MBR ya kinga. Kipengele hiki kipo kwenye nafasi ya MBR ya zamani lakini imeundwa kuzuia programu za zamani zinazotegemea MBR kwa makosa kufuta diski za GPT, hivyo kulinda uadilifu wa data kwenye diski zilizo na muundo wa GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Kutoka Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Katika mifumo ya uendeshaji ambayo inasaidia **upakiaji wa GPT kupitia huduma za BIOS** badala ya EFI, sekta ya kwanza inaweza pia kutumika kuhifadhi hatua ya kwanza ya kificho cha **upakiaji wa mfumo** , lakini **imebadilishwa** ili kutambua **sehemu za GPT**. Kificho cha upakiaji wa MBR haitakiwi kudhani ukubwa wa sekta ya 512 baiti.

**Kichwa cha meza ya sehemu (LBA 1)**

[Kutoka Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Kichwa cha meza ya sehemu kinatambua vitalu vinavyoweza kutumiwa kwenye diski. Pia inatambua idadi na ukubwa wa kuingia kwenye meza ya sehemu (offsets 80 na 84 kwenye meza).

| Offset    | Urefu    | Yaliyomo                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 baiti  | Saini ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h au 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)kwenye mashine za little-endian) |
| 8 (0x08)  | 4 baiti  | Toleo 1.0 (00h 00h 01h 00h) kwa UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 baiti  | Ukubwa wa kichwa kwa mtindo wa little endian (kwa baiti, kawaida 5Ch 00h 00h 00h au baiti 92)                                                                                   |
| 16 (0x10) | 4 baiti  | [CRC32](https://en.wikipedia.org/wiki/CRC32) ya kichwa (offset +0 hadi ukubwa wa kichwa) kwa mtindo wa little endian, na uga huu ukiwa umefutwa wakati wa kuhesabu               |
| 20 (0x14) | 4 baiti  | Imehifadhiwa; lazima iwe sifuri                                                                                                                                                 |
| 24 (0x18) | 8 baiti  | LBA ya sasa (eneo la nakala hii ya kichwa)                                                                                                                                     |
| 32 (0x20) | 8 baiti  | LBA ya nakala nyingine ya kichwa                                                                                                                                                |
| 40 (0x28) | 8 baiti  | LBA ya kwanza inayoweza kutumiwa kwa sehemu (meza ya sehemu ya msingi ya mwisho LBA + 1)                                                                                         |
| 48 (0x30) | 8 baiti  | LBA ya mwisho inayoweza kutumiwa (meza ya sehemu ya sekondari ya kwanza LBA − 1)                                                                                                  |
| 56 (0x38) | 16 baiti | GUID ya diski kwa mtindo wa endian iliyochanganywa                                                                                                                               |
| 72 (0x48) | 8 baiti  | Kuanzia LBA ya safu ya kuingia kwenye sehemu (daima 2 kwenye nakala ya msingi)                                                                                                    |
| 80 (0x50) | 4 baiti  | Idadi ya kuingia kwenye sehemu kwenye safu                                                                                                                                      |
| 84 (0x54) | 4 baiti  | Ukubwa wa kuingia kwenye sehemu moja (kawaida 80h au 128)                                                                                                                        |
| 88 (0x58) | 4 baiti  | CRC32 ya safu ya kuingia kwenye sehemu kwa mtindo wa little endian                                                                                                               |
| 92 (0x5C) | \*       | Imehifadhiwa; lazima iwe sifuri kwa sehemu iliyobaki ya kizuizi (baiti 420 kwa ukubwa wa sekta ya 512 baiti; lakini inaweza kuwa zaidi na ukubwa mkubwa wa sekta)                 |

**Kuingia kwenye sehemu (LBA 2–33)**

| Muundo wa kuingia kwenye sehemu ya GUID |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Urefu    | Yaliyomo                                                                                                          |
| 0 (0x00)                    | 16 baiti | [Kitambulisho cha aina ya sehemu](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (endian iliyochanganywa) |
| 16 (0x10)                   | 16 baiti | Kitambulisho cha kipekee cha sehemu (endian iliyochanganywa)                                                        |
| 32 (0x20)                   | 8 baiti  | LBA ya kwanza ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 baiti  | LBA ya mwisho (pamoja, kawaida ni namba isiyo ya kawaida)                                                                                 |
| 48 (0x30)                   | 8 baiti  | Alama za sifa (kwa mfano, biti 60 inaonyesha tu kusoma)                                                                   |
| 56 (0x38)                   | 72 baiti | Jina la sehemu (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE vitengo vya nambari)                                   |

**Aina za Sehemu**

![](<../../../.gitbook/assets/image (492).png>)

Aina zaidi za sehemu zinapatikana kwenye [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Ukaguzi

Baada ya kufunga picha ya uchunguzi na [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), unaweza kukagua sekta ya kwanza kwa kutumia zana ya Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Katika picha ifuatayo, **MBR** iligunduliwa kwenye
## Mifumo ya Faili

### Orodha ya mifumo ya faili ya Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

Mfumo wa faili wa **FAT (File Allocation Table)** umebuniwa karibu na sehemu yake kuu, meza ya kugawanya faili, iliyo katika mwanzo wa kiasi. Mfumo huu unalinda data kwa kudumisha **nakala mbili** za meza, ikihakikisha uadilifu wa data hata kama moja imeharibika. Meza, pamoja na folda ya mizizi, lazima iwe katika **eneo lililofungwa**, muhimu kwa mchakato wa kuanza kwa mfumo.

Kitengo cha msingi cha kuhifadhi cha mfumo wa faili ni **kikundi, kawaida 512B**, kinachojumuisha sehemu kadhaa. FAT imeendelea kupitia toleo:

- **FAT12**, inayounga mkono anwani za kikundi cha biti 12 na kushughulikia hadi vikundi 4078 (4084 na UNIX).
- **FAT16**, ikiboreshwa hadi anwani za biti 16, hivyo kuhifadhi hadi vikundi 65,517.
- **FAT32**, ikiboreshwa zaidi na anwani za biti 32, ikiruhusu vikundi vya kushangaza 268,435,456 kwa kiasi.

Kikomo kikubwa katika matoleo ya FAT ni **ukubwa wa faili wa 4GB**, uliowekwa na uga wa biti 32 unaotumiwa kuhifadhi ukubwa wa faili.

Vipengele muhimu vya saraka ya mizizi, haswa kwa FAT12 na FAT16, ni pamoja na:

- **Jina la Faili/Folda** (hadithi 8)
- **Sifa**
- **Tarehe za Uundaji, Kubadilisha, na Kufikia Mwisho**
- **Anwani ya Meza ya FAT** (inayoonyesha kikundi cha kuanza cha faili)
- **Ukubwa wa Faili**

### EXT

**Ext2** ni mfumo wa faili unaotumiwa sana kwa kugawanya **bila kujaribu** (kugawanya ambazo hazibadiliki sana) kama kugawanya kuanza. **Ext3/4** ni za **kujaribu** na hutumiwa kawaida kwa **kugawanya zilizobaki**.

## **Metadata**

Baadhi ya faili zina metadata. Habari hii ni kuhusu maudhui ya faili ambayo mara nyingi inaweza kuwa ya kuvutia kwa mchambuzi kulingana na aina ya faili, inaweza kuwa na habari kama:

* Kichwa
* Toleo la MS Office lililotumiwa
* Mwandishi
* Tarehe za uundaji na ubadilishaji wa mwisho
* Mfano wa kamera
* Wiani wa GPS
* Habari ya Picha

Unaweza kutumia zana kama [**exiftool**](https://exiftool.org) na [**Metadiver**](https://www.easymetadata.com/metadiver-2/) kupata metadata ya faili.

## **Kurejesha Faili Zilizofutwa**

### Kurejesha Faili Zilizosajiliwa

Kama ilivyoonekana hapo awali, kuna maeneo kadhaa ambapo faili bado imehifadhiwa baada ya "kufutwa". Hii ni kwa sababu kawaida kufuta faili kutoka kwa mfumo wa faili kunaiweka kama imefutwa lakini data haijaguswa. Kwa hivyo, ni muhimu kuangalia kwenye usajili wa faili (kama MFT) na kupata faili zilizofutwa.

Pia, mfumo wa uendeshaji kawaida huhifadhi habari nyingi kuhusu mabadiliko ya mfumo wa faili na nakala rudufu, kwa hivyo ni muhimu kujaribu kuzitumia kurejesha faili au habari nyingi iwezekanavyo.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Uchongaji wa Faili**

**Uchongaji wa faili** ni mbinu inayojaribu **kupata faili katika data nyingi**. Kuna njia 3 kuu ambazo zana kama hizi hufanya kazi: **Kulingana na vichwa na miguu ya aina za faili**, kulingana na **muundo wa aina za faili** na kulingana na **maudhui** yenyewe.

Tafadhali kumbuka kuwa mbinu hii **haitafanya kazi kuokoa faili zilizovunjika**. Ikiwa faili **haipo katika sehemu zinazofuata**, basi mbinu hii haitaweza kuipata au angalau sehemu yake.

Kuna zana kadhaa unazoweza kutumia kwa Uchongaji wa Faili kwa kuonyesha aina za faili unazotaka kutafuta

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Uchongaji wa Data Stream

Uchongaji wa Data Stream ni sawa na Uchongaji wa Faili lakini **badala ya kutafuta faili kamili, inatafuta vipande vya habari vilivyo na umuhimu**. Kwa mfano, badala ya kutafuta faili kamili inayohusisha URL zilizosajiliwa, mbinu hii itatafuta URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Kufuta kwa Usalama

Kwa dhahiri, kuna njia za **kufuta faili kwa usalama na sehemu ya kumbukumbu juu yao**. Kwa mfano, inawezekana **kubadilisha maudhui** ya faili na data ya taka mara kadhaa, na kisha **kuondoa** **kumbukumbu** kutoka **$MFT** na **$LOGFILE** kuhusu faili, na **kuondoa Nakala za Kivuli za Kiasi**.\
Unaweza kugundua kuwa hata kwa kutekeleza hatua hiyo, kunaweza kuwa na **sehemu zingine ambapo uwepo wa faili bado unajisajili**, na hiyo ni kweli na sehemu ya kazi ya mtaalamu wa uchunguzi wa kisayansi.

## Marejeo

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki m
