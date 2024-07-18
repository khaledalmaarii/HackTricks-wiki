# Partitions/File Systems/Carving

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

## Partitions

Diski ngumu au **SSD inaweza kuwa na sehemu tofauti** kwa lengo la kutenganisha data kimwili.\
Kitengo cha **chini** cha diski ni **sehemu** (ambayo kawaida ina 512B). Hivyo, kila ukubwa wa sehemu unahitaji kuwa ni mara kadhaa ya ukubwa huo.

### MBR (master Boot Record)

Imewekwa katika **sehemu ya kwanza ya diski baada ya 446B ya msimbo wa boot**. Sehemu hii ni muhimu kuonyesha kwa PC ni nini na kutoka wapi sehemu inapaswa kuunganishwa.\
Inaruhusu hadi **sehemu 4** (kwa kiwango cha juu **sehemu 1 tu** inaweza kuwa hai/**bootable**). Hata hivyo, ikiwa unahitaji sehemu zaidi unaweza kutumia **sehemu za kupanua**. **Byte ya mwisho** ya sehemu hii ya kwanza ni saini ya boot record **0x55AA**. Sehemu moja tu inaweza kuashiriawa kama hai.\
MBR inaruhusu **max 2.2TB**.

![](<../../../.gitbook/assets/image (350).png>)

![](<../../../.gitbook/assets/image (304).png>)

Kutoka **bytes 440 hadi 443** za MBR unaweza kupata **Saini ya Disk ya Windows** (ikiwa Windows inatumika). Barua ya diski ya mantiki ya diski ngumu inategemea Saini ya Disk ya Windows. Kubadilisha saini hii kunaweza kuzuia Windows kuanza (chombo: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Msimbo wa boot      |
| 446 (0x1BE) | 16 (0x10)  | Sehemu ya Kwanza    |
| 462 (0x1CE) | 16 (0x10)  | Sehemu ya Pili      |
| 478 (0x1DE) | 16 (0x10)  | Sehemu ya Tatu      |
| 494 (0x1EE) | 16 (0x10)  | Sehemu ya Nne       |
| 510 (0x1FE) | 2 (0x2)    | Saini 0x55 0xAA     |

**Muundo wa Rekodi ya Sehemu**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Bendera ya hai (0x80 = bootable)                       |
| 1 (0x01)  | 1 (0x01) | Kichwa cha mwanzo                                      |
| 2 (0x02)  | 1 (0x01) | Sehemu ya mwanzo (bits 0-5); bits za juu za silinda (6- 7) |
| 3 (0x03)  | 1 (0x01) | Silinda ya mwanzo bits 8 za chini                       |
| 4 (0x04)  | 1 (0x01) | Msimbo wa aina ya sehemu (0x83 = Linux)                |
| 5 (0x05)  | 1 (0x01) | Kichwa cha mwisho                                      |
| 6 (0x06)  | 1 (0x01) | Sehemu ya mwisho (bits 0-5); bits za juu za silinda (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Silinda ya mwisho bits 8 za chini                       |
| 8 (0x08)  | 4 (0x04) | Sehemu zinazotangulia sehemu (little endian)           |
| 12 (0x0C) | 4 (0x04) | Sehemu katika sehemu                                    |

Ili kuunganisha MBR katika Linux unahitaji kwanza kupata offset ya mwanzo (unaweza kutumia `fdisk` na amri `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Na kisha tumia msimbo ufuatao
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Anwani ya block ya kimantiki** (**LBA**) ni mpango wa kawaida unaotumika kwa **kuelezea eneo la blocks** za data zilizohifadhiwa kwenye vifaa vya kuhifadhi kompyuta, kwa ujumla mifumo ya kuhifadhi sekondari kama vile diski ngumu. LBA ni mpango wa anwani rahisi wa mstari; **blocks zinapatikana kwa index ya nambari nzima**, block ya kwanza ikiwa LBA 0, ya pili LBA 1, na kadhalika.

### GPT (GUID Partition Table)

Jedwali la Sehemu za GUID, linalojulikana kama GPT, linapendekezwa kwa uwezo wake ulioimarishwa ikilinganishwa na MBR (Master Boot Record). Inajulikana kwa **kitambulisho chake cha kipekee duniani** kwa sehemu, GPT inajitokeza kwa njia kadhaa:

* **Mahali na Ukubwa**: GPT na MBR zote huanza kwenye **sehemu 0**. Hata hivyo, GPT inafanya kazi kwa **64bits**, tofauti na MBR ambayo ni 32bits.
* **Mipaka ya Sehemu**: GPT inasaidia hadi **sehemu 128** kwenye mifumo ya Windows na inaruhusu hadi **9.4ZB** ya data.
* **Majina ya Sehemu**: Inatoa uwezo wa kupewa majina sehemu zikiwa na wahusika 36 wa Unicode.

**Ustahimilivu wa Data na Urejeleaji**:

* **Ukarabati**: Tofauti na MBR, GPT haitoi mipaka ya sehemu na data ya boot mahali pamoja. Inarudia data hii kwenye diski, ikiongeza uaminifu wa data na ustahimilivu.
* **Cyclic Redundancy Check (CRC)**: GPT inatumia CRC kuhakikisha uaminifu wa data. Inachunguza kwa makini uharibifu wa data, na inapogundulika, GPT inajaribu kurejesha data iliyoathirika kutoka eneo lingine la diski.

**MBR ya Kulinda (LBA0)**:

* GPT inahifadhi ulinganifu wa nyuma kupitia MBR ya kulinda. Kipengele hiki kinapatikana katika nafasi ya MBR ya zamani lakini kimeundwa ili kuzuia zana za zamani za MBR zisifanye makosa ya kuandika tena diski za GPT, hivyo kulinda uaminifu wa data kwenye diski zilizofomatiwa kwa GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Katika mifumo ya uendeshaji inayounga mkono **boot ya GPT kupitia huduma za BIOS** badala ya EFI, sehemu ya kwanza inaweza pia kutumika kuhifadhi hatua ya kwanza ya **bootloader** code, lakini **imebadilishwa** kutambua **GPT** **sehemu**. Bootloader katika MBR haipaswi kudhani ukubwa wa sehemu kuwa 512 bytes.

**Kichwa cha jedwali la sehemu (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Kichwa cha jedwali la sehemu kinaelezea blocks zinazoweza kutumika kwenye diski. Pia kinaelezea idadi na ukubwa wa entries za sehemu zinazounda jedwali la sehemu (offsets 80 na 84 katika jedwali).

| Offset    | Length   | Contents                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Sahihi ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h au 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8) kwenye mashine za little-endian) |
| 8 (0x08)  | 4 bytes  | Toleo 1.0 (00h 00h 01h 00h) kwa UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bytes  | Ukubwa wa kichwa katika little endian (katika bytes, kawaida 5Ch 00h 00h 00h au 92 bytes)                                                                                                    |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) ya kichwa (offset +0 hadi ukubwa wa kichwa) katika little endian, huku uwanja huu ukiwa na sifuri wakati wa hesabu                                |
| 20 (0x14) | 4 bytes  | Imehifadhiwa; lazima iwe sifuri                                                                                                                                                          |
| 24 (0x18) | 8 bytes  | LBA ya sasa (mahali pa nakala hii ya kichwa)                                                                                                                                      |
| 32 (0x20) | 8 bytes  | LBA ya nakala (mahali pa nakala nyingine ya kichwa)                                                                                                                                  |
| 40 (0x28) | 8 bytes  | LBA ya kwanza inayoweza kutumika kwa sehemu (jedwali la sehemu ya msingi LBA ya mwisho + 1)                                                                                                          |
| 48 (0x30) | 8 bytes  | LBA ya mwisho inayoweza kutumika (jedwali la sehemu ya sekondari LBA ya kwanza − 1)                                                                                                                       |
| 56 (0x38) | 16 bytes | Disk GUID katika mchanganyiko wa endian                                                                                                                                                       |
| 72 (0x48) | 8 bytes  | LBA ya kuanzia ya safu ya entries za sehemu (daima 2 katika nakala ya msingi)                                                                                                        |
| 80 (0x50) | 4 bytes  | Idadi ya entries za sehemu katika safu                                                                                                                                            |
| 84 (0x54) | 4 bytes  | Ukubwa wa entry moja ya sehemu (kawaida 80h au 128)                                                                                                                           |
| 88 (0x58) | 4 bytes  | CRC32 ya safu ya entries za sehemu katika little endian                                                                                                                               |
| 92 (0x5C) | \*       | Imehifadhiwa; lazima iwe sifuri kwa sehemu nyingine za block (420 bytes kwa ukubwa wa sehemu ya 512 bytes; lakini inaweza kuwa zaidi na ukubwa wa sehemu kubwa)                                         |

**Entries za Sehemu (LBA 2–33)**

| Muundo wa entry ya sehemu ya GUID |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                          |
| 0 (0x00)                    | 16 bytes | [Aina ya sehemu ya GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mchanganyiko wa endian) |
| 16 (0x10)                   | 16 bytes | GUID ya kipekee ya sehemu (mchanganyiko wa endian)                                                                              |
| 32 (0x20)                   | 8 bytes  | LBA ya kwanza ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 bytes  | LBA ya mwisho (inajumuisha, kawaida ni odd)                                                                                 |
| 48 (0x30)                   | 8 bytes  | Bendera za sifa (mfano, bit 60 inaashiria kusoma pekee)                                                                   |
| 56 (0x38)                   | 72 bytes | Jina la sehemu (mifumo 36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                                   |

**Aina za Sehemu**

![](<../../../.gitbook/assets/image (83).png>)

Aina zaidi za sehemu katika [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Kukagua

Baada ya kuunganisha picha ya forensics na [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), unaweza kukagua sehemu ya kwanza kwa kutumia zana ya Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Katika picha ifuatayo **MBR** iligundulika kwenye **sehemu 0** na kutafsiriwa:

![](<../../../.gitbook/assets/image (354).png>)

Ikiwa ilikuwa **jedwali la GPT badala ya MBR** inapaswa kuonekana sahihi _EFI PART_ katika **sehemu 1** (ambayo katika picha ya awali ni tupu).

## Mifumo ya Faili

### Orodha ya mifumo ya faili ya Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

Mfumo wa faili wa **FAT (File Allocation Table)** umeundwa kuzunguka kipengele chake cha msingi, jedwali la ugawaji wa faili, lililopo kwenye mwanzo wa volumu. Mfumo huu unalinda data kwa kudumisha **nakala mbili** za jedwali, kuhakikisha uaminifu wa data hata kama moja imeharibika. Jedwali, pamoja na folda ya mzizi, lazima iwe katika **mahali thabiti**, muhimu kwa mchakato wa kuanzisha mfumo.

Kitengo cha msingi cha kuhifadhi cha mfumo wa faili ni **cluster, kawaida 512B**, kinachojumuisha sekta kadhaa. FAT imeendelea kupitia matoleo:

* **FAT12**, inasaidia anwani za cluster za bit 12 na kushughulikia hadi clusters 4078 (4084 na UNIX).
* **FAT16**, ikiongeza hadi anwani za bit 16, hivyo inaruhusu clusters hadi 65,517.
* **FAT32**, ikipiga hatua zaidi na anwani za bit 32, ikiruhusu clusters 268,435,456 kwa kila volumu.

Kikwazo kikubwa katika matoleo yote ya FAT ni **ukubwa wa faili wa juu wa 4GB**, ulioanzishwa na uwanja wa bit 32 unaotumika kuhifadhi ukubwa wa faili.

Vipengele muhimu vya saraka ya mzizi, hasa kwa FAT12 na FAT16, ni pamoja na:

* **Jina la Faili/Folda** (hadi wahusika 8)
* **Sifa**
* **Tarehe za uumbaji, mabadiliko, na ufikiaji wa mwisho**
* **Anwani ya Jedwali la FAT** (inaonyesha cluster ya kuanzia ya faili)
* **Ukubwa wa Faili**

### EXT

**Ext2** ni mfumo wa faili wa kawaida kwa **sehemu zisizo na journaling** (**sehemu ambazo hazibadiliki sana**) kama sehemu ya boot. **Ext3/4** ni **journaling** na hutumiwa kawaida kwa **sehemu zingine**.

## **Metadata**

Faili zingine zina metadata. Habari hii ni kuhusu maudhui ya faili ambayo wakati mwingine inaweza kuwa ya kuvutia kwa mchambuzi kwani kulingana na aina ya faili, inaweza kuwa na habari kama:

* Kichwa
* Toleo la MS Office lililotumika
* Mwandishi
* Tarehe za uumbaji na mabadiliko ya mwisho
* Mfano wa kamera
* Koordinati za GPS
* Habari za picha

Unaweza kutumia zana kama [**exiftool**](https://exiftool.org) na [**Metadiver**](https://www.easymetadata.com/metadiver-2/) kupata metadata ya faili.

## **Urejeleaji wa Faili Zilizofutwa**

### Faili Zilizofutwa Zilizorekodiwa

Kama ilivyoonekana hapo awali kuna maeneo kadhaa ambapo faili bado imehifadhiwa baada ya "kufutwa". Hii ni kwa sababu kawaida kufutwa kwa faili kutoka mfumo wa faili kunaashiria tu kuwa imefutwa lakini data haiguswi. Hivyo, inawezekana kukagua rekodi za faili (kama MFT) na kupata faili zilizofutwa.

Pia, OS kawaida huhifadhi habari nyingi kuhusu mabadiliko ya mfumo wa faili na nakala za akiba, hivyo inawezekana kujaribu kuzitumia kurejesha faili au habari nyingi kadri inavyowezekana.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Kuchonga Faili**

**Kuchonga faili** ni mbinu inayojaribu **kupata faili katika wingi wa data**. Kuna njia 3 kuu ambazo zana kama hizi hufanya kazi: **Kulingana na vichwa na miguu ya aina za faili**, kulingana na **miundo** ya aina za faili na kulingana na **maudhui** yenyewe.

Kumbuka kwamba mbinu hii **haiwezi kufanya kazi kurejesha faili zilizovunjika**. Ikiwa faili **haijahifadhiwa katika sekta zinazofuatana**, basi mbinu hii haitakuwa na uwezo wa kuipata au angalau sehemu yake.

Kuna zana kadhaa ambazo unaweza kutumia kwa kuchonga faili zikionyesha aina za faili unazotaka kutafuta.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Kuchonga Msimu wa Data

Kuchonga Msimu wa Data ni sawa na Kuchonga Faili lakini **badala ya kutafuta faili kamili, inatafuta vipande vya habari vinavyovutia**.\
Kwa mfano, badala ya kutafuta faili kamili inayojumuisha URL zilizorekodiwa, mbinu hii itatafuta URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Kufuta Salama

Kwa wazi, kuna njia za **"kufuta salama" faili na sehemu ya rekodi kuhusu hizo**. Kwa mfano, inawezekana **kuandika tena maudhui** ya faili kwa data ya takataka mara kadhaa, na kisha **kuondoa** **rekodi** kutoka **$MFT** na **$LOGFILE** kuhusu faili hiyo, na **kuondoa Nakala za Kivuli za Volumu**.\
Unaweza kugundua kwamba hata ukifanya kitendo hicho kunaweza kuwa na **sehemu nyingine ambapo uwepo wa faili bado umeandikwa**, na hiyo ni kweli na sehemu ya kazi ya kitaalamu ya forensics ni kuzipata.

## Marejeo

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

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
