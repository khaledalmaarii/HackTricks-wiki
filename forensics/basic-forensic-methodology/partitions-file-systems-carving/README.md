# Partisies/ Lêersisteme/ Uitsnyding

## Partisies/ Lêersisteme/ Uitsnyding

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Partisies

'n Harde skyf of 'n **SSD-skyf kan verskillende partisies bevat** met die doel om data fisies te skei.\
Die **minimum** eenheid van 'n skyf is die **sektor** (gewoonlik saamgestel uit 512B). Dus moet elke partisie grootte 'n veelvoud van daardie grootte wees.

### MBR (Master Boot Record)

Dit word toegewys in die **eerste sektor van die skyf na die 446B van die opstartkode**. Hierdie sektor is noodsaaklik om aan die rekenaar aan te dui wat en waarvandaan 'n partisie gemonteer moet word.\
Dit laat tot **4 partisies** toe (slegs **1** kan aktief/ opstartbaar wees). As jy egter meer partisies nodig het, kan jy **uitgebreide partisies** gebruik. Die **laaste byte** van hierdie eerste sektor is die opstartrekord-handtekening **0x55AA**. Slegs een partisie kan as aktief gemerk word.\
MBR laat **maksimum 2.2TB** toe.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Vanaf die **byte 440 tot 443** van die MBR kan jy die **Windows Disk Signature** vind (as Windows gebruik word). Die logiese aanduiding van die harde skyf hang af van die Windows Disk Signature. Die verandering van hierdie handtekening kan voorkom dat Windows opstart (hulpmiddel: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Formaat**

| Offset      | Lengte     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Opstartkode         |
| 446 (0x1BE) | 16 (0x10)  | Eerste Partisie     |
| 462 (0x1CE) | 16 (0x10)  | Tweede Partisie     |
| 478 (0x1DE) | 16 (0x10)  | Derde Partisie      |
| 494 (0x1EE) | 16 (0x10)  | Vierde Partisie     |
| 510 (0x1FE) | 2 (0x2)    | Handtekening 0x55 0xAA |

**Partisie Rekord Formaat**

| Offset    | Lengte   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktiewe vlag (0x80 = opstartbaar)                      |
| 1 (0x01)  | 1 (0x01) | Beginkop                                               |
| 2 (0x02)  | 1 (0x01) | Beginsektor (bits 0-5); boonste bits van silinder (6-7) |
| 3 (0x03)  | 1 (0x01) | Begin silinder laagste 8 bits                           |
| 4 (0x04)  | 1 (0x01) | Partisie tipe kode (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | Eindkop                                                |
| 6 (0x06)  | 1 (0x01) | Eindsektor (bits 0-5); boonste bits van silinder (6-7)  |
| 7 (0x07)  | 1 (0x01) | Eind silinder laagste 8 bits                            |
| 8 (0x08)  | 4 (0x04) | Sektors voor partisie (little endian)                   |
| 12 (0x0C) | 4 (0x04) | Sektors in partisie                                    |

Om 'n MBR in Linux te monteer, moet jy eers die beginverskuiwing kry (jy kan `fdisk` en die `p`-opdrag gebruik)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

En gebruik dan die volgende kode
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logiese blokadressering)**

**Logiese blokadressering** (**LBA**) is 'n algemene skema wat gebruik word om die ligging van blokke data op rekenaarstoorapparate, gewoonlik sekondêre stoorstelsels soos harde skywe, te spesifiseer. LBA is 'n besonder eenvoudige lineêre adresseringstelsel; blokke word geïdentifiseer deur 'n heelgetalindeks, waar die eerste blok LBA 0 is, die tweede LBA 1, en so aan.

### GPT (GUID-partisietabel)

Die GUID-partisietabel, bekend as GPT, word verkies vir sy verbeterde vermoëns in vergelyking met MBR (Meester Opstartrekord). Kenmerkend vir sy unieke identifiseerder vir partisies, steek GPT uit op verskeie maniere:

- **Ligging en Grootte**: Beide GPT en MBR begin by **sektor 0**. Tog werk GPT met **64-bits**, teenoor MBR se 32-bits.
- **Partisiebeperkings**: GPT ondersteun tot **128 partisies** op Windows-stelsels en kan tot **9.4ZB** data akkommodeer.
- **Partisienames**: Bied die vermoë om partisies te benoem met tot 36 Unicode-karakters.

**Databestendigheid en -herwinning**:

- **Redundansie**: Anders as MBR beperk GPT partisionering en opstartdata nie tot 'n enkele plek nie. Dit dupliseer hierdie data oor die skyf, wat data-integriteit en bestendigheid verbeter.
- **Sikliese Redundansie Kontrole (CRC)**: GPT gebruik CRC om data-integriteit te verseker. Dit monitor aktief vir datakorrupsie, en wanneer dit opgespoor word, probeer GPT om die gekorruppeerde data van 'n ander skyfplek te herstel.

**Beskermende MBR (LBA0)**:

- GPT handhaaf agterwaartse verenigbaarheid deur middel van 'n beskermende MBR. Hierdie funksie bly in die erfenis MBR-ruimte, maar is ontwerp om te voorkom dat ouer MBR-gebaseerde hulpprogramme GPT-skywe per ongeluk oorskryf, en sodoende die data-integriteit op GPT-geformateerde skywe beskerm.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hibriede MBR (LBA 0 + GPT)**

[Vanaf Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

In bedryfstelsels wat **GPT-gebaseerde opstart deur BIOS**-dienste ondersteun eerder as EFI, kan die eerste sektor ook steeds gebruik word om die eerste stadium van die **opstartlader**-kode te stoor, maar **aangepas** om **GPT-partisies** te herken. Die opstartlader in die MBR mag nie 'n sektor-grootte van 512 byte aanneem nie.

**Partisietabelkop (LBA 1)**

[Vanaf Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Die partisietabelkop definieer die bruikbare blokke op die skyf. Dit definieer ook die aantal en grootte van die partisieinskrywings wat die partisietabel uitmaak (offsets 80 en 84 in die tabel).

| Offset    | Lengte   | Inhoud                                                                                                                                                                          |
| --------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 byte   | Handtekening ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h of 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)op klein-eindige masjiene) |
| 8 (0x08)  | 4 byte   | Hersiening 1.0 (00h 00h 01h 00h) vir UEFI 2.8                                                                                                                                   |
| 12 (0x0C) | 4 byte   | Kopgrootte in klein-eindige (in byte, gewoonlik 5Ch 00h 00h 00h of 92 byte)                                                                                                     |
| 16 (0x10) | 4 byte   | [CRC32](https://en.wikipedia.org/wiki/CRC32) van die kop (offset +0 tot kopgrootte) in klein-eindige, met hierdie veld nul gemaak tydens berekening                                |
| 20 (0x14) | 4 byte   | Voorbehou; moet nul wees                                                                                                                                                        |
| 24 (0x18) | 8 byte   | Huidige LBA (ligging van hierdie kopie van die kop)                                                                                                                             |
| 32 (0x20) | 8 byte   | Rugsteun LBA (ligging van die ander kopie van die kop)                                                                                                                          |
| 40 (0x28) | 8 byte   | Eerste bruikbare LBA vir partisies (laaste LBA van primêre partisietabel + 1)                                                                                                   |
| 48 (0x30) | 8 byte   | Laaste bruikbare LBA (eerste LBA van sekondêre partisietabel - 1)                                                                                                                |
| 56 (0x38) | 16 byte  | Skyf-GUID in gemengde eindige                                                                                                                                                    |
| 72 (0x48) | 8 byte   | Begin-LBA van 'n reeks partisieinskrywings (altyd 2 in primêre kopie)                                                                                                            |
| 80 (0x50) | 4 byte   | Aantal partisieinskrywings in reeks                                                                                                                                              |
| 84 (0x54) | 4 byte   | Grootte van 'n enkele partisieinskrywing (gewoonlik 80h of 128)                                                                                                                  |
| 88 (0x58) | 4 byte   | CRC32 van die reeks partisieinskrywings in klein-eindige                                                                                                                         |
| 92 (0x5C) | \*       | Voorbehou; moet nulle wees vir die res van die blok (420 byte vir 'n sektorgrootte van 512 byte; maar kan meer wees met groter sektorgroottes)                                   |

**Partisieinskrywings (LBA 2–33)**

| GUID-partisieinskrywingsformaat |          |                                                                                                                     |
| ------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------- |
| Offset                         | Lengte   | Inhoud                                                                                                              |
| 0 (0x00)                       | 16 byte  | [Partisietipe-GUID](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (gemengde eindige) |
| 16 (0x10)                      | 16 byte  | Unieke partisie-GUID (gemengde eindige)                                                                             |
| 32 (0x20)                      | 8 byte   | Eerste LBA ([klein-eindige](https://en.wikipedia.org/wiki/Little\_endian))                                          |
| 40 (0x28)                      | 8 byte   | Laaste LBA (inklusief, gewoonlik oneweredig)                                                                        |
| 48 (0x30)                      | 8 byte   | Kenmerkvlaggies (bv. bit 60 dui op skryfbeskerming)                                                                 |
| 56 (0x38)                      | 72 byte  | Partisienaam (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-kode-eenhede)                                     |

**Partisietipes**

![](<../../../.gitbook/assets/image (492).png>)

Meer partisietipes in [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspekteer

Nadat die forensiese beeld met [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) gemoniteer is, kan jy die eerste sektor inspekteer met die Windows-hulpmiddel [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** In die volgende afbeelding is 'n **MBR** op **sektor 0** opgespoor en geïnterpreteer:

![](<../../../.gitbook/assets/image (494).png>)

As dit 'n **GPT-tabel in plaas van 'n MBR** was, sou die handtekening _EFI PART_ in **sektor 1** verskyn (wat in die vorige afbeelding leeg is).
## Lêerstelsels

### Lys van Windows-lêerstelsels

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

Die **FAT (File Allocation Table)** lêerstelsel is ontwerp rondom sy kernkomponent, die lêertoewysingstabel, wat by die begin van die volume geplaas is. Hierdie stelsel beskerm data deur **twee kopieë** van die tabel te behou, wat data-integriteit verseker selfs as een daarvan beskadig is. Die tabel, tesame met die hoofmap, moet in 'n **vasgestelde posisie** wees, wat noodsaaklik is vir die opstartproses van die stelsel.

Die basiese eenheid van stoor van die lêerstelsel is 'n **kluster, gewoonlik 512B**, wat uit verskeie sektore bestaan. FAT het deur weergawes geëvolueer:

- **FAT12**, wat 12-bits klusteradres ondersteun en tot 4078 klusters hanteer (4084 met UNIX).
- **FAT16**, wat verbeter tot 16-bits adresse, en dus tot 65,517 klusters kan akkommodeer.
- **FAT32**, wat verder gevorder het met 32-bits adresse, wat 'n indrukwekkende 268,435,456 klusters per volume moontlik maak.

'n Belangrike beperking oor alle FAT-weergawes is die **maksimum lêergrootte van 4GB**, wat opgelê word deur die 32-bits veld wat vir lêergrootte stoor gebruik word.

Sleutelkomponente van die hoofgids, veral vir FAT12 en FAT16, sluit in:

- **Lêer/Map Naam** (tot 8 karakters)
- **Eienskappe**
- **Skep-, Wysigings- en Laaste Toegangsdatums**
- **FAT Tabeladres** (wat die beginkluster van die lêer aandui)
- **Lêergrootte**

### EXT

**Ext2** is die mees algemene lêerstelsel vir **nie-joernalering** partisies (**partisies wat nie veel verander nie**) soos die opstartpartisie. **Ext3/4** is **joernalering** en word gewoonlik gebruik vir die **res van die partisies**.

## **Metadata**

Sommige lêers bevat metadata. Hierdie inligting gaan oor die inhoud van die lêer wat soms interessant kan wees vir 'n analis as gevolg van die lêertipe, wat inligting soos die volgende kan bevat:

* Titel
* MS Office-weergawe wat gebruik is
* Outeur
* Skep- en laaste wysigingsdatums
* Kamera model
* GPS-koördinate
* Beeldinligting

Jy kan hulpmiddels soos [**exiftool**](https://exiftool.org) en [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gebruik om die metadata van 'n lêer te verkry.

## **Herwinning van Verwyderde Lêers**

### Gelogde Verwyderde Lêers

Soos voorheen gesien is daar verskeie plekke waar die lêer steeds gestoor word nadat dit "verwyder" is. Dit is omdat die verwydering van 'n lêer uit 'n lêerstelsel dit gewoonlik merk as verwyder, maar die data word nie geraak nie. Daarom is dit moontlik om die rekords van die lêers (soos die MFT) te ondersoek en die verwyderde lêers te vind.

Die bedryfstelsel stoor ook gewoonlik baie inligting oor lêerstelselveranderinge en rugsteun, so dit is moontlik om te probeer om dit te gebruik om die lêer of soveel moontlike inligting te herwin.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Lêer Carving**

**Lêer carving** is 'n tegniek wat probeer om lêers in die massa data te vind. Daar is 3 hoofmaniere waarop sulke gereedskap werk: **Gebaseer op lêertipes se koppe en voette**, gebaseer op lêertipes se **strukture** en gebaseer op die **inhoud** self.

Let daarop dat hierdie tegniek **nie werk om gefragmenteerde lêers te herwin nie**. As 'n lêer **nie in aaneenlopende sektore gestoor word nie**, sal hierdie tegniek dit nie kan vind nie, of ten minste 'n deel daarvan.

Daar is verskeie gereedskap wat jy kan gebruik vir lêer Carving deur die lêertipes aan te dui wat jy wil soek

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Datastroom **C**arving

Datastroom Carving is soortgelyk aan Lêer Carving, maar **in plaas daarvan om volledige lêers te soek, soek dit na interessante fragmente** van inligting.\
Byvoorbeeld, in plaas daarvan om 'n volledige lêer te soek wat gelogde URL's bevat, sal hierdie tegniek soek na URL's.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Veilige Verwydering

Daar is natuurlik maniere om lêers en dele van logboeke oor hulle **"veilig" te verwyder**. Dit is byvoorbeeld moontlik om die inhoud van 'n lêer herhaaldelik met rommeldata te **oorlê**, en dan die **logboeke** van die **$MFT** en **$LOGFILE** oor die lêer te **verwyder**, en die **Volume Shadow Copies** te **verwyder**.\
Jy mag opmerk dat selfs nadat daardie aksie uitgevoer is, daar **ander dele is waar die bestaan van die lêer steeds gelog word**, en dit is waar en deel van die forensiese professionele se werk is om dit te vind.

## Verwysings

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
