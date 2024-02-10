# Particije/Fajl Sistemi/Izvlačenje

## Particije/Fajl Sistemi/Izvlačenje

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Pogledajte [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Particije

Hard disk ili **SSD disk mogu sadržati različite particije** sa ciljem fizičkog razdvajanja podataka.\
**Minimalna** jedinica diska je **sektor** (obično sastavljen od 512B). Dakle, veličina svake particije mora biti višekratnik te veličine.

### MBR (master Boot Record)

Nalazi se u **prvom sektoru diska nakon 446B boot koda**. Ovaj sektor je bitan da bi se računaru pokazalo šta i odakle treba da se montira particija.\
Dozvoljava do **4 particije** (najviše **samo 1** može biti aktivna/pokretljiva). Međutim, ako vam je potrebno više particija, možete koristiti **proširene particije**. Poslednji bajt ovog prvog sektora je potpis boot zapisa **0x55AA**. Samo jedna particija može biti označena kao aktivna.\
MBR dozvoljava **maksimalno 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Od **bajta 440 do 443** MBR-a možete pronaći **Windows Disk Signature** (ako se koristi Windows). Logičko slovo pogona tvrdog diska zavisi od Windows Disk Signature. Promena ovog potpisa može sprečiti pokretanje Windows-a (alat: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Format**

| Offset      | Dužina     | Stavka               |
| ----------- | ---------- | -------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot kod             |
| 446 (0x1BE) | 16 (0x10)  | Prva particija       |
| 462 (0x1CE) | 16 (0x10)  | Druga particija      |
| 478 (0x1DE) | 16 (0x10)  | Treća particija      |
| 494 (0x1EE) | 16 (0x10)  | Četvrta particija    |
| 510 (0x1FE) | 2 (0x2)    | Potpis 0x55 0xAA     |

**Format Zapisa Particije**

| Offset    | Dužina   | Stavka                                                     |
| --------- | -------- | ---------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Aktivna oznaka (0x80 = pokretljiva)                        |
| 1 (0x01)  | 1 (0x01) | Početna glava                                              |
| 2 (0x02)  | 1 (0x01) | Početni sektor (bitovi 0-5); gornji bitovi cilindra (6- 7) |
| 3 (0x03)  | 1 (0x01) | Najnižih 8 bitova početnog cilindra                         |
| 4 (0x04)  | 1 (0x01) | Kod tipa particije (0x83 = Linux)                           |
| 5 (0x05)  | 1 (0x01) | Krajnja glava                                              |
| 6 (0x06)  | 1 (0x01) | Krajnji sektor (bitovi 0-5); gornji bitovi cilindra (6- 7) |
| 7 (0x07)  | 1 (0x01) | Najnižih 8 bitova krajnjeg cilindra                         |
| 8 (0x08)  | 4 (0x04) | Sektori pre particije (little endian)                      |
| 12 (0x0C) | 4 (0x04) | Sektori u particiji                                        |

Da biste montirali MBR u Linux-u, prvo morate dobiti početni offset (možete koristiti `fdisk` i komandu `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

A zatim koristite sledeći kod
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logičko blokiranje)**

**Logičko blokiranje** (**LBA**) je uobičajena šema koja se koristi za **određivanje lokacije blokova** podataka koji se čuvaju na računarskim skladištima, uglavnom sekundarnim skladišnim sistemima kao što su hard diskovi. LBA je posebno jednostavna linearna šema adresiranja; **blokovi se lociraju pomoću celobrojnog indeksa**, pri čemu je prvi blok LBA 0, drugi LBA 1, i tako dalje.

### GPT (GUID tabela particija)

GUID tabela particija, poznata kao GPT, ima prednost u odnosu na MBR (Master Boot Record) zbog svojih unapređenih mogućnosti. GPT se ističe na nekoliko načina:

- **Lokacija i veličina**: I GPT i MBR počinju od **sektora 0**. Međutim, GPT radi sa **64 bita**, za razliku od MBR-a koji radi sa 32 bita.
- **Ograničenja particija**: GPT podržava do **128 particija** na Windows sistemima i može da primi do **9,4ZB** podataka.
- **Nazivi particija**: Omogućava nazivanje particija sa do 36 Unicode karaktera.

**Otpornost i oporavak podataka**:

- **Redundantnost**: Za razliku od MBR-a, GPT ne ograničava particionisanje i podatke o pokretanju na jednom mestu. On replikuje ove podatke na celom disku, poboljšavajući integritet i otpornost podataka.
- **Ciklična redundancijska provjera (CRC)**: GPT koristi CRC za osiguravanje integriteta podataka. Aktivno nadgleda korupciju podataka i, kada je otkrivena, GPT pokušava da oporavi oštećene podatke sa druge lokacije na disku.

**Zaštitni MBR (LBA0)**:

- GPT održava kompatibilnost unazad putem zaštitnog MBR-a. Ova funkcija se nalazi u prostoru za nasleđeni MBR, ali je dizajnirana da spreči starije MBR bazirane alate da greškom prepišu GPT diskove, čime se čuva integritet podataka na GPT formatiranim diskovima.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hibridni MBR (LBA 0 + GPT)**

[Prema Vikipediji](https://en.wikipedia.org/wiki/GUID_Partition_Table)

U operativnim sistemima koji podržavaju **GPT bazirano pokretanje putem BIOS** usluga umesto EFI, prvi sektor se može koristiti za skladištenje prvog koraka koda **bootloadera**, ali **izmenjenog** da prepozna **GPT particije**. Bootloader u MBR-u ne sme pretpostavljati veličinu sektora od 512 bajtova.

**Zaglavlje tabele particija (LBA 1)**

[Prema Vikipediji](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Zaglavlje tabele particija definiše upotrebljive blokove na disku. Takođe definiše broj i veličinu unosa particija koji čine tabelu particija (offseti 80 i 84 u tabeli).

| Offset    | Dužina   | Sadržaj                                                                                                                                                                         |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bajtova  | Potpis ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ili 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)na malo-endijskim mašinama) |
| 8 (0x08)  | 4 bajta  | Revizija 1.0 (00h 00h 01h 00h) za UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bajta  | Veličina zaglavlja u malo-endijskom formatu (u bajtovima, obično 5Ch 00h 00h 00h ili 92 bajta)                                                                                                    |
| 16 (0x10) | 4 bajta  | [CRC32](https://en.wikipedia.org/wiki/CRC32) zaglavlja (offset +0 do veličine zaglavlja) u malo-endijskom formatu, pri čemu je ovo polje nula tokom izračunavanja                                |
| 20 (0x14) | 4 bajta  | Rezervisano; mora biti nula                                                                                                                                                          |
| 24 (0x18) | 8 bajtova  | Trenutni LBA (lokacija ovog kopiranog zaglavlja)                                                                                                                                      |
| 32 (0x20) | 8 bajtova  | Rezervni LBA (lokacija drugog kopiranog zaglavlja)                                                                                                                                  |
| 40 (0x28) | 8 bajtova  | Prvi upotrebljivi LBA za particije (poslednji LBA primarne tabele particija + 1)                                                                                                          |
| 48 (0x30) | 8 bajtova  | Poslednji upotrebljivi LBA (prvi LBA sekundarne tabele particija − 1)                                                                                                                       |
| 56 (0x38) | 16 bajtova | Disk GUID u mešovitom endian formatu                                                                                                                                                       |
| 72 (0x48) | 8 bajtova  | Početni LBA niza unosa particija (uvek 2 u primarnoj kopiji)                                                                                                        |
| 80 (0x50) | 4 bajta  | Broj unosa particija u nizu                                                                                                                                            |
| 84 (0x54) | 4 bajta  | Veličina jednog unosa particije (obično 80h ili 128)                                                                                                                           |
| 88 (0x58) | 4 bajta  | CRC32 niza unosa particija u malo-endijskom formatu                                                                                                                               |
| 92 (0x5C) | \*       | Rezervisano; mora biti nula za ostatak bloka (420 bajta za veličinu sektora od 512 bajtova; ali može biti više sa većim veličinama sektora)                                         |

**Unosi particija (LBA 2–33)**

| Format unosa particije GUID |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Dužina   | Sadržaj                                                                                                          |
| 0 (0x00)                    | 16 bajtova | [GUID particije](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mešoviti endian) |
| 16 (0x10)                   | 16 bajtova | Jedinstveni GUID particije (mešoviti endian)                                                                              |
| 32 (0x20)                   | 8 bajtova  | Prvi LBA ([malo-endijski](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 bajtova  | Poslednji LBA (uključujući, obično neparan)                                                                                 |
| 48 (0x30)                   | 8 bajtova  | Zastavice atributa (npr. bit 60 označava samo za čitanje)                                                                   |
| 56 (0x38)                   | 72 bajta | Naziv particije (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kodnih jedinica)                                   |

**Tipovi particija**

![](<../../../.gitbook/assets/image (492).png>)

Više tipova particija na [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspekcija

Nakon montiranja forenzičke slike pomoću [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), možete pregledati prvi sektor pomoću Windows alata [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na sledećoj slici je detektovan **MBR** na **sektoru 0** i interpretiran:

![](<../../../.gitbook/assets/image (494).png>)

Ako je umesto MBR-a tabela GPT, trebalo bi da se pojavi potpis _EFI PART_ u **sektoru 1** (koji je prazan na prethodnoj slici).
## Fajl-sistemi

### Lista Windows fajl-sistema

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** fajl-sistem je dizajniran oko svog osnovnog komponenta, tabele alokacije fajlova, koja se nalazi na početku volumena. Ovaj sistem čuva podatke održavajući **dve kopije** tabele, čime se obezbeđuje integritet podataka čak i ako je jedna kopija oštećena. Tabela, zajedno sa korenskim folderom, mora biti na **fiksnom mestu**, što je ključno za proces pokretanja sistema.

Osnovna jedinica skladištenja fajl-sistema je **klaster, obično 512B**, koji se sastoji od više sektora. FAT se razvijao kroz verzije:

- **FAT12**, podržava 12-bitne adrese klastera i može da upravlja do 4078 klastera (4084 sa UNIX-om).
- **FAT16**, unapređuje se na 16-bitne adrese, čime se omogućava do 65.517 klastera.
- **FAT32**, dalje napreduje sa 32-bitnim adresama, omogućavajući impresivnih 268.435.456 klastera po volumenu.

Značajno ograničenje kod svih verzija FAT-a je **maksimalna veličina fajla od 4GB**, nametnuta 32-bitnim poljem koje se koristi za skladištenje veličine fajla.

Ključne komponente korenskog direktorijuma, posebno za FAT12 i FAT16, uključuju:

- **Ime fajla/foldera** (do 8 karaktera)
- **Atributi**
- **Datumi kreiranja, izmene i poslednjeg pristupa**
- **Adresa FAT tabele** (koja označava početni klaster fajla)
- **Veličina fajla**

### EXT

**Ext2** je najčešći fajl-sistem za particije **bez žurnala** (**particije koje se retko menjaju**), poput boot particije. **Ext3/4** su **fajl-sistemi sa žurnalom** i obično se koriste za **ostale particije**.

## **Metapodaci**

Neke datoteke sadrže metapodatke. Ove informacije se odnose na sadržaj datoteke koji ponekad može biti zanimljiv analitičaru, jer u zavisnosti od vrste datoteke, može sadržati informacije kao što su:

* Naslov
* Korišćena verzija MS Office-a
* Autor
* Datumi kreiranja i poslednje izmene
* Model kamere
* GPS koordinate
* Informacije o slici

Možete koristiti alate poput [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/) da biste dobili metapodatke datoteke.

## **Obnova obrisanih datoteka**

### Evidentirane obrisane datoteke

Kao što je već viđeno, postoji nekoliko mesta gde se datoteka i dalje čuva nakon što je "obrisana". To je zato što brisanje datoteke sa fajl-sistema obično označava da je datoteka obrisana, ali podaci nisu dirnuti. Zatim je moguće pregledati registre datoteka (poput MFT-a) i pronaći obrisane datoteke.

Takođe, operativni sistem obično čuva mnogo informacija o promenama na fajl-sistemu i rezervnim kopijama, pa je moguće pokušati ih koristiti za obnovu datoteke ili što više informacija.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Izvlačenje fajlova**

**Izvlačenje fajlova** je tehnika koja pokušava **pronaći fajlove u velikoj količini podataka**. Postoje 3 glavna načina na koja alati poput ovih rade: **Na osnovu zaglavlja i podnožja fajl-tipova**, na osnovu **strukture fajl-tipova** i na osnovu **sadržaja** samog fajla.

Napomena: Ova tehnika **ne funkcioniše za obnovu fragmentiranih fajlova**. Ako fajl **nije smešten u kontinuiranim sektorima**, tada ova tehnika neće moći da ga pronađe ili barem deo njega.

Postoji nekoliko alata koje možete koristiti za izvlačenje fajlova, navodeći fajl-tipove koje želite pretražiti.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Izvlačenje podataka iz **C**arvinga

Izvlačenje podataka iz Carvinga je slično izvlačenju fajlova, ali **umesto potpunih fajlova, traži interesantne fragmente** informacija.\
Na primer, umesto potpunog fajla koji sadrži evidentirane URL-ove, ova tehnika će tražiti URL-ove.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Sigurno brisanje

Očigledno, postoje načini za **"sigurno" brisanje fajlova i delova zapisa o njima**. Na primer, moguće je **prepisati sadržaj** fajla sa beskorisnim podacima nekoliko puta, a zatim **ukloniti** zapise iz **$MFT** i **$LOGFILE** o fajlu, i **ukloniti rezervne kopije senki volumena**.\
Primetićete da čak i prilikom izvršavanja te radnje može postojati **drugi deo gde se još uvek evidentira postojanje fajla**, i to je tačno, a deo posla forenzičkog stručnjaka je da ih pronađe.

## Reference

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje tako što ćete slati PR-ove na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
