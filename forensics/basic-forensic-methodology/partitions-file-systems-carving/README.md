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

Hard disk ili **SSD disk može sadržati različite particije** sa ciljem fizičkog razdvajanja podataka.\
**Minimalna** jedinica diska je **sektor** (normalno sastavljen od 512B). Tako da, veličina svake particije mora biti višekratnik te veličine.

### MBR (master Boot Record)

Dodeljuje se u **prvom sektoru diska nakon 446B boot koda**. Ovaj sektor je ključan za indikaciju PC-u šta i odakle treba da se montira particija.\
Omogućava do **4 particije** (najviše **samo 1** može biti aktivna/**bootable**). Međutim, ako vam je potrebno više particija, možete koristiti **proširene particije**. **Zadnji bajt** ovog prvog sektora je potpis boot zapisa **0x55AA**. Samo jedna particija može biti označena kao aktivna.\
MBR omogućava **maksimalno 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Od **bajtova 440 do 443** MBR-a možete pronaći **Windows Disk Signature** (ako se koristi Windows). Logičko slovo diska hard diska zavisi od Windows Disk Signature. Promena ovog potpisa može sprečiti Windows da se pokrene (alat: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | Prva particija     |
| 462 (0x1CE) | 16 (0x10)  | Druga particija    |
| 478 (0x1DE) | 16 (0x10)  | Treća particija     |
| 494 (0x1EE) | 16 (0x10)  | Četvrta particija    |
| 510 (0x1FE) | 2 (0x2)    | Potpis 0x55 0xAA |

**Format zapisa particije**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktivna zastavica (0x80 = bootable)                   |
| 1 (0x01)  | 1 (0x01) | Početna glava                                         |
| 2 (0x02)  | 1 (0x01) | Početni sektor (bitovi 0-5); gornji bitovi cilindra (6- 7) |
| 3 (0x03)  | 1 (0x01) | Početni cilindar najniži 8 bitova                     |
| 4 (0x04)  | 1 (0x01) | Kod tipa particije (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | Kraj glave                                            |
| 6 (0x06)  | 1 (0x01) | Kraj sektora (bitovi 0-5); gornji bitovi cilindra (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Kraj cilindra najniži 8 bitova                        |
| 8 (0x08)  | 4 (0x04) | Sektori pre particije (mali endian)                   |
| 12 (0x0C) | 4 (0x04) | Sektori u particiji                                   |

Da biste montirali MBR u Linux-u, prvo morate dobiti početni offset (možete koristiti `fdisk` i `p` komandu)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

I zatim koristite sledeći kod
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logičko adresiranje blokova)**

**Logičko adresiranje blokova** (**LBA**) je uobičajen sistem koji se koristi za **specifikaciju lokacije blokova** podataka koji su pohranjeni na uređajima za skladištenje računara, obično sekundarnim sistemima skladištenja kao što su hard diskovi. LBA je posebno jednostavan linearni sistem adresiranja; **blokovi se lociraju pomoću celobrojnih indeksa**, pri čemu je prvi blok LBA 0, drugi LBA 1, i tako dalje.

### GPT (GUID tabela particija)

GUID tabela particija, poznata kao GPT, favorizovana je zbog svojih poboljšanih mogućnosti u poređenju sa MBR (Master Boot Record). Karakteristična po svom **globalno jedinstvenom identifikatoru** za particije, GPT se izdvaja na nekoliko načina:

* **Lokacija i veličina**: I GPT i MBR počinju na **sektoru 0**. Međutim, GPT radi na **64bita**, u kontrastu sa MBR-ovih 32bita.
* **Ograničenja particija**: GPT podržava do **128 particija** na Windows sistemima i može da primi do **9.4ZB** podataka.
* **Imena particija**: Nudi mogućnost imenovanja particija sa do 36 Unicode karaktera.

**Otpornost podataka i oporavak**:

* **Redundancija**: Za razliku od MBR-a, GPT ne ograničava particionisanje i podatke za pokretanje na jedno mesto. Replikuje ove podatke širom diska, poboljšavajući integritet i otpornost podataka.
* **Ciklična kontrola redundancije (CRC)**: GPT koristi CRC za osiguranje integriteta podataka. Aktivno prati oštećenje podataka, a kada se otkrije, GPT pokušava da povrati oštećene podatke iz druge lokacije na disku.

**Zaštitni MBR (LBA0)**:

* GPT održava unazad kompatibilnost putem zaštitnog MBR-a. Ova funkcija se nalazi u prostoru nasleđenog MBR-a, ali je dizajnirana da spreči starije MBR-bazirane alate da greškom prepisuju GPT diskove, čime se štiti integritet podataka na GPT-formatiranim diskovima.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hibridni MBR (LBA 0 + GPT)**

[Iz Wikipedije](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

U operativnim sistemima koji podržavaju **GPT-bazirano pokretanje putem BIOS** usluga umesto EFI, prvi sektor se takođe može koristiti za skladištenje prve faze **bootloader** koda, ali **modifikovan** da prepozna **GPT** **particije**. Bootloader u MBR-u ne sme da pretpostavlja veličinu sektora od 512 bajta.

**Zaglavlje tabele particija (LBA 1)**

[Iz Wikipedije](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Zaglavlje tabele particija definiše upotrebljive blokove na disku. Takođe definiše broj i veličinu unosa particija koji čine tabelu particija (offseti 80 i 84 u tabeli).

| Offset    | Dužina   | Sadržaj                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bajta  | Potpis ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ili 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)na little-endian mašinama) |
| 8 (0x08)  | 4 bajta  | Revizija 1.0 (00h 00h 01h 00h) za UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bajta  | Veličina zaglavlja u little endian (u bajtovima, obično 5Ch 00h 00h 00h ili 92 bajta)                                                                                                    |
| 16 (0x10) | 4 bajta  | [CRC32](https://en.wikipedia.org/wiki/CRC32) zaglavlja (offset +0 do veličine zaglavlja) u little endian, sa ovim poljem nula tokom izračunavanja                                |
| 20 (0x14) | 4 bajta  | Rezervisano; mora biti nula                                                                                                                                                          |
| 24 (0x18) | 8 bajta  | Trenutni LBA (lokacija ove kopije zaglavlja)                                                                                                                                      |
| 32 (0x20) | 8 bajta  | Backup LBA (lokacija druge kopije zaglavlja)                                                                                                                                  |
| 40 (0x28) | 8 bajta  | Prvi upotrebljivi LBA za particije (poslednji LBA primarne tabele particija + 1)                                                                                                          |
| 48 (0x30) | 8 bajta  | Poslednji upotrebljivi LBA (prvi LBA sekundarne tabele particija − 1)                                                                                                                       |
| 56 (0x38) | 16 bajta | Disk GUID u mešovitom endian                                                                                                                                                       |
| 72 (0x48) | 8 bajta  | Početni LBA niza unosa particija (uvek 2 u primarnoj kopiji)                                                                                                        |
| 80 (0x50) | 4 bajta  | Broj unosa particija u nizu                                                                                                                                            |
| 84 (0x54) | 4 bajta  | Veličina jednog unosa particije (obično 80h ili 128)                                                                                                                           |
| 88 (0x58) | 4 bajta  | CRC32 niza unosa particija u little endian                                                                                                                               |
| 92 (0x5C) | \*       | Rezervisano; mora biti nule za ostatak bloka (420 bajta za veličinu sektora od 512 bajta; ali može biti više sa većim veličinama sektora)                                         |

**Unosi particija (LBA 2–33)**

| Format unosa GUID particije |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Dužina   | Sadržaj                                                                                                          |
| 0 (0x00)                    | 16 bajta | [GUID tipa particije](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mešovit endian) |
| 16 (0x10)                   | 16 bajta | Jedinstveni GUID particije (mešovit endian)                                                                              |
| 32 (0x20)                   | 8 bajta  | Prvi LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 bajta  | Poslednji LBA (uključivo, obično neparan)                                                                                 |
| 48 (0x30)                   | 8 bajta  | Zastavice atributa (npr. bit 60 označava samo za čitanje)                                                                   |
| 56 (0x38)                   | 72 bajta | Ime particije (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kodnih jedinica)                                   |

**Tipovi particija**

![](<../../../.gitbook/assets/image (492).png>)

Više tipova particija na [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Istraživanje

Nakon montiranja forenzičke slike sa [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), možete ispitati prvi sektor koristeći Windows alat [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na sledećoj slici je otkriven **MBR** na **sektoru 0** i interpretiran:

![](<../../../.gitbook/assets/image (494).png>)

Ako je to bila **GPT tabela umesto MBR-a**, trebala bi se pojaviti potpis _EFI PART_ u **sektoru 1** (koji je na prethodnoj slici prazan).

## Sistemi datoteka

### Lista Windows sistema datoteka

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

**FAT (Tabela alokacije datoteka)** sistem datoteka je dizajniran oko svoje osnovne komponente, tabele alokacije datoteka, koja se nalazi na početku volumena. Ovaj sistem štiti podatke održavanjem **dvije kopije** tabele, osiguravajući integritet podataka čak i ako je jedna oštećena. Tabela, zajedno sa korenskim folderom, mora biti na **fiksnoj lokaciji**, što je ključno za proces pokretanja sistema.

Osnovna jedinica skladištenja sistema datoteka je **klaster, obično 512B**, koji se sastoji od više sektora. FAT se razvijao kroz verzije:

* **FAT12**, podržava 12-bitne adrese klastera i obrađuje do 4078 klastera (4084 sa UNIX-om).
* **FAT16**, unapređuje na 16-bitne adrese, čime se omogućava do 65,517 klastera.
* **FAT32**, dalje napreduje sa 32-bitnim adresama, omogućavajući impresivnih 268,435,456 klastera po volumenu.

Značajno ograničenje kod FAT verzija je **maksimalna veličina datoteke od 4GB**, koju nameće 32-bitno polje korišćeno za skladištenje veličine datoteke.

Ključne komponente korenskog direktorijuma, posebno za FAT12 i FAT16, uključuju:

* **Ime datoteke/foldera** (do 8 karaktera)
* **Atributi**
* **Datumi kreiranja, modifikacije i poslednjeg pristupa**
* **Adresa FAT tabele** (koja označava početni klaster datoteke)
* **Veličina datoteke**

### EXT

**Ext2** je najčešći sistem datoteka za **ne-journal** particije (**particije koje se ne menjaju mnogo**) kao što je particija za pokretanje. **Ext3/4** su **journal** i obično se koriste za **ostale particije**.

## **Metapodaci**

Neke datoteke sadrže metapodatke. Ove informacije se odnose na sadržaj datoteke koji ponekad može biti zanimljiv analitičaru jer, u zavisnosti od tipa datoteke, može sadržati informacije kao što su:

* Naslov
* Verzija MS Office-a koja se koristi
* Autor
* Datumi kreiranja i poslednje modifikacije
* Model kamere
* GPS koordinate
* Informacije o slici

Možete koristiti alate kao što su [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/) da dobijete metapodatke datoteke.

## **Oporavak obrisanih datoteka**

### Zabeležene obrisane datoteke

Kao što je ranije viđeno, postoji nekoliko mesta gde je datoteka još uvek sačuvana nakon što je "obrisana". To je zato što obično brisanje datoteke iz sistema datoteka samo označava da je obrisana, ali podaci nisu dodirnuti. Tada je moguće ispitati registre datoteka (kao što je MFT) i pronaći obrisane datoteke.

Takođe, OS obično čuva mnogo informacija o promenama u sistemu datoteka i rezervnim kopijama, tako da je moguće pokušati koristiti ih za oporavak datoteke ili što više informacija.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **File Carving**

**File carving** je tehnika koja pokušava da **pronađe datoteke u masi podataka**. Postoje 3 glavna načina na koje alati poput ovog funkcionišu: **Na osnovu zaglavlja i repova tipova datoteka**, na osnovu struktura tipova datoteka i na osnovu **sadržaja** samog.

Napomena da ova tehnika **ne funkcioniše za vraćanje fragmentisanih datoteka**. Ako datoteka **nije pohranjena u kontiguitetnim sektorima**, tada ova tehnika neće moći da je pronađe ili barem deo nje.

Postoji nekoliko alata koje možete koristiti za file carving koji označavaju tipove datoteka koje želite da pretražujete.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Data Stream **C**arving

Data Stream Carving je sličan File Carving-u, ali **umesto da traži kompletne datoteke, traži zanimljive fragmente** informacija.\
Na primer, umesto da traži kompletnu datoteku koja sadrži zabeležene URL-ove, ova tehnika će tražiti URL-ove.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Sigurno brisanje

Očigledno, postoje načini da se **"sigurno" obrišu datoteke i deo logova o njima**. Na primer, moguće je **prepisati sadržaj** datoteke sa smešnim podacima nekoliko puta, a zatim **ukloniti** **logove** iz **$MFT** i **$LOGFILE** o datoteci, i **ukloniti kopije senki volumena**.\
Možda ćete primetiti da čak i nakon izvođenja te akcije može postojati **drugi delovi gde je postojanje datoteke još uvek zabeleženo**, i to je tačno, a deo posla forenzičkog stručnjaka je da ih pronađe.

## Reference

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Sertifikovani Digitalni Forenzik Windows**

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
