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

Dysk twardy lub **dysk SSD może zawierać różne partycje** w celu fizycznego oddzielenia danych.\
**Minimalną** jednostką dysku jest **sektor** (zwykle składający się z 512B). Zatem rozmiar każdej partycji musi być wielokrotnością tego rozmiaru.

### MBR (master Boot Record)

Jest przydzielony w **pierwszym sektorze dysku po 446B kodu rozruchowego**. Ten sektor jest niezbędny, aby wskazać PC, co i skąd powinno być zamontowane jako partycja.\
Pozwala na maksymalnie **4 partycje** (najwyżej **tylko 1** może być aktywna/**rozruchowa**). Jednak jeśli potrzebujesz więcej partycji, możesz użyć **partycji rozszerzonej**. **Ostatni bajt** tego pierwszego sektora to sygnatura rekordu rozruchowego **0x55AA**. Tylko jedna partycja może być oznaczona jako aktywna.\
MBR pozwala na **maks. 2.2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

W **bajtach od 440 do 443** MBR możesz znaleźć **Sygnaturę Dysku Windows** (jeśli używany jest Windows). Litera logicznego dysku twardego zależy od Sygnatury Dysku Windows. Zmiana tej sygnatury może uniemożliwić uruchomienie Windows (narzędzie: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Kod rozruchowy      |
| 446 (0x1BE) | 16 (0x10)  | Pierwsza partycja   |
| 462 (0x1CE) | 16 (0x10)  | Druga partycja      |
| 478 (0x1DE) | 16 (0x10)  | Trzecia partycja    |
| 494 (0x1EE) | 16 (0x10)  | Czwarta partycja    |
| 510 (0x1FE) | 2 (0x2)    | Sygnatura 0x55 0xAA |

**Format rekordu partycji**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Flaga aktywności (0x80 = rozruchowa)                  |
| 1 (0x01)  | 1 (0x01) | Głowica startowa                                       |
| 2 (0x02)  | 1 (0x01) | Sektor startowy (bity 0-5); wyższe bity cylindra (6- 7) |
| 3 (0x03)  | 1 (0x01) | Cylinder startowy najniższe 8 bitów                    |
| 4 (0x04)  | 1 (0x01) | Kod typu partycji (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | Głowica końcowa                                        |
| 6 (0x06)  | 1 (0x01) | Sektor końcowy (bity 0-5); wyższe bity cylindra (6- 7) |
| 7 (0x07)  | 1 (0x01) | Cylinder końcowy najniższe 8 bitów                     |
| 8 (0x08)  | 4 (0x04) | Sektory poprzedzające partycję (little endian)        |
| 12 (0x0C) | 4 (0x04) | Sektory w partycji                                     |

Aby zamontować MBR w systemie Linux, najpierw musisz uzyskać offset startowy (możesz użyć `fdisk` i polecenia `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

A następnie użyj następującego kodu
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) to powszechnie stosowany schemat do **określania lokalizacji bloków** danych przechowywanych na urządzeniach pamięci masowej komputerów, zazwyczaj w systemach pamięci wtórnej, takich jak dyski twarde. LBA jest szczególnie prostym liniowym schematem adresowania; **bloki są lokalizowane za pomocą indeksu całkowitego**, przy czym pierwszy blok to LBA 0, drugi LBA 1, i tak dalej.

### GPT (GUID Partition Table)

Tabela partycji GUID, znana jako GPT, jest preferowana ze względu na swoje ulepszone możliwości w porównaniu do MBR (Master Boot Record). Wyróżnia się **globalnie unikalnym identyfikatorem** dla partycji, GPT wyróżnia się w kilku aspektach:

* **Lokalizacja i rozmiar**: Zarówno GPT, jak i MBR zaczynają się od **sektora 0**. Jednak GPT działa na **64 bitach**, w przeciwieństwie do 32 bitów MBR.
* **Limity partycji**: GPT obsługuje do **128 partycji** w systemach Windows i pomieści do **9,4ZB** danych.
* **Nazwy partycji**: Oferuje możliwość nadawania nazw partycjom z maksymalnie 36 znakami Unicode.

**Odporność danych i odzyskiwanie**:

* **Redundancja**: W przeciwieństwie do MBR, GPT nie ogranicza partycjonowania i danych rozruchowych do jednego miejsca. Replikuje te dane w całym dysku, co zwiększa integralność danych i odporność.
* **Cykliczna kontrola redundancji (CRC)**: GPT stosuje CRC, aby zapewnić integralność danych. Aktywnie monitoruje uszkodzenia danych, a po ich wykryciu GPT próbuje odzyskać uszkodzone dane z innej lokalizacji na dysku.

**Ochronny MBR (LBA0)**:

* GPT utrzymuje zgodność wsteczną poprzez ochronny MBR. Ta funkcja znajduje się w przestrzeni MBR, ale jest zaprojektowana, aby zapobiec przypadkowemu nadpisaniu dysków GPT przez starsze narzędzia oparte na MBR, co chroni integralność danych na dyskach sformatowanych w GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID\_Partition\_Table\_Scheme.svg/800px-GUID\_Partition\_Table\_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

W systemach operacyjnych, które obsługują **rozruch oparty na GPT przez usługi BIOS** zamiast EFI, pierwszy sektor może być również używany do przechowywania pierwszej fazy kodu **bootloadera**, ale **zmodyfikowanego** w celu rozpoznawania **partycji GPT**. Bootloader w MBR nie powinien zakładać rozmiaru sektora wynoszącego 512 bajtów.

**Nagłówek tabeli partycji (LBA 1)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

Nagłówek tabeli partycji definiuje użyteczne bloki na dysku. Definiuje również liczbę i rozmiar wpisów partycji, które tworzą tabelę partycji (offsety 80 i 84 w tabeli).

| Offset    | Długość  | Zawartość                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bajtów | Podpis ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h lub 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8) na maszynach little-endian) |
| 8 (0x08)  | 4 bajty  | Wersja 1.0 (00h 00h 01h 00h) dla UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bajty  | Rozmiar nagłówka w formacie little endian (w bajtach, zazwyczaj 5Ch 00h 00h 00h lub 92 bajty)                                                                                                    |
| 16 (0x10) | 4 bajty  | [CRC32](https://en.wikipedia.org/wiki/CRC32) nagłówka (offset +0 do rozmiaru nagłówka) w formacie little endian, z tym polem wyzerowanym podczas obliczeń                                |
| 20 (0x14) | 4 bajty  | Zarezerwowane; musi być zerowe                                                                                                                                                          |
| 24 (0x18) | 8 bajtów | Bieżące LBA (lokalizacja tej kopii nagłówka)                                                                                                                                      |
| 32 (0x20) | 8 bajtów | Kopia zapasowa LBA (lokalizacja drugiej kopii nagłówka)                                                                                                                                  |
| 40 (0x28) | 8 bajtów | Pierwsze użyteczne LBA dla partycji (ostatnie LBA głównej tabeli partycji + 1)                                                                                                          |
| 48 (0x30) | 8 bajtów | Ostatnie użyteczne LBA (pierwsze LBA drugiej tabeli partycji − 1)                                                                                                                       |
| 56 (0x38) | 16 bajtów| GUID dysku w mieszanym porządku bajtów                                                                                                                                                       |
| 72 (0x48) | 8 bajtów | Początkowe LBA tablicy wpisów partycji (zawsze 2 w kopii głównej)                                                                                                        |
| 80 (0x50) | 4 bajty  | Liczba wpisów partycji w tablicy                                                                                                                                            |
| 84 (0x54) | 4 bajty  | Rozmiar pojedynczego wpisu partycji (zazwyczaj 80h lub 128)                                                                                                                           |
| 88 (0x58) | 4 bajty  | CRC32 tablicy wpisów partycji w formacie little endian                                                                                                                               |
| 92 (0x5C) | \*       | Zarezerwowane; musi być zerami przez resztę bloku (420 bajtów dla rozmiaru sektora 512 bajtów; ale może być więcej przy większych rozmiarach sektorów)                                         |

**Wpisy partycji (LBA 2–33)**

| Format wpisu partycji GUID |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Długość  | Zawartość                                                                                                          |
| 0 (0x00)                    | 16 bajtów| [Typ GUID partycji](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (mieszany porządek bajtów) |
| 16 (0x10)                   | 16 bajtów| Unikalny GUID partycji (mieszany porządek bajtów)                                                                              |
| 32 (0x20)                   | 8 bajtów | Pierwsze LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 bajtów | Ostatnie LBA (włącznie, zazwyczaj nieparzyste)                                                                                 |
| 48 (0x30)                   | 8 bajtów | Flagi atrybutów (np. bit 60 oznacza tylko do odczytu)                                                                   |
| 56 (0x38)                   | 72 bajty | Nazwa partycji (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE jednostek kodowych)                                   |

**Typy partycji**

![](<../../../.gitbook/assets/image (492).png>)

Więcej typów partycji w [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspekcja

Po zamontowaniu obrazu forensycznego za pomocą [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), możesz zbadać pierwszy sektor za pomocą narzędzia Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na poniższym obrazie wykryto **MBR** w **sektorze 0** i zinterpretowano:

![](<../../../.gitbook/assets/image (494).png>)

Gdyby to była **tabela GPT zamiast MBR**, powinien pojawić się podpis _EFI PART_ w **sektorze 1** (który na poprzednim obrazie jest pusty).

## Systemy plików

### Lista systemów plików Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

System plików **FAT (File Allocation Table)** jest zaprojektowany wokół swojego podstawowego komponentu, tabeli alokacji plików, umieszczonej na początku woluminu. System ten chroni dane, utrzymując **dwie kopie** tabeli, zapewniając integralność danych, nawet jeśli jedna z nich ulegnie uszkodzeniu. Tabela, wraz z folderem głównym, musi znajdować się w **stałej lokalizacji**, co jest kluczowe dla procesu uruchamiania systemu.

Podstawową jednostką przechowywania w systemie plików jest **klaster, zazwyczaj 512B**, składający się z wielu sektorów. FAT ewoluował przez wersje:

* **FAT12**, obsługujący 12-bitowe adresy klastrów i obsługujący do 4078 klastrów (4084 z UNIX).
* **FAT16**, rozwijający się do 16-bitowych adresów, co pozwala na obsługę do 65 517 klastrów.
* **FAT32**, dalej rozwijający się z 32-bitowymi adresami, pozwalający na imponującą liczbę 268 435 456 klastrów na wolumin.

Znaczącym ograniczeniem we wszystkich wersjach FAT jest **maksymalny rozmiar pliku wynoszący 4GB**, narzucony przez 32-bitowe pole używane do przechowywania rozmiaru pliku.

Kluczowe komponenty katalogu głównego, szczególnie dla FAT12 i FAT16, obejmują:

* **Nazwa pliku/folderu** (do 8 znaków)
* **Atrybuty**
* **Daty utworzenia, modyfikacji i ostatniego dostępu**
* **Adres tabeli FAT** (wskazujący na początkowy klaster pliku)
* **Rozmiar pliku**

### EXT

**Ext2** jest najczęściej używanym systemem plików dla **partycji bez dziennika** (**partycji, które nie zmieniają się zbyt często**) jak partycja rozruchowa. **Ext3/4** są **z dziennikiem** i są zazwyczaj używane dla **pozostałych partycji**.

## **Metadane**

Niektóre pliki zawierają metadane. Informacje te dotyczą zawartości pliku, które czasami mogą być interesujące dla analityka, ponieważ w zależności od typu pliku mogą zawierać informacje takie jak:

* Tytuł
* Wersja MS Office używana
* Autor
* Daty utworzenia i ostatniej modyfikacji
* Model aparatu
* Współrzędne GPS
* Informacje o obrazie

Możesz użyć narzędzi takich jak [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/) do uzyskania metadanych pliku.

## **Odzyskiwanie usuniętych plików**

### Zarejestrowane usunięte pliki

Jak wcześniej wspomniano, istnieje kilka miejsc, w których plik jest nadal zapisany po jego "usunięciu". Dzieje się tak, ponieważ zazwyczaj usunięcie pliku z systemu plików po prostu oznacza go jako usunięty, ale dane nie są dotykane. Następnie możliwe jest zbadanie rejestrów plików (takich jak MFT) i znalezienie usuniętych plików.

Ponadto system operacyjny zazwyczaj zapisuje wiele informacji o zmianach w systemie plików i kopiach zapasowych, więc możliwe jest próbowanie ich użycia do odzyskania pliku lub jak największej ilości informacji.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Carving plików**

**File carving** to technika, która próbuje **znaleźć pliki w masie danych**. Istnieją 3 główne sposoby, w jakie działają takie narzędzia: **Na podstawie nagłówków i stóp typów plików**, na podstawie **struktur** typów plików oraz na podstawie **samej zawartości**.

Należy zauważyć, że ta technika **nie działa w celu odzyskania fragmentowanych plików**. Jeśli plik **nie jest przechowywany w sąsiadujących sektorach**, to ta technika nie będzie w stanie go znaleźć lub przynajmniej jego części.

Istnieje wiele narzędzi, które możesz użyć do carvingu plików, wskazując typy plików, które chcesz wyszukiwać.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Carving strumieni danych

Carving strumieni danych jest podobny do carvingu plików, ale **zamiast szukać kompletnych plików, szuka interesujących fragmentów** informacji.\
Na przykład, zamiast szukać kompletnego pliku zawierającego zarejestrowane adresy URL, ta technika będzie szukać adresów URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Bezpieczne usuwanie

Oczywiście istnieją sposoby na **"bezpieczne" usunięcie plików i części logów o nich**. Na przykład, możliwe jest **nadpisanie zawartości** pliku danymi śmieciowymi kilka razy, a następnie **usunięcie** **logów** z **$MFT** i **$LOGFILE** dotyczących pliku oraz **usunięcie kopii zapasowych woluminu**.\
Możesz zauważyć, że nawet wykonując tę akcję, mogą istnieć **inne części, w których istnienie pliku jest nadal zarejestrowane**, i to prawda, a częścią pracy profesjonalisty w dziedzinie forensyki jest ich znalezienie.

## Referencje

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
