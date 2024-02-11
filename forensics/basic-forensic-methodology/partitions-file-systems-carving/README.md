# Partycje/Systemy plików/Wycinanie

## Partycje/Systemy plików/Wycinanie

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub**.

</details>

## Partycje

Dysk twardy lub **dysk SSD może zawierać różne partycje**, które mają na celu fizyczne oddzielenie danych.\
**Minimalną** jednostką dysku jest **sektor** (zwykle składający się z 512B). Dlatego rozmiar każdej partycji musi być wielokrotnością tej wielkości.

### MBR (Master Boot Record)

Znajduje się w **pierwszym sektorze dysku po 446B kodu rozruchowego**. Ten sektor jest niezbędny, aby wskazać komputerowi, co i skąd należy zamontować partycję.\
Pozwala na **maksymalnie 4 partycje** (najwyżej **tylko 1** może być aktywna/**rozruchowa**). Jednak jeśli potrzebujesz więcej partycji, możesz użyć **partycji rozszerzonych**. Ostatnim bajtem tego pierwszego sektora jest sygnatura rekordu rozruchowego **0x55AA**. Może być oznaczona tylko jedna partycja jako aktywna.\
MBR pozwala na **maksymalnie 2,2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Od **bajtu 440 do 443** MBR można znaleźć **Windows Disk Signature** (jeśli używany jest system Windows). Litera logiczna dysku twardego zależy od sygnatury dysku Windows. Zmiana tej sygnatury może uniemożliwić uruchomienie systemu Windows (narzędzie: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Format**

| Offset      | Długość    | Element              |
| ----------- | ---------- | -------------------- |
| 0 (0x00)    | 446(0x1BE) | Kod rozruchowy       |
| 446 (0x1BE) | 16 (0x10)  | Pierwsza partycja    |
| 462 (0x1CE) | 16 (0x10)  | Druga partycja       |
| 478 (0x1DE) | 16 (0x10)  | Trzecia partycja     |
| 494 (0x1EE) | 16 (0x10)  | Czwarta partycja     |
| 510 (0x1FE) | 2 (0x2)    | Sygnatura 0x55 0xAA  |

**Format rekordu partycji**

| Offset    | Długość   | Element                                                     |
| --------- | --------- | ------------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01)  | Flaga aktywna (0x80 = rozruchowa)                            |
| 1 (0x01)  | 1 (0x01)  | Głowica początkowa                                          |
| 2 (0x02)  | 1 (0x01)  | Sektor początkowy (bity 0-5); wyższe bity cylindra (6-7)      |
| 3 (0x03)  | 1 (0x01)  | Najmłodsze 8 bitów cylindra początkowego                     |
| 4 (0x04)  | 1 (0x01)  | Kod typu partycji (0x83 = Linux)                             |
| 5 (0x05)  | 1 (0x01)  | Głowica końcowa                                            |
| 6 (0x06)  | 1 (0x01)  | Sektor końcowy (bity 0-5); wyższe bity cylindra (6-7)        |
| 7 (0x07)  | 1 (0x01)  | Najmłodsze 8 bitów cylindra końcowego                        |
| 8 (0x08)  | 4 (0x04)  | Sektorów poprzedzających partycję (little endian)            |
| 12 (0x0C) | 4 (0x04)  | Sektorów w partycji                                         |

Aby zamontować MBR w systemie Linux, najpierw musisz uzyskać początkowe przesunięcie (możesz użyć `fdisk` i polecenia `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

A następnie użyj następującego kodu
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) to powszechnie stosowany schemat określania lokalizacji bloków danych przechowywanych na urządzeniach pamięci komputerowych, zwykle na systemach pamięci podręcznej, takich jak dyski twarde. LBA to szczególnie prosty schemat adresowania liniowego; bloki są lokalizowane za pomocą indeksu całkowitego, przy czym pierwszy blok to LBA 0, drugi to LBA 1, i tak dalej.

### GPT (GUID Partition Table)

Tabela partycji GUID, znana jako GPT, jest preferowana ze względu na swoje rozszerzone możliwości w porównaniu do MBR (Master Boot Record). Wyróżnia się kilkoma cechami:

- **Lokalizacja i rozmiar**: Zarówno GPT, jak i MBR zaczynają się od **sektora 0**. Jednak GPT działa na **64 bitach**, w przeciwieństwie do 32 bitów MBR.
- **Ograniczenia partycji**: GPT obsługuje do **128 partycji** w systemach Windows i pomieści do **9,4 ZB** danych.
- **Nazwy partycji**: Oferuje możliwość nadawania partycjom nazw o długości do 36 znaków Unicode.

**Odporność i odzyskiwanie danych**:

- **Redundancja**: W przeciwieństwie do MBR, GPT nie ogranicza partycjonowania i danych rozruchowych do jednego miejsca. Powiela te dane na całym dysku, poprawiając integralność i odporność danych.
- **Cyclic Redundancy Check (CRC)**: GPT używa CRC do zapewnienia integralności danych. Aktywnie monitoruje uszkodzenia danych i w przypadku wykrycia próbuje odzyskać uszkodzone dane z innego miejsca na dysku.

**Protective MBR (LBA0)**:

- GPT utrzymuje kompatybilność wsteczną za pomocą ochronnego MBR. Ta funkcja znajduje się w przestrzeni MBR, ale została zaprojektowana w celu zapobieżenia przypadkowemu nadpisaniu dysków GPT przez starsze narzędzia oparte na MBR, chroniąc tym samym integralność danych na dyskach sformatowanych w formacie GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../.gitbook/assets/image (491).png>)

**Hybrydowy MBR (LBA 0 + GPT)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID_Partition_Table)

W systemach operacyjnych obsługujących **rozruch oparty na GPT przez usługi BIOS** zamiast EFI, pierwszy sektor może nadal być używany do przechowywania pierwszego etapu kodu **bootloadera**, ale **zmodyfikowanego**, aby rozpoznawał **partycje GPT**. Bootloader w MBR nie może zakładać rozmiaru sektora 512 bajtów.

**Nagłówek tabeli partycji (LBA 1)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Nagłówek tabeli partycji definiuje bloki użyteczne na dysku. Określa również liczbę i rozmiar wpisów partycji, które tworzą tabelę partycji (offsety 80 i 84 w tabeli).

| Offset    | Długość  | Zawartość                                                                                                                                                                        |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bajtów | Sygnatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h lub 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)na małych maszynach endian) |
| 8 (0x08)  | 4 bajty  | Wersja 1.0 (00h 00h 01h 00h) dla UEFI 2.8                                                                                                                                     |
| 12 (0x0C) | 4 bajty  | Rozmiar nagłówka w małym endianie (w bajtach, zwykle 5Ch 00h 00h 00h lub 92 bajty)                                                                                                    |
| 16 (0x10) | 4 bajty  | [CRC32](https://en.wikipedia.org/wiki/CRC32) nagłówka (offset +0 do rozmiaru nagłówka) w małym endianie, z tym polem zerowanym podczas obliczania                                |
| 20 (0x14) | 4 bajty  | Zarezerwowane; musi być zerem                                                                                                                                                          |
| 24 (0x18) | 8 bajtów  | Bieżące LBA (położenie tej kopii nagłówka)                                                                                                                                      |
| 32 (0x20) | 8 bajtów  | LBA kopii zapasowej (położenie drugiej kopii nagłówka)                                                                                                                                  |
| 40 (0x28) | 8 bajtów  | Pierwsze użyteczne LBA dla partycji (ostatnie LBA tabeli partycji + 1)                                                                                                          |
| 48 (0x30) | 8 bajtów  | Ostatnie użyteczne LBA (pierwsze LBA drugiej tabeli partycji − 1)                                                                                                                       |
| 56 (0x38) | 16 bajtów | GUID dysku w endianie mieszanych                                                                                                                                                       |
| 72 (0x48) | 8 bajtów  | Początkowe LBA tablicy wpisów partycji (zawsze 2 w kopii podstawowej)                                                                                                        |
| 80 (0x50) | 4 bajty  | Liczba wpisów partycji w tablicy                                                                                                                                            |
| 84 (0x54) | 4 bajty  | Rozmiar pojedynczego wpisu partycji (zwykle 80h lub 128)                                                                                                                           |
| 88 (0x58) | 4 bajty  | CRC32 tablicy wpisów partycji w małym endianie                                                                                                                               |
| 92 (0x5C) | \*       | Zarezerwowane; musi być zerami dla reszty bloku (420 bajtów dla rozmiaru sektora 512 bajtów; ale może być większe dla większych rozmiarów sektorów)                                         |

**Wpisy partycji (LBA 2–33)**

| Format wpisu partycji GUID |          |                                                                                                                   |
| --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Offset                      | Długość  | Zawartość                                                                                                          |
| 0 (0x00)                    | 16 bajtów | [GUID typu partycji](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#Partition\_type\_GUIDs) (endian mieszany) |
| 16 (0x10)                   | 16 bajtów | Unikalny GUID partycji (endian mieszany)                                                                              |
| 32 (0x20)                   | 8 bajtów  | Pierwsze LBA ([little endian](https://en.wikipedia.org/wiki/Little\_endian))                                         |
| 40 (0x28)                   | 8 bajtów  | Ostatnie LBA (włącznie, zwykle nieparzyste)                                                                                 |
| 48 (0x30)                   | 8 bajtów  | Flagi atrybutów (np. bit 60 oznacza tylko do odczytu)                                                                   |
| 56 (0x38)                   | 72 bajty | Nazwa partycji (36 jednostek kodu [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                                   |

**Typy partycji**

![](<../../../.gitbook/assets/image (492).png>)

Więcej typów partycji na stronie [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)

### Inspekcja

Po zamontowaniu obrazu do analizy przy użyciu [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), można sprawdzić pierwszy sektor za pomocą narzędzia Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na poniższym obrazie wykryto **MBR** na **sektorze 0** i został zinterpretowany:

![](<../../../.gitbook/assets/image (494).png>)

Jeśli byłoby to **tabela GPT zamiast MBR**, w sektorze 1 powinna pojawić się sygnatura _EFI PART_ (która na poprzednim obrazie jest pusta).
## Systemy plików

### Lista systemów plików Windows

* **FAT12/16**: MSDOS, WIN95/98/NT/200
* **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
* **ExFAT**: 2008/2012/2016/VISTA/7/8/10
* **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
* **ReFS**: 2012/2016

### FAT

System plików **FAT (File Allocation Table)** został zaprojektowany wokół swojego głównego komponentu, tabeli alokacji plików, umieszczonej na początku woluminu. Ten system chroni dane, utrzymując **dwie kopie** tabeli, zapewniając integralność danych nawet w przypadku uszkodzenia jednej z nich. Tabela, wraz z folderem głównym, musi znajdować się w **stałej lokalizacji**, kluczowej dla procesu uruchamiania systemu.

Podstawową jednostką przechowywania w systemie plików FAT jest **klaster, zwykle o rozmiarze 512B**, składający się z wielu sektorów. FAT ewoluował w kolejnych wersjach:

- **FAT12**, obsługujący adresy klastrów 12-bitowe i obsługujący do 4078 klastrów (4084 z UNIX).
- **FAT16**, rozszerzający się do adresów 16-bitowych, co pozwala na obsługę do 65 517 klastrów.
- **FAT32**, dalsze udoskonalenie z adresami 32-bitowymi, umożliwiające imponującą liczbę 268 435 456 klastrów na wolumin.

Znaczącym ograniczeniem we wszystkich wersjach FAT jest **maksymalny rozmiar pliku 4GB**, narzucony przez 32-bitowe pole używane do przechowywania rozmiaru pliku.

Kluczowe składniki katalogu głównego, zwłaszcza dla FAT12 i FAT16, obejmują:

- **Nazwa pliku/katalogu** (do 8 znaków)
- **Atrybuty**
- **Daty utworzenia, modyfikacji i ostatniego dostępu**
- **Adres tabeli FAT** (wskazujący na początkowy klaster pliku)
- **Rozmiar pliku**

### EXT

**Ext2** to najczęstszy system plików dla partycji **bez dziennika** (**partycje, które się nie zmieniają zbyt często**), takich jak partycja rozruchowa. **Ext3/4** są **z dziennikiem** i zazwyczaj są używane dla **pozostałych partycji**.

## **Metadane**

Niektóre pliki zawierają metadane. Informacje te dotyczą zawartości pliku, które czasami mogą być interesujące dla analityka, ponieważ w zależności od typu pliku mogą zawierać informacje takie jak:

* Tytuł
* Użyta wersja MS Office
* Autor
* Daty utworzenia i ostatniej modyfikacji
* Model aparatu
* Współrzędne GPS
* Informacje o obrazie

Możesz użyć narzędzi takich jak [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/), aby uzyskać metadane pliku.

## **Odzyskiwanie usuniętych plików**

### Zarejestrowane usunięte pliki

Jak już widzieliśmy, istnieje kilka miejsc, w których plik jest nadal zapisany po jego "usunięciu". Wynika to z faktu, że zazwyczaj usunięcie pliku z systemu plików oznacza go jako usunięty, ale dane nie są dotykane. Następnie można sprawdzić rejestracje plików (takie jak MFT) i odnaleźć usunięte pliki.

Ponadto, system operacyjny zazwyczaj przechowuje wiele informacji na temat zmian w systemie plików i kopii zapasowych, więc można spróbować ich wykorzystać do odzyskania pliku lub jak największej ilości informacji.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### **Wycinanie plików**

**Wycinanie plików** to technika, która próbuje **odnaleźć pliki w dużej ilości danych**. Istnieją 3 główne sposoby działania narzędzi tego typu: **Na podstawie nagłówków i stopki typów plików**, na podstawie **struktur typów plików** i na podstawie **samej zawartości**.

Należy zauważyć, że ta technika **nie działa do odzyskiwania fragmentowanych plików**. Jeśli plik **nie jest przechowywany w sąsiadujących sektorach**, ta technika nie będzie w stanie go odnaleźć lub przynajmniej częściowo.

Istnieje wiele narzędzi, które można użyć do wycinania plików, wskazując typy plików, których szukasz.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Wycinanie strumieni danych

Wycinanie strumieni danych jest podobne do wycinania plików, ale **zamiast szukać kompletnych plików, szuka interesujących fragmentów** informacji.\
Na przykład, zamiast szukać kompletnego pliku zawierającego zarejestrowane adresy URL, ta technika będzie szukać adresów URL.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Bezpieczne usuwanie

Oczywiście istnieją sposoby na **"bezpieczne" usuwanie plików i części logów o nich**. Na przykład można **nadpisać zawartość** pliku kilkukrotnie danymi bezużytecznymi, a następnie **usunąć** z **$MFT** i **$LOGFILE** logi dotyczące pliku oraz **usunąć kopie woluminu w tle**.\
Może się zdarzyć, że nawet po wykonaniu tej operacji **inne części systemu nadal rejestrują istnienie pliku**, i to jest prawda, a zadaniem profesjonalisty zajmującego się informatyką śledczą jest ich odnalezienie.

## Odwołania

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
