# Analiza oprogramowania układowego

{% hint style="success" %}
Dowiedz się i ćwicz hakowanie AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz hakowanie GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plan abonamentowy**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## **Wprowadzenie**

Oprogramowanie układowe to istotne oprogramowanie umożliwiające urządzeniom poprawne działanie poprzez zarządzanie i ułatwianie komunikacji między podzespołami sprzętu a oprogramowaniem, z którym użytkownicy wchodzą w interakcje. Jest przechowywane w pamięci stałej, zapewniając urządzeniu dostęp do istotnych instrukcji od momentu włączenia zasilania, co prowadzi do uruchomienia systemu operacyjnego. Badanie i ewentualna modyfikacja oprogramowania układowego to kluczowy krok w identyfikowaniu podatności na ataki.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy krok w zrozumieniu budowy urządzenia i technologii, jakich używa. Proces ten polega na zbieraniu danych dotyczących:

* Architektury CPU i systemu operacyjnego, który uruchamia
* Szczegółów bootloadera
* Układu sprzętowego i kart katalogowych
* Metryk kodu źródłowego i lokalizacji źródeł
* Zewnętrznych bibliotek i typów licencji
* Historii aktualizacji i certyfikatów regulacyjnych
* Diagramów architektonicznych i przepływów
* Oceny bezpieczeństwa i zidentyfikowanych podatności

W tym celu narzędzia **open-source intelligence (OSINT)** są nieocenione, podobnie jak analiza dostępnych składników oprogramowania open-source za pomocą procesów ręcznych i zautomatyzowanych. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do znalezienia potencjalnych problemów.

## **Pobieranie oprogramowania układowego**

Pobranie oprogramowania układowego można podjąć na różne sposoby, z różnym stopniem skomplikowania:

* **Bezpośrednio** od producenta (programistów, producentów)
* **Budując** je z dostarczonych instrukcji
* **Pobierając** z oficjalnych stron wsparcia
* Wykorzystując zapytania **Google dork** do znalezienia hostowanych plików oprogramowania układowego
* Bezpośredni dostęp do **przechowywania w chmurze** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Przechwytywanie **aktualizacji** za pomocą technik man-in-the-middle
* **Wyodrębnianie** z urządzenia poprzez połączenia takie jak **UART**, **JTAG** lub **PICit**
* **Podglądanie** żądań aktualizacji w komunikacji urządzenia
* Identyfikowanie i korzystanie z **wbudowanych punktów końcowych aktualizacji**
* **Dumpowanie** z bootloadera lub sieci
* **Usuwanie i odczytywanie** chipa pamięci, gdy wszystko inne zawodzi, za pomocą odpowiednich narzędzi sprzętowych

## Analiza oprogramowania układowego

Teraz, gdy **masz oprogramowanie układowe**, musisz wydobyć z niego informacje, aby wiedzieć, jak je przetwarzać. Różne narzędzia, których możesz użyć do tego:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele za pomocą tych narzędzi, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>`, jeśli entropia jest niska, to prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, jest prawdopodobnie zaszyfrowany (lub skompresowany w jakiś sposób).

Ponadto, możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych w oprogramowaniu układowym**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Lub [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) do inspekcji pliku.

### Pobieranie systemu plików

Dzięki wcześniej wspomnianym narzędziom, takim jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu nazwanego zgodnie z typem systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie będzie miał magicznego bajtu systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalka, aby **znaleźć przesunięcie systemu plików i wydobyć skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików zgodnie z jego typem, korzystając z poniższych kroków.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące polecenie **dd**, wycinając system plików Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatywnie można również uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Dla squashfs (użytego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się w katalogu "`squashfs-root`" po wykonaniu powyższych poleceń.

* Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

* Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware

Po uzyskaniu firmware'u istotne jest jego szczegółowe przeanalizowanie w celu zrozumienia struktury oraz potencjalnych podatności. Proces ten polega na wykorzystaniu różnych narzędzi do analizy i wydobycia wartościowych danych z obrazu firmware'u.

### Narzędzia do Analizy Początkowej

Zestaw poleceń jest dostarczony do wstępnej inspekcji pliku binarnego (nazwanego `<bin>`). Te polecenia pomagają zidentyfikować typy plików, wydobywać ciągi znaków, analizować dane binarne oraz zrozumieć szczegóły partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić stan szyfrowania obrazu, **entropia** jest sprawdzana za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, podczas gdy wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików**, zaleca się korzystanie z narzędzi i zasobów takich jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zazwyczaj wyodrębnić system plików, często do katalogu nazwanego zgodnie z typem systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu braku magicznych bajtów, konieczne jest ręczne wyodrębnienie. Polega to na użyciu `binwalk` do zlokalizowania przesunięcia systemu plików, a następnie polecenia `dd` do wyodrębnienia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Uwaga jest skupiona na niezabezpieczonych demonach sieciowych, stałych poświadczeniach, punktach końcowych interfejsu API, funkcjach serwera aktualizacji, nie skompilowanym kodzie, skryptach uruchamiania oraz skompilowanych binariach do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** dla poświadczeń użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skryptowe pod kątem potencjalnych podatności
- Osadzone binaria do dalszej analizy
- Powszechne serwery WWW urządzeń IoT i binaria

Kilka narzędzi pomaga w odkrywaniu poufnych informacji i podatności w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) do kompleksowej analizy oprogramowania układowego
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Sprawdzanie zabezpieczeń skompilowanych binariów

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą być dokładnie przeanalizowane pod kątem podatności. Narzędzia takie jak **checksec.sh** dla binariów Unix oraz **PESecurity** dla binariów Windows pomagają zidentyfikować niezabezpieczone binaria, które mogą być wykorzystane.

## Emulowanie oprogramowania układowego do analizy dynamicznej

Proces emulowania oprogramowania układowego umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. To podejście może napotkać wyzwania z zależnościami sprzętowymi lub architektonicznymi, ale przeniesienie systemu plików głównego lub określonych binariów do urządzenia o pasującej architekturze i kolejności bajtów, takiego jak Raspberry Pi, lub do wirtualnej maszyny z gotowym oprogramowaniem, może ułatwić dalsze testowanie.

### Emulowanie pojedynczych binariów

Przy badaniu pojedynczych programów istotne jest zidentyfikowanie kolejności bajtów programu oraz architektury CPU.

#### Przykład z architekturą MIPS

Aby emulować binaria z architekturą MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
I aby zainstalować niezbędne narzędzia do emulacji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### Emulacja architektury ARM

Dla binarnych plików ARM proces jest podobny, z użyciem emulatora `qemu-arm` do emulacji.

### Emulacja pełnego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację oprogramowania układowego, automatyzują proces i pomagają w dynamicznej analizie.

## Analiza dynamiczna w praktyce

W tym etapie używane jest środowisko rzeczywiste lub zemulowane urządzenie do analizy. Istotne jest utrzymanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie doskonale odwzorowywać interakcji sprzętowych, co wymaga czasami ponownego uruchomienia emulacji. Analiza powinna ponownie przejrzeć system plików, wykorzystać wystawione strony internetowe i usługi sieciowe oraz zbadać podatności bootloadera. Testy integralności oprogramowania układowego są kluczowe dla identyfikacji potencjalnych podatności na tylne drzwi.

## Techniki analizy w czasie rzeczywistym

Analiza w czasie rzeczywistym polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym, z użyciem narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania punktów przerwania i identyfikowania podatności poprzez testowanie wydajności i inne techniki.

## Eksploatacja binarna i dowód koncepcji

Opracowanie PoC dla zidentyfikowanych podatności wymaga głębokiego zrozumienia architektury docelowej i programowania w językach niskiego poziomu. Ochrony czasu wykonania binarnego w systemach wbudowanych są rzadkie, ale gdy występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

## Przygotowane systemy operacyjne do analizy oprogramowania układowego

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają prekonfigurowane środowiska do testów bezpieczeństwa oprogramowania układowego, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy oprogramowania układowego

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu Rzeczy (IoT). Oszczędza czas, dostarczając prekonfigurowane środowisko z załadowanymi wszystkimi niezbędnymi narzędziami.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): System operacyjny do testów bezpieczeństwa wbudowany w Ubuntu 18.04, załadowany narzędziami do testowania bezpieczeństwa oprogramowania układowego.

## Podatne oprogramowanie układowe do praktyki

Aby ćwiczyć odkrywanie podatności w oprogramowaniu układowym, użyj następujących projektów podatnego oprogramowania układowego jako punktu wyjścia.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referencje

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Szkolenia i certyfikaty

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
