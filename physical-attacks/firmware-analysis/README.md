# Analiza oprogramowania układowego

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## **Wprowadzenie**

Oprogramowanie układowe to niezbędne oprogramowanie, które umożliwia urządzeniom prawidłowe działanie, zarządzając i ułatwiając komunikację między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywane w pamięci trwałej, co zapewnia, że urządzenie może uzyskać dostęp do istotnych instrukcji od momentu włączenia, prowadząc do uruchomienia systemu operacyjnego. Badanie i potencjalne modyfikowanie oprogramowania układowego jest kluczowym krokiem w identyfikacji luk w zabezpieczeniach.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy krok w zrozumieniu budowy urządzenia i technologii, które wykorzystuje. Proces ten obejmuje zbieranie danych na temat:

- Architektury CPU i systemu operacyjnego, na którym działa
- Szczegółów bootloadera
- Układu sprzętowego i kart katalogowych
- Metryk kodu źródłowego i lokalizacji źródeł
- Zewnętrznych bibliotek i typów licencji
- Historii aktualizacji i certyfikacji regulacyjnych
- Diagramów architektonicznych i przepływowych
- Oceny bezpieczeństwa i zidentyfikowanych luk

W tym celu narzędzia **inteligencji open-source (OSINT)** są nieocenione, podobnie jak analiza dostępnych komponentów oprogramowania open-source poprzez ręczne i zautomatyzowane procesy przeglądowe. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują darmową analizę statyczną, która może być wykorzystana do znalezienia potencjalnych problemów.

## **Pozyskiwanie oprogramowania układowego**

Pozyskiwanie oprogramowania układowego można podejść na różne sposoby, z których każdy ma swój poziom złożoności:

- **Bezpośrednio** ze źródła (deweloperzy, producenci)
- **Budując** je na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron wsparcia
- Wykorzystując **zapytania Google dork** do znajdowania hostowanych plików oprogramowania układowego
- Uzyskując dostęp do **chmury** bezpośrednio, za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Ekstrahując** z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Podsłuchując** żądania aktualizacji w komunikacji urządzenia
- Identyfikując i używając **twardo zakodowanych punktów końcowych aktualizacji**
- **Zrzucając** z bootloadera lub sieci
- **Usuwając i odczytując** chip pamięci, gdy wszystko inne zawiedzie, używając odpowiednich narzędzi sprzętowych

## Analiza oprogramowania układowego

Teraz, gdy **masz oprogramowanie układowe**, musisz wyodrębnić informacje na jego temat, aby wiedzieć, jak je traktować. Różne narzędzia, które możesz użyć do tego:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Jeśli nie znajdziesz wiele za pomocą tych narzędzi, sprawdź **entropię** obrazu za pomocą `binwalk -E <bin>`, jeśli entropia jest niska, to prawdopodobnie nie jest zaszyfrowany. Jeśli entropia jest wysoka, prawdopodobnie jest zaszyfrowany (lub skompresowany w jakiś sposób).

Ponadto możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych w firmware**:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Lub [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby zbadać plik.

### Uzyskiwanie systemu plików

Za pomocą wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go w **folderze nazwanym zgodnie z typem systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma magicznego bajtu systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików i wyciąć skompresowany system plików** z binarnego pliku oraz **ręcznie wyodrębnić** system plików zgodnie z jego typem, korzystając z poniższych kroków.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Uruchom następujące **polecenie dd**, aby wyodrębnić system plików Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatywnie, można również uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki będą w katalogu "`squashfs-root`" po tym.

* Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

* Dla systemów plików ubifs z pamięcią NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`


## Analiza Oprogramowania Układowego

Gdy oprogramowanie układowe zostanie uzyskane, istotne jest jego rozłożenie w celu zrozumienia struktury i potencjalnych luk. Proces ten polega na wykorzystaniu różnych narzędzi do analizy i wydobywania cennych danych z obrazu oprogramowania układowego.

### Narzędzia do Wstępnej Analizy

Zestaw poleceń jest dostarczany do wstępnej inspekcji pliku binarnego (nazywanego `<bin>`). Te polecenia pomagają w identyfikacji typów plików, wydobywaniu ciągów, analizie danych binarnych oraz zrozumieniu szczegółów partycji i systemu plików:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Aby ocenić status szyfrowania obrazu, sprawdzana jest **entropia** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, podczas gdy wysoka entropia wskazuje na możliwe szyfrowanie lub kompresję.

Do **wyodrębniania plików osadzonych** zaleca się korzystanie z narzędzi i zasobów, takich jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Używając `binwalk -ev <bin>`, można zazwyczaj wyodrębnić system plików, często do katalogu nazwanego na cześć typu systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu brakujących bajtów magicznych, konieczne jest ręczne wyodrębnienie. Wymaga to użycia `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Po tym, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używane są różne polecenia do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niebezpieczne demony sieciowe, twardo zakodowane dane uwierzytelniające, punkty końcowe API, funkcjonalności serwera aktualizacji, niekompilowany kod, skrypty uruchamiające oraz skompilowane binaria do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** w celu uzyskania danych uwierzytelniających użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty w poszukiwaniu potencjalnych luk
- Wbudowane binaria do dalszej analizy
- Typowe serwery internetowe urządzeń IoT i binaria

Kilka narzędzi pomaga w odkrywaniu wrażliwych informacji i luk w zabezpieczeniach w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania wrażliwych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) do kompleksowej analizy oprogramowania układowego
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych binariów

Zarówno kod źródłowy, jak i skompilowane binaria znalezione w systemie plików muszą być dokładnie sprawdzone pod kątem luk. Narzędzia takie jak **checksec.sh** dla binariów Unix i **PESecurity** dla binariów Windows pomagają zidentyfikować niechronione binaria, które mogą być wykorzystane.

## Emulacja oprogramowania układowego do analizy dynamicznej

Proces emulacji oprogramowania układowego umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać trudności związane z zależnościami sprzętowymi lub architektonicznymi, ale przeniesienie systemu plików root lub konkretnych binariów na urządzenie o dopasowanej architekturze i endianness, takie jak Raspberry Pi, lub na wstępnie zbudowaną maszynę wirtualną, może ułatwić dalsze testowanie.

### Emulacja pojedynczych binariów

Aby zbadać pojedyncze programy, kluczowe jest zidentyfikowanie endianness programu i architektury CPU.

#### Przykład z architekturą MIPS

Aby emulować binarium architektury MIPS, można użyć polecenia:
```bash
file ./squashfs-root/bin/busybox
```
Aby zainstalować niezbędne narzędzia emulacyjne:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Dla MIPS (big-endian) używa się `qemu-mips`, a dla binarnych w formacie little-endian wybór padnie na `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binarnych ARM proces jest podobny, z emulatorem `qemu-arm` wykorzystywanym do emulacji.

### Emulacja pełnego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne, ułatwiają pełną emulację firmware, automatyzując proces i wspierając analizę dynamiczną.

## Analiza dynamiczna w praktyce

Na tym etapie używa się rzeczywistego lub emulowanego środowiska urządzenia do analizy. Ważne jest, aby utrzymać dostęp do powłoki systemu operacyjnego i systemu plików. Emulacja może nie idealnie odwzorowywać interakcje sprzętowe, co wymaga okazjonalnych restartów emulacji. Analiza powinna ponownie badać system plików, wykorzystywać ujawnione strony internetowe i usługi sieciowe oraz badać luki w bootloaderze. Testy integralności firmware są kluczowe do identyfikacji potencjalnych luk backdoor.

## Techniki analizy w czasie rzeczywistym

Analiza w czasie rzeczywistym polega na interakcji z procesem lub binarnym w jego środowisku operacyjnym, wykorzystując narzędzia takie jak gdb-multiarch, Frida i Ghidra do ustawiania punktów przerwania i identyfikacji luk poprzez fuzzing i inne techniki.

## Eksploatacja binarna i dowód koncepcji

Opracowanie PoC dla zidentyfikowanych luk wymaga głębokiego zrozumienia architektury docelowej i programowania w językach niskiego poziomu. Ochrony w czasie rzeczywistym w systemach wbudowanych są rzadkie, ale gdy są obecne, mogą być konieczne techniki takie jak Programowanie Zwracające (ROP).

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja mająca na celu pomoc w przeprowadzaniu oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu Rzeczy (IoT). Oszczędza dużo czasu, zapewniając wstępnie skonfigurowane środowisko z wszystkimi niezbędnymi narzędziami.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): System operacyjny do testowania bezpieczeństwa wbudowanego, oparty na Ubuntu 18.04, wstępnie załadowany narzędziami do testowania bezpieczeństwa firmware.

## Wrażliwe firmware do ćwiczeń

Aby ćwiczyć odkrywanie luk w firmware, użyj następujących projektów firmware jako punktu wyjścia.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* Projekt Damn Vulnerable Router Firmware
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Odniesienia

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Szkolenie i certyfikacja

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
