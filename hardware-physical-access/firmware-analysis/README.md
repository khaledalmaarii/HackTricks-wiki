# Firmware Analysis

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Wprowadzenie**

Oprogramowanie układowe to niezbędne oprogramowanie, które umożliwia urządzeniom prawidłowe działanie poprzez zarządzanie i ułatwianie komunikacji między komponentami sprzętu a oprogramowaniem, z którym użytkownicy współpracują. Jest przechowywane w pamięci stałej, zapewniając, że urządzenie może uzyskać dostęp do istotnych instrukcji od momentu włączenia zasilania, co prowadzi do uruchomienia systemu operacyjnego. Badanie i ewentualna modyfikacja oprogramowania układowego to kluczowy krok w identyfikacji podatności na zagrożenia.

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy początkowy krok w zrozumieniu budowy urządzenia i technologii, które wykorzystuje. Proces ten polega na gromadzeniu danych dotyczących:

* Architektury procesora i systemu operacyjnego, na którym działa
* Szczegółów dotyczących ładowania systemu
* Układu sprzętowego i kart katalogowych
* Metryk kodu źródłowego i lokalizacji źródeł
* Zewnętrznych bibliotek i typów licencji
* Historii aktualizacji i certyfikatów regulacyjnych
* Diagramów architektonicznych i przepływu
* Oceny bezpieczeństwa i zidentyfikowanych podatności

W tym celu narzędzia **open-source intelligence (OSINT)** są niezwykle cenne, podobnie jak analiza dostępnych komponentów oprogramowania open-source za pomocą procesów manualnych i automatycznych. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, która może być wykorzystana do znalezienia potencjalnych problemów.

## **Pobieranie oprogramowania układowego**

Pobieranie oprogramowania układowego można przeprowadzić na różne sposoby, z różnym stopniem skomplikowania:

* **Bezpośrednio** od źródła (programistów, producentów)
* **Budowanie** go na podstawie dostarczonych instrukcji
* **Pobieranie** z oficjalnych stron wsparcia
* Wykorzystywanie zapytań **Google dork** do wyszukiwania hostowanego oprogramowania układowego
* Bezpośredni dostęp do **przechowywania w chmurze** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Przechwytywanie **aktualizacji** za pomocą technik man-in-the-middle
* **Wyodrębnianie** z urządzenia za pomocą połączeń takich jak **UART**, **JTAG** lub **PICit**
* **Przechwytywanie** żądań aktualizacji w ramach komunikacji urządzenia
* Identyfikowanie i wykorzystywanie **zadanych punktów aktualizacji**
* **Dumpowanie** z bootloadera lub sieci
* **Usuwanie i odczytywanie** układu pamięci, gdy wszystko inne zawiedzie, za pomocą odpowiednich narzędzi sprzętowych

## Analiza oprogramowania układowego

Teraz, gdy **masz oprogramowanie układowe**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak je przetwarzać. Możesz użyć różnych narzędzi do tego celu:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli nie znajdziesz wiele za pomocą tych narzędzi, sprawdź **entropię** obrazu za pomocą polecenia `binwalk -E <bin>`. Jeśli entropia jest niska, to mało prawdopodobne, że jest zaszyfrowany. Jeśli entropia jest wysoka, to prawdopodobnie jest zaszyfrowany (lub skompresowany w jakiś sposób).

Ponadto, możesz użyć tych narzędzi do wyodrębnienia **plików osadzonych w oprogramowaniu układowym**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Lub [**binvis.io**](https://binvis.io/#/) ([kod](https://code.google.com/archive/p/binvis/)) do analizy pliku.

### Uzyskiwanie systemu plików

Z pomocą wcześniej wspomnianych narzędzi, takich jak `binwalk -ev <bin>`, powinieneś być w stanie **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu o nazwie typu systemu plików**, który zazwyczaj jest jednym z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie posiada magicznego bajtu systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalka, aby **znaleźć przesunięcie systemu plików i wyodrębnić skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnij** system plików zgodnie z jego typem, korzystając z poniższych kroków.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Uruchom poniższą komendę **dd**, wycinając system plików Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternatywnie, można również uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Dla squashfs (użytego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki będą znajdować się w katalogu "`squashfs-root`" po wykonaniu powyższych poleceń.

* Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

* Dla systemów plików ubifs z pamięcią NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza Firmware

Po uzyskaniu firmware'u ważne jest jego rozłożenie na części w celu zrozumienia jego struktury i potencjalnych podatności. Proces ten polega na wykorzystaniu różnych narzędzi do analizy i wydobycia wartościowych danych z obrazu firmware'u.

### Narzędzia do początkowej analizy

Dostępny jest zestaw poleceń do wstępnej analizy pliku binarnego (o nazwie `<bin>`). Te polecenia pomagają w identyfikacji typów plików, wydobyciu ciągów znaków, analizie danych binarnych oraz zrozumieniu szczegółów partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdzana jest **entropia** za pomocą polecenia `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, podczas gdy wysoka entropia wskazuje możliwe szyfrowanie lub kompresję.

Aby wyodrębnić **osadzone pliki**, zaleca się korzystanie z narzędzi i zasobów takich jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Zwykle za pomocą polecenia `binwalk -ev <bin>` można wyodrębnić system plików, często do katalogu o nazwie odpowiadającej typowi systemu plików (np. squashfs, ubifs). Jednak gdy **binwalk** nie rozpoznaje typu systemu plików z powodu braku magicznych bajtów, konieczne jest ręczne wyodrębnienie. Polega to na użyciu polecenia `binwalk` do zlokalizowania przesunięcia systemu plików, a następnie polecenia `dd` do wyodrębnienia systemu plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), używane są różne polecenia do ręcznego wyodrębnienia zawartości.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie podatności. Zwraca się uwagę na niebezpieczne demony sieciowe, wbudowane poświadczenia, punkty końcowe interfejsów API, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe i skompilowane pliki binarne do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia to:

* **etc/shadow** i **etc/passwd** dla poświadczeń użytkowników
* Certyfikaty SSL i klucze w **etc/ssl**
* Pliki konfiguracyjne i skryptowe pod kątem potencjalnych podatności
* Wbudowane pliki binarne do dalszej analizy
* Wspólne serwery internetowe i pliki binarne urządzeń IoT

Kilka narzędzi pomaga w odkrywaniu poufnych informacji i podatności w systemie plików:

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) do kompleksowej analizy oprogramowania układowego
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Sprawdzanie zabezpieczeń skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików muszą być dokładnie przeanalizowane pod kątem podatności. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają zidentyfikować niezabezpieczone pliki binarne, które mogą być wykorzystane w ataku.

## Emulowanie oprogramowania układowego dla analizy dynamicznej

Proces emulowania oprogramowania układowego umożliwia **analizę dynamiczną** działania urządzenia lub poszczególnego programu. Ta metoda może napotykać trudności zależne od sprzętu lub architektury, ale przeniesienie systemu plików głównego lub konkretnych plików binarnych do urządzenia o takiej samej architekturze i kolejności bajtów, takiego jak Raspberry Pi, lub do wirtualnej maszyny z wcześniej skonfigurowanym oprogramowaniem, może ułatwić dalsze testowanie.

### Emulowanie poszczególnych plików binarnych

Przy badaniu pojedynczych programów istotne jest zidentyfikowanie kolejności bajtów i architektury CPU programu.

#### Przykład z architekturą MIPS

Aby emulować plik binarny o architekturze MIPS, można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

Aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Dla architektury MIPS (big-endian) używany jest emulator `qemu-mips`, a dla binarnych plików little-endian wybiera się emulator `qemu-mipsel`.

#### Emulacja architektury ARM

Dla binarnych plików ARM proces jest podobny, z wykorzystaniem emulatora `qemu-arm` do emulacji.

### Emulacja pełnego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware, automatyzując proces i pomagając w analizie dynamicznej.

## Analiza dynamiczna w praktyce

W tym etapie do analizy używa się rzeczywistego lub emulowanego środowiska urządzenia. Ważne jest utrzymanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie doskonale odwzorowywać interakcje sprzętowe, co czasami wymaga ponownego uruchomienia emulacji. Analiza powinna obejmować ponowne sprawdzenie systemu plików, wykorzystanie wystawionych stron internetowych i usług sieciowych oraz badanie podatności bootloadera. Testy integralności firmware są kluczowe dla identyfikacji potencjalnych podatności na backdoor.

## Techniki analizy w czasie rzeczywistym

Analiza w czasie rzeczywistym polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym, przy użyciu narzędzi takich jak gdb-multiarch, Frida i Ghidra do ustawiania punktów przerwania i identyfikowania podatności poprzez fuzzing i inne techniki.

## Eksploatacja binarna i dowód koncepcji

Aby opracować dowód koncepcji dla zidentyfikowanych podatności, konieczne jest głębokie zrozumienie architektury docelowej i programowania w językach niskiego poziomu. Ochrona czasu wykonywania binarnego w systemach wbudowanych jest rzadka, ale gdy występuje, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) zapewniają prekonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu Rzeczy (IoT). Oszczędza dużo czasu, dostarczając prekonfigurowane środowisko z załadowanymi wszystkimi niezbędnymi narzędziami.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): System operacyjny do testowania bezpieczeństwa wbudowanego oparty na Ubuntu 18.04, wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Podatne firmware do ćwiczeń

Aby ćwiczyć odkrywanie podatności w firmware, można użyć następujących projektów podatnych firmware jako punktu wyjścia.

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

## Odwołania

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Szkolenia i certyfikaty

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
