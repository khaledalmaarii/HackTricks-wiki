# macOS Aplikacje - Inspekcja, debugowanie i Fuzzing

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana przez **dark web**, która oferuje **darmowe** funkcje do sprawdzania, czy firma lub jej klienci zostali **skompromitowani** przez **stealery malware**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z malware kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

***

## Analiza statyczna

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}
```bash
nm -m ./tccd # List of symbols
```
### jtool2 & Disarm

Możesz [**pobrać disarm stąd**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Możesz [**pobrać jtool2 tutaj**](http://www.newosxbook.com/tools/jtool.html) lub zainstalować za pomocą `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
{% hint style="danger" %}
**jtool został zdezaktualizowany na rzecz disarm**
{% endhint %}

### Codesign / ldid

{% hint style="success" %}
**`Codesign`** można znaleźć w **macOS**, podczas gdy **`ldid`** można znaleźć w **iOS**
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) to narzędzie przydatne do inspekcji plików **.pkg** (instalatorów) i zobaczenia, co znajduje się w środku przed ich zainstalowaniem.\
Te instalatory mają skrypty bash `preinstall` i `postinstall`, których autorzy złośliwego oprogramowania zazwyczaj nadużywają do **utrwalenia** **złośliwego** **oprogramowania**.

### hdiutil

To narzędzie pozwala na **zamontowanie** obrazów dysków Apple (**.dmg**) do inspekcji przed uruchomieniem cokolwiek:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
### Spakowane binaria

* Sprawdź wysoką entropię
* Sprawdź ciągi znaków (jeśli nie ma praktycznie żadnych zrozumiałych ciągów, jest spakowane)
* Packer UPX dla systemu MacOS generuje sekcję o nazwie "\_\_XHDR"

## Statyczna analiza Objective-C

### Metadane

{% hint style="danger" %}
Zauważ, że programy napisane w Objective-C **zachowują** swoje deklaracje klas **po** **skompilowaniu** do [binariów Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takie deklaracje klas obejmują nazwę i typ:
{% endhint %}

* Zdefiniowane interfejsy
* Metody interfejsu
* Zmienne instancji interfejsu
* Zdefiniowane protokoły

Zauważ, że te nazwy mogą być zaciemnione, aby utrudnić odwracanie binariów.

### Wywoływanie funkcji

Kiedy funkcja jest wywoływana w binariach używających Objective-C, skompilowany kod zamiast wywoływać tę funkcję, wywoła **`objc_msgSend`**. Która wywoła ostateczną funkcję:

![](<../../../.gitbook/assets/image (305).png>)

Parametry, których ta funkcja oczekuje, to:

* Pierwszy parametr (**self**) to "wskaźnik wskazujący na **instancję klasy, która ma otrzymać wiadomość**". Innymi słowy, jest to obiekt, na którym wywoływana jest metoda. Jeśli metoda jest metodą klasy, będzie to instancja obiektu klasy (całość), podczas gdy dla metody instancji self wskaże zainstalowaną instancję klasy jako obiekt.
* Drugi parametr, (**op**), to "selektor metody obsługującej wiadomość". Ponownie, w prostszy sposób, jest to po prostu **nazwa metody**.
* Pozostałe parametry to wszelkie **wartości wymagane przez metodę** (op).

Zobacz, jak **łatwo uzyskać te informacje za pomocą `lldb` w ARM64** na tej stronie:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Argument**      | **Rejestr**                                                    | **(dla) objc\_msgSend**                                |
| ----------------- | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**  | **rdi**                                                        | **self: obiekt, na którym wywoływana jest metoda**     |
| **2. argument**  | **rsi**                                                        | **op: nazwa metody**                                  |
| **3. argument**  | **rdx**                                                        | **1. argument metody**                                |
| **4. argument**  | **rcx**                                                        | **2. argument metody**                                |
| **5. argument**  | **r8**                                                         | **3. argument metody**                                |
| **6. argument**  | **r9**                                                         | **4. argument metody**                                |
| **7. i kolejne argumenty** | <p><strong>rsp+</strong><br><strong>(na stosie)</strong></p> | **5. i kolejne argumenty metody**                     |

### Zrzutuj metadane ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) to narzędzie do wydobywania klas z binariów Objective-C. Repozytorium na githubie określa dyliby, ale działa również z plikami wykonywalnymi.
```bash
./dynadump dump /path/to/bin
```
W chwili pisania, to **obecnie działa najlepiej**.

#### Zwykłe narzędzia
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) to oryginalne narzędzie generujące deklaracje klas, kategorii i protokołów w kodzie sformatowanym w ObjetiveC.

Jest to stare i nieaktualizowane, więc prawdopodobnie nie będzie działać poprawnie.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) to nowoczesne i wieloplatformowe narzędzie do wydobywania klas Objective-C. W porównaniu do istniejących narzędzi, iCDump może działać niezależnie od ekosystemu Apple i udostępnia wiązania Pythona.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Statyczna analiza Swift

W przypadku binarnych plików Swift, ponieważ istnieje kompatybilność z Objective-C, czasami można wyodrębnić deklaracje za pomocą [class-dump](https://github.com/nygard/class-dump/), ale nie zawsze.

Za pomocą poleceń **`jtool -l`** lub **`otool -l`** można znaleźć kilka sekcji z prefiksem **`__swift5`**:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Możesz znaleźć dalsze informacje na temat [**informacji przechowywanych w tych sekcjach w tym wpisie na blogu**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Co więcej, **binaria Swift mogą mieć symbole** (na przykład biblioteki muszą przechowywać symbole, aby ich funkcje mogły być wywoływane). **Symbole zazwyczaj zawierają informacje o nazwie funkcji** i atrybutach w nieczytelny sposób, dlatego są bardzo przydatne, a istnieją **"demanglery"**, które mogą odzyskać oryginalną nazwę:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Analiza dynamiczna

{% hint style="warning" %}
Zauważ, że aby debugować binaria, **SIP musi być wyłączony** (`csrutil disable` lub `csrutil enable --without debug`) lub skopiować binaria do tymczasowego folderu i **usunąć podpis** za pomocą `codesign --remove-signature <ścieżka-do-binaria>` lub zezwolić na debugowanie binariów (możesz skorzystać z [tego skryptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Zauważ, że aby **instrumentować binaria systemowe** (takie jak `cloudconfigurationd`) w macOS, **SIP musi być wyłączony** (tylko usunięcie podpisu nie zadziała).
{% endhint %}

### Interfejsy programistyczne aplikacji (API)

macOS udostępnia kilka interesujących interfejsów programistycznych aplikacji, które dostarczają informacji na temat procesów:

* `proc_info`: Jest to główny interfejs dostarczający wiele informacji o każdym procesie. Aby uzyskać informacje o innych procesach, musisz być rootem, ale nie potrzebujesz specjalnych uprawnień ani portów mach.
* `libsysmon.dylib`: Pozwala uzyskać informacje o procesach za pomocą funkcji XPC, jednak konieczne jest posiadanie uprawnienia `com.apple.sysmond.client`.

### Stackshot i microstackshots

**Stackshotting** to technika używana do przechwytywania stanu procesów, w tym stosów wywołań wszystkich działających wątków. Jest to szczególnie przydatne do debugowania, analizy wydajności i zrozumienia zachowania systemu w określonym punkcie czasowym. W systemach iOS i macOS stackshotting można wykonać za pomocą kilku narzędzi i metod, takich jak narzędzia **`sample`** i **`spindump`**.

### Sysdiagnose

To narzędzie (`/usr/bini/ysdiagnose`) zbiera wiele informacji z twojego komputera, wykonując dziesiątki różnych poleceń, takich jak `ps`, `zprint`...

Musisz uruchomić je jako **root** i demon `/usr/libexec/sysdiagnosed` ma bardzo interesujące uprawnienia, takie jak `com.apple.system-task-ports` i `get-task-allow`.

Jego plist znajduje się w `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, który deklaruje 3 usługi Mach:

* `com.apple.sysdiagnose.CacheDelete`: Usuwa stare archiwa w /var/rmp
* `com.apple.sysdiagnose.kernel.ipc`: Specjalny port 23 (jądro)
* `com.apple.sysdiagnose.service.xpc`: Interfejs trybu użytkownika za pomocą klasy `Libsysdiagnose` Obj-C. Można przekazać trzy argumenty w postaci słownika (`compress`, `display`, `run`)

### Zjednoczone dzienniki

macOS generuje wiele dzienników, które mogą być bardzo przydatne podczas uruchamiania aplikacji, próbując zrozumieć **co robi**.

Co więcej, istnieją dzienniki, które będą zawierać tag `<private>` w celu **ukrycia** pewnych informacji **identyfikujących użytkownika** lub **komputer**. Jednak można **zainstalować certyfikat, aby ujawnić te informacje**. Postępuj zgodnie z wyjaśnieniami z [**tutaj**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Lewy panel

W lewym panelu hoppera można zobaczyć symbole (**Etykiety**) binariów, listę procedur i funkcji (**Proc**) oraz ciągi znaków (**Str**). Nie są to wszystkie ciągi znaków, ale te zdefiniowane w kilku częściach pliku Mac-O (takich jak _cstring lub_ `objc_methname`).

#### Środkowy panel

W środkowym panelu można zobaczyć **kod zdekompilowany**. Możesz zobaczyć go jako **surowy** rozkład, jako **graf**, jako **zdekompilowany** i jako **binarny**, klikając na odpowiednią ikonę:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Klikając prawym przyciskiem myszy na obiekcie kodu, możesz zobaczyć **odwołania do/od tego obiektu** lub nawet zmienić jego nazwę (to nie działa w zdekompilowanym pseudokodzie):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Co więcej, w **środku na dole możesz pisać polecenia pythona**.

#### Prawy panel

W prawym panelu można zobaczyć interesujące informacje, takie jak **historia nawigacji** (aby wiedzieć, jak dotarłeś do obecnej sytuacji), **graf wywołań**, gdzie można zobaczyć wszystkie **funkcje, które wywołują tę funkcję** i wszystkie funkcje, **które ta funkcja wywołuje**, oraz informacje o **zmiennych lokalnych**.

### dtrace

Pozwala użytkownikom uzyskać dostęp do aplikacji na niezwykle **niskim poziomie** i zapewnia sposób śledzenia **programów** oraz nawet zmiany ich przepływu wykonania. Dtrace używa **sond** umieszczonych w całym jądrze, takich jak na początku i końcu wywołań systemowych.

DTrace używa funkcji **`dtrace_probe_create`** do utworzenia sondy dla każdego wywołania systemowego. Sondy te mogą być wyzwalane na **wejściu i wyjściu z każdego wywołania systemowego**. Interakcja z DTrace odbywa się poprzez /dev/dtrace, który jest dostępny tylko dla użytkownika roota.

{% hint style="success" %}
Aby włączyć Dtrace bez pełnego wyłączania ochrony SIP, możesz wykonać w trybie odzyskiwania: `csrutil enable --without dtrace`

Możesz również **`dtrace`** lub **`dtruss`** binaria, **które skompilowałeś**.
{% endhint %}

Dostępne sondy dtrace można uzyskać za pomocą:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Nazwa sondy składa się z czterech części: dostawcy, modułu, funkcji i nazwy (`fbt:mach_kernel:ptrace:entry`). Jeśli nie określisz części nazwy, DTrace zastosuje tę część jako symbol wieloznaczny.

Aby skonfigurować DTrace do aktywowania sond i określenia działań do wykonania po ich wyzwoleniu, będziemy musieli użyć języka D.

Szczegółowe wyjaśnienie i więcej przykładów można znaleźć na stronie [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Przykłady

Uruchom `man -k dtrace`, aby wyświetlić **dostępne skrypty DTrace**. Przykład: `sudo dtruss -n binary`

* W linii
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* skrypt
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

Jest to narzędzie do śledzenia jądra. Udokumentowane kody można znaleźć w **`/usr/share/misc/trace.codes`**.

Narzędzia takie jak `latency`, `sc_usage`, `fs_usage` i `trace` używają go wewnętrznie.

Do interakcji z `kdebug` używany jest `sysctl` w przestrzeni nazw `kern.kdebug`, a MIBs do użycia można znaleźć w `sys/sysctl.h`, gdzie funkcje są zaimplementowane w `bsd/kern/kdebug.c`.

Aby komunikować się z kdebug za pomocą niestandardowego klienta, zazwyczaj wykonywane są następujące kroki:

* Usuń istniejące ustawienia za pomocą KERN\_KDSETREMOVE
* Ustaw śledzenie za pomocą KERN\_KDSETBUF i KERN\_KDSETUP
* Użyj KERN\_KDGETBUF, aby uzyskać liczbę wpisów bufora
* Wyłącz własnego klienta ze śledzenia za pomocą KERN\_KDPINDEX
* Włącz śledzenie za pomocą KERN\_KDENABLE
* Odczytaj bufor, wywołując KERN\_KDREADTR
* Aby dopasować każdy wątek do jego procesu, wywołaj KERN\_KDTHRMAP.

Aby uzyskać tę informację, można użyć narzędzia Apple **`trace`** lub niestandardowego narzędzia [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Zauważ, że Kdebug jest dostępny tylko dla jednego klienta na raz.** Dlatego tylko jedno narzędzie z obsługą k-debug może być uruchomione w tym samym czasie.

### ktrace

API `ktrace_*` pochodzi z `libktrace.dylib`, które owijają te z `Kdebug`. Następnie klient może po prostu wywołać `ktrace_session_create` i `ktrace_events_[single/class]` aby ustawić wywołania zwrotne na konkretne kody, a następnie uruchomić je za pomocą `ktrace_start`.

Można go używać nawet z **SIP aktywowanym**.

Można użyć jako klientów narzędzie `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### kperf

To jest używane do profilowania na poziomie jądra i jest zbudowane przy użyciu wywołań `Kdebug`.

W zasadzie, sprawdzana jest globalna zmienna `kernel_debug_active` i jeśli jest ustawiona, wywoływana jest funkcja `kperf_kdebug_handler` z kodem `Kdebug` i adresem ramki jądra wywołującej. Jeśli kod `Kdebug` pasuje do wybranego, pobierane są "akcje" skonfigurowane jako mapa bitowa (sprawdź `osfmk/kperf/action.h` w opcjach).

Kperf ma również tabelę MIB sysctl: (jako root) `sysctl kperf`. Ten kod można znaleźć w `osfmk/kperf/kperfbsd.c`.

Co więcej, podzbiór funkcjonalności Kperf znajduje się w `kpc`, który dostarcza informacje o licznikach wydajności maszyny.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) to bardzo przydatne narzędzie do sprawdzania działań związanych z procesem, które proces wykonuje (na przykład monitorowanie, które nowe procesy tworzy proces).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) to narzędzie do wyświetlania relacji między procesami.\
Musisz monitorować swój Mac za pomocą polecenia takiego jak **`sudo eslogger fork exec rename create > cap.json`** (terminal uruchamiający to wymagał FDA). Następnie możesz załadować plik json do tego narzędzia, aby zobaczyć wszystkie relacje:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) pozwala monitorować zdarzenia plików (takie jak tworzenie, modyfikacje i usuwanie), dostarczając szczegółowych informacji na ich temat.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) to narzędzie GUI z wyglądem i funkcjonalnością, które użytkownicy Windows mogą znać z _Procmon_ firmy Microsoft Sysinternal. Narzędzie to pozwala na rozpoczęcie i zatrzymanie nagrywania różnych typów zdarzeń, umożliwia filtrowanie tych zdarzeń według kategorii, takich jak plik, proces, sieć, itp., oraz zapewnia funkcjonalność zapisywania zarejestrowanych zdarzeń w formacie json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) są częścią narzędzi deweloperskich Xcode - używane do monitorowania wydajności aplikacji, identyfikowania wycieków pamięci i śledzenia aktywności systemu plików.

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

Pozwala śledzić działania wykonywane przez procesy:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) jest przydatny do zobaczenia **bibliotek** używanych przez plik binarny, **plików**, z którymi się komunikuje oraz połączeń **sieciowych**.\
Sprawdza również procesy binarne pod kątem **virustotal** i wyświetla informacje o pliku binarnym.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

W [**tym wpisie na blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) znajdziesz przykład, jak **debugować działające demony**, które używają **`PT_DENY_ATTACH`** do uniemożliwienia debugowania, nawet jeśli SIP jest wyłączone.

### lldb

**lldb** to narzędzie **de facto** do **debugowania** plików binarnych w systemie **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Możesz ustawić wersję intel, korzystając z lldb, tworząc plik o nazwie **`.lldbinit`** w swoim folderze domowym i dodając następującą linijkę:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Wewnątrz lldb, zrzuć proces za pomocą `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Polecenie</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Rozpoczęcie wykonania, które będzie kontynuowane do momentu trafienia w punkt przerwania lub zakończenia procesu.</td></tr><tr><td><strong>continue (c)</strong></td><td>Kontynuacja wykonania procesu w trybie debugowania.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Wykonaj następną instrukcję. To polecenie pomija wywołania funkcji.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Wykonaj następną instrukcję. W przeciwieństwie do polecenia nexti, to polecenie wejdzie w wywołania funkcji.</td></tr><tr><td><strong>finish (f)</strong></td><td>Wykonaj resztę instrukcji w bieżącej funkcji ("ramce") i zatrzymaj.</td></tr><tr><td><strong>control + c</strong></td><td>Wstrzymaj wykonanie. Jeśli proces został uruchomiony (r) lub kontynuowany (c), spowoduje to zatrzymanie procesu ...gdziekolwiek jest obecnie wykonywany.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Dowolna funkcja o nazwie main</p><p>b &#x3C;binname>`main #Główna funkcja pliku binarnego</p><p>b set -n main --shlib &#x3C;lib_name> #Główna funkcja wskazanego pliku binarnego</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista punktów przerwania</p><p>br e/dis &#x3C;num> #Włącz/Wyłącz punkt przerwania</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Uzyskaj pomoc dotyczącą polecenia punktu przerwania</p><p>help memory write #Uzyskaj pomoc w zapisywaniu do pamięci</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address</strong></td><td>Wyświetl pamięć jako łańcuch zakończony znakiem null.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address</strong></td><td>Wyświetl pamięć jako instrukcję asemblerową.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address</strong></td><td>Wyświetl pamięć jako bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>To polecenie wyświetli obiekt wskazywany przez parametr</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Zauważ, że większość interfejsów API Objective-C firmy Apple zwraca obiekty i powinny być wyświetlane za pomocą polecenia "print object" (po). Jeśli po nie generuje sensownego wyniku, użyj <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Zapisz AAAA pod tym adresem<br>memory write -f s $rip+0x11f+7 "AAAA" #Zapisz AAAA pod adresem</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Rozkład bieżącej funkcji</p><p>dis -n &#x3C;funcname> #Rozkład funkcji</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Rozkład funkcji<br>dis -c 6 #Rozkład 6 linii<br>dis -c 0x100003764 -e 0x100003768 # Od jednego adresu do drugiego<br>dis -p -c 4 # Rozpocznij rozkładanie w bieżącym adresie</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Sprawdź tablicę 3 komponentów w rejestrze x1</td></tr></tbody></table>

{% hint style="info" %}
Podczas wywoływania funkcji **`objc_sendMsg`**, rejestr **rsi** przechowuje **nazwę metody** jako łańcuch zakończony znakiem null ("C"). Aby wyświetlić nazwę za pomocą lldb, wykonaj:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anty-Analiza Dynamiczna

#### Wykrywanie maszyn wirtualnych

* Polecenie **`sysctl hw.model`** zwraca "Mac", gdy **hostem jest MacOS**, ale coś innego, gdy jest to maszyna wirtualna.
* Grając z wartościami **`hw.logicalcpu`** i **`hw.physicalcpu`**, niektóre złośliwe oprogramowanie próbuje wykryć, czy jest to maszyna wirtualna.
* Niektóre złośliwe oprogramowanie może również **wykryć**, czy maszyna jest oparta na **VMware** na podstawie adresu MAC (00:50:56).
* Można również sprawdzić, czy proces jest debugowany za pomocą prostego kodu takiego jak:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proces jest debugowany }`
* Można również wywołać wywołanie systemowe **`ptrace`** z flagą **`PT_DENY_ATTACH`**. To **uniemożliwia** dołączenie i śledzenie przez debugera.
* Można sprawdzić, czy funkcja **`sysctl`** lub **`ptrace`** jest **importowana** (ale złośliwe oprogramowanie mogłoby importować je dynamicznie)
* Jak zauważono w tym artykule, „[Pokonanie Technik Anty-Debugowania: macOS warianty ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
„_Wiadomość Proces # zakończony ze **statusem = 45 (0x0000002d)** jest zwykle wyraźnym sygnałem, że cel debugowania używa **PT\_DENY\_ATTACH**_”
## Zrzuty pamięci

Zrzuty pamięci są tworzone, jeśli:

- sysctl `kern.coredump` jest ustawiony na 1 (domyślnie)
- Jeśli proces nie był suid/sgid lub `kern.sugid_coredump` jest ustawione na 1 (domyślnie jest 0)
- Limit `AS_CORE` pozwala na operację. Można zablokować tworzenie zrzutów pamięci, wykonując polecenie `ulimit -c 0`, a następnie ponownie włączyć je za pomocą `ulimit -c unlimited`.

W tych przypadkach zrzuty pamięci są generowane zgodnie z sysctl `kern.corefile` i zazwyczaj przechowywane są w `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizuje procesy, które uległy awarii i zapisuje raport o awarii na dysku**. Raport o awarii zawiera informacje, które mogą **pomóc programiście zdiagnozować** przyczynę awarii.\
Dla aplikacji i innych procesów **uruchamianych w kontekście uruchamiania per użytkownika**, ReportCrash działa jako LaunchAgent i zapisuje raporty o awariach w `~/Library/Logs/DiagnosticReports/` użytkownika.\
Dla demonów, innych procesów **uruchamianych w kontekście uruchamiania systemowego** i innych uprzywilejowanych procesów, ReportCrash działa jako LaunchDaemon i zapisuje raporty o awariach w `/Library/Logs/DiagnosticReports` systemu.

Jeśli martwisz się o to, że raporty o awariach **są wysyłane do Apple**, możesz je wyłączyć. W przeciwnym razie raporty o awariach mogą być przydatne do **zrozumienia, jak doszło do awarii serwera**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sen

Podczas przeprowadzania fuzzingu w systemie MacOS ważne jest, aby nie pozwalać Macowi zasypiać:

* systemsetup -setsleep Never
* pmset, Preferencje systemowe
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Rozłączenie SSH

Jeśli przeprowadzasz fuzzing za pośrednictwem połączenia SSH, ważne jest, aby upewnić się, że sesja nie zostanie przerwana. Zmodyfikuj plik sshd\_config:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Wewnętrzne obsługiwane

**Sprawdź następującą stronę**, aby dowiedzieć się, jak można znaleźć, która aplikacja jest odpowiedzialna za **obsługę określonego schematu lub protokołu:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Wyliczanie procesów sieciowych
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
### Lub użyj `netstat` lub `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Działa dla narzędzi CLI.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

To "**po prostu działa"** z narzędziami GUI macOS. Zauważ, że niektóre aplikacje macOS mają określone wymagania, takie jak unikalne nazwy plików, odpowiednie rozszerzenie, konieczność odczytu plików z piaskownicy (`~/Library/Containers/com.apple.Safari/Data`)...

Przykłady:
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### Więcej informacji o Fuzzing MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referencje

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana **dark-webem**, która oferuje **darmowe** funkcje sprawdzania, czy firma lub jej klienci zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące informacje**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z oprogramowania kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Naucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępniaj sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
