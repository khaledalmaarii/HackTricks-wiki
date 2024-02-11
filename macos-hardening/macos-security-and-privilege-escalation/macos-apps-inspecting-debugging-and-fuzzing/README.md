# macOS Apps - Inspekcja, debugowanie i Fuzzing

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakowania, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>

## Analiza statyczna

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

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

### jtool2

Ten narzędzie może być używane jako **zamiennik** dla **codesign**, **otool** i **objdump**, oraz dostarcza kilka dodatkowych funkcji. [**Pobierz je tutaj**](http://www.newosxbook.com/tools/jtool.html) lub zainstaluj je za pomocą `brew`.
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
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** można znaleźć w systemie **macOS**, podczas gdy **`ldid`** można znaleźć w systemie **iOS**.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) to narzędzie przydatne do sprawdzania plików **.pkg** (instalatorów) i zobaczenia, co jest w środku przed ich instalacją.\
Te instalatory mają skrypty bash `preinstall` i `postinstall`, których autorzy złośliwego oprogramowania zazwyczaj nadużywają do **utrwalania** **złośliwego** **oprogramowania**.

### hdiutil

To narzędzie pozwala na **montowanie** obrazów dysków Apple (**.dmg**) w celu ich sprawdzenia przed uruchomieniem czegokolwiek:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Zostanie zamontowany w `/Volumes`

### Objective-C

#### Metadane

{% hint style="danger" %}
Zauważ, że programy napisane w Objective-C **zachowują** swoje deklaracje klas **po** **kompilacji** do [binarnych plików Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Takie deklaracje klas **zawierają** nazwę i typ:
{% endhint %}

* Klasa
* Metody klasy
* Zmienne instancji klasy

Możesz uzyskać te informacje za pomocą [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Wywoływanie funkcji

Kiedy funkcja jest wywoływana w binarnym pliku, który używa Objective-C, skompilowany kod zamiast wywoływać tę funkcję, wywoła **`objc_msgSend`**. To spowoduje wywołanie ostatecznej funkcji:

![](<../../../.gitbook/assets/image (560).png>)

Ta funkcja oczekuje następujących parametrów:

* Pierwszy parametr (**self**) to "wskaźnik wskazujący na **instancję klasy, która ma otrzymać wiadomość**". Innymi słowy, jest to obiekt, na którym jest wywoływana metoda. Jeśli metoda jest metodą klasy, będzie to instancja obiektu klasy (jako całość), podczas gdy dla metody instancji self będzie wskazywać na zainicjowaną instancję klasy jako obiekt.
* Drugi parametr (**op**) to "selektor metody obsługującej wiadomość". Prościej mówiąc, jest to po prostu **nazwa metody**.
* Pozostałe parametry to **wartości wymagane przez metodę** (op).

| **Argument**      | **Rejestr**                                                     | **(dla) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. argument**   | **rdi**                                                         | **self: obiekt, na którym jest wywoływana metoda**     |
| **2. argument**   | **rsi**                                                         | **op: nazwa metody**                                  |
| **3. argument**   | **rdx**                                                         | **1. argument metody**                                |
| **4. argument**   | **rcx**                                                         | **2. argument metody**                                |
| **5. argument**   | **r8**                                                          | **3. argument metody**                                |
| **6. argument**   | **r9**                                                          | **4. argument metody**                                |
| **7. i kolejne**  | <p><strong>rsp+</strong><br><strong>(na stosie)</strong></p>   | **5. i kolejne argumenty metody**                     |

### Swift

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

Ponadto, **binarne pliki Swift mogą zawierać symbole** (na przykład biblioteki muszą przechowywać symbole, aby można było wywołać ich funkcje). **Symbole zazwyczaj zawierają informacje o nazwie funkcji** i atrybutach w nieczytelny sposób, dlatego są bardzo przydatne, a istnieją "**demanglery"**, które mogą odtworzyć oryginalną nazwę:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Spakowane pliki binarne

* Sprawdź wysoką entropię
* Sprawdź ciągi znaków (jeśli nie ma prawie żadnych zrozumiałych ciągów, jest spakowany)
* Packer UPX dla MacOS generuje sekcję o nazwie "\_\_XHDR"

## Analiza dynamiczna

{% hint style="warning" %}
Należy pamiętać, że w celu debugowania plików binarnych **SIP musi być wyłączony** (`csrutil disable` lub `csrutil enable --without debug`) lub skopiować pliki binarne do tymczasowego folderu i **usunąć podpis** za pomocą `codesign --remove-signature <ścieżka-do-binarnego>` lub umożliwić debugowanie binarnego (można użyć [tego skryptu](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Należy pamiętać, że w celu **instrumentowania binarnych plików systemowych** (takich jak `cloudconfigurationd`) na macOS, **SIP musi być wyłączony** (usunięcie podpisu nie zadziała).
{% endhint %}

### Unified Logs

MacOS generuje wiele logów, które mogą być bardzo przydatne podczas uruchamiania aplikacji w celu zrozumienia, **co robi**.

Ponadto, istnieją pewne logi, które będą zawierać tag `<private>` w celu **ukrycia** pewnych informacji **identyfikujących użytkownika** lub **komputera**. Jednak można **zainstalować certyfikat w celu ujawnienia tych informacji**. Postępuj zgodnie z wyjaśnieniami [**tutaj**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Lewy panel

W lewym panelu hoppera można zobaczyć symbole (**etykiety**) binarnego pliku, listę procedur i funkcji (**Proc**) oraz ciągi znaków (**Str**). Nie są to wszystkie ciągi znaków, ale te zdefiniowane w różnych częściach pliku Mac-O (takie jak _cstring_ lub `objc_methname`).

#### Środkowy panel

W środkowym panelu można zobaczyć **skompilowany kod**. Można go zobaczyć jako **surowy** rozkład, jako **graf**, jako **zdekompilowany** i jako **binarny**, klikając na odpowiednią ikonę:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Klikając prawym przyciskiem myszy na obiekcie kodu, można zobaczyć **odwołania do/od tego obiektu** lub nawet zmienić jego nazwę (to nie działa w zdekompilowanym pseudokodzie):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Ponadto, w **środkowej dolnej części można pisać polecenia pythona**.

#### Prawy panel

W prawym panelu można zobaczyć interesujące informacje, takie jak **historię nawigacji** (aby wiedzieć, jak dotarłeś do obecnej sytuacji), **graf wywołań**, w którym można zobaczyć wszystkie funkcje, które wywołują tę funkcję, i wszystkie funkcje, **które ta funkcja wywołuje**, oraz informacje o **zmiennych lokalnych**.

### dtrace

Pozwala użytkownikom uzyskać dostęp do aplikacji na **bardzo niskim poziomie** i umożliwia śledzenie **programów** oraz nawet zmianę ich przebiegu. Dtrace używa **sond** umieszczonych w całym jądrze, takich jak na początku i na końcu wywołań systemowych.

DTrace używa funkcji **`dtrace_probe_create`** do utworzenia sondy dla każdego wywołania systemowego. Sondy te mogą być wywoływane na **wejściu i wyjściu każdego wywołania systemowego**. Interakcja z DTrace odbywa się za pośrednictwem /dev/dtrace, który jest dostępny tylko dla użytkownika root.

{% hint style="success" %}
Aby włączyć Dtrace bez pełnego wyłączania ochrony SIP, można wykonać w trybie odzyskiwania: `csrutil enable --without dtrace`

Można również **uruchamiać binarne** **`dtrace`** lub **`dtruss`**, które **skompilowałeś**.
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
Nazwa sondy składa się z czterech części: dostawca, moduł, funkcja i nazwa (`fbt:mach_kernel:ptrace:entry`). Jeśli nie określisz części nazwy, Dtrace potraktuje ją jako symbol wieloznaczny.

Aby skonfigurować DTrace w celu aktywacji sond i określenia działań do wykonania po ich wyzwoleniu, będziemy musieli użyć języka D.

Szczegółowe wyjaśnienie i więcej przykładów można znaleźć pod adresem [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

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

`dtruss` is a command-line tool available on macOS that allows you to trace and inspect system calls made by a process. It can be used for debugging and analyzing the behavior of applications.

To use `dtruss`, you need to specify the target process by its process ID (PID) or by the name of the executable file. Once the process is traced, `dtruss` will display the system calls made by the process, along with their arguments and return values.

Here is an example of how to use `dtruss`:

```bash
$ sudo dtruss -p <PID>
```

Replace `<PID>` with the process ID of the target process. Running `dtruss` with root privileges (`sudo`) may be necessary to trace certain system calls.

`dtruss` can be a powerful tool for understanding how an application interacts with the operating system and for identifying potential security vulnerabilities or performance issues. However, it should be used responsibly and only on systems or processes that you have permission to inspect.

For more information about `dtruss` and its usage, you can refer to the [official macOS man page](https://developer.apple.com/library/archive/documentation/Darwin/Reference/ManPages/man1/dtruss.1.html).
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Możesz używać tego nawet z **aktywowanym SIP**
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) to bardzo przydatne narzędzie do sprawdzania działań związanych z procesem, które wykonuje dany proces (na przykład monitorowanie, jakie nowe procesy tworzy dany proces).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) to narzędzie do wyświetlania relacji między procesami.\
Musisz monitorować swojego Maca za pomocą polecenia **`sudo eslogger fork exec rename create > cap.json`** (terminal uruchamiający to polecenie wymaga FDA). Następnie możesz załadować plik json do tego narzędzia, aby zobaczyć wszystkie relacje:

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) pozwala monitorować zdarzenia związane z plikami (takie jak tworzenie, modyfikacje i usuwanie), dostarczając szczegółowych informacji na temat tych zdarzeń.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) to narzędzie GUI o wyglądzie i funkcjonalności znanej użytkownikom systemu Windows z narzędzia _Procmon_ firmy Microsoft Sysinternal. Narzędzie to umożliwia rozpoczęcie i zatrzymanie rejestracji różnych typów zdarzeń, umożliwia filtrowanie tych zdarzeń według kategorii, takich jak plik, proces, sieć, itp., oraz zapewnia funkcjonalność zapisywania zarejestrowanych zdarzeń w formacie json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) są częścią narzędzi deweloperskich Xcode - służą do monitorowania wydajności aplikacji, identyfikowania wycieków pamięci i śledzenia aktywności systemu plików.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Pozwala śledzić działania wykonywane przez procesy:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) jest przydatny do sprawdzania **bibliotek** używanych przez plik binarny, **plików**, których używa oraz **połączeń sieciowych**.\
Sprawdza również procesy binarne w **virustotal** i wyświetla informacje o pliku binarnym.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

W [**tym wpisie na blogu**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) znajdziesz przykład, jak **debugować działającego daemona**, który używa **`PT_DENY_ATTACH`** do uniemożliwienia debugowania, nawet jeśli SIP jest wyłączony.

### lldb

**lldb** to narzędzie **de facto** do **debugowania** plików binarnych na **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Możesz ustawić wersję Intel podczas korzystania z lldb, tworząc plik o nazwie **`.lldbinit`** w folderze domowym i dodając do niego następującą linię:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Wewnątrz lldb, zapisz proces za pomocą `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>Polecenie (lldb)</strong></td><td><strong>Opis</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Rozpoczęcie wykonania, które będzie kontynuowane, dopóki nie zostanie osiągnięty punkt przerwania lub proces nie zostanie zakończony.</td></tr><tr><td><strong>continue (c)</strong></td><td>Kontynuowanie wykonania procesu w trybie debugowania.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Wykonaj następną instrukcję. To polecenie pomija wywołania funkcji.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Wykonaj następną instrukcję. W przeciwieństwie do polecenia nexti, to polecenie wchodzi w wywołania funkcji.</td></tr><tr><td><strong>finish (f)</strong></td><td>Wykonaj pozostałe instrukcje w bieżącej funkcji ("ramce") i zakończ.</td></tr><tr><td><strong>control + c</strong></td><td>Wstrzymaj wykonanie. Jeśli proces został uruchomiony (r) lub kontynuowany (c), spowoduje to zatrzymanie procesu ...gdziekolwiek jest obecnie wykonywany.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Dowolna funkcja o nazwie main</p><p>b &#x3C;binname>`main #Główna funkcja binarki</p><p>b set -n main --shlib &#x3C;lib_name> #Główna funkcja wskazanej binarki</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista punktów przerwań</p><p>br e/dis &#x3C;num> #Włącz/Wyłącz punkt przerwania</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Uzyskaj pomoc dotyczącą polecenia breakpoint</p><p>help memory write #Uzyskaj pomoc dotyczącą zapisu do pamięci</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Wyświetl pamięć jako ciąg zakończony zerem.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Wyświetl pamięć jako instrukcję asemblera.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Wyświetl pamięć jako bajt.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Spowoduje to wydrukowanie obiektu wskazywanego przez parametr</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Zauważ, że większość interfejsów API Objective-C Apple'a lub metod zwraca obiekty i powinny być wyświetlane za pomocą polecenia "print object" (po). Jeśli polecenie po nie daje sensownego wyniku, użyj <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Zapisz AAAA pod tym adresem<br>memory write -f s $rip+0x11f+7 "AAAA" #Zapisz AAAA pod tym adresem</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Rozkład bieżącej funkcji</p><p>dis -n &#x3C;funcname> #Rozkład funkcji</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Rozkład funkcji<br>dis -c 6 #Rozkład 6 linii<br>dis -c 0x100003764 -e 0x100003768 #Od jednego adresu do drugiego<br>dis -p -c 4 #Rozpocznij rozkładanie od bieżącego adresu</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 #Sprawdź tablicę 3 składników w rejestrze x1</td></tr></tbody></table>

{% hint style="info" %}
Podczas wywoływania funkcji **`objc_sendMsg`**, rejestr **rsi** przechowuje **nazwę metody** jako ciąg zakończony zerem ("C"). Aby wydrukować nazwę za pomocą lldb, wykonaj:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anty-Analiza Dynamiczna

#### Wykrywanie maszyn wirtualnych

* Polecenie **`sysctl hw.model`** zwraca "Mac", gdy **hostem jest MacOS**, ale coś innego, gdy jest to maszyna wirtualna.
* Niektóre złośliwe oprogramowanie próbuje wykryć, czy jest to maszyna wirtualna, poprzez manipulację wartościami **`hw.logicalcpu`** i **`hw.physicalcpu`**.
* Niektóre złośliwe oprogramowanie może również **wykryć**, czy maszyna jest oparta na VMware na podstawie adresu MAC (00:50:56).
* Można również sprawdzić, czy proces jest debugowany za pomocą prostego kodu, na przykład:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proces jest debugowany }`
* Można również wywołać systemowe wywołanie **`ptrace`** z flagą **`PT_DENY_ATTACH`**. Zapobiega to dołączaniu i śledzeniu przez debugera.
* Można sprawdzić, czy funkcja **`sysctl`** lub **`ptrace`** jest **importowana** (ale złośliwe oprogramowanie może importować je dynamicznie)
* Jak zauważono w tym artykule, "[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)":\
"_Wiadomość Process # exited with **status = 45 (0x0000002d)** jest zwykle wyraźnym sygnałem, że debugowany cel używa **PT\_DENY\_ATTACH**_"
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analizuje procesy, które uległy awarii i zapisuje raport o awarii na dysku**. Raport o awarii zawiera informacje, które mogą **pomóc programiście zdiagnozować** przyczynę awarii.\
Dla aplikacji i innych procesów **działających w kontekście uruchamiania per użytkownik**, ReportCrash działa jako LaunchAgent i zapisuje raporty o awariach w folderze `~/Library/Logs/DiagnosticReports/` użytkownika.\
Dla demonów, innych procesów **działających w kontekście uruchamiania systemowego** oraz innych uprzywilejowanych procesów, ReportCrash działa jako LaunchDaemon i zapisuje raporty o awariach w folderze `/Library/Logs/DiagnosticReports` systemu.

Jeśli martwisz się o to, że raporty o awariach **są wysyłane do Apple**, możesz je wyłączyć. Jeśli nie, raporty o awariach mogą być przydatne do **ustalenia przyczyny awarii serwera**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Uśpienie

Podczas fuzzingu w systemie MacOS ważne jest, aby nie pozwolić na uśpienie komputera Mac:

* systemsetup -setsleep Never
* pmset, Preferencje systemowe
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Rozłączenie SSH

Jeśli przeprowadzasz fuzzing za pośrednictwem połączenia SSH, ważne jest, aby upewnić się, że sesja nie zostanie przerwana. Aby to zrobić, zmień plik sshd\_config:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Wewnętrzne obsługiwane

**Sprawdź następującą stronę**, aby dowiedzieć się, jak można znaleźć aplikację odpowiedzialną za **obsługę określonego schematu lub protokołu:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Wyliczanie procesów sieciowych

To interesujące, aby znaleźć procesy zarządzające danymi sieciowymi:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Lub użyj `netstat` lub `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzery

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Działa dla narzędzi CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

To "**po prostu działa"** z narzędziami GUI dla macOS. Należy zauważyć, że niektóre aplikacje macOS mają specyficzne wymagania, takie jak unikalne nazwy plików, odpowiednie rozszerzenie, konieczność odczytu plików z piaskownicy (`~/Library/Containers/com.apple.Safari/Data`)...

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

### Więcej informacji o testowaniu poprawności działania aplikacji na MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Odnośniki

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
