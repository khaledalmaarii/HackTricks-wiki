# macOS Apps - Inspektion, Debugging und Fuzzing

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Statische Analyse

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

Das Tool kann als **Ersatz** für **codesign**, **otool** und **objdump** verwendet werden und bietet einige zusätzliche Funktionen. [**Hier herunterladen**](http://www.newosxbook.com/tools/jtool.html) oder mit `brew` installieren.
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
**`Codesign`** kann in **macOS** gefunden werden, während **`ldid`** in **iOS** gefunden werden kann.
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) ist ein nützliches Tool, um **.pkg**-Dateien (Installationsprogramme) zu inspizieren und zu sehen, was sich darin befindet, bevor sie installiert werden.\
Diese Installationsprogramme enthalten `preinstall`- und `postinstall`-Bash-Skripte, die von Malware-Autoren häufig missbraucht werden, um die Malware **dauerhaft** zu machen.

### hdiutil

Dieses Tool ermöglicht das **Mounten** von Apple-Disk-Images (**.dmg**-Dateien), um sie vor der Ausführung zu inspizieren:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Es wird in `/Volumes` eingebunden.

### Objective-C

#### Metadaten

{% hint style="danger" %}
Beachten Sie, dass Programme, die in Objective-C geschrieben sind, ihre Klassendeklarationen beibehalten, wenn sie in [Mach-O-Binärdateien](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md) kompiliert werden. Solche Klassendeklarationen enthalten den Namen und Typ von:
{% endhint %}

* Die Klasse
* Die Klassenmethoden
* Die Instanzvariablen der Klasse

Sie können diese Informationen mit [**class-dump**](https://github.com/nygard/class-dump) erhalten:
```bash
class-dump Kindle.app
```
#### Funktionsaufruf

Wenn eine Funktion in einem Binärprogramm aufgerufen wird, das Objective-C verwendet, ruft der kompilierte Code anstelle dieser Funktion **`objc_msgSend`** auf. Dieser ruft dann die endgültige Funktion auf:

![](<../../../.gitbook/assets/image (560).png>)

Die von dieser Funktion erwarteten Parameter sind:

* Der erste Parameter (**self**) ist ein "Zeiger, der auf die **Instanz der Klasse zeigt, die die Nachricht empfangen soll**". Einfacher ausgedrückt handelt es sich um das Objekt, auf dem die Methode aufgerufen wird. Wenn die Methode eine Klassenmethode ist, handelt es sich dabei um eine Instanz des Klassenobjekts (insgesamt), während bei einer Instanzmethode self auf eine instanziierte Instanz der Klasse als Objekt verweist.
* Der zweite Parameter (**op**) ist "der Selektor der Methode, die die Nachricht behandelt". Auch hier handelt es sich einfach um den **Namen der Methode**.
* Die restlichen Parameter sind alle **Werte, die von der Methode** (op) **benötigt werden**.

| **Argument**      | **Register**                                                    | **(für) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1. Argument**   | **rdi**                                                         | **self: Objekt, auf dem die Methode aufgerufen wird**  |
| **2. Argument**   | **rsi**                                                         | **op: Name der Methode**                              |
| **3. Argument**   | **rdx**                                                         | **1. Argument der Methode**                           |
| **4. Argument**   | **rcx**                                                         | **2. Argument der Methode**                           |
| **5. Argument**   | **r8**                                                          | **3. Argument der Methode**                           |
| **6. Argument**   | **r9**                                                          | **4. Argument der Methode**                           |
| **7. und mehr**   | <p><strong>rsp+</strong><br><strong>(auf dem Stack)</strong></p> | **5. und weitere Argumente der Methode**               |

### Swift

Bei Swift-Binärdateien kann es aufgrund der Objective-C-Kompatibilität manchmal möglich sein, Deklarationen mit [class-dump](https://github.com/nygard/class-dump/) zu extrahieren, aber nicht immer.

Mit den Befehlszeilen **`jtool -l`** oder **`otool -l`** ist es möglich, mehrere Abschnitte zu finden, die mit dem Präfix **`__swift5`** beginnen:
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
Sie können weitere Informationen über die in diesem Abschnitt gespeicherten Informationen in diesem [Blog-Beitrag](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html) finden.

Darüber hinaus können **Swift-Binärdateien Symbole enthalten** (zum Beispiel müssen Bibliotheken Symbole speichern, damit ihre Funktionen aufgerufen werden können). Die **Symbole enthalten normalerweise Informationen über den Funktionsnamen** und die Attribute auf eine unansehnliche Weise, daher sind sie sehr nützlich und es gibt "**Demangler"**, die den ursprünglichen Namen erhalten können:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Gepackte Binärdateien

* Überprüfen Sie die hohe Entropie
* Überprüfen Sie die Zeichenketten (wenn es fast keine verständliche Zeichenkette gibt, ist sie gepackt)
* Der UPX-Packer für MacOS generiert einen Abschnitt namens "\_\_XHDR"

## Dynamische Analyse

{% hint style="warning" %}
Beachten Sie, dass zum Debuggen von Binärdateien **SIP deaktiviert sein muss** (`csrutil disable` oder `csrutil enable --without debug`) oder dass die Binärdateien in einen temporären Ordner kopiert und die Signatur mit `codesign --remove-signature <binary-path>` entfernt werden müssen oder dass das Debuggen der Binärdatei erlaubt ist (Sie können [dieses Skript](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b) verwenden).
{% endhint %}

{% hint style="warning" %}
Beachten Sie, dass zum **Instrumentieren von Systembinärdateien** (wie `cloudconfigurationd`) auf macOS **SIP deaktiviert sein muss** (das Entfernen der Signatur allein funktioniert nicht).
{% endhint %}

### Vereinheitlichte Protokolle

MacOS generiert viele Protokolle, die sehr nützlich sein können, wenn eine Anwendung ausgeführt wird, um zu verstehen, **was sie tut**.

Darüber hinaus gibt es einige Protokolle, die das Tag `<private>` enthalten, um einige **benutzer- oder computeridentifizierbare Informationen** zu **verbergen**. Es ist jedoch möglich, ein Zertifikat zu installieren, um diese Informationen offenzulegen. Befolgen Sie die Erklärungen von [**hier**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Linkes Panel

Im linken Panel von Hopper können Sie die Symbole (**Labels**) der Binärdatei, die Liste der Prozeduren und Funktionen (**Proc**) und die Zeichenketten (**Str**) sehen. Dies sind nicht alle Zeichenketten, sondern diejenigen, die in verschiedenen Teilen der Mac-O-Datei definiert sind (wie _cstring oder_ `objc_methname`).

#### Mittleres Panel

Im mittleren Panel sehen Sie den **disassemblierten Code**. Und Sie können ihn als **rohen** Disassemblierung, als **Graph**, als **decompilierten** Code und als **Binärdatei** anzeigen, indem Sie auf das entsprechende Symbol klicken:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Durch Klicken mit der rechten Maustaste auf ein Codeobjekt können Sie **Verweise auf/von diesem Objekt** sehen oder sogar dessen Namen ändern (dies funktioniert nicht im dekompilierten Pseudocode):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Darüber hinaus können Sie im **mittleren unteren Bereich Python-Befehle** eingeben.

#### Rechtes Panel

Im rechten Panel können Sie interessante Informationen wie den **Navigationsverlauf** (damit Sie wissen, wie Sie zur aktuellen Situation gekommen sind), den **Aufrufgraphen**, in dem Sie alle Funktionen sehen können, die diese Funktion aufrufen, und alle Funktionen, die **diese Funktion aufruft**, und Informationen zu **lokalen Variablen** sehen.

### dtrace

Es ermöglicht Benutzern den Zugriff auf Anwendungen auf einer äußerst **niedrigen Ebene** und bietet eine Möglichkeit für Benutzer, **Programme zu verfolgen** und sogar ihren Ausführungsfluss zu ändern. DTrace verwendet **Sonden**, die im gesamten Kernel platziert sind und sich an Orten wie dem Anfang und Ende von Systemaufrufen befinden.

DTrace verwendet die Funktion **`dtrace_probe_create`**, um eine Sonde für jeden Systemaufruf zu erstellen. Diese Sonden können an der **Einstiegs- und Ausstiegspunkten jedes Systemaufrufs** ausgelöst werden. Die Interaktion mit DTrace erfolgt über /dev/dtrace, das nur für den Root-Benutzer verfügbar ist.

{% hint style="success" %}
Um Dtrace zu aktivieren, ohne den SIP-Schutz vollständig zu deaktivieren, können Sie im Wiederherstellungsmodus folgenden Befehl ausführen: `csrutil enable --without dtrace`

Sie können auch **`dtrace`** oder **`dtruss`** Binärdateien ausführen, die **Sie kompiliert haben**.
{% endhint %}

Die verfügbaren Sonden von dtrace können mit dem Befehl erhalten werden:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Der Sondierungsname besteht aus vier Teilen: dem Anbieter, dem Modul, der Funktion und dem Namen (`fbt:mach_kernel:ptrace:entry`). Wenn Sie keinen Teil des Namens angeben, wird Dtrace diesen Teil als Platzhalter verwenden.

Um DTrace zu konfigurieren, um Sonden zu aktivieren und anzugeben, welche Aktionen bei ihrem Auslösen ausgeführt werden sollen, müssen wir die D-Sprache verwenden.

Eine ausführlichere Erklärung und weitere Beispiele finden Sie unter [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Beispiele

Führen Sie `man -k dtrace` aus, um die verfügbaren **DTrace-Skripte** aufzulisten. Beispiel: `sudo dtruss -n binary`

* In Zeile
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
# macOS Apps: Inspecting, Debugging, and Fuzzing

In this section, we will explore various techniques for inspecting, debugging, and fuzzing macOS apps. These techniques are useful for identifying vulnerabilities and potential security issues in applications running on macOS.

## Inspecting Apps

Inspecting apps involves analyzing the binary code and resources of an application to gain a deeper understanding of its inner workings. This can be done using various tools and techniques, such as:

- **Static Analysis**: This involves examining the binary code of an application without executing it. Tools like `otool` and `Hopper` can be used to disassemble and analyze the code.

- **Dynamic Analysis**: This involves running the application and monitoring its behavior in real-time. Tools like `lldb` and `Instruments` can be used to debug and trace the execution of the application.

- **Reverse Engineering**: This involves decompiling the binary code of an application to understand its logic and functionality. Tools like `IDA Pro` and `Ghidra` can be used for this purpose.

## Debugging Apps

Debugging apps involves identifying and fixing issues in the code of an application. This can be done using various debugging techniques, such as:

- **Breakpoints**: This involves setting breakpoints in the code to pause the execution and inspect the state of the application. Tools like `lldb` and `Xcode` provide support for setting breakpoints.

- **Stepping**: This involves stepping through the code line by line to understand its flow and identify potential issues. Tools like `lldb` and `Xcode` provide support for stepping through the code.

- **Memory Analysis**: This involves analyzing the memory usage of an application to identify memory-related issues, such as memory leaks and buffer overflows. Tools like `Instruments` and `Valgrind` can be used for memory analysis.

## Fuzzing Apps

Fuzzing apps involves testing an application by providing it with unexpected and invalid inputs to identify vulnerabilities and crashes. This can be done using various fuzzing techniques, such as:

- **File Fuzzing**: This involves providing the application with malformed or specially crafted files to trigger vulnerabilities. Tools like `AFL` and `Peach` can be used for file fuzzing.

- **Network Fuzzing**: This involves sending malformed or specially crafted network packets to the application to trigger vulnerabilities. Tools like `Spike` and `Boofuzz` can be used for network fuzzing.

- **Protocol Fuzzing**: This involves fuzzing the application's communication protocols to identify vulnerabilities. Tools like `Sulley` and `Peach` can be used for protocol fuzzing.

By using these techniques, you can gain valuable insights into the security of macOS apps and identify potential vulnerabilities that can be exploited by attackers.
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

To use `dtruss`, you need to specify the process ID (PID) of the target application. You can find the PID using the `ps` command or other process monitoring tools.

Once you have the PID, you can run `dtruss` with the `-p` option followed by the PID. This will start tracing the system calls made by the application.

By default, `dtruss` will display the system calls and their arguments in real-time. You can also use various options to filter and format the output. For example, the `-t` option can be used to display timestamps for each system call.

`dtruss` can be a powerful tool for understanding how an application interacts with the operating system and identifying potential vulnerabilities or performance issues. However, it should be used responsibly and with proper authorization, as it can be considered intrusive and may violate privacy or security policies.

**Note:** `dtruss` requires root privileges to trace system calls made by other processes.
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Sie können dies auch verwenden, selbst wenn **SIP aktiviert** ist.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) ist ein sehr nützliches Tool, um die prozessbezogenen Aktionen zu überprüfen, die ein Prozess durchführt (zum Beispiel, um zu überwachen, welche neuen Prozesse ein Prozess erstellt).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) ist ein Tool, das die Beziehungen zwischen Prozessen darstellt.\
Sie müssen Ihren Mac mit einem Befehl wie **`sudo eslogger fork exec rename create > cap.json`** überwachen (das Terminal, das dies startet, erfordert FDA). Anschließend können Sie die JSON-Datei in diesem Tool laden, um alle Beziehungen anzuzeigen:

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) ermöglicht das Überwachen von Dateiaktionen (wie Erstellung, Änderungen und Löschungen) und liefert detaillierte Informationen zu solchen Ereignissen.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) ist ein GUI-Tool mit dem Look and Feel, das Windows-Benutzer möglicherweise von Microsoft Sysinternal's _Procmon_ kennen. Dieses Tool ermöglicht das Starten und Stoppen der Aufzeichnung verschiedener Ereignistypen, das Filtern dieser Ereignisse nach Kategorien wie Datei, Prozess, Netzwerk usw. und bietet die Möglichkeit, die aufgezeichneten Ereignisse im JSON-Format zu speichern.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) sind Teil der Xcode Developer Tools und werden zur Überwachung der Anwendungsleistung, zur Identifizierung von Speicherlecks und zur Verfolgung von Dateisystemaktivitäten verwendet.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Ermöglicht das Verfolgen von Aktionen, die von Prozessen durchgeführt werden:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) ist nützlich, um die von einer Binärdatei verwendeten **Bibliotheken**, die von ihr verwendeten **Dateien** und die **Netzwerk**-Verbindungen zu sehen.\
Es überprüft auch die Binärprozesse gegen **virustotal** und zeigt Informationen über die Binärdatei an.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

In [**diesem Blog-Beitrag**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) finden Sie ein Beispiel, wie man ein laufendes Daemon-Programm **debuggt**, das **`PT_DENY_ATTACH`** verwendet, um das Debuggen zu verhindern, auch wenn SIP deaktiviert ist.

### lldb

**lldb** ist das **De-facto-Tool** für das **Debuggen** von Binärdateien unter **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Sie können den Intel-Modus festlegen, wenn Sie lldb verwenden, indem Sie eine Datei namens **`.lldbinit`** in Ihrem Home-Verzeichnis erstellen und die folgende Zeile hinzufügen:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
In lldb können Sie einen Prozess mit `process save-core` dumpen.
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Befehl</strong></td><td><strong>Beschreibung</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Startet die Ausführung, die fortgesetzt wird, bis ein Breakpoint erreicht wird oder der Prozess beendet wird.</td></tr><tr><td><strong>continue (c)</strong></td><td>Führt die Ausführung des debuggten Prozesses fort.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Führt die nächste Anweisung aus. Dieser Befehl überspringt Funktionsaufrufe.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Führt die nächste Anweisung aus. Im Gegensatz zum Befehl nexti wird dieser Befehl Funktionen aufrufen.</td></tr><tr><td><strong>finish (f)</strong></td><td>Führt den Rest der Anweisungen in der aktuellen Funktion ("Frame") aus und hält an.</td></tr><tr><td><strong>Strg + C</strong></td><td>Unterbricht die Ausführung. Wenn der Prozess ausgeführt (r) oder fortgesetzt (c) wurde, wird er an der aktuellen Ausführungsstelle angehalten.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Jede Funktion namens main</p><p>b &#x3C;binname>`main #Hauptfunktion der Binärdatei</p><p>b set -n main --shlib &#x3C;lib_name> #Hauptfunktion der angegebenen Binärdatei</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Liste der Breakpoints</p><p>br e/dis &#x3C;num> #Aktivieren/Deaktivieren des Breakpoints</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Hilfe zum Breakpoint-Befehl erhalten</p><p>help memory write #Hilfe zum Schreiben in den Speicher erhalten</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Zeigt den Speicher als nullterminierten String an.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Zeigt den Speicher als Assembler-Anweisung an.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Zeigt den Speicher als Byte an.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Gibt das Objekt aus, auf das der Parameter verweist</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Beachten Sie, dass die meisten Objective-C-APIs oder -Methoden von Apple Objekte zurückgeben und daher über den Befehl "print object" (po) angezeigt werden sollten. Wenn po keine sinnvolle Ausgabe liefert, verwenden Sie <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Schreibt AAAA an diese Adresse<br>memory write -f s $rip+0x11f+7 "AAAA" #Schreibt AAAA an die Adresse</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disassembliert die aktuelle Funktion</p><p>dis -n &#x3C;funcname> #Disassembliert die Funktion</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Disassembliert die Funktion<br>dis -c 6 #Disassembliert 6 Zeilen<br>dis -c 0x100003764 -e 0x100003768 # Von einer Adresse bis zur anderen<br>dis -p -c 4 # Beginnt an der aktuellen Adresse mit dem Disassemblieren</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Überprüft das Array mit 3 Komponenten im Register x1</td></tr></tbody></table>

{% hint style="info" %}
Bei Aufruf der Funktion **`objc_sendMsg`** enthält das Register **rsi** den **Methodennamen** als nullterminierten ("C") String. Um den Namen über lldb auszugeben, verwenden Sie:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Dynamic Analysis

#### VM-Erkennung

* Der Befehl **`sysctl hw.model`** gibt "Mac" zurück, wenn der Host ein MacOS ist, aber etwas anderes, wenn es sich um eine VM handelt.
* Durch Manipulation der Werte von **`hw.logicalcpu`** und **`hw.physicalcpu`** versuchen einige Malware, festzustellen, ob es sich um eine VM handelt.
* Einige Malware können auch anhand der MAC-Adresse (00:50:56) erkennen, ob die Maschine auf VMware basiert.
* Es ist auch möglich festzustellen, ob ein Prozess debuggt wird, mit einem einfachen Code wie diesem:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //Prozess wird debuggt }`
* Es kann auch der Systemaufruf **`ptrace`** mit dem Flag **`PT_DENY_ATTACH`** aufgerufen werden. Dadurch wird verhindert, dass ein Debugger angehängt und verfolgt wird.
* Sie können überprüfen, ob die Funktion **`sysctl`** oder **`ptrace`** importiert wird (aber die Malware könnte sie dynamisch importieren).
* Wie in diesem Artikel "[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)" festgestellt wurde:\
"_Die Meldung Prozess # wurde mit **Status = 45 (0x0000002d)** beendet, ist normalerweise ein deutliches Zeichen dafür, dass das Debug-Ziel **PT\_DENY\_ATTACH** verwendet._"
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analysiert abstürzende Prozesse und speichert einen Absturzbericht auf der Festplatte**. Ein Absturzbericht enthält Informationen, die einem Entwickler helfen können, die Ursache eines Absturzes zu diagnostizieren.\
Für Anwendungen und andere Prozesse, die **im Kontext des per-Benutzer launchd** ausgeführt werden, läuft ReportCrash als LaunchAgent und speichert Absturzberichte im Verzeichnis `~/Library/Logs/DiagnosticReports/` des Benutzers.\
Für Daemonen, andere Prozesse, die **im Kontext des systemweiten launchd** und andere privilegierte Prozesse ausgeführt werden, läuft ReportCrash als LaunchDaemon und speichert Absturzberichte im Verzeichnis `/Library/Logs/DiagnosticReports` des Systems.

Wenn Sie sich Sorgen machen, dass Absturzberichte **an Apple gesendet** werden, können Sie sie deaktivieren. Andernfalls können Absturzberichte nützlich sein, um herauszufinden, **wie ein Server abgestürzt ist**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sleep

Beim Fuzzing in MacOS ist es wichtig, dass der Mac nicht in den Ruhezustand geht:

* systemsetup -setsleep Never
* pmset, Systemeinstellungen
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### SSH-Verbindung trennen

Wenn Sie über eine SSH-Verbindung fuzzing betreiben, ist es wichtig sicherzustellen, dass die Sitzung nicht abbricht. Ändern Sie daher die sshd\_config-Datei wie folgt:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Interne Handler

**Schauen Sie sich die folgende Seite an**, um herauszufinden, wie Sie herausfinden können, welche App für **die Bearbeitung des angegebenen Schemas oder Protokolls verantwortlich ist:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Netzwerkprozesse auflisten

Dies ist interessant, um Prozesse zu finden, die Netzwerkdaten verwalten:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Oder verwenden Sie `netstat` oder `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funktioniert für CLI-Tools.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Es funktioniert "**einfach so"** mit macOS GUI-Tools. Beachten Sie, dass einige macOS-Apps spezifische Anforderungen haben, wie z.B. eindeutige Dateinamen, die richtige Erweiterung und das Lesen der Dateien aus der Sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Einige Beispiele:

{% code overflow="wrap" %}
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

### Weitere Informationen zum Fuzzing von MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referenzen

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
