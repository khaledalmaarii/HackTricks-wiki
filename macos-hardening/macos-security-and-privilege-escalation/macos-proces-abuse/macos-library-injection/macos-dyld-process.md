# macOS Dyld Prozess

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Grundlegende Informationen

Der eigentliche **Einstiegspunkt** eines Mach-o-Binärdatei ist der dynamische Linker, der in `LC_LOAD_DYLINKER` definiert ist und normalerweise `/usr/lib/dyld` ist.

Dieser Linker muss alle ausführbaren Bibliotheken lokalisieren, sie im Speicher abbilden und alle nicht-faulen Bibliotheken verknüpfen. Erst nach diesem Prozess wird der Einstiegspunkt der Binärdatei ausgeführt.

Natürlich hat **`dyld`** keine Abhängigkeiten (es verwendet Systemaufrufe und libSystem-Auszüge).

{% hint style="danger" %}
Wenn dieser Linker eine Sicherheitslücke aufweist, da er vor der Ausführung von Binärdateien (auch hochprivilegierten) ausgeführt wird, wäre es möglich, **Berechtigungen zu eskalieren**.
{% endhint %}

### Ablauf

Dyld wird von **`dyldboostrap::start`** geladen, der auch Dinge wie den **Stack-Canary** lädt. Dies liegt daran, dass diese Funktion im **`apple`**-Argumentvektor diesen und andere **sensible Werte** erhält.

**`dyls::_main()`** ist der Einstiegspunkt von dyld und seine erste Aufgabe besteht darin, `configureProcessRestrictions()` auszuführen, das normalerweise die **`DYLD_*`**-Umgebungsvariablen einschränkt, wie in erklärt:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Dann wird der dyld-Shared-Cache abgebildet, der alle wichtigen Systembibliotheken vorverknüpft, und dann werden die Bibliotheken abgebildet, von denen die Binärdatei abhängt, und dies wird rekursiv fortgesetzt, bis alle benötigten Bibliotheken geladen sind. Daher:

1. beginnt es mit dem Laden eingefügter Bibliotheken mit `DYLD_INSERT_LIBRARIES` (falls erlaubt)
2. Dann die freigegebenen gecachten
3. Dann die importierten
1. &#x20;Dann weiterhin Bibliotheken rekursiv importieren

Sobald alle geladen sind, werden die **Initialisierer** dieser Bibliotheken ausgeführt. Diese sind mit **`__attribute__((constructor))`** codiert, definiert in `LC_ROUTINES[_64]` (jetzt veraltet) oder durch Zeiger in einem Abschnitt mit der Markierung `S_MOD_INIT_FUNC_POINTERS` (normalerweise: **`__DATA.__MOD_INIT_FUNC`**).

Terminatoren sind mit **`__attribute__((destructor))`** codiert und befinden sich in einem Abschnitt mit der Markierung `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Stubs

Alle Binärdateien in macOS sind dynamisch verknüpft. Daher enthalten sie einige Stub-Abschnitte, die der Binärdatei helfen, zum richtigen Code in verschiedenen Maschinen und Kontexten zu springen. Es ist dyld, wenn die Binärdatei ausgeführt wird, das Gehirn, das diese Adressen auflösen muss (zumindest die nicht-faulen).

Einige Stub-Abschnitte in der Binärdatei:

* **`__TEXT.__[auth_]stubs`**: Zeiger aus `__DATA`-Abschnitten
* **`__TEXT.__stub_helper`**: Kleiner Code, der das dynamische Verknüpfen mit Informationen zum aufzurufenden Funktion aufruft
* **`__DATA.__[auth_]got`**: Global Offset Table (Adressen zu importierten Funktionen, wenn aufgelöst, (während der Ladezeit gebunden, da er mit der Flagge `S_NON_LAZY_SYMBOL_POINTERS` markiert ist)
* **`__DATA.__nl_symbol_ptr`**: Nicht-faule Symbolzeiger (während der Ladezeit gebunden, da er mit der Flagge `S_NON_LAZY_SYMBOL_POINTERS` markiert ist)
* **`__DATA.__la_symbol_ptr`**: Lazy-Symbolzeiger (beim ersten Zugriff gebunden)

{% hint style="warning" %}
Beachten Sie, dass die Zeiger mit dem Präfix "auth\_" einen in-process-Verschlüsselungsschlüssel verwenden, um sie zu schützen (PAC). Außerdem ist es möglich, die arm64-Anweisung `BLRA[A/B]` zu verwenden, um den Zeiger vor dem Folgen zu überprüfen. Und das RETA\[A/B\] kann anstelle einer RET-Adresse verwendet werden.\
Tatsächlich wird der Code in **`__TEXT.__auth_stubs`** **`braa`** anstelle von **`bl`** verwenden, um die angeforderte Funktion aufzurufen, um den Zeiger zu authentifizieren.

Beachten Sie auch, dass aktuelle dyld-Versionen **alles als nicht-faul** laden.
{% endhint %}

### Lazy-Symbole finden
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Interessanter Disassembly-Teil:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Es ist möglich zu sehen, dass der Sprung zum Aufruf von printf zu **`__TEXT.__stubs`** führt:
```bash
objdump --section-headers ./load

./load:	file format mach-o arm64

Sections:
Idx Name          Size     VMA              Type
0 __text        00000038 0000000100003f60 TEXT
1 __stubs       0000000c 0000000100003f98 TEXT
2 __cstring     00000004 0000000100003fa4 DATA
3 __unwind_info 00000058 0000000100003fa8 DATA
4 __got         00000008 0000000100004000 DATA
```
Bei der Disassemblierung des **`__stubs`** Abschnitts:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Du kannst sehen, dass wir **zur Adresse des GOT springen**, die in diesem Fall nicht träge aufgelöst wird und die Adresse der printf-Funktion enthält.

In anderen Situationen könnte anstelle des direkten Springens zum GOT **`__DATA.__la_symbol_ptr`** verwendet werden, das einen Wert lädt, der die Funktion repräsentiert, die geladen werden soll. Anschließend wird zum **`__TEXT.__stub_helper`** gesprungen, der zum **`__DATA.__nl_symbol_ptr`** springt, der die Adresse des **`dyld_stub_binder`** enthält, der als Parameter die Nummer der Funktion und eine Adresse erhält.\
Diese letzte Funktion schreibt nach dem Auffinden der Adresse der gesuchten Funktion diese an die entsprechende Stelle in **`__TEXT.__stub_helper`**, um zukünftige Nachschlagen zu vermeiden.

{% hint style="success" %}
Beachte jedoch, dass aktuelle dyld-Versionen alles als nicht träge laden.
{% endhint %}

#### Dyld-Operationen

Schließlich muss **`dyld_stub_binder`** die angegebene Funktion finden und an die richtige Adresse schreiben, um nicht erneut danach suchen zu müssen. Dazu verwendet es Opcodes (eine endliche Zustandsmaschine) innerhalb von dyld.

## apple\[] Argumentvektor

In macOS erhält die Hauptfunktion tatsächlich 4 Argumente anstelle von 3. Das vierte wird apple genannt und jeder Eintrag hat die Form `key=value`. Zum Beispiel:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
Der folgende Inhalt ist aus einer Hacking-Buch über Hacking-Techniken. Der folgende Inhalt stammt aus der Datei macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-process.md. Übersetze den relevanten englischen Text ins Deutsche und gib die Übersetzung zurück, wobei genau die gleiche Markdown- und HTML-Syntax beibehalten wird. Übersetze keine Dinge wie Code, Hacking-Technikenamen, Hacking-Wörter, Cloud/SaaS-Plattformnamen (wie Workspace, aws, gcp...), das Wort 'leak', Pentesting und Markdown-Tags. Füge auch keine zusätzlichen Informationen hinzu, außer der Übersetzung und der Markdown-Syntax.
```
0: executable_path=./a
1:
2:
3:
4: ptr_munge=
5: main_stack=
6: executable_file=0x1a01000012,0x5105b6a
7: dyld_file=0x1a01000012,0xfffffff0009834a
8: executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b
9: executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa
10: arm64e_abi=os
11: th_port=
```
{% hint style="success" %}
Zu dem Zeitpunkt, an dem diese Werte die Hauptfunktion erreichen, wurde bereits sensitive Information daraus entfernt oder es hätte zu einem Datenleck geführt.
{% endhint %}

Es ist möglich, all diese interessanten Werte beim Debuggen zu sehen, bevor sie in die Hauptfunktion gelangen:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Aktuelle ausführbare Datei auf '/tmp/a' gesetzt (arm64).
(lldb) process launch -s
[..]

<strong>(lldb) mem read $sp
</strong>0x16fdff510: 00 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00  ................
0x16fdff520: d8 f6 df 6f 01 00 00 00 00 00 00 00 00 00 00 00  ...o............

<strong>(lldb) x/55s 0x016fdff6d8
</strong>[...]
0x16fdffd6a: "TERM_PROGRAM=WarpTerminal"
0x16fdffd84: "WARP_USE_SSH_WRAPPER=1"
0x16fdffd9b: "WARP_IS_LOCAL_SHELL_SESSION=1"
0x16fdffdb9: "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.4.sdk"
0x16fdffe24: "NVM_DIR=/Users/carlospolop/.nvm"
0x16fdffe44: "CONDA_CHANGEPS1=false"
0x16fdffe5a: ""
0x16fdffe5b: ""
0x16fdffe5c: ""
0x16fdffe5d: ""
0x16fdffe5e: ""
0x16fdffe5f: ""
0x16fdffe60: "pfz=0xffeaf0000"
0x16fdffe70: "stack_guard=0x8af2b510e6b800b5"
0x16fdffe8f: "malloc_entropy=0xf2349fbdea53f1e4,0x3fd85d7dcf817101"
0x16fdffec4: "ptr_munge=0x983e2eebd2f3e746"
0x16fdffee1: "main_stack=0x16fe00000,0x7fc000,0x16be00000,0x4000000"
0x16fdfff17: "executable_file=0x1a01000012,0x5105b6a"
0x16fdfff3e: "dyld_file=0x1a01000012,0xfffffff0009834a"
0x16fdfff67: "executable_cdhash=757a1b08ab1a79c50a66610f3adbca86dfd3199b"
0x16fdfffa2: "executable_boothash=f32448504e788a2c5935e372d22b7b18372aa5aa"
0x16fdfffdf: "arm64e_abi=os"
0x16fdfffed: "th_port=0x103"
0x16fdffffb: ""
</code></pre>

## dyld\_all\_image\_infos

Dies ist eine Struktur, die von dyld mit Informationen über den dyld-Zustand exportiert wird und die im [**Quellcode**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) gefunden werden kann, mit Informationen wie der Version, einem Zeiger auf das dyld\_image\_info-Array, auf dyld\_image\_notifier, ob der Prozess vom gemeinsamen Cache getrennt ist, ob der libSystem-Initializer aufgerufen wurde, einem Zeiger auf den eigenen Mach-Header von dyls, einem Zeiger auf die dyld-Version...

## dyld Umgebungsvariablen

### dyld debuggen

Interessante Umgebungsvariablen, die helfen zu verstehen, was dyld macht:

* **DYLD\_PRINT\_LIBRARIES**

Überprüfen Sie jede Bibliothek, die geladen wird:
```
DYLD_PRINT_LIBRARIES=1 ./apple
dyld[19948]: <9F848759-9AB8-3BD2-96A1-C069DC1FFD43> /private/tmp/a
dyld[19948]: <F0A54B2D-8751-35F1-A3CF-F1A02F842211> /usr/lib/libSystem.B.dylib
dyld[19948]: <C683623C-1FF6-3133-9E28-28672FDBA4D3> /usr/lib/system/libcache.dylib
dyld[19948]: <BFDF8F55-D3DC-3A92-B8A1-8EF165A56F1B> /usr/lib/system/libcommonCrypto.dylib
dyld[19948]: <B29A99B2-7ADE-3371-A774-B690BEC3C406> /usr/lib/system/libcompiler_rt.dylib
dyld[19948]: <65612C42-C5E4-3821-B71D-DDE620FB014C> /usr/lib/system/libcopyfile.dylib
dyld[19948]: <B3AC12C0-8ED6-35A2-86C6-0BFA55BFF333> /usr/lib/system/libcorecrypto.dylib
dyld[19948]: <8790BA20-19EC-3A36-8975-E34382D9747C> /usr/lib/system/libdispatch.dylib
dyld[19948]: <4BB77515-DBA8-3EDF-9AF7-3C9EAE959EA6> /usr/lib/system/libdyld.dylib
dyld[19948]: <F7CE9486-FFF5-3CB8-B26F-75811EF4283A> /usr/lib/system/libkeymgr.dylib
dyld[19948]: <1A7038EC-EE49-35AE-8A3C-C311083795FB> /usr/lib/system/libmacho.dylib
[...]
```
* **DYLD\_PRINT\_SEGMENTS**

Überprüfen Sie, wie jede Bibliothek geladen wird:
```
DYLD_PRINT_SEGMENTS=1 ./apple
dyld[21147]: re-using existing shared cache (/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e):
dyld[21147]:         0x181944000->0x1D5D4BFFF init=5, max=5 __TEXT
dyld[21147]:         0x1D5D4C000->0x1D5EC3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x1D7EC4000->0x1D8E23FFF init=3, max=3 __DATA
dyld[21147]:         0x1D8E24000->0x1DCEBFFFF init=3, max=3 __AUTH
dyld[21147]:         0x1DCEC0000->0x1E22BFFFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x1E42C0000->0x1E5457FFF init=1, max=1 __LINKEDIT
dyld[21147]:         0x1E5458000->0x22D173FFF init=5, max=5 __TEXT
dyld[21147]:         0x22D174000->0x22D9E3FFF init=1, max=3 __DATA_CONST
dyld[21147]:         0x22F9E4000->0x230F87FFF init=3, max=3 __DATA
dyld[21147]:         0x230F88000->0x234EC3FFF init=3, max=3 __AUTH
dyld[21147]:         0x234EC4000->0x237573FFF init=1, max=3 __AUTH_CONST
dyld[21147]:         0x239574000->0x270BE3FFF init=1, max=1 __LINKEDIT
dyld[21147]: Kernel mapped /private/tmp/a
dyld[21147]:     __PAGEZERO (...) 0x000000904000->0x000101208000
dyld[21147]:         __TEXT (r.x) 0x000100904000->0x000100908000
dyld[21147]:   __DATA_CONST (rw.) 0x000100908000->0x00010090C000
dyld[21147]:     __LINKEDIT (r..) 0x00010090C000->0x000100910000
dyld[21147]: Using mapping in dyld cache for /usr/lib/libSystem.B.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E59D000->0x00018E59F000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDB98->0x0001D5DFDBA8
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE015A8->0x0001DDE01878
dyld[21147]:         __AUTH (rw.) 0x0001D9688650->0x0001D9688658
dyld[21147]:         __DATA (rw.) 0x0001D808AD60->0x0001D808AD68
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
dyld[21147]: Using mapping in dyld cache for /usr/lib/system/libcache.dylib
dyld[21147]:         __TEXT (r.x) 0x00018E597000->0x00018E59D000
dyld[21147]:   __DATA_CONST (rw.) 0x0001D5DFDAF0->0x0001D5DFDB98
dyld[21147]:   __AUTH_CONST (rw.) 0x0001DDE014D0->0x0001DDE015A8
dyld[21147]:     __LINKEDIT (r..) 0x000239574000->0x000270BE4000
[...]
```
* **DYLD\_PRINT\_INITIALIZERS**

Drucken, wann jeder Bibliotheksinitialisierer ausgeführt wird:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Andere

* `DYLD_BIND_AT_LAUNCH`: Lazy-Bindungen werden mit nicht-lazy Bindungen aufgelöst
* `DYLD_DISABLE_PREFETCH`: Deaktiviert das Vorabladen von \_\_DATA- und \_\_LINKEDIT-Inhalten
* `DYLD_FORCE_FLAT_NAMESPACE`: Bindungen auf einer Ebene
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Auflösungspfade
* `DYLD_INSERT_LIBRARIES`: Laden einer bestimmten Bibliothek
* `DYLD_PRINT_TO_FILE`: Schreibt dyld-Debug in eine Datei
* `DYLD_PRINT_APIS`: Druckt libdyld-API-Aufrufe
* `DYLD_PRINT_APIS_APP`: Druckt libdyld-API-Aufrufe, die von main gemacht wurden
* `DYLD_PRINT_BINDINGS`: Druckt Symbole beim Binden
* `DYLD_WEAK_BINDINGS`: Druckt nur schwache Symbole beim Binden
* `DYLD_PRINT_CODE_SIGNATURES`: Druckt Registrierungsvorgänge für Codesignaturen
* `DYLD_PRINT_DOFS`: Druckt D-Trace-Objektformatabschnitte beim Laden
* `DYLD_PRINT_ENV`: Druckt von dyld gesehene Umgebungen
* `DYLD_PRINT_INTERPOSTING`: Druckt Interposting-Vorgänge
* `DYLD_PRINT_LIBRARIES`: Druckt geladene Bibliotheken
* `DYLD_PRINT_OPTS`: Druckt Ladeoptionen
* `DYLD_REBASING`: Druckt Symbol-Rebasierungsoperationen
* `DYLD_RPATHS`: Druckt Erweiterungen von @rpath
* `DYLD_PRINT_SEGMENTS`: Druckt Zuordnungen von Mach-O-Segmenten
* `DYLD_PRINT_STATISTICS`: Druckt Zeitstatistiken
* `DYLD_PRINT_STATISTICS_DETAILS`: Druckt detaillierte Zeitstatistiken
* `DYLD_PRINT_WARNINGS`: Druckt Warnmeldungen
* `DYLD_SHARED_CACHE_DIR`: Pfad zur Verwendung des gemeinsamen Bibliothekscaches
* `DYLD_SHARED_REGION`: "use", "private", "avoid"
* `DYLD_USE_CLOSURES`: Aktiviert Closures

Es ist möglich, mehr mit etwas wie zu finden:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Oder laden Sie das dyld-Projekt von [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) herunter und führen Sie es im Ordner aus:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Referenzen

* [**\*OS Internals, Band I: Benutzermodus. Von Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositorys einreichen.

</details>
