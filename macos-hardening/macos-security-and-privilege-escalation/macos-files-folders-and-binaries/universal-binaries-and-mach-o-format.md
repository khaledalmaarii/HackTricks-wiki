# macOS Universelle Binärdateien & Mach-O Format

{% hint style="success" %}
Lernen & üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
{% endhint %}

## Grundlegende Informationen

Mac OS-Binärdateien sind normalerweise als **universelle Binärdateien** kompiliert. Eine **universelle Binärdatei** kann **mehrere Architekturen in derselben Datei unterstützen**.

Diese Binärdateien folgen der **Mach-O-Struktur**, die im Wesentlichen aus folgendem besteht:

* Header
* Ladebefehle
* Daten

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Fat-Header

Suchen Sie nach der Datei mit: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* Anzahl der folgenden Strukturen */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* CPU-Spezifikator (int) */
cpu_subtype_t	cpusubtype;	/* Maschinenspezifikator (int) */
uint32_t	offset;		/* Dateioffset zu dieser Objektdatei */
uint32_t	size;		/* Größe dieser Objektdatei */
uint32_t	align;		/* Ausrichtung als Potenz von 2 */
};
</code></pre>

Der Header enthält die **magischen** Bytes gefolgt von der **Anzahl** der **Architekturen**, die die Datei **enthält** (`nfat_arch`) und jede Architektur wird eine `fat_arch`-Struktur haben.

Überprüfen Sie es mit:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universelle Binärdatei mit 2 Architekturen: [x86_64:Mach-O 64-Bit ausführbare x86_64] [arm64e:Mach-O 64-Bit ausführbare arm64e]
/bin/ls (für Architektur x86_64):	Mach-O 64-Bit ausführbare x86_64
/bin/ls (für Architektur arm64e):	Mach-O 64-Bit ausführbare arm64e

% otool -f -v /bin/ls
Fat-Header
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>Architektur x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
Fähigkeiten 0x0
<strong>    offset 16384
</strong><strong>    Größe 72896
</strong>    Ausrichtung 2^14 (16384)
<strong>Architektur arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
Fähigkeiten PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    Größe 88816
</strong>    Ausrichtung 2^14 (16384)
</code></pre>

oder mit dem [Mach-O View](https://sourceforge.net/projects/machoview/) Tool:

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Wie Sie vielleicht denken, verdoppelt eine universelle Binärdatei, die für 2 Architekturen kompiliert ist, normalerweise die Größe einer, die nur für 1 Architektur kompiliert ist.

## **Mach-O-Header**

Der Header enthält grundlegende Informationen über die Datei, wie magische Bytes zur Identifizierung als Mach-O-Datei und Informationen über die Zielarchitektur. Sie finden ihn unter: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Mach-O Dateitypen

Es gibt verschiedene Dateitypen, die in der [**Quellcodebeispiel hier**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h) definiert sind. Die wichtigsten sind:

* `MH_OBJECT`: Relokalisierbare Objektdatei (Zwischenprodukte der Kompilierung, noch keine ausführbaren Dateien).
* `MH_EXECUTE`: Ausführbare Dateien.
* `MH_FVMLIB`: Datei einer festen VM-Bibliothek.
* `MH_CORE`: Code-Dumps
* `MH_PRELOAD`: Vorab geladene ausführbare Datei (nicht mehr in XNU unterstützt)
* `MH_DYLIB`: Dynamische Bibliotheken
* `MH_DYLINKER`: Dynamischer Linker
* `MH_BUNDLE`: "Plugin-Dateien". Generiert mit -bundle in gcc und explizit geladen von `NSBundle` oder `dlopen`.
* `MH_DYSM`: Begleitende `.dSym`-Datei (Datei mit Symbolen für Debugging).
* `MH_KEXT_BUNDLE`: Kernelerweiterungen.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oder mit [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Der Quellcode definiert auch mehrere nützliche Flags zum Laden von Bibliotheken:

* `MH_NOUNDEFS`: Keine undefinierten Verweise (vollständig verknüpft)
* `MH_DYLDLINK`: Dyld-Verknüpfung
* `MH_PREBOUND`: Dynamische Verweise vorab gebunden.
* `MH_SPLIT_SEGS`: Datei teilt r/o- und r/w-Segmente auf.
* `MH_WEAK_DEFINES`: Binärdatei hat schwach definierte Symbole
* `MH_BINDS_TO_WEAK`: Binärdatei verwendet schwache Symbole
* `MH_ALLOW_STACK_EXECUTION`: Den Stack ausführbar machen
* `MH_NO_REEXPORTED_DYLIBS`: Bibliothek ohne LC\_REEXPORT-Befehle
* `MH_PIE`: Positionsunabhängige ausführbare Datei
* `MH_HAS_TLV_DESCRIPTORS`: Es gibt einen Abschnitt mit thread-lokalen Variablen
* `MH_NO_HEAP_EXECUTION`: Keine Ausführung für Heap-/Daten-Seiten
* `MH_HAS_OBJC`: Binärdatei hat oBject-C-Abschnitte
* `MH_SIM_SUPPORT`: Simulatorunterstützung
* `MH_DYLIB_IN_CACHE`: Verwendet auf dylibs/Frameworks im gemeinsamen Bibliotheks-Cache.

## **Mach-O Load-Befehle**

Die **Speicherlayout der Datei** ist hier festgelegt, wobei der **Speicherort der Symboltabelle**, der Kontext des Hauptthreads beim Start der Ausführung und die erforderlichen **gemeinsam genutzten Bibliotheken** beschrieben werden. Anweisungen werden dem dynamischen Loader **(dyld)** zum Laden des Binärprogramms in den Speicher bereitgestellt.

Es wird die **load\_command**-Struktur verwendet, die in der genannten **`loader.h`** definiert ist:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Es gibt ungefähr **50 verschiedene Arten von Ladungsbefehlen**, die das System unterschiedlich behandelt. Die häufigsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Grundsätzlich definieren diese Arten von Ladungsbefehlen, **wie der \_\_TEXT** (ausführbarer Code) **und \_\_DATA** (Daten für den Prozess) **Segmenten** entsprechend den **Offsets geladen werden, die im Datenabschnitt** angegeben sind, wenn die Binärdatei ausgeführt wird.
{% endhint %}

Diese Befehle **definieren Segmente**, die in den **virtuellen Speicherbereich** eines Prozesses abgebildet werden, wenn er ausgeführt wird.

Es gibt **verschiedene Arten** von Segmenten, wie das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das Daten enthält, die vom Prozess verwendet werden. Diese **Segmente befinden sich im Datenabschnitt** der Mach-O-Datei.

**Jedes Segment** kann weiter in mehrere **Abschnitte** unterteilt werden. Die **Ladungsbefehlsstruktur** enthält **Informationen** zu **diesen Abschnitten** innerhalb des jeweiligen Segments.

Im Header finden Sie zuerst den **Segment-Header**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* für 64-Bit-Architekturen */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* enthält die Größe der section_64-Strukturen */
char		segname[16];	/* Segmentname */
uint64_t	vmaddr;		/* Speicheradresse dieses Segments */
uint64_t	vmsize;		/* Speichergröße dieses Segments */
uint64_t	fileoff;	/* Dateioffset dieses Segments */
uint64_t	filesize;	/* Menge, die aus der Datei abgebildet werden soll */
int32_t		maxprot;	/* maximale VM-Schutzmaßnahme */
int32_t		initprot;	/* anfänglicher VM-Schutz */
<strong>	uint32_t	nsects;		/* Anzahl der Abschnitte im Segment */
</strong>	uint32_t	flags;		/* Flags */
};
</code></pre>

Beispiel für einen Segment-Header:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Dieser Header definiert die **Anzahl der Abschnitte, deren Header danach erscheinen**:
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
Beispiel für **Abschnittsüberschrift**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Wenn Sie den **Abschnittsversatz** (0x37DC) + den **Versatz** hinzufügen, an dem die **Architektur beginnt**, in diesem Fall `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Es ist auch möglich, **Headerinformationen** von der **Befehlszeile** aus abzurufen:
```bash
otool -lv /bin/ls
```
```md
Gemeinsame Segmente, die von diesem Befehl geladen werden:

* **`__PAGEZERO`:** Es weist den Kernel an, die **Adresse Null** so zu **zuordnen**, dass sie **nicht gelesen, geschrieben oder ausgeführt werden kann**. Die Variablen maxprot und minprot in der Struktur sind auf Null gesetzt, um anzuzeigen, dass es **keine Lese-Schreib-Ausführungsrechte auf dieser Seite** gibt.
* Diese Zuweisung ist wichtig, um **NULL-Pointer-Dereferenz-Schwachstellen zu mildern**. Dies liegt daran, dass XNU eine harte Nullseite durchsetzt, die sicherstellt, dass die erste Seite (nur die erste) des Speichers unzugänglich ist (außer in i386). Ein Binärfile könnte diese Anforderungen erfüllen, indem es ein kleines \_\_PAGEZERO (unter Verwendung von `-pagezero_size`) erstellt, um die ersten 4 KB abzudecken und den Rest des 32-Bit-Speichers sowohl im Benutzer- als auch im Kernelmodus zugänglich zu machen.
* **`__TEXT`**: Enthält **ausführbaren** **Code** mit **Lese-** und **Ausführungsberechtigungen** (nicht schreibbar)**.** Gemeinsame Abschnitte dieses Segments:
* `__text`: Kompilierter Binärcode
* `__const`: Konstante Daten (nur lesbar)
* `__[c/u/os_log]string`: C-, Unicode- oder os-Log-Zeichenfolgenkonstanten
* `__stubs` und `__stubs_helper`: Werden während des dynamischen Bibliotheksladevorgangs verwendet
* `__unwind_info`: Stack-Unwind-Daten.
* Beachten Sie, dass all diese Inhalte signiert sind, aber auch als ausführbar markiert sind (was mehr Möglichkeiten für die Ausnutzung von Abschnitten schafft, die diese Berechtigung nicht unbedingt benötigen, wie z. B. für spezielle Zeichenfolgenabschnitte).
* **`__DATA`**: Enthält Daten, die **lesbar** und **schreibbar** sind (nicht ausführbar)**.**
* `__got:` Global Offset Table
* `__nl_symbol_ptr`: Nicht träge (bei Laden binden) Symbolzeiger
* `__la_symbol_ptr`: Träge (bei Verwendung binden) Symbolzeiger
* `__const`: Sollte schreibgeschützte Daten sein (ist es aber nicht wirklich)
* `__cfstring`: CoreFoundation-Zeichenfolgen
* `__data`: Globale Variablen (die initialisiert wurden)
* `__bss`: Statische Variablen (die nicht initialisiert wurden)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist usw.): Informationen, die vom Objective-C-Laufzeitumgebung verwendet werden
* **`__DATA_CONST`**: \_\_DATA.\_\_const ist nicht garantiert konstant zu sein (Schreibberechtigungen), ebenso wie andere Zeiger und die GOT. Dieser Abschnitt macht `__const`, einige Initialisierer und die GOT-Tabelle (nach der Auflösung) mit `mprotect` **schreibgeschützt**.
* **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld) wie Symbol-, Zeichenfolgen- und Relokationstabelleneinträge. Es ist ein generischer Container für Inhalte, die weder in `__TEXT` noch in `__DATA` sind, und sein Inhalt wird in anderen Ladebefehlen beschrieben.
* dyld-Informationen: Rebase, Nicht-träge/träge/schwache Bindungsoperationen und Exportinformationen
* Funktionsstarts: Tabelle der Startadressen von Funktionen
* Daten im Code: Dateninseln in \_\_text
* Symboltabelle: Symbole im Binärfile
* Indirekte Symboltabelle: Zeiger/Stub-Symbole
* Zeichentabelle
* Codesignatur
* **`__OBJC`**: Enthält Informationen, die von der Objective-C-Laufzeitumgebung verwendet werden. Diese Informationen können auch im \_\_DATA-Segment in verschiedenen \_\_objc\_\*-Abschnitten gefunden werden.
* **`__RESTRICT`**: Ein Segment ohne Inhalt mit einem einzigen Abschnitt namens **`__restrict`** (ebenfalls leer), der sicherstellt, dass beim Ausführen des Binärfiles die DYLD-Umgebungsvariablen ignoriert werden.

Wie im Code zu sehen war, **unterstützen Segmente auch Flags** (obwohl sie nicht sehr häufig verwendet werden):

* `SG_HIGHVM`: Nur Core (nicht verwendet)
* `SG_FVMLIB`: Nicht verwendet
* `SG_NORELOC`: Segment hat keine Relokation
* `SG_PROTECTED_VERSION_1`: Verschlüsselung. Wird beispielsweise vom Finder verwendet, um den Text im `__TEXT`-Segment zu verschlüsseln.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** enthält den Einstiegspunkt im **entryoff-Attribut**. Zur Ladezeit **addiert** **dyld** einfach diesen Wert zur (im Speicher befindlichen) **Basis des Binärfiles** und **springt** dann zu dieser Anweisung, um die Ausführung des Codes des Binärfiles zu starten.

**`LC_UNIXTHREAD`** enthält die Werte, die die Register haben müssen, wenn der Hauptthread gestartet wird. Dies wurde bereits veraltet, aber **`dyld`** verwendet es immer noch. Es ist möglich, die Werte der Register, die durch dies festgelegt sind, mit anzusehen:
```
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

Enthält Informationen zur **Codesignatur der Mach-O-Datei**. Es enthält nur einen **Offset**, der auf den **Signatur-Blob** zeigt. Dies befindet sich normalerweise am Ende der Datei.\
Sie können jedoch einige Informationen zu diesem Abschnitt in [**diesem Blog-Beitrag**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und in diesem [**Gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4) finden.

### **`LC_ENCRYPTION_INFO[_64]`**

Unterstützung für die binäre Verschlüsselung. Wenn es einem Angreifer jedoch gelingt, den Prozess zu kompromittieren, kann er den Speicher unverschlüsselt auslesen.

### **`LC_LOAD_DYLINKER`**

Enthält den **Pfad zum dynamischen Linker-Programm**, das gemeinsam genutzte Bibliotheken in den Adressraum des Prozesses abbildet. Der **Wert ist immer auf `/usr/lib/dyld` gesetzt**. Es ist wichtig zu beachten, dass in macOS das Dylib-Mapping im **Benutzermodus** und nicht im Kernelmodus erfolgt.

### **`LC_IDENT`**

Veraltet, aber wenn so konfiguriert, dass Dumps bei einem Absturz erstellt werden, wird ein Mach-O-Core-Dump erstellt und die Kernelversion im `LC_IDENT`-Befehl festgelegt.

### **`LC_UUID`**

Zufällige UUID. Es ist direkt für nichts nützlich, aber XNU speichert es zusammen mit dem Rest der Prozessinformationen im Cache. Es kann in Absturzberichten verwendet werden.

### **`LC_DYLD_ENVIRONMENT`**

Ermöglicht das Angeben von Umgebungsvariablen für den dyld, bevor der Prozess ausgeführt wird. Dies kann sehr gefährlich sein, da es ermöglichen kann, beliebigen Code im Prozess auszuführen. Daher wird dieser Ladungsbefehl nur in dyld-Builds mit `#define SUPPORT_LC_DYLD_ENVIRONMENT` verwendet und beschränkt die Verarbeitung weiterhin nur auf Variablen im Format `DYLD_..._PATH`, die Ladepfade angeben.

### **`LC_LOAD_DYLIB`**

Dieser Ladungsbefehl beschreibt eine **dynamische Bibliotheksabhängigkeit**, die den **Loader** (dyld) anweist, diese Bibliothek zu **laden und zu verknüpfen**. Es gibt einen `LC_LOAD_DYLIB`-Ladungsbefehl **für jede Bibliothek**, die die Mach-O-Binärdatei benötigt.

* Dieser Ladungsbefehl ist eine Struktur vom Typ **`dylib_command`** (die eine Struktur `dylib` enthält, die die tatsächliche abhängige dynamische Bibliothek beschreibt):
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![](<../../../.gitbook/assets/image (486).png>)

Sie könnten diese Informationen auch über die Befehlszeile mit erhalten:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Einige potenziell mit Malware verbundene Bibliotheken sind:

* **DiskArbitration**: Überwachung von USB-Laufwerken
* **AVFoundation:** Aufnahme von Audio und Video
* **CoreWLAN**: WLAN-Scans.

{% hint style="info" %}
Ein Mach-O-Binärfile kann einen oder **mehrere Konstruktoren** enthalten, die **vor** der in **LC\_MAIN** angegebenen Adresse **ausgeführt** werden.\
Die Offsets aller Konstruktoren werden im Abschnitt **\_\_mod\_init\_func** des Segments **\_\_DATA\_CONST** gespeichert.
{% endhint %}

## **Mach-O-Daten**

Im Kern der Datei befindet sich der Datenbereich, der aus mehreren Segmenten besteht, wie im Bereich der Ladungsbefehle definiert. **In jedem Segment können verschiedene Datensektionen untergebracht sein**, wobei jede Sektion **Code oder Daten** spezifisch für einen Typ enthält.

{% hint style="success" %}
Die Daten sind im Wesentlichen der Teil, der alle **Informationen** enthält, die von den Ladungsbefehlen **LC\_SEGMENTS\_64** geladen werden.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Dazu gehören:

* **Funktionstabelle:** Die Informationen über die Programmfunktionen enthält.
* **Symboltabelle**: Enthält Informationen über die externen Funktionen, die vom Binärfile verwendet werden.
* Es könnte auch interne Funktionen, Variablennamen und mehr enthalten.

Um dies zu überprüfen, könnten Sie das [**Mach-O View**](https://sourceforge.net/projects/machoview/) Tool verwenden:

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Oder über die Befehlszeile:
```bash
size -m /bin/ls
```
## Objektive-C Gemeinsame Abschnitte

Im `__TEXT` Segment (r-x):

- `__objc_classname`: Klassennamen (Zeichenketten)
- `__objc_methname`: Methodennamen (Zeichenketten)
- `__objc_methtype`: Methodentypen (Zeichenketten)

Im `__DATA` Segment (rw-):

- `__objc_classlist`: Zeiger auf alle Objektive-C-Klassen
- `__objc_nlclslist`: Zeiger auf nicht-lazy Objektive-C-Klassen
- `__objc_catlist`: Zeiger auf Kategorien
- `__objc_nlcatlist`: Zeiger auf nicht-lazy Kategorien
- `__objc_protolist`: Protokollliste
- `__objc_const`: Konstante Daten
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
