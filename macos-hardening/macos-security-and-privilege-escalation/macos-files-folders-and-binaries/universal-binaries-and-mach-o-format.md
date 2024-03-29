# macOS Universelle Binärdateien & Mach-O Format

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Grundlegende Informationen

Mac OS-Binärdateien sind normalerweise als **universelle Binärdateien** kompiliert. Eine **universelle Binärdatei** kann **mehrere Architekturen in derselben Datei unterstützen**.

Diese Binärdateien folgen der **Mach-O-Struktur**, die im Wesentlichen aus folgendem besteht:

* Header
* Ladebefehle
* Daten

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

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

Der Header enthält die **magischen** Bytes, gefolgt von der **Anzahl** der **Architekturen**, die die Datei **enthält** (`nfat_arch`), und jede Architektur wird eine `fat_arch`-Struktur haben.

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
<strong>    Offset 16384
</strong><strong>    Größe 72896
</strong>    Ausrichtung 2^14 (16384)
<strong>Architektur arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
Fähigkeiten PTR_AUTH_VERSION USERSPACE 0
<strong>    Offset 98304
</strong><strong>    Größe 88816
</strong>    Ausrichtung 2^14 (16384)
</code></pre>

oder mit dem [Mach-O View](https://sourceforge.net/projects/machoview/) Tool:

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Wie Sie vielleicht denken, verdoppelt eine universelle Binärdatei, die für 2 Architekturen kompiliert wurde, normalerweise die Größe einer, die nur für 1 Architektur kompiliert wurde.

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
**Dateitypen**:

* MH\_EXECUTE (0x2): Standard Mach-O ausführbare Datei
* MH\_DYLIB (0x6): Eine Mach-O dynamische Bibliothek (d.h. .dylib)
* MH\_BUNDLE (0x8): Ein Mach-O Bundle (d.h. .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oder mit [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Load-Befehle**

Die **Speicherlayoutdatei** ist hier angegeben, wobei der **Speichertabellenstandort**, der Kontext des Hauptthreads beim Start der Ausführung und die erforderlichen **gemeinsam genutzten Bibliotheken** im Detail beschrieben werden. Anweisungen werden an den dynamischen Lader **(dyld)** zum Ladevorgang der Binärdatei in den Speicher übermittelt.

Die Verwendung der **load\_command**-Struktur, wie in der genannten **`loader.h`** definiert:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Es gibt etwa **50 verschiedene Arten von Ladungsbefehlen**, die das System unterschiedlich behandelt. Die häufigsten sind: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` und `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Grundsätzlich definieren diese Arten von Ladungsbefehlen, **wie die \_\_TEXT** (ausführbarer Code) **und \_\_DATA** (Daten für den Prozess) **Segmente** geladen werden, gemäß der **in der Datensektion angegebenen Offset** beim Ausführen der Binärdatei.
{% endhint %}

Diese Befehle **definieren Segmente**, die in den **virtuellen Speicherbereich** eines Prozesses gemappt werden, wenn er ausgeführt wird.

Es gibt **verschiedene Arten** von Segmenten, wie das **\_\_TEXT**-Segment, das den ausführbaren Code eines Programms enthält, und das **\_\_DATA**-Segment, das vom Prozess verwendete Daten enthält. Diese **Segmente befinden sich im Datenteil** der Mach-O-Datei.

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

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Wenn Sie die **Abschnittsverschiebung** (0x37DC) + den **Offset** hinzufügen, an dem die **Architektur beginnt**, in diesem Fall `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Es ist auch möglich, **Headerinformationen** von der **Befehlszeile** aus abzurufen:
```bash
otool -lv /bin/ls
```
Gemeinsame Segmente, die von diesem Befehl geladen werden:

- **`__PAGEZERO`:** Es weist den Kernel an, die **Adresse Null** so zu **zuordnen**, dass sie **nicht gelesen, geschrieben oder ausgeführt** werden kann. Die Variablen maxprot und minprot in der Struktur sind auf Null gesetzt, um anzuzeigen, dass es **keine Lese-Schreib-Ausführungsrechte auf dieser Seite** gibt.
- Diese Zuweisung ist wichtig, um **NULL-Pointer-Dereferenz-Schwachstellen zu mildern**.
- **`__TEXT`**: Enthält **ausführbaren** **Code** mit **Lese-** und **Ausführungsrechten** (nicht schreibbar)**.** Gemeinsame Abschnitte dieses Segments:
  - `__text`: Kompilierter Binärcode
  - `__const`: Konstante Daten
  - `__cstring`: Zeichenkonstanten
  - `__stubs` und `__stubs_helper`: Beteiligt am dynamischen Bibliotheks-Ladevorgang
- **`__DATA`**: Enthält Daten, die **lesbar** und **schreibbar** sind (nicht ausführbar)**.**
  - `__data`: Globale Variablen (die initialisiert wurden)
  - `__bss`: Statische Variablen (die nicht initialisiert wurden)
  - `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, usw.): Informationen, die vom Objective-C-Laufzeitumgebung verwendet werden
- **`__LINKEDIT`**: Enthält Informationen für den Linker (dyld) wie "Symbol-, Zeichenfolgen- und Relokationstabelleneinträge".
- **`__OBJC`**: Enthält Informationen, die von der Objective-C-Laufzeitumgebung verwendet werden. Diese Informationen können auch im \_\_DATA-Segment in verschiedenen \_\_objc\_\*-Abschnitten gefunden werden.

### **`LC_MAIN`**

Enthält den Einstiegspunkt im **entryoff-Attribut**. Zur Ladezeit **addiert** **dyld** einfach diesen Wert zur (im Speicher befindlichen) **Basis der Binärdatei** und **springt** dann zu dieser Anweisung, um die Ausführung des Binärcodes zu starten.

### **LC\_CODE\_SIGNATURE**

Enthält Informationen über die **Codesignatur der Macho-O-Datei**. Es enthält nur einen **Offset**, der auf den **Signatur-Blob** zeigt. Dies befindet sich normalerweise am Ende der Datei.\
Einige Informationen zu diesem Abschnitt finden Sie jedoch in [**diesem Blog-Beitrag**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) und in diesem [**Gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Enthält den **Pfad zum dynamischen Linker-Programm**, das gemeinsam genutzte Bibliotheken in den Adressraum des Prozesses abbildet. Der **Wert ist immer auf `/usr/lib/dyld`** festgelegt. Es ist wichtig zu beachten, dass in macOS das Dylib-Mapping im **Benutzermodus** und nicht im Kernelmodus erfolgt.

### **`LC_LOAD_DYLIB`**

Dieser Ladungsbefehl beschreibt eine **dynamische** **Bibliotheksabhängigkeit**, die den **Lader** (dyld) anweist, diese Bibliothek zu **laden und zu verknüpfen**. Es gibt einen LC\_LOAD\_DYLIB-Ladungsbefehl **für jede Bibliothek**, die von der Mach-O-Binärdatei benötigt wird.

- Dieser Ladungsbefehl ist eine Struktur vom Typ **`dylib_command`** (die eine Struktur dylib enthält, die die tatsächliche abhängige dynamische Bibliothek beschreibt):
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
![](<../../../.gitbook/assets/image (558).png>)

Sie könnten diese Informationen auch über die Befehlszeile erhalten:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Einige potenziell mit Malware verbundene Bibliotheken sind:

- **DiskArbitration**: Überwachung von USB-Laufwerken
- **AVFoundation**: Aufnahme von Audio und Video
- **CoreWLAN**: WLAN-Scans.

{% hint style="info" %}
Ein Mach-O-Binärdatei kann einen oder **mehrere Konstruktoren** enthalten, die **vor** der Adresse, die in **LC\_MAIN** angegeben ist, **ausgeführt** werden.\
Die Offsetwerte aller Konstruktoren werden im Abschnitt **\_\_mod\_init\_func** des Segments **\_\_DATA\_CONST** gespeichert.
{% endhint %}

## **Mach-O-Daten**

Im Kern der Datei befindet sich der Datenbereich, der aus mehreren Segmenten besteht, wie im Bereich der Ladungsbefehle definiert. **In jedem Segment können verschiedene Datensektionen untergebracht sein**, wobei jede Sektion **Code oder Daten** spezifisch für einen Typ enthält.

{% hint style="success" %}
Die Daten sind im Wesentlichen der Teil, der alle **Informationen** enthält, die von den Ladungsbefehlen **LC\_SEGMENTS\_64** geladen werden.
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Dazu gehören:

- **Funktionstabelle**: Enthält Informationen über die Programmfunktionen.
- **Symboltabelle**: Enthält Informationen über die externen Funktionen, die von der Binärdatei verwendet werden.
- Es könnte auch interne Funktionen, Variablennamen und mehr enthalten.

Um dies zu überprüfen, könnten Sie das [**Mach-O View**](https://sourceforge.net/projects/machoview/) Tool verwenden:

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Oder über die Befehlszeile:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
