# macOS Universal binaries & Formato Mach-O

{% hint style="success" %}
Impara e pratica l'Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}

## Informazioni di Base

Di solito i binari di Mac OS sono compilati come **universal binaries**. Un **universal binary** può **supportare più architetture nello stesso file**.

Questi binari seguono la **struttura Mach-O** che è composta principalmente da:

* Header
* Comandi di Caricamento
* Dati

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Intestazione Fat

Cerca il file con: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* numero di strutture che seguono */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* specificatore della CPU (int) */
cpu_subtype_t	cpusubtype;	/* specificatore della macchina (int) */
uint32_t	offset;		/* offset del file a questo file oggetto */
uint32_t	size;		/* dimensione di questo file oggetto */
uint32_t	align;		/* allineamento come potenza di 2 */
};
</code></pre>

L'intestazione ha i byte **magic** seguiti dal **numero** di **architetture** contenute nel file (`nfat_arch`) e ogni architettura avrà una struttura `fat_arch`.

Controlla con:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (per architettura x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (per architettura arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Intestazioni Fat
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architettura x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architettura arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

o usando lo strumento [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Come potresti pensare, di solito un binary universale compilato per 2 architetture **raddoppia la dimensione** di uno compilato per una sola architettura.

## Intestazione Mach-O

L'intestazione contiene informazioni di base sul file, come i byte magici per identificarlo come file Mach-O e informazioni sull'architettura di destinazione. Puoi trovarlo in: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Tipi di File Mach-O

Ci sono diversi tipi di file, puoi trovarli definiti nel [**codice sorgente ad esempio qui**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). I più importanti sono:

- `MH_OBJECT`: File oggetto relocabile (prodotti intermedi della compilazione, non ancora eseguibili).
- `MH_EXECUTE`: File eseguibili.
- `MH_FVMLIB`: File di libreria VM fissa.
- `MH_CORE`: Dump di codice.
- `MH_PRELOAD`: File eseguibile precaricato (non più supportato in XNU).
- `MH_DYLIB`: Librerie dinamiche.
- `MH_DYLINKER`: Linker dinamico.
- `MH_BUNDLE`: File "plugin". Generati utilizzando -bundle in gcc e caricati esplicitamente da `NSBundle` o `dlopen`.
- `MH_DYSM`: File `.dSym` compagno (file con simboli per il debug).
- `MH_KEXT_BUNDLE`: Estensioni del kernel.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oppure utilizzando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flag Mach-O**

Il codice sorgente definisce anche diversi flag utili per il caricamento delle librerie:

* `MH_NOUNDEFS`: Nessun riferimento non definito (completamente collegato)
* `MH_DYLDLINK`: Collegamento Dyld
* `MH_PREBOUND`: Riferimenti dinamici precollegati.
* `MH_SPLIT_SEGS`: File divide segmenti r/o e r/w.
* `MH_WEAK_DEFINES`: Il binario ha simboli definiti deboli
* `MH_BINDS_TO_WEAK`: Il binario utilizza simboli deboli
* `MH_ALLOW_STACK_EXECUTION`: Rendere lo stack eseguibile
* `MH_NO_REEXPORTED_DYLIBS`: Libreria senza comandi LC\_REEXPORT
* `MH_PIE`: Esecuzione indipendente dalla posizione
* `MH_HAS_TLV_DESCRIPTORS`: C'è una sezione con variabili locali al thread
* `MH_NO_HEAP_EXECUTION`: Nessuna esecuzione per pagine heap/dati
* `MH_HAS_OBJC`: Il binario ha sezioni Objective-C
* `MH_SIM_SUPPORT`: Supporto del simulatore
* `MH_DYLIB_IN_CACHE`: Usato su dylib/framework nella cache delle librerie condivise.

## **Comandi di caricamento Mach-O**

La **struttura del file in memoria** è specificata qui, dettagliando la **posizione della tabella dei simboli**, il contesto del thread principale all'avvio dell'esecuzione e le **librerie condivise** richieste. Sono fornite istruzioni al caricatore dinamico **(dyld)** sul processo di caricamento del binario in memoria.

Viene utilizzata la struttura **load\_command**, definita nel menzionato **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Ci sono circa **50 diversi tipi di comandi di caricamento** che il sistema gestisce in modo diverso. I più comuni sono: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` e `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Fondamentalmente, questo tipo di Comando di Caricamento definisce **come caricare il \_\_TEXT** (codice eseguibile) **e il \_\_DATA** (dati per il processo) **segmenti** in base agli **offset indicati nella sezione dei Dati** quando il binario viene eseguito.
{% endhint %}

Questi comandi **definiscono segmenti** che vengono **mappati** nello **spazio di memoria virtuale** di un processo quando viene eseguito.

Ci sono **diversi tipi** di segmenti, come il segmento **\_\_TEXT**, che contiene il codice eseguibile di un programma, e il segmento **\_\_DATA**, che contiene dati utilizzati dal processo. Questi **segmenti sono situati nella sezione dei dati** del file Mach-O.

**Ogni segmento** può essere ulteriormente **diviso** in più **sezioni**. La **struttura del comando di caricamento** contiene **informazioni** su **queste sezioni** all'interno del rispettivo segmento.

Nell'intestazione trovi prima l'**intestazione del segmento**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* per architetture a 64 bit */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* include la dimensione delle strutture section_64 */
char		segname[16];	/* nome del segmento */
uint64_t	vmaddr;		/* indirizzo di memoria di questo segmento */
uint64_t	vmsize;		/* dimensione di memoria di questo segmento */
uint64_t	fileoff;	/* offset del file di questo segmento */
uint64_t	filesize;	/* quantità da mappare dal file */
int32_t		maxprot;	/* protezione VM massima */
int32_t		initprot;	/* protezione VM iniziale */
<strong>	uint32_t	nsects;		/* numero di sezioni nel segmento */
</strong>	uint32_t	flags;		/* flag */
};
</code></pre>

Esempio di intestazione del segmento:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Questa intestazione definisce il **numero di sezioni le cui intestazioni appaiono dopo** di essa:
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
Esempio di **intestazione di sezione**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Se si **aggiunge** l'**offset della sezione** (0x37DC) + l'**offset** in cui inizia l'**architettura**, in questo caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

È anche possibile ottenere le **informazioni sull'intestazione** dalla **riga di comando** con:
```bash
otool -lv /bin/ls
```
I segmenti comuni caricati da questo cmd:

* **`__PAGEZERO`:** Istruisce il kernel a **mappare** l'**indirizzo zero** in modo che **non possa essere letto, scritto o eseguito**. Le variabili maxprot e minprot nella struttura sono impostate su zero per indicare che non ci sono **diritti di lettura-scrittura-esecuzione su questa pagina**.
* Questa allocazione è importante per **mitigare le vulnerabilità di dereferenziazione del puntatore NULL**. Questo perché XNU impone una pagina zero rigida che garantisce che la prima pagina (solo la prima) della memoria sia inaccessibile (eccetto in i386). Un binario potrebbe soddisfare questi requisiti creando un piccolo \_\_PAGEZERO (usando `-pagezero_size`) per coprire i primi 4k e rendere il resto della memoria a 32 bit accessibile sia in modalità utente che kernel.
* **`__TEXT`**: Contiene **codice eseguibile** con permessi di **lettura** ed **esecuzione** (non scrivibile)**.** Sezioni comuni di questo segmento:
* `__text`: Codice binario compilato
* `__const`: Dati costanti (solo lettura)
* `__[c/u/os_log]string`: Costanti di stringhe C, Unicode o os logs
* `__stubs` e `__stubs_helper`: Coinvolti durante il processo di caricamento della libreria dinamica
* `__unwind_info`: Dati di unwind dello stack.
* Si noti che tutto questo contenuto è firmato ma anche contrassegnato come eseguibile (creando più opzioni per lo sfruttamento di sezioni che non necessariamente richiedono questo privilegio, come le sezioni dedicate alle stringhe).
* **`__DATA`**: Contiene dati che sono **leggibili** e **scrivibili** (non eseguibili)**.**
* `__got:` Tabella degli offset globali
* `__nl_symbol_ptr`: Puntatore al simbolo non lazy (bind al caricamento)
* `__la_symbol_ptr`: Puntatore al simbolo lazy (bind all'uso)
* `__const`: Dovrebbe essere dati di sola lettura (ma non lo è realmente)
* `__cfstring`: Stringhe di CoreFoundation
* `__data`: Variabili globali (che sono state inizializzate)
* `__bss`: Variabili statiche (che non sono state inizializzate)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, ecc): Informazioni utilizzate dall'Objective-C runtime
* **`__DATA_CONST`**: \_\_DATA.\_\_const non è garantito essere costante (permessi di scrittura), così come gli altri puntatori e la GOT. Questa sezione rende `__const`, alcuni inizializzatori e la tabella GOT (una volta risolta) **solo lettura** utilizzando `mprotect`.
* **`__LINKEDIT`**: Contiene informazioni per il linker (dyld) come simboli, stringhe e voci della tabella di rilocazione. È un contenitore generico per contenuti che non sono né in `__TEXT` né in `__DATA` e il suo contenuto è descritto in altri comandi di caricamento.
* Informazioni dyld: Rebase, opcode di binding non-lazy/lazy/debole e informazioni di esportazione
* Inizio delle funzioni: Tabella degli indirizzi di inizio delle funzioni
* Dati nel codice: Isole di dati in \_\_text
* Tabella dei simboli: Simboli nel binario
* Tabella dei simboli indiretti: Simboli di puntatore/stub
* Tabella delle stringhe
* Firma del codice
* **`__OBJC`**: Contiene informazioni utilizzate dall'Objective-C runtime. Anche se queste informazioni potrebbero essere trovate nel segmento \_\_DATA, all'interno di varie sezioni in \_\_objc\_\*.
* **`__RESTRICT`**: Un segmento senza contenuto con una singola sezione chiamata **`__restrict`** (anche vuota) che garantisce che quando si esegue il binario, verranno ignorate le variabili ambientali DYLD.

Come è stato possibile vedere nel codice, **i segmenti supportano anche dei flag** (anche se non vengono utilizzati molto):

* `SG_HIGHVM`: Solo core (non utilizzato)
* `SG_FVMLIB`: Non utilizzato
* `SG_NORELOC`: Il segmento non ha rilocazione
* `SG_PROTECTED_VERSION_1`: Crittografia. Utilizzato ad esempio da Finder per crittografare il segmento di testo `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contiene il punto di ingresso nell'attributo **entryoff**. Al momento del caricamento, **dyld** semplicemente **aggiunge** questo valore alla (in memoria) **base del binario**, quindi **salta** a questa istruzione per avviare l'esecuzione del codice binario.

**`LC_UNIXTHREAD`** contiene i valori che i registri devono avere all'avvio del thread principale. Questo è già deprecato ma **`dyld`** lo utilizza ancora. È possibile vedere i valori dei registri impostati da questo con:
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

Contiene informazioni sulla **firma del codice del file Mach-O**. Contiene solo un **offset** che **punta** al **blocco della firma**. Di solito si trova alla fine del file.\
Tuttavia, è possibile trovare ulteriori informazioni su questa sezione in [**questo post sul blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e in questo [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Supporto per la crittografia binaria. Tuttavia, naturalmente, se un attaccante riesce a compromettere il processo, sarà in grado di scaricare la memoria non crittografata.

### **`LC_LOAD_DYLINKER`**

Contiene il **percorso dell'eseguibile del linker dinamico** che mappa le librerie condivise nello spazio degli indirizzi del processo. Il **valore è sempre impostato su `/usr/lib/dyld`**. È importante notare che in macOS, il mapping delle dylib avviene in **modalità utente**, non in modalità kernel.

### **`LC_IDENT`**

Obsoleto ma quando configurato per generare dump in caso di panico, viene creato un dump core Mach-O e la versione del kernel è impostata nel comando `LC_IDENT`.

### **`LC_UUID`**

UUID casuale. È utile per niente direttamente ma XNU lo memorizza con il resto delle informazioni sul processo. Può essere utilizzato nei report di crash.

### **`LC_DYLD_ENVIRONMENT`**

Permette di indicare le variabili d'ambiente al dyld prima che il processo venga eseguito. Questo può essere molto pericoloso in quanto consente di eseguire codice arbitrario all'interno del processo, quindi questo comando di caricamento viene utilizzato solo in dyld compilati con `#define SUPPORT_LC_DYLD_ENVIRONMENT` e limita ulteriormente l'elaborazione solo alle variabili della forma `DYLD_..._PATH` specificando i percorsi di caricamento.

### **`LC_LOAD_DYLIB`**

Questo comando di caricamento descrive una **dipendenza da libreria dinamica** che **istruisce** il **caricatore** (dyld) a **caricare e collegare tale libreria**. C'è un comando di caricamento `LC_LOAD_DYLIB` **per ogni libreria** richiesta dal binario Mach-O.

* Questo comando di caricamento è una struttura di tipo **`dylib_command`** (che contiene una struttura dylib, descrivendo la libreria dinamica dipendente effettiva):
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

È possibile ottenere queste informazioni anche da riga di comando con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Alcune potenziali librerie correlate al malware sono:

- **DiskArbitration**: Monitoraggio delle unità USB
- **AVFoundation**: Cattura audio e video
- **CoreWLAN**: Scansioni Wifi.

{% hint style="info" %}
Un binario Mach-O può contenere uno o **più costruttori**, che verranno **eseguiti prima** dell'indirizzo specificato in **LC\_MAIN**.\
Gli offset di eventuali costruttori sono contenuti nella sezione **\_\_mod\_init\_func** del segmento **\_\_DATA\_CONST**.
{% endhint %}

## **Dati Mach-O**

Al centro del file si trova la regione dei dati, composta da diversi segmenti come definito nella regione dei comandi di caricamento. **Una varietà di sezioni dati può essere contenuta in ciascun segmento**, con ciascuna sezione che **contiene codice o dati** specifici per un tipo.

{% hint style="success" %}
I dati sono essenzialmente la parte che contiene tutte le **informazioni** caricate dai comandi di caricamento **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Ciò include:

- **Tabella delle funzioni**: Che contiene informazioni sulle funzioni del programma.
- **Tabella dei simboli**: Che contiene informazioni sulle funzioni esterne utilizzate dal binario
- Potrebbe contenere anche funzioni interne, nomi di variabili e altro.

Per controllarlo, potresti utilizzare lo strumento [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

O tramite la riga di comando:
```bash
size -m /bin/ls
```
## Sezioni Comuni di Objective-C

Nel segmento `__TEXT` (r-x):

- `__objc_classname`: Nomi delle classi (stringhe)
- `__objc_methname`: Nomi dei metodi (stringhe)
- `__objc_methtype`: Tipi dei metodi (stringhe)

Nel segmento `__DATA` (rw-):

- `__objc_classlist`: Puntatori a tutte le classi Objective-C
- `__objc_nlclslist`: Puntatori alle classi Objective-C non lazy
- `__objc_catlist`: Puntatore alle Categorie
- `__objc_nlcatlist`: Puntatore alle Categorie non lazy
- `__objc_protolist`: Elenco dei protocolli
- `__objc_const`: Dati costanti
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
