# macOS Universal binaries & Mach-O Format

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

I binari di Mac OS di solito vengono compilati come **binari universali**. Un **binario universale** può **supportare più architetture nello stesso file**.

Questi binari seguono la **struttura Mach-O** che è essenzialmente composta da:

* Intestazione
* Comandi di caricamento
* Dati

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

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

L'intestazione ha i byte **magic** seguiti dal **numero** di **architetture** che il file **contiene** (`nfat_arch`) e ogni architettura avrà una struttura `fat_arch`.

Verificalo con:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

o utilizzando lo strumento [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Come potresti pensare, di solito un binario universale compilato per 2 architetture **raddoppia la dimensione** di uno compilato per una sola architettura.

## **Intestazione Mach-O**

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
**Tipi di file**:

* MH\_EXECUTE (0x2): Eseguibile Mach-O standard
* MH\_DYLIB (0x6): Una libreria dinamica Mach-O (ad esempio .dylib)
* MH\_BUNDLE (0x8): Un bundle Mach-O (ad esempio .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Oppure utilizzando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Comandi di caricamento Mach-O**

Qui viene specificato il **layout del file in memoria**, dettagliando la **posizione della tabella dei simboli**, il contesto del thread principale all'avvio dell'esecuzione e le **librerie condivise** richieste. Vengono fornite istruzioni al dynamic loader **(dyld)** sul processo di caricamento del binario in memoria.

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
Fondamentalmente, questo tipo di comando di caricamento definisce **come caricare i segmenti \_\_TEXT** (codice eseguibile) **e \_\_DATA** (dati per il processo) in base agli **offset indicati nella sezione dei dati** quando il binario viene eseguito.
{% endhint %}

Questi comandi **definiscono i segmenti** che vengono **mappati** nello **spazio di memoria virtuale** di un processo quando viene eseguito.

Ci sono **diversi tipi** di segmenti, come il segmento **\_\_TEXT**, che contiene il codice eseguibile di un programma, e il segmento **\_\_DATA**, che contiene i dati utilizzati dal processo. Questi **segmenti si trovano nella sezione dei dati** del file Mach-O.

**Ogni segmento** può essere ulteriormente **diviso** in più **sezioni**. La struttura del comando di caricamento contiene **informazioni** su **queste sezioni** all'interno del rispettivo segmento.

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

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Se **aggiungi** l'**offset della sezione** (0x37DC) + l'**offset** in cui **inizia l'architettura**, in questo caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

È anche possibile ottenere le **informazioni dell'intestazione** dalla **riga di comando** con:
```bash
otool -lv /bin/ls
```
Segmenti comuni caricati da questo comando:

* **`__PAGEZERO`:** Istruisce il kernel a **mappare** l'**indirizzo zero** in modo che **non possa essere letto, scritto o eseguito**. Le variabili maxprot e minprot nella struttura sono impostate su zero per indicare che non ci sono **diritti di lettura-scrittura-esecuzione su questa pagina**.
* Questa allocazione è importante per **mitigare le vulnerabilità di dereferenziazione del puntatore NULL**.
* **`__TEXT`**: Contiene **codice eseguibile** con permessi di **lettura** ed **esecuzione** (non scrivibile)**.** Sezioni comuni di questo segmento:
* `__text`: Codice binario compilato
* `__const`: Dati costanti
* `__cstring`: Costanti di stringa
* `__stubs` e `__stubs_helper`: Coinvolti durante il processo di caricamento delle librerie dinamiche
* **`__DATA`**: Contiene dati che sono **leggibili** e **scrivibili** (non eseguibili)**.**
* `__data`: Variabili globali (che sono state inizializzate)
* `__bss`: Variabili statiche (che non sono state inizializzate)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, ecc.): Informazioni utilizzate dall'Objective-C runtime
* **`__LINKEDIT`**: Contiene informazioni per il linker (dyld) come "simbolo, stringa ed entry della tabella di rilocazione".
* **`__OBJC`**: Contiene informazioni utilizzate dall'Objective-C runtime. Tuttavia, queste informazioni potrebbero essere presenti anche nel segmento \_\_DATA, all'interno delle varie sezioni \_\_objc\_\*.

### **`LC_MAIN`**

Contiene il punto di ingresso nell'attributo **entryoff**. Al momento del caricamento, **dyld** semplicemente **aggiunge** questo valore alla **base del binario** in memoria, quindi **salta** a questa istruzione per avviare l'esecuzione del codice del binario.

### **LC\_CODE\_SIGNATURE**

Contiene informazioni sulla **firma del codice del file Mach-O**. Contiene solo un **offset** che **punta** al **blocco di firma**. Di solito si trova alla fine del file.\
Tuttavia, è possibile trovare ulteriori informazioni su questa sezione in [**questo post del blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e in questo [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Contiene il **percorso dell'eseguibile del linker dinamico** che mappa le librerie condivise nello spazio degli indirizzi del processo. Il **valore è sempre impostato su `/usr/lib/dyld`**. È importante notare che in macOS, il mapping delle dylib avviene in **modalità utente**, non in modalità kernel.

### **`LC_LOAD_DYLIB`**

Questo comando di caricamento descrive una **dipendenza da una libreria dinamica** che **istruisce** il **loader** (dyld) a **caricare e collegare tale libreria**. C'è un comando di caricamento LC\_LOAD\_DYLIB **per ogni libreria** richiesta dal binario Mach-O.

* Questo comando di caricamento è una struttura di tipo **`dylib_command`** (che contiene una struttura dylib, che descrive la libreria dinamica dipendente effettiva):
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

Puoi ottenere queste informazioni anche dalla CLI con:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Alcune librerie potenzialmente correlate al malware sono:

* **DiskArbitration**: Monitoraggio delle unità USB
* **AVFoundation**: Cattura audio e video
* **CoreWLAN**: Scansioni WiFi.

{% hint style="info" %}
Un binario Mach-O può contenere uno o **più** **costruttori**, che verranno **eseguiti** **prima** dell'indirizzo specificato in **LC\_MAIN**.\
Gli offset di eventuali costruttori sono contenuti nella sezione **\_\_mod\_init\_func** del segmento **\_\_DATA\_CONST**.
{% endhint %}

## **Dati Mach-O**

Al centro del file si trova la regione dei dati, composta da diversi segmenti definiti nella regione dei comandi di caricamento. **All'interno di ogni segmento possono essere presenti diverse sezioni di dati**, con ciascuna sezione che **contiene codice o dati** specifici per un determinato tipo.

{% hint style="success" %}
I dati sono fondamentalmente la parte che contiene tutte le **informazioni** che vengono caricate dai comandi di caricamento **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Ciò include:

* **Tabella delle funzioni**: Che contiene informazioni sulle funzioni del programma.
* **Tabella dei simboli**: Che contiene informazioni sulle funzioni esterne utilizzate dal binario.
* Potrebbe contenere anche funzioni interne, nomi di variabili e altro ancora.

Per verificarlo, è possibile utilizzare lo strumento [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

O tramite la riga di comando:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
