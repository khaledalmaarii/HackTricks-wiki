# macOS Univerzalni binarni fajlovi i Mach-O format

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne informacije

Mac OS binarni fajlovi obično su kompajlirani kao **univerzalni binarni fajlovi**. **Univerzalni binarni fajl** može **podržavati više arhitektura u istom fajlu**.

Ovi binarni fajlovi prate **Mach-O strukturu** koja se uglavnom sastoji od:

* Header-a
* Load komandi
* Podataka

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Fat Header

Pretražite fajl sa: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* broj struktura koje slede */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* specifikacija CPU-a (int) */
cpu_subtype_t	cpusubtype;	/* specifikacija mašine (int) */
uint32_t	offset;		/* fajl offset do ovog objektnog fajla */
uint32_t	size;		/* veličina ovog objektnog fajla */
uint32_t	align;		/* poravnanje kao stepen broja 2 */
};
</code></pre>

Header ima **magic** bajtove praćene **brojem** **arhitektura** koje fajl **sadrži** (`nfat_arch`) i svaka arhitektura će imati `fat_arch` strukturu.

Proverite sa:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O univerzalni binarni fajl sa 2 arhitekture: [x86_64:Mach-O 64-bit izvršni x86_64] [arm64e:Mach-O 64-bit izvršni arm64e]
/bin/ls (za arhitekturu x86_64):	Mach-O 64-bit izvršni x86_64
/bin/ls (za arhitekturu arm64e):	Mach-O 64-bit izvršni arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>arhitektura x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
mogućnosti 0x0
<strong>    offset 16384
</strong><strong>    veličina 72896
</strong>    poravnanje 2^14 (16384)
<strong>arhitektura arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
mogućnosti PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    veličina 88816
</strong>    poravnanje 2^14 (16384)
</code></pre>

ili korišćenjem alata [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Kao što možda mislite, obično univerzalni binarni fajl kompajliran za 2 arhitekture **udvostručuje veličinu** onog kompajliranog samo za 1 arhitekturu.

## **Mach-O Header**

Header sadrži osnovne informacije o fajlu, kao što su magic bajtovi za identifikaciju fajla kao Mach-O fajla i informacije o ciljnoj arhitekturi. Možete ga pronaći u: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Vrste Mach-O fajlova

Postoje različite vrste fajlova, možete ih pronaći definisane u [**izvornom kodu na primer ovde**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). Najvažnije su:

* `MH_OBJECT`: Objektni fajl sa premeštanjem (međufazi kompilacije, još uvek nisu izvršni fajlovi).
* `MH_EXECUTE`: Izvršni fajlovi.
* `MH_FVMLIB`: Fiksna VM biblioteka.
* `MH_CORE`: Dump fajlovi koda.
* `MH_PRELOAD`: Prethodno učitani izvršni fajl (više nije podržan u XNU).
* `MH_DYLIB`: Dinamičke biblioteke.
* `MH_DYLINKER`: Dinamički linker.
* `MH_BUNDLE`: "Fajlovi dodataka". Generisani korišćenjem -bundle u gcc-u i eksplicitno učitani pomoću `NSBundle` ili `dlopen`.
* `MH_DYSM`: Pratni `.dSym` fajl (fajl sa simbolima za debagovanje).
* `MH_KEXT_BUNDLE`: Proširenja jezgra.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ili koristeći [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Zastave**

Izvorni kod takođe definiše nekoliko zastava korisnih za učitavanje biblioteka:

* `MH_NOUNDEFS`: Bez nedefinisanih referenci (potpuno povezano)
* `MH_DYLDLINK`: Dyld povezivanje
* `MH_PREBOUND`: Dinamičke reference unapred povezane.
* `MH_SPLIT_SEGS`: Datoteka deli r/o i r/w segmente.
* `MH_WEAK_DEFINES`: Binarni ima slabo definisane simbole
* `MH_BINDS_TO_WEAK`: Binarni koristi slabe simbole
* `MH_ALLOW_STACK_EXECUTION`: Čini stek izvršivim
* `MH_NO_REEXPORTED_DYLIBS`: Biblioteka nema LC\_REEXPORT komande
* `MH_PIE`: Izvršna datoteka sa nezavisnim položajem
* `MH_HAS_TLV_DESCRIPTORS`: Postoji odeljak sa lokalnim promenljivama niti
* `MH_NO_HEAP_EXECUTION`: Bez izvršavanja za stranice heap/podataka
* `MH_HAS_OBJC`: Binarni ima oBject-C odeljke
* `MH_SIM_SUPPORT`: Podrška za simulator
* `MH_DYLIB_IN_CACHE`: Korišćeno na dylibs/frameworks u deljenom kešu biblioteka.

## **Mach-O Komande učitavanja**

**Raspored datoteke u memoriji** je ovde naveden, detalji o **lokaciji tabele simbola**, kontekst glavne niti pri pokretanju izvršavanja, i potrebne **deljene biblioteke**. Instrukcije su pružene dinamičkom učitavaču **(dyld)** o procesu učitavanja binarnog koda u memoriju.

Koristi se struktura **load\_command**, definisana u pomenutom **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Postoje oko **50 različitih tipova komandi za učitavanje** koje sistem obrađuje na različite načine. Najčešće korištene su: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` i `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Ovaj tip Load Command-a definiše **kako učitati \_\_TEXT** (izvršni kod) **i \_\_DATA** (podatke za proces) **segmente** prema **ofsetima naznačenim u Data sekciji** prilikom izvršavanja binarnog fajla.
{% endhint %}

Ove komande **definišu segmente** koji su **mapirani** u **virtuelni memorijski prostor** procesa prilikom izvršavanja.

Postoje **različite vrste** segmenata, kao što je **\_\_TEXT** segment, koji drži izvršni kod programa, i **\_\_DATA** segment, koji sadrži podatke korišćene od strane procesa. Ovi **segmenti se nalaze u data sekciji** Mach-O fajla.

**Svaki segment** može biti dodatno **podeljen** u više **sekcija**. Struktura load komande sadrži **informacije** o **ovim sekcijama** unutar odgovarajućeg segmenta.

U zaglavlju prvo nalazite **zaglavlje segmenta**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* za 64-bitne arhitekture */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* uključuje veličinu section_64 struktura */
char		segname[16];	/* ime segmenta */
uint64_t	vmaddr;		/* memorijska adresa ovog segmenta */
uint64_t	vmsize;		/* veličina memorije ovog segmenta */
uint64_t	fileoff;	/* ofset fajla ovog segmenta */
uint64_t	filesize;	/* količina za mapiranje iz fajla */
int32_t		maxprot;	/* maksimalna VM zaštita */
int32_t		initprot;	/* početna VM zaštita */
<strong>	uint32_t	nsects;		/* broj sekcija u segmentu */
</strong>	uint32_t	flags;		/* zastave */
};
</code></pre>

Primer zaglavlja segmenta:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Ovo zaglavlje definiše **broj sekcija čiji zaglavlji slede** nakon njega:
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
Primer **naslova odeljka**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Ako **dodate** **pomeraj odeljka** (0x37DC) + **pomeraj** gde **arhiva počinje**, u ovom slučaju `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Takođe je moguće dobiti **informacije o zaglavljima** sa **komandne linije** pomoću:
```bash
otool -lv /bin/ls
```
Uobičajeni segmenti učitani ovom komandom:

* **`__PAGEZERO`:** Naređuje jezgru da **mapira** **adresu nula** tako da se **ne može čitati, pisati ili izvršavati**. Maxprot i minprot promenljive u strukturi postavljene su na nulu da bi se naznačilo da nema **prava za čitanje-pisanje-izvršavanje na ovoj stranici**.
* Ova alokacija je važna za **smanjenje ranjivosti nul pokazivača**. To je zato što XNU sprovodi tvrdu stranicu nula koja osigurava da je prva stranica (samo prva) memorije nedostupna (osim na i386). Binarni fajl može ispuniti ove zahteve kreiranjem male \_\_PAGEZERO (koristeći `-pagezero_size`) da pokrije prvih 4k i imajući ostatak memorije od 32 bita dostupan i u korisničkom i u režimu jezgra.
* **`__TEXT`**: Sadrži **izvršni** **kod** sa **dozvolama za čitanje** i **izvršavanje** (bez mogućnosti pisanja)**.** Uobičajeni delovi ovog segmenta:
* `__text`: Kompajlirani binarni kod
* `__const`: Konstantni podaci (samo za čitanje)
* `__[c/u/os_log]string`: Konstante niski C, Unicode ili os logova
* `__stubs` i `__stubs_helper`: Uključeni tokom procesa učitavanja dinamičkih biblioteka
* `__unwind_info`: Podaci o odmotavanju steka.
* Napomena da je sav ovaj sadržaj potpisan ali označen i kao izvršan (stvarajući više opcija za eksploataciju delova koji ne moraju nužno imati ovu privilegiju, poput delova posvećenih niskama).
* **`__DATA`**: Sadrži podatke koji su **čitljivi** i **pisivi** (bez mogućnosti izvršavanja)**.**
* `__got:` Globalna tabela offseta
* `__nl_symbol_ptr`: Pokazivač simbola koji nije lenj (vezan pri učitavanju)
* `__la_symbol_ptr`: Lenj (vezan pri upotrebi) pokazivač simbola
* `__const`: Trebalo bi da budu podaci samo za čitanje (ali nisu)
* `__cfstring`: CoreFoundation niske
* `__data`: Globalne promenljive (koje su inicijalizovane)
* `__bss`: Statičke promenljive (koje nisu inicijalizovane)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, itd): Informacije korišćene od strane Objective-C runtime-a
* **`__DATA_CONST`**: \_\_DATA.\_\_const nije garantovano konstantan (dozvole za pisanje), niti su to ostali pokazivači i GOT. Ovaj deo čini `__const`, neki inicijalizatori i GOT tabela (jednom kada su rešeni) **samo za čitanje** koristeći `mprotect`.
* **`__LINKEDIT`**: Sadrži informacije za linkera (dyld) kao što su, simbol, niska i unosi tabele premeštanja. To je generički kontejner za sadržaje koji nisu ni u `__TEXT` ni u `__DATA` i njegov sadržaj je opisan u drugim komandama učitavanja.
* Informacije dyld-a: Rebase, Non-lazy/lazy/weak binding opkodi i informacije o izvozu
* Početak funkcija: Tabela početnih adresa funkcija
* Podaci u kodu: Podaci ostrva u \_\_text
* Tabela simbola: Simboli u binarnom fajlu
* Indirektna tabela simbola: Pokazivači/stub simboli
* Tabela niski
* Potpis koda
* **`__OBJC`**: Sadrži informacije korišćene od strane Objective-C runtime-a. Iako se ove informacije mogu naći i u segmentu \_\_DATA, unutar različitih odeljaka u \_\_objc\_\* sekcijama.
* **`__RESTRICT`**: Segment bez sadržaja sa jednim odeljkom nazvanim **`__restrict`** (takođe prazan) koji osigurava da prilikom pokretanja binarnog fajla, ignorisaće DYLD okružne promenljive.

Kako je bilo moguće videti u kodu, **segmenti takođe podržavaju zastave** (iako se retko koriste):

* `SG_HIGHVM`: Samo za Core (ne koristi se)
* `SG_FVMLIB`: Ne koristi se
* `SG_NORELOC`: Segment nema premeštanje
* `SG_PROTECTED_VERSION_1`: Enkripcija. Korišćeno na primer od strane Finder-a za enkripciju teksta u `__TEXT` segmentu.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** sadrži ulaznu tačku u **entryoff atributu.** Prilikom učitavanja, **dyld** jednostavno **dodaje** ovu vrednost na (u memoriji) **bazu binarnog fajla**, zatim **skoči** na ovu instrukciju da započne izvršavanje koda binarnog fajla.

**`LC_UNIXTHREAD`** sadrži vrednosti koje registri moraju imati prilikom pokretanja glavne niti. Ovo je već zastarelo ali **`dyld`** i dalje koristi. Moguće je videti vrednosti registara postavljene ovim sa:
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

Sadrži informacije o **potpisu koda Mach-O fajla**. Sadrži samo **offset** koji **ukazuje** na **blok potpisa**. Obično se nalazi na samom kraju fajla.\
Međutim, možete pronaći neke informacije o ovoj sekciji u [**ovom blog postu**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) i ovom [**gistu**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Podrška za enkripciju binarnih fajlova. Međutim, naravno, ako napadač uspe da kompromituje proces, moći će da izvuče memoriju nešifrovanu.

### **`LC_LOAD_DYLINKER`**

Sadrži **putanju do izvršne datoteke dinamičkog linkera** koji mapira deljene biblioteke u adresni prostor procesa. **Vrednost je uvek postavljena na `/usr/lib/dyld`**. Važno je napomenuti da se u macOS-u mapiranje dylib-a dešava u **korisničkom režimu**, a ne u režimu jezgra.

### **`LC_IDENT`**

Zastarelo, ali kada je konfigurisano da generiše dump-ove prilikom panike, kreiran je Mach-O core dump i verzija jezgra je postavljena u `LC_IDENT` komandi.

### **`LC_UUID`**

Slučajni UUID. Koristan je za bilo šta direktno, ali XNU ga kešira sa ostalim informacijama o procesu. Može se koristiti u izveštajima o padu.

### **`LC_DYLD_ENVIRONMENT`**

Omogućava da se naznače okružne promenljive dyld-u pre nego što se proces izvrši. Ovo može biti veoma opasno jer može omogućiti izvršavanje proizvoljnog koda unutar procesa, pa se ova komanda učitavanja koristi samo u dyld-u izgrađenom sa `#define SUPPORT_LC_DYLD_ENVIRONMENT` i dodatno ograničava obradu samo na promenljive oblika `DYLD_..._PATH` koje specificiraju putanje za učitavanje.

### **`LC_LOAD_DYLIB`**

Ova komanda učitavanja opisuje **zavisnost dinamičke biblioteke** koja **nalaže** **loaderu** (dyld) da **učita i poveže tu biblioteku**. Postoji `LC_LOAD_DYLIB` komanda učitavanja **za svaku biblioteku** koju Mach-O binarni fajl zahteva.

* Ova komanda učitavanja je struktura tipa **`dylib_command`** (koja sadrži strukturu dylib, opisuje stvarnu zavisnu dinamičku biblioteku):
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

Ove informacije takođe možete dobiti putem komandne linije sa:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Neke potencijalno zlonamerne biblioteke su:

* **DiskArbitration**: Praćenje USB uređaja
* **AVFoundation:** Snimanje zvuka i videa
* **CoreWLAN**: Skeniranje WiFi mreža.

{% hint style="info" %}
Mach-O binarni fajl može sadržati jedan ili **više konstruktora**, koji će biti **izvršeni pre** adrese navedene u **LC\_MAIN**.\
Ofseti bilo kog konstruktora se čuvaju u sekciji **\_\_mod\_init\_func** segmenta **\_\_DATA\_CONST**.
{% endhint %}

## **Mach-O Podaci**

U osnovi fajla se nalazi region podataka, koji se sastoji od nekoliko segmenata definisanih u regionu komandi učitavanja. **Različite sekcije podataka mogu biti smeštene unutar svakog segmenta**, pri čemu svaka sekcija **sadrži kod ili podatke** specifične za tip.

{% hint style="success" %}
Podaci su zapravo deo koji sadrži sve **informacije** koje se učitavaju pomoću komandi učitavanja **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

To uključuje:

* **Tabela funkcija:** Koja sadrži informacije o funkcijama programa.
* **Tabela simbola**: Koja sadrži informacije o eksternim funkcijama koje koristi binarni fajl
* Takođe može sadržati interne funkcije, imena promenljivih i još mnogo toga.

Za proveru možete koristiti alat [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Ili putem komandne linije:
```bash
size -m /bin/ls
```
## Zajedničke sekcije Objective-C

U segmentu `__TEXT` (r-x):

* `__objc_classname`: Imena klasa (stringovi)
* `__objc_methname`: Imena metoda (stringovi)
* `__objc_methtype`: Tipovi metoda (stringovi)

U segmentu `__DATA` (rw-):

* `__objc_classlist`: Pokazivači na sve Objective-C klase
* `__objc_nlclslist`: Pokazivači na Non-Lazy Objective-C klase
* `__objc_catlist`: Pokazivač na kategorije
* `__objc_nlcatlist`: Pokazivač na Non-Lazy kategorije
* `__objc_protolist`: Lista protokola
* `__objc_const`: Konstantni podaci
* `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

* `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
