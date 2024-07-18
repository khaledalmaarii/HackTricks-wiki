# macOS Πανεπιστημιακά δυαδικά & Μορφή Mach-O

{% hint style="success" %}
Μάθε & εξάσκησε το Hacking στο AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε το Hacking στο GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Βασικές Πληροφορίες

Τα δυαδικά αρχεία του Mac OS συνήθως μεταγλωττίζονται ως **πανεπιστημιακά δυαδικά**. Ένα **πανεπιστημιακό δυαδικό** μπορεί να **υποστηρίζει πολλές αρχιτεκτονικές στον ίδιο φάκελο**.

Αυτά τα δυαδικά ακολουθούν τη **δομή Mach-O** η οποία αποτελείται βασικά από:

* Κεφαλίδα
* Εντολές Φόρτωσης
* Δεδομένα

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (470).png>)

## Παχύ Κεφαλίδα

Αναζήτηση για το αρχείο με: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* αριθμός των δομών που ακολουθούν */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* καθοριστής επεξεργαστή (int) */
cpu_subtype_t	cpusubtype;	/* καθοριστής μηχανής (int) */
uint32_t	offset;		/* μετατόπιση αρχείου προς αυτό το αρχείο αντικείμενο */
uint32_t	size;		/* μέγεθος αυτού του αρχείου αντικειμένου */
uint32_t	align;		/* ευθυγράμμιση ως δύναμη του 2 */
};
</code></pre>

Η κεφαλίδα έχει τα **μαγικά** bytes ακολουθούμενα από τον **αριθμό** των **αρχιτεκτονικών** που περιέχει το αρχείο (`nfat_arch`) και κάθε αρχιτεκτονική θα έχει μια δομή `fat_arch`.

Ελέγξτε το με:

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Πανεπιστημιακό δυαδικό Mach-O με 2 αρχιτεκτονικές: [x86_64:Mach-O 64-bit εκτελέσιμο x86_64] [arm64e:Mach-O 64-bit εκτελέσιμο arm64e]
/bin/ls (για αρχιτεκτονική x86_64):	Mach-O 64-bit εκτελέσιμο x86_64
/bin/ls (για αρχιτεκτονική arm64e):	Mach-O 64-bit εκτελέσιμο arm64e

% otool -f -v /bin/ls
Παχύ κεφαλίδες
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>αρχιτεκτονική x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
δυνατότητες 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    ευθυγράμμιση 2^14 (16384)
<strong>αρχιτεκτονική arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
δυνατότητες PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    ευθυγράμμιση 2^14 (16384)
</code></pre>

ή χρησιμοποιώντας το εργαλείο [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1094).png" alt=""><figcaption></figcaption></figure>

Όπως ίσως σκέφτεστε συνήθως ένα πανεπιστημιακό δυαδικό μεταγλωττισμένο για 2 αρχιτεκτονικές **διπλασιάζει το μέγεθος** ενός μεταγλωττισμένου για μόνο 1 αρχιτεκτονική.

## **Κεφαλίδα Mach-O**

Η κεφαλίδα περιέχει βασικές πληροφορίες σχετικά με το αρχείο, όπως τα μαγικά bytes για την αναγνώρισή του ως αρχείο Mach-O και πληροφορίες σχετικά με την επιθυμητή αρχιτεκτονική. Μπορείτε να το βρείτε στο: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Τύποι Αρχείων Mach-O

Υπάρχουν διαφορετικοί τύποι αρχείων, μπορείτε να τους βρείτε ορισμένους ορισμένους στον [**πηγαίο κώδικα για παράδειγμα εδώ**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL\_HEADERS/mach-o/loader.h). Οι πιο σημαντικοί είναι:

- `MH_OBJECT`: Αρχείο αντικειμένου που μπορεί να μετακινηθεί (ενδιάμεσα προϊόντα σύνθεσης, αλλά όχι ακόμα εκτελέσιμα).
- `MH_EXECUTE`: Εκτελέσιμα αρχεία.
- `MH_FVMLIB`: Αρχείο βιβλιοθήκης σταθερής VM.
- `MH_CORE`: Αποθήκευση κώδικα
- `MH_PRELOAD`: Προφορτωμένο εκτελέσιμο αρχείο (πλέον δεν υποστηρίζεται στο XNU)
- `MH_DYLIB`: Δυναμικές βιβλιοθήκες
- `MH_DYLINKER`: Δυναμικός σύνδεσμος
- `MH_BUNDLE`: "Αρχεία πρόσθετων". Δημιουργούνται χρησιμοποιώντας την επιλογή -bundle στο gcc και φορτώνονται ρητά από `NSBundle` ή `dlopen`.
- `MH_DYSM`: Συνοδευτικό αρχείο `.dSym` (αρχείο με σύμβολα για αποσφαλμάτωση).
- `MH_KEXT_BUNDLE`: Πρόσθετα πυρήνα.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ή χρησιμοποιώντας το [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Σημαίες Mach-O**

Ο πηγαίος κώδικας ορίζει επίσης αρκετές σημαίες χρήσιμες για τη φόρτωση βιβλιοθηκών:

* `MH_NOUNDEFS`: Χωρίς απροσδιόριστες αναφορές (πλήρως συνδεδεμένο)
* `MH_DYLDLINK`: Δέσμευση Dyld
* `MH_PREBOUND`: Δυναμικές αναφορές προδεμένες.
* `MH_SPLIT_SEGS`: Το αρχείο χωρίζει τμήματα r/o και r/w.
* `MH_WEAK_DEFINES`: Το δυαδικό έχει ασθενώς ορισμένα σύμβολα
* `MH_BINDS_TO_WEAK`: Το δυαδικό χρησιμοποιεί ασθενή σύμβολα
* `MH_ALLOW_STACK_EXECUTION`: Κάνει τη στοίβα εκτελέσιμη
* `MH_NO_REEXPORTED_DYLIBS`: Η βιβλιοθήκη δεν έχει εντολές LC\_REEXPORT
* `MH_PIE`: Εκτελέσιμο με ανεξάρτητη θέση
* `MH_HAS_TLV_DESCRIPTORS`: Υπάρχει μια ενότητα με τοπικές μεταβλητές νήματος
* `MH_NO_HEAP_EXECUTION`: Χωρίς εκτέλεση για σελίδες σωρού/δεδομένων
* `MH_HAS_OBJC`: Το δυαδικό έχει ενότητες Object-C
* `MH_SIM_SUPPORT`: Υποστήριξη προσομοιωτή
* `MH_DYLIB_IN_CACHE`: Χρησιμοποιείται σε dylibs/frameworks στην κοινόχρηστη μνήμη βιβλιοθηκών.

## **Εντολές Φόρτωσης Mach-O**

Η **διάταξη του αρχείου στη μνήμη** καθορίζεται εδώ, λεπτομερώς η **τοποθεσία του πίνακα συμβόλων**, το πλαίσιο του κύριου νήματος στην έναρξη εκτέλεσης και οι απαιτούμενες **κοινόχρηστες βιβλιοθήκες**. Δίνονται οδηγίες στον δυναμικό φορτωτή **(dyld)** για τη διαδικασία φόρτωσης του δυαδικού στη μνήμη.

Χρησιμοποιεί τη δομή **load\_command**, ορισμένη στο αναφερόμενο **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Υπάρχουν περίπου **50 διαφορετικοί τύποι εντολών φόρτωσης** που το σύστημα χειρίζεται διαφορετικά. Οι πιο κοινοί είναι: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` και `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Βασικά, αυτός ο τύπος Load Command ορίζει **πώς να φορτώσει το \_\_TEXT** (εκτελέσιμος κώδικας) **και το \_\_DATA** (δεδομένα για τη διαδικασία) **segments** σύμφωνα με τα **offsets που υποδεικνύονται στην ενότητα Δεδομένων** όταν το δυαδικό εκτελείται.
{% endhint %}

Αυτές οι εντολές **ορίζουν segments** που **αντιστοιχίζονται** στο **εικονικό χώρο μνήμης** μιας διαδικασίας όταν εκτελείται.

Υπάρχουν **διαφορετικοί τύποι** segments, όπως το segment **\_\_TEXT**, που κρατά τον εκτελέσιμο κώδικα ενός προγράμματος, και το segment **\_\_DATA**, που περιέχει δεδομένα που χρησιμοποιούνται από τη διαδικασία. Αυτά τα **segments βρίσκονται στην ενότητα δεδομένων** του αρχείου Mach-O.

**Κάθε segment** μπορεί να χωριστεί περαιτέρω σε πολλαπλές **ενότητες**. Η δομή της **εντολής φόρτωσης** περιέχει **πληροφορίες** σχετικά με **αυτές τις ενότητες** εντός του αντίστοιχου segment.

Στην κεφαλίδα πρώτα βρίσκετε η **κεφαλίδα του segment**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* για 64-bit αρχιτεκτονικές */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* περιλαμβάνει το μέγεθος των section_64 structs */
char		segname[16];	/* όνομα segment */
uint64_t	vmaddr;		/* διεύθυνση μνήμης αυτού του segment */
uint64_t	vmsize;		/* μέγεθος μνήμης αυτού του segment */
uint64_t	fileoff;	/* αρχείο offset αυτού του segment */
uint64_t	filesize;	/* ποσό για αντιστοίχιση από το αρχείο */
int32_t		maxprot;	/* μέγιστη προστασία VM */
int32_t		initprot;	/* αρχική προστασία VM */
<strong>	uint32_t	nsects;		/* αριθμός ενοτήτων στο segment */
</strong>	uint32_t	flags;		/* σημαίες */
};
</code></pre>

Παράδειγμα κεφαλίδας segment:

<figure><img src="../../../.gitbook/assets/image (1126).png" alt=""><figcaption></figcaption></figure>

Αυτή η κεφαλίδα ορίζει τον **αριθμό των ενοτήτων των οποίων οι κεφαλίδες εμφανίζονται μετά** από αυτήν:
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
Παράδειγμα του **επικεφαλίδας ενότητας**:

<figure><img src="../../../.gitbook/assets/image (1108).png" alt=""><figcaption></figcaption></figure>

Εάν **προσθέσετε** το **μετατόπισμα της ενότητας** (0x37DC) + το **μετατόπισμα** όπου **ξεκινά η αρχιτεκτονική**, σε αυτήν την περίπτωση `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (701).png" alt=""><figcaption></figcaption></figure>

Είναι επίσης δυνατό να πάρετε **πληροφορίες επικεφαλίδων** από τη **γραμμή εντολών** με:
```bash
otool -lv /bin/ls
```
Κοινά τμήματα που φορτώνονται από αυτήν την εντολή:

* **`__PAGEZERO`:** Οδηγεί τον πυρήνα να **χαρτογραφήσει** τη **διεύθυνση μηδέν** έτσι ώστε να **μην μπορεί να διαβαστεί, να γραφτεί ή να εκτελεστεί**. Οι μεταβλητές maxprot και minprot στη δομή ορίζονται σε μηδέν για να υποδείξουν ότι δεν υπάρχουν **δικαιώματα ανάγνωσης-εγγραφής-εκτέλεσης σε αυτήν τη σελίδα**.
* Αυτή η δέσμευση είναι σημαντική για την **αντιμετώπιση των ευπαθειών αναφοράς σε μηδενικό δείκτη**. Αυτό συμβαίνει επειδή το XNU επιβάλλει ένα σκληρό μηδενικό σελίδας που εξασφαλίζει ότι η πρώτη σελίδα (μόνο η πρώτη) της μνήμης είναι μη προσβάσιμη (εκτός από το i386). Ένα δυαδικό αρχείο θα μπορούσε να πληροί αυτές τις απαιτήσεις δημιουργώντας ένα μικρό \_\_PAGEZERO (χρησιμοποιώντας το `-pagezero_size`) για να καλύψει τα πρώτα 4k και να έχει το υπόλοιπο της μνήμης 32bit προσβάσιμο και σε λειτουργία χρήστη και πυρήνα.
* **`__TEXT`**: Περιέχει **εκτελέσιμο** **κώδικα** με δικαιώματα **ανάγνωσης** και **εκτέλεσης** (χωρίς εγγραφή)**.** Κοινές ενότητες αυτού του τμήματος:
* `__text`: Μεταγλωττισμένος δυαδικός κώδικας
* `__const`: Σταθερά δεδομένα (μόνο για ανάγνωση)
* `__[c/u/os_log]string`: Σταθερές συμβολοσειρές C, Unicode ή os logs
* `__stubs` και `__stubs_helper`: Εμπλέκονται κατά τη διαδικασία φόρτωσης δυναμικής βιβλιοθήκης
* `__unwind_info`: Δεδομένα ανάπτυξης στοίβας.
* Σημειώστε ότι όλο αυτό το περιεχόμενο είναι υπογεγραμμένο αλλά και επισημασμένο ως εκτελέσιμο (δημιουργώντας περισσότερες επιλογές για εκμετάλλευση τμημάτων που δεν χρειάζονται απαραίτητα αυτό το προνόμιο, όπως τμήματα αφιερωμένα σε συμβολοσειρές).
* **`__DATA`**: Περιέχει δεδομένα που είναι **αναγνώσιμα** και **εγγράψιμα** (χωρίς εκτέλεση)**.**
* `__got:` Πίνακας Καθολικής Μετατόπισης
* `__nl_symbol_ptr`: Δείκτης συμβόλου μη-αργό (δεσμευμένος κατά τη φόρτωση)
* `__la_symbol_ptr`: Δείκτης συμβόλου αργό (δεσμευμένος κατά τη χρήση)
* `__const`: Θα έπρεπε να είναι δεδομένα μόνο για ανάγνωση (στην πραγματικότητα όχι)
* `__cfstring`: Συμβολοσειρές CoreFoundation
* `__data`: Παγκόσμιες μεταβλητές (που έχουν αρχικοποιηθεί)
* `__bss`: Στατικές μεταβλητές (που δεν έχουν αρχικοποιηθεί)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, κλπ): Πληροφορίες που χρησιμοποιούνται από το runtime της Objective-C
* **`__DATA_CONST`**: Το \_\_DATA.\_\_const δεν είναι εγγυημένα σταθερό (δικαιώματα εγγραφής), ούτε και άλλοι δείκτες και ο πίνακας GOT. Αυτή η ενότητα καθιστά το `__const`, μερικούς αρχικοποιητές και τον πίνακα GOT (αφού επιλυθεί) **μόνο για ανάγνωση** χρησιμοποιώντας το `mprotect`.
* **`__LINKEDIT`**: Περιέχει πληροφορίες για τον σύνδεσμο (dyld) όπως, σύμβολα, συμβολοσειρές και καταχωρήσεις πίνακα ανακατεύθυνσης. Είναι ένα γενικός δοχείο για περιεχόμενα που δεν βρίσκονται ούτε στο `__TEXT` ούτε στο `__DATA` και το περιεχόμενό του περιγράφεται σε άλλες εντολές φόρτωσης.
* Πληροφορίες dyld: Επαντοποίηση, μη-αργή/αργή/αδύναμη σύνδεση συμβόλων και πληροφορίες εξαγωγής
* Έναρξη συναρτήσεων: Πίνακας διευθύνσεων έναρξης συναρτήσεων
* Δεδομένα Στον Κώδικα: Δεδομένα νησίδες στο \_\_text
* Πίνακας Συμβόλων: Σύμβολα στο δυαδικό
* Έμμεσος Πίνακας Συμβόλων: Δείκτες συμβόλων/στάμπ
* Πίνακας Συμβολοσειρών
* Υπογραφή Κώδικα
* **`__OBJC`**: Περιέχει πληροφορίες που χρησιμοποιούνται από το runtime της Objective-C. Αυτές οι πληροφορίες μπορεί επίσης να βρεθούν στο τμήμα \_\_DATA, εντός διαφόρων τμημάτων \_\_objc\_\*.
* **`__RESTRICT`**: Ένα τμήμα χωρίς περιεχόμενο με ένα μόνο τμήμα που ονομάζεται **`__restrict`** (επίσης κενό) που εξασφαλίζει ότι κατά την εκτέλεση του δυαδικού, θα αγνοήσει τις μεταβλητές περιβάλλοντος DYLD.

Όπως ήταν δυνατό να δει κανείς στον κώδικα, **τα τμήματα υποστηρίζουν επίσης σημαίες** (αν και δεν χρησιμοποιούνται πολύ):

* `SG_HIGHVM`: Μόνο πυρήνας (δεν χρησιμοποιείται)
* `SG_FVMLIB`: Δεν χρησιμοποιείται
* `SG_NORELOC`: Το τμήμα δεν έχει ανακατεύθυνση
* `SG_PROTECTED_VERSION_1`: Κρυπτογράφηση. Χρησιμοποιείται για παράδειγμα από το Finder για να κρυπτογραφήσει το κείμενο του τμήματος `__TEXT`. 

### **`LC_UNIXTHREAD/LC_MAIN`**

Το **`LC_MAIN`** περιέχει το σημείο εισόδου στο χαρακτηριστικό **entryoff**. Κατά τη φόρτωση, το **dyld** απλά **προσθέτει** αυτήν την τιμή στη (στη μνήμη) **βάση του δυαδικού**, και στη συνέχεια **μεταβαίνει** σε αυτήν την εντολή για να ξεκινήσει η εκτέλεση του κώδικα του δυαδικού.

Το **`LC_UNIXTHREAD`** περιέχει τις τιμές που πρέπει να έχουν τα καταχωρητέα όταν ξεκινά ο κύριος νήματος. Αυτό έχει ήδη αποσυρθεί, αλλά το **`dyld`** το χρησιμοποιεί ακόμα. Είναι δυνατό να δείτε τις τιμές των καταχωρητών που έχουν οριστεί από αυτό με:
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

Περιέχει πληροφορίες σχετικά με τη **υπογραφή κώδικα του αρχείου Mach-O**. Περιέχει μόνο ένα **μετατόπιση** που **δείχνει** στο **blob υπογραφής**. Αυτό είναι τυπικά στο πολύ τέλος του αρχείου.\
Ωστόσο, μπορείτε να βρείτε πληροφορίες σχετικά με αυτήν την ενότητα στην [**ανάρτηση στο blog αυτό**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) και αυτό το [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Υποστήριξη για κρυπτογράφηση δυαδικού κώδικα. Ωστόσο, φυσικά, αν ένας επιτιθέμενος καταφέρει να διακινδυνεύσει τη διαδικασία, θα μπορεί να ανακτήσει τη μνήμη μη κρυπτογραφημένη.

### **`LC_LOAD_DYLINKER`**

Περιέχει τη **διαδρομή προς το εκτελέσιμο δυναμικού συνδέτη** που αντιστοιχεί τις κοινόχρηστες βιβλιοθήκες στο χώρο διεύθυνσης της διεργασίας. Η **τιμή είναι πάντα ορισμένη σε `/usr/lib/dyld`**. Σημαντικό είναι να σημειωθεί ότι στο macOS, η αντιστοίχιση dylib συμβαίνει σε **λειτουργία χρήστη**, όχι σε λειτουργία πυρήνα.

### **`LC_IDENT`**

Παρωχημένο αλλά όταν ρυθμιστεί για τη δημιουργία αναφορών σφαλμάτων, δημιουργείται ένας πυρήνας Mach-O και η έκδοση πυρήνα ορίζεται στην εντολή `LC_IDENT`.

### **`LC_UUID`**

Τυχαίο UUID. Είναι χρήσιμο για οτιδήποτε άμεσα, αλλά το XNU το αποθηκεύει μαζί με τις υπόλοιπες πληροφορίες της διεργασίας. Μπορεί να χρησιμοποιηθεί σε αναφορές σφαλμάτων.

### **`LC_DYLD_ENVIRONMENT`**

Επιτρέπει την υποδειξη μεταβλητών περιβάλλοντος στο dyld πριν εκτελεστεί η διαδικασία. Αυτό μπορεί να είναι επικίνδυνο καθώς μπορεί να επιτρέψει την εκτέλεση αυθαίρετου κώδικα μέσα στη διαδικασία, οπότε αυτή η εντολή φόρτωσης χρησιμοποιείται μόνο σε dyld που χτίστηκε με `#define SUPPORT_LC_DYLD_ENVIRONMENT` και περαιτέρω περιορίζει την επεξεργασία μόνο σε μεταβλητές της μορφής `DYLD_..._PATH` που καθορίζουν διαδρομές φόρτωσης.

### **`LC_LOAD_DYLIB`**

Αυτή η εντολή φόρτωσης περιγράφει μια **δυναμική** **εξάρτηση βιβλιοθήκης** που **οδηγεί** τον **φορτωτή** (dyld) να **φορτώσει και να συνδέσει τη συγκεκριμένη βιβλιοθήκη**. Υπάρχει μια εντολή φόρτωσης `LC_LOAD_DYLIB` **για κάθε βιβλιοθήκη** που απαιτεί το δυαδικό Mach-O.

* Αυτή η εντολή φόρτωσης είναι μια δομή τύπου **`dylib_command`** (η οποία περιέχει μια δομή dylib, περιγράφοντας την πραγματική εξαρτώμενη δυναμική βιβλιοθήκη):
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

Μπορείτε επίσης να λάβετε αυτές τις πληροφορίες από το cli με:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Μερικές πιθανές βιβλιοθήκες που σχετίζονται με malware είναι:

* **DiskArbitration**: Παρακολούθηση USB drives
* **AVFoundation:** Καταγραφή ήχου και βίντεο
* **CoreWLAN**: Σάρωση Wifi.

{% hint style="info" %}
Ένα δυαδικό Mach-O μπορεί να περιέχει έναν ή **περισσότερους κατασκευαστές**, οι οποίοι θα εκτελεστούν **πριν** τη διεύθυνση που καθορίζεται στο **LC\_MAIN**.\
Τα offsets οποιουδήποτε κατασκευαστή κρατούνται στην ενότητα **\_\_mod\_init\_func** του τμήματος **\_\_DATA\_CONST**.
{% endhint %}

## **Δεδομένα Mach-O**

Στον πυρήνα του αρχείου βρίσκεται η περιοχή δεδομένων, η οποία αποτελείται από διάφορα τμήματα όπως ορίζεται στην περιοχή εντολών φόρτωσης. **Μια ποικιλία τμημάτων δεδομένων μπορεί να φιλοξενείται σε κάθε τμήμα**, με κάθε τμήμα να **κρατάει κώδικα ή δεδομένα** που είναι συγκεκριμένα για έναν τύπο.

{% hint style="success" %}
Τα δεδομένα είναι βασικά η περιοχή που περιέχει όλες τις **πληροφορίες** που φορτώνονται από τις εντολές φόρτωσης **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055\_02\_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Αυτό περιλαμβάνει:

* **Πίνακας συναρτήσεων:** Ο οποίος περιέχει πληροφορίες σχετικά με τις λειτουργίες του προγράμματος.
* **Πίνακας συμβόλων**: Ο οποίος περιέχει πληροφορίες σχετικά με τις εξωτερικές λειτουργίες που χρησιμοποιούνται από το δυαδικό
* Μπορεί επίσης να περιέχει εσωτερικές συναρτήσεις, ονόματα μεταβλητών και άλλα.

Για να το ελέγξετε μπορείτε να χρησιμοποιήσετε το εργαλείο [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (1120).png" alt=""><figcaption></figcaption></figure>

Ή από το cli:
```bash
size -m /bin/ls
```
## Κοινές Ενότητες Objective-C

Στο τμήμα `__TEXT` (r-x):

* `__objc_classname`: Ονόματα κλάσεων (αλφαριθμητικά)
* `__objc_methname`: Ονόματα μεθόδων (αλφαριθμητικά)
* `__objc_methtype`: Τύποι μεθόδων (αλφαριθμητικά)

Στο τμήμα `__DATA` (rw-):

* `__objc_classlist`: Δείκτες προς όλες τις κλάσεις Objective-C
* `__objc_nlclslist`: Δείκτες προς μη-τεμπέλιες κλάσεις Objective-C
* `__objc_catlist`: Δείκτης προς Κατηγορίες
* `__objc_nlcatlist`: Δείκτης προς μη-τεμπέλιες Κατηγορίες
* `__objc_protolist`: Λίστα πρωτοκόλλων
* `__objc_const`: Σταθερά δεδομένα
* `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

* `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`
