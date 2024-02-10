# macOS Πανεπιστημιακά αρχεία και Μορφή Mach-O

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές πληροφορίες

Τα δυαδικά αρχεία του Mac OS συνήθως μεταγλωττίζονται ως **πανεπιστημιακά αρχεία**. Ένα **πανεπιστημιακό αρχείο** μπορεί να **υποστηρίζει πολλές αρχιτεκτονικές στο ίδιο αρχείο**.

Αυτά τα δυαδικά ακολουθούν τη **δομή Mach-O** που αποτελείται βασικά από:

* Κεφαλίδα
* Φορτώσεις εντολών
* Δεδομένα

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../.gitbook/assets/image (559).png>)

## Παχύ Κεφαλίδα

Αναζητήστε το αρχείο με: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu specifier (int) */
cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
uint32_t	offset;		/* file offset to this object file */
uint32_t	size;		/* size of this object file */
uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

Η κεφαλίδα έχει τα **μαγικά** bytes που ακολουθούνται από τον **αριθμό** των **αρχιτεκτονικών** που περιέχει το αρχείο (`nfat_arch`) και κάθε αρχιτεκτονική θα έχει μια δομή `fat_arch`.

Ελέγξτε το με:

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

ή χρησιμοποιώντας το εργαλείο [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Όπως μπορείτε να σκεφτείτε, ένα πανεπιστημιακό δυαδικό που έχει μεταγλωττιστεί για 2 αρχιτεκτονικές **διπλασιάζει το μέγεθος** ενός που έχει μεταγλωττιστεί για μόνο 1 αρχιτεκτονική.

## **Κεφαλίδα Mach-O**

Η κεφαλίδα περιέχει βασικές πληροφορίες για το αρχείο, όπως μαγικά bytes για να το αναγνωρίσει ως αρχείο Mach-O και πληροφορίες για την αρχιτεκτονική στόχο. Μπορείτε να το βρείτε στο: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Τύποι αρχείων**:

* MH\_EXECUTE (0x2): Κανονικό εκτελέσιμο αρχείο Mach-O
* MH\_DYLIB (0x6): Δυναμική συνδεδεμένη βιβλιοθήκη Mach-O (δηλαδή .dylib)
* MH\_BUNDLE (0x8): Πακέτο Mach-O (δηλαδή .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ή χρησιμοποιώντας το [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Εντολές φόρτωσης Mach-O**

Εδώ καθορίζεται η **διάταξη του αρχείου στη μνήμη**, αναλύοντας τη **θέση του πίνακα συμβόλων**, το πλαίσιο του κύριου νήματος κατά την έναρξη εκτέλεσης και τις απαιτούμενες **κοινόχρηστες βιβλιοθήκες**. Δίνονται οδηγίες στον δυναμικό φορτωτή **(dyld)** για τη διαδικασία φόρτωσης του δυαδικού αρχείου στη μνήμη.

Χρησιμοποιείται η δομή **load\_command**, που ορίζεται στο αναφερόμενο **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Υπάρχουν περίπου **50 διαφορετικοί τύποι εντολών φόρτωσης** που το σύστημα χειρίζεται διαφορετικά. Οι πιο συνηθισμένοι είναι: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` και `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Βασικά, αυτός ο τύπος εντολής φόρτωσης καθορίζει **πώς να φορτώσει τα \_\_TEXT** (εκτελέσιμος κώδικας) **και \_\_DATA** (δεδομένα για τη διεργασία) **τμήματα** σύμφωνα με τις **μετατοπίσεις που υποδεικνύονται στην ενότητα Δεδομένων** όταν εκτελείται το δυαδικό αρχείο.
{% endhint %}

Αυτές οι εντολές **καθορίζουν τα τμήματα** που **αντιστοιχίζονται** στον **εικονικό χώρο μνήμης** μιας διεργασίας όταν εκτελείται.

Υπάρχουν **διάφοροι τύποι** τμημάτων, όπως το τμήμα **\_\_TEXT**, που περιέχει τον εκτελέσιμο κώδικα ενός προγράμματος, και το τμήμα **\_\_DATA**, που περιέχει δεδομένα που χρησιμοποιούνται από τη διεργασία. Αυτά τα **τμήματα βρίσκονται στην ενότητα δεδομένων** του αρχείου Mach-O.

**Κάθε τμήμα** μπορεί να χωριστεί περαιτέρω σε πολλαπλές **ενότητες**. Η δομή της εντολής φόρτωσης περιέχει **πληροφορίες** για **αυτές τις ενότητες** εντός του αντίστοιχου τμήματος.

Στην κεφαλίδα πρώτα βρίσκεται η **κεφαλίδα τμήματος**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* για 64-bit αρχιτεκτονικές */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* περιλαμβάνει το μέγεθος των δομών section_64 */
char		segname[16];	/* όνομα τμήματος */
uint64_t	vmaddr;		/* διεύθυνση μνήμης αυτού του τμήματος */
uint64_t	vmsize;		/* μέγεθος μνήμης αυτού του τμήματος */
uint64_t	fileoff;	/* αρχείο μετατόπισης αυτού του τμήματος */
uint64_t	filesize;	/* ποσό για χαρτογράφηση από το αρχείο */
int32_t		maxprot;	/* μέγιστη προστασία VM */
int32_t		initprot;	/* αρχική προστασία VM */
<strong>	uint32_t	nsects;		/* αριθμός ενοτήτων στο τμήμα */
</strong>	uint32_t	flags;		/* σημαίες */
};
</code></pre>

Παράδειγμα κεφαλίδας τμήματος:

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Αυτή η κεφαλίδα καθορίζει τον **αριθμό των ενοτήτων των οποίων οι κεφαλίδες ακολουθούν** μετά από αυτήν:
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

<figure><img src="../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

Εάν **προσθέσετε** το **offset της ενότητας** (0x37DC) + το **offset** όπου **αρχίζει η αρχιτεκτονική**, σε αυτήν την περίπτωση `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Είναι επίσης δυνατό να πάρετε τις πληροφορίες των **επικεφαλίδων** από τη **γραμμή εντολών** με:
```bash
otool -lv /bin/ls
```
Κοινά τμήματα που φορτώνονται από αυτήν την εντολή:

* **`__PAGEZERO`:** Οδηγεί τον πυρήνα να **χαρτογραφήσει** τη **διεύθυνση μηδέν** έτσι ώστε να **μην μπορεί να διαβαστεί, να γραφτεί ή να εκτελεστεί**. Οι μεταβλητές maxprot και minprot στη δομή ορίζονται σε μηδέν για να υποδείξουν ότι δεν υπάρχουν **δικαιώματα ανάγνωσης-εγγραφής-εκτέλεσης σε αυτήν τη σελίδα**.
* Αυτή η δέσμευση είναι σημαντική για την **αντιμετώπιση ευπάθειας αναφοράς σε μηδενικό δείκτη**.
* **`__TEXT`**: Περιέχει **εκτελέσιμο** **κώδικα** με δικαιώματα **ανάγνωσης** και **εκτέλεσης** (χωρίς εγγράψιμο)**.** Κοινά τμήματα αυτού του τμήματος:
* `__text`: Μεταγλωττισμένος δυαδικός κώδικας
* `__const`: Σταθερά δεδομένα
* `__cstring`: Σταθερές συμβολοσειρές
* `__stubs` και `__stubs_helper`: Συμμετέχουν κατά τη διάρκεια της διαδικασίας φόρτωσης δυναμικής βιβλιοθήκης
* **`__DATA`**: Περιέχει δεδομένα που είναι **αναγνώσιμα** και **εγγράψιμα** (χωρίς εκτελέσιμο)**.**
* `__data`: Παγκόσμιες μεταβλητές (που έχουν αρχικοποιηθεί)
* `__bss`: Στατικές μεταβλητές (που δεν έχουν αρχικοποιηθεί)
* `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, κλπ): Πληροφορίες που χρησιμοποιούνται από τον χρόνο εκτέλεσης Objective-C
* **`__LINKEDIT`**: Περιέχει πληροφορίες για τον σύνδεσμο (dyld) όπως "σύμβολο, συμβολοσειρά και καταχωρητές ανακατάταξης".
* **`__OBJC`**: Περιέχει πληροφορίες που χρησιμοποιούνται από τον χρόνο εκτέλεσης Objective-C. Ωστόσο, αυτές οι πληροφορίες μπορεί επίσης να βρεθούν στο τμήμα \_\_DATA, μέσα σε διάφορα τμήματα \_\_objc\_\*.

### **`LC_MAIN`**

Περιέχει το σημείο εισόδου στο **attribute entryoff**. Κατά τη φόρτωση, ο **dyld** απλά **προσθέτει** αυτήν την τιμή στη (στη μνήμη) **βάση του δυαδικού**, και στη συνέχεια **μεταβαίνει** σε αυτήν την εντολή για να ξεκινήσει την εκτέλεση του κώδικα του δυαδικού.

### **LC\_CODE\_SIGNATURE**

Περιέχει πληροφορίες σχετικά με την **υπογραφή κώδικα του αρχείου Macho-O**. Περιέχει μόνο μια **μετατόπιση** που **δείχνει** στο **μπλοκ υπογραφής**. Αυτό συνήθως βρίσκεται στο τέλος του αρχείου.\
Ωστόσο, μπορείτε να βρείτε ορισμένες πληροφορίες σχετικά με αυτήν την ενότητα σε αυτήν την [**ανάρτηση στο blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) και αυτό το [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **LC\_LOAD\_DYLINKER**

Περιέχει τη **διαδρομή προς το εκτελέσιμο δυναμικού συνδέσμου** που αντιστοιχεί τις κοινόχρηστες βιβλιοθήκες στο χώρο διευθύνσεων της διεργασίας. Η τιμή ορίζεται πάντα σε `/usr/lib/dyld`. Σημαντικό είναι να σημειωθεί ότι στο macOS, η αντιστοίχιση dylib γίνεται σε **χρήστης** και όχι σε λειτουργία πυρήνα.

### **`LC_LOAD_DYLIB`**

Αυτή η εντολή φόρτωσης περιγράφει μια **δυναμική** **εξάρτηση βιβλιοθήκης** που **οδηγεί** τον **φορτωτή** (dyld) να **φορτώσει και να συνδέσει τη συγκεκριμένη βιβλιοθήκη**. Υπάρχει μια εντολή φόρτωσης LC\_LOAD\_DYLIB **για κάθε βιβλιοθήκη** που απαιτείται από το δυαδικό Mach-O.

* Αυτή η εντολή φόρτωσης είναι μια δομή τύπου **`dylib_command`** (η οποία περιέχει μια δομή dylib που περιγράφει την πραγματική εξαρτώμενη δυναμική βιβλιοθήκη):
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

Μπορείτε επίσης να λάβετε αυτές τις πληροφορίες από το cli με την εντολή:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Ορισμένες δυνητικές βιβλιοθήκες που σχετίζονται με κακόβουλο λογισμικό είναι:

* **DiskArbitration**: Παρακολούθηση των USB μονάδων
* **AVFoundation:** Καταγραφή ήχου και εικόνας
* **CoreWLAN**: Σάρωση Wifi.

{% hint style="info" %}
Ένα δυαδικό Mach-O μπορεί να περιέχει έναν ή **περισσότερους** **constructors**, που θα εκτελεστούν **πριν** τη διεύθυνση που καθορίζεται στο **LC\_MAIN**.\
Οι μετατοπίσεις οποιουδήποτε constructor βρίσκονται στην ενότητα **\_\_mod\_init\_func** του τμήματος **\_\_DATA\_CONST**.
{% endhint %}

## **Δεδομένα Mach-O**

Στην καρδιά του αρχείου βρίσκεται η περιοχή δεδομένων, η οποία αποτελείται από αρκετά τμήματα όπως ορίζονται στην περιοχή των φορτωτικών εντολών. **Μια ποικιλία τμημάτων δεδομένων μπορεί να φιλοξενηθεί σε κάθε τμήμα**, με κάθε τμήμα να **κρατά κώδικα ή δεδομένα** που είναι συγκεκριμένα για έναν τύπο.

{% hint style="success" %}
Τα δεδομένα είναι βασικά η μέρος που περιέχει όλες τις **πληροφορίες** που φορτώνονται από τις φορτωτικές εντολές **LC\_SEGMENTS\_64**
{% endhint %}

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../.gitbook/assets/image (507) (3).png>)

Αυτό περιλαμβάνει:

* **Πίνακας συναρτήσεων:** Ο οποίος περιέχει πληροφορίες για τις συναρτήσεις του προγράμματος.
* **Πίνακας συμβόλων**: Ο οποίος περιέχει πληροφορίες για τις εξωτερικές συναρτήσεις που χρησιμοποιούνται από το δυαδικό αρχείο
* Μπορεί επίσης να περιέχει εσωτερικές συναρτήσεις, ονόματα μεταβλητών και άλλα.

Για να το ελέγξετε, μπορείτε να χρησιμοποιήσετε το εργαλείο [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (2) (1) (4).png" alt=""><figcaption></figcaption></figure>

Ή από το cli:
```bash
size -m /bin/ls
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
