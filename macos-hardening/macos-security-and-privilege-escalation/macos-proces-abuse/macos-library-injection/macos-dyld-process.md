# macOS Διεργασία Dyld

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Το πραγματικό **σημείο εισόδου** ενός δυαδικού Mach-o είναι το δυναμικά συνδεδεμένο, που ορίζεται στο `LC_LOAD_DYLINKER` και συνήθως είναι `/usr/lib/dyld`.

Αυτός ο συνδέστης θα πρέπει να εντοπίσει όλες τις βιβλιοθήκες εκτελέσιμων αρχείων, να τις χαρτογραφήσει στη μνήμη και να συνδέσει όλες τις μη-τεμπέλικες βιβλιοθήκες. Μόνο μετά από αυτήν τη διαδικασία, θα εκτελεστεί το σημείο εισόδου του δυαδικού.

Φυσικά, το **`dyld`** δεν έχει καμία εξάρτηση (χρησιμοποιεί κλήσεις συστήματος και αποσπάσματα libSystem).

{% hint style="danger" %}
Αν αυτός ο συνδέστης περιέχει κάποια ευπάθεια, καθώς εκτελείται πριν από την εκτέλεση οποιουδήποτε δυαδικού (ακόμα και υψηλά προνομιούχων), θα ήταν δυνατή η **ανάδειξη προνομίων**.
{% endhint %}

### Ροή

Το Dyld θα φορτωθεί από το **`dyldboostrap::start`**, το οποίο θα φορτώσει επίσης πράγματα όπως το **stack canary**. Αυτό συμβαίνει επειδή αυτή η λειτουργία θα λάβει στο διάνυσμά της **`apple`** αυτή και άλλες **ευαίσθητες** **τιμές**.

Το **`dyls::_main()`** είναι το σημείο εισόδου του dyld και η πρώτη του εργασία είναι να εκτελέσει το `configureProcessRestrictions()`, το οποίο συνήθως περιορίζει τις **`DYLD_*`** μεταβλητές περιβάλλοντος που εξηγούνται στο:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

Στη συνέχεια, χαρτογραφεί την κοινόχρηστη προσωρινή μνήμη dyld που προ-συνδέει όλες τις σημαντικές βιβλιοθήκες συστήματος και στη συνέχεια χαρτογραφεί τις βιβλιοθήκες στις οποίες εξαρτάται το δυαδικό και συνεχίζει αναδρομικά μέχρι να φορτωθούν όλες οι απαιτούμενες βιβλιοθήκες. Συνεπώς:

1. ξεκινά τη φόρτωση εισαγόμενων βιβλιοθηκών με το `DYLD_INSERT_LIBRARIES` (εάν επιτρέπεται)
2. Στη συνέχεια οι κοινόχρηστες προσωρινές μνήμες
3. Στη συνέχεια οι εισαγόμενες
4. Στη συνέχεια συνεχίζει την εισαγωγή βιβλιοθηκών αναδρομικά

Μόλις φορτωθούν όλα, εκτελούνται οι **αρχικοποιητές** αυτών των βιβλιοθηκών. Αυτοί κωδικοποιούνται χρησιμοποιώντας το **`__attribute__((constructor))`** που ορίζεται στο `LC_ROUTINES[_64]` (πλέον αποσυρμένο) ή με δείκτη σε ενότητα με σημαία `S_MOD_INIT_FUNC_POINTERS` (συνήθως: **`__DATA.__MOD_INIT_FUNC`**).

Οι τερματοφόροι κωδικοποιούνται με **`__attribute__((destructor))`** και βρίσκονται σε μια ενότητα με σημαία `S_MOD_TERM_FUNC_POINTERS` (**`__DATA.__mod_term_func`**).

### Αντικείμενα

Όλα τα δυαδικά στο macOS είναι δυναμικά συνδεδεμένα. Συνεπώς, περιέχουν ορισμένες ενότητες stubs που βοηθούν το δυαδικό να μεταβεί στον σωστό κώδικα σε διαφορετικές μηχανές και πλαίσια. Είναι το dyld όταν εκτελείται το δυαδικό το μυαλό που πρέπει να επιλύσει αυτές τις διευθύνσεις (τουλάχιστον τις μη-τεμπέλικες).

Ορισμένες ενότητες stubs στο δυαδικό:

* **`__TEXT.__[auth_]stubs`**: Δείκτες από ενότητες `__DATA`
* **`__TEXT.__stub_helper`**: Μικρός κώδικας που καλεί δυναμική σύνδεση με πληροφορίες για τη συνάρτηση προς κλήση
* **`__DATA.__[auth_]got`**: Πίνακας Παγίων Τιμών (διευθύνσεις σε εισαγόμενες συναρτήσεις, όταν επιλυθούν, (δεσμευμένες κατά τη φόρτωση καθώς είναι σημειωμένες με τη σημαία `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__nl_symbol_ptr`**: Δείκτες μη-τεμπέλικων συμβόλων (δεσμευμένοι κατά τη φόρτωση καθώς είναι σημειωμένοι με τη σημαία `S_NON_LAZY_SYMBOL_POINTERS`)
* **`__DATA.__la_symbol_ptr`**: Δείκτες τεμπέλικων συμβόλων (δεσμευμένοι κατά την πρώτη πρόσβαση)

{% hint style="warning" %}
Σημειώστε ότι οι δείκτες με το πρόθεμα "auth\_" χρησιμοποιούν ένα κλειδί κρυπτογράφησης σε διαδικασία για προστασία (PAC). Επιπλέον, είναι δυνατόν να χρησιμοποιηθεί η εντολή arm64 `BLRA[A/B]` για να επαληθευτεί ο δείκτης πριν ακολουθηθεί. Και το RETA\[A/B\] μπορεί να χρησιμοποιηθεί αντί για μια διεύθυνση RET.\
Πράγματι, ο κώδικας στο **`__TEXT.__auth_stubs`** θα χρησιμοποιήσει **`braa`** αντί για **`bl`** για να καλέσει την απαιτούμενη συνάρτηση για την επαλήθευση του δείκτη.

Επίσης, σημειώστε ότι οι τρέχουσες εκδόσεις dyld φορτώνουν **όλα ως μη-τεμπέλικα**.
{% endhint %}

### Εύρεση τεμπέλικων συμβόλων
```c
//gcc load.c -o load
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
printf("Hi\n");
}
```
Ενδιαφέρουσα μεταφρασμένη μερίδα:
```armasm
; objdump -d ./load
100003f7c: 90000000    	adrp	x0, 0x100003000 <_main+0x1c>
100003f80: 913e9000    	add	x0, x0, #4004
100003f84: 94000005    	bl	0x100003f98 <_printf+0x100003f98>
```
Είναι δυνατόν να δούμε ότι το άλμα προς το κάλεσμα της printf πηγαίνει στο **`__TEXT.__stubs`**:
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
Στην αποσυναρμολόγηση της ενότητας **`__stubs`**:
```bash
objdump -d --section=__stubs ./load

./load:	file format mach-o arm64

Disassembly of section __TEXT,__stubs:

0000000100003f98 <__stubs>:
100003f98: b0000010    	adrp	x16, 0x100004000 <__stubs+0x4>
100003f9c: f9400210    	ldr	x16, [x16]
100003fa0: d61f0200    	br	x16
```
Μπορείτε να δείτε ότι **αλλάζουμε στη διεύθυνση του GOT**, η οποία σε αυτήν την περίπτωση επιλύεται μη-τεμπέλικα και θα περιέχει τη διεύθυνση της συνάρτησης printf.

Σε άλλες καταστάσεις αντί να αλλάξει απευθείας στο GOT, θα μπορούσε να αλλάξει στο **`__DATA.__la_symbol_ptr`** το οποίο θα φορτώσει μια τιμή που αντιπροσωπεύει τη συνάρτηση που προσπαθεί να φορτώσει, στη συνέχεια θα αλλάξει στο **`__TEXT.__stub_helper`** το οποίο αλλάζει το **`__DATA.__nl_symbol_ptr`** που περιέχει τη διεύθυνση του **`dyld_stub_binder`** το οποίο παίρνει ως παραμέτρους τον αριθμό της συνάρτησης και μια διεύθυνση.\
Αυτή η τελευταία συνάρτηση, μετά τον εντοπισμό της διεύθυνσης της αναζητούμενης συνάρτησης, τη γράφει στην αντίστοιχη θέση στο **`__TEXT.__stub_helper`** για να αποφευχθούν μελλοντικές αναζητήσεις.

{% hint style="success" %}
Ωστόσο, παρατηρήστε ότι οι τρέχουσες εκδόσεις dyld φορτώνουν όλα τα πράγματα ως μη-τεμπέλικα.
{% endhint %}

#### Οδηγίες Dyld

Τέλος, το **`dyld_stub_binder`** χρειάζεται να βρει την υποδειγμένη συνάρτηση και να τη γράψει στη σωστή διεύθυνση για να μην την αναζητήσει ξανά. Για να το κάνει αυτό χρησιμοποιεί οδηγίες (ένα πεπερασμένο αυτόματο κατάστασης) μέσα στο dyld.

## apple\[] argument vector

Στο macOS η κύρια συνάρτηση λαμβάνει πραγματικά 4 ορίσματα αντί για 3. Το τέταρτο ονομάζεται apple και κάθε καταχώρηση είναι στη μορφή `key=value`. Για παράδειγμα:
```c
// gcc apple.c -o apple
#include <stdio.h>
int main (int argc, char **argv, char **envp, char **apple)
{
for (int i=0; apple[i]; i++)
printf("%d: %s\n", i, apple[i])
}
```
```markdown
## macOS Dyld Process

### macOS Library Injection

macOS uses the dynamic linker `dyld` to load libraries into a process's address space. This mechanism can be abused by injecting a malicious library into a process, allowing an attacker to execute arbitrary code within the context of the target process.

#### Techniques

1. **Code Injection**: The attacker injects malicious code into the target process by loading a malicious library using `dyld`.

2. **Function Hooking**: By intercepting and modifying function calls within the target process, an attacker can manipulate the behavior of the process.

3. **Environment Variable Injection**: Attackers can set environment variables to manipulate the behavior of the target process, such as changing library paths to load malicious libraries.

#### Mitigation

1. **Code Signing**: Enforce code signing requirements to ensure that only trusted libraries are loaded into processes.

2. **Library Validation**: Enable library validation to verify the integrity of loaded libraries and prevent the loading of unsigned or modified libraries.

3. **Restricted Library Paths**: Limit the directories from which libraries can be loaded to prevent unauthorized libraries from being injected into processes.
```
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
Μέχρι τη στιγμή που αυτές οι τιμές φτάνουν στην κύρια συνάρτηση, έχει ήδη αφαιρεθεί από αυτές ευαίσθητη πληροφορία ή θα μπορούσε να οδηγήσει σε διαρροή δεδομένων.
{% endhint %}

είναι δυνατόν να δείτε όλες αυτές τις ενδιαφέρουσες τιμές αποσφαλματώντας πριν μπείτε στην κύρια με:

<pre><code>lldb ./apple

<strong>(lldb) target create "./a"
</strong>Το τρέχον εκτελέσιμο έχει οριστεί σε '/tmp/a' (arm64).
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

Αυτή είναι μια δομή που εξάγεται από το dyld με πληροφορίες σχετικά με την κατάσταση του dyld που μπορεί να βρεθεί στο [**source code**](https://opensource.apple.com/source/dyld/dyld-852.2/include/mach-o/dyld\_images.h.auto.html) με πληροφορίες όπως η έκδοση, δείκτης προς τον πίνακα dyld\_image\_info, προς τον dyld\_image\_notifier, αν η διαδικασία έχει αποσυνδεθεί από την κοινόχρηστη μνήμη, αν έχει κληθεί ο αρχικοποιητής του libSystem, δείκτης προς τη δική Mach κεφαλίδα του dyld, δείκτης προς τη συμβολοσειρά έκδοσης του dyld...

## dyld μεταβλητές περιβάλλοντος

### αποσφαλμάτωση dyld

Ενδιαφέρουσες μεταβλητές περιβάλλοντος που βοηθούν στην κατανόηση του τι κάνει το dyld:

* **DYLD\_PRINT\_LIBRARIES**

Ελέγξτε κάθε βιβλιοθήκη που φορτώνεται:
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

Ελέγξτε πώς φορτώνεται κάθε βιβλιοθήκη:
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

Εκτύπωση όταν εκτελείται κάθε αρχικοποιητής βιβλιοθήκης:
```
DYLD_PRINT_INITIALIZERS=1 ./apple
dyld[21623]: running initializer 0x18e59e5c0 in /usr/lib/libSystem.B.dylib
[...]
```
### Άλλα

* `DYLD_BIND_AT_LAUNCH`: Οι lazy δεσμεύσεις επιλύονται με μη-αδρά
* `DYLD_DISABLE_PREFETCH`: Απενεργοποίηση προ-φόρτωσης περιεχομένων \_\_DATA και \_\_LINKEDIT
* `DYLD_FORCE_FLAT_NAMESPACE`: Δεσμεύσεις μονού επιπέδου
* `DYLD_[FRAMEWORK/LIBRARY]_PATH | DYLD_FALLBACK_[FRAMEWORK/LIBRARY]_PATH | DYLD_VERSIONED_[FRAMEWORK/LIBRARY]_PATH`: Διαδρομές ανάλυσης
* `DYLD_INSERT_LIBRARIES`: Φόρτωση μιας συγκεκριμένης βιβλιοθήκης
* `DYLD_PRINT_TO_FILE`: Εγγραφή αποσφαλμάτωσης dyld σε ένα αρχείο
* `DYLD_PRINT_APIS`: Εκτύπωση κλήσεων API libdyld
* `DYLD_PRINT_APIS_APP`: Εκτύπωση κλήσεων API libdyld που πραγματοποιούνται από το main
* `DYLD_PRINT_BINDINGS`: Εκτύπωση συμβόλων όταν δεσμεύονται
* `DYLD_WEAK_BINDINGS`: Εκτύπωση μόνο αδύναμων συμβόλων όταν δεσμεύονται
* `DYLD_PRINT_CODE_SIGNATURES`: Εκτύπωση λειτουργιών εγγραφής υπογραφής κώδικα
* `DYLD_PRINT_DOFS`: Εκτύπωση τμημάτων μορφής αντικειμένου D-Trace όπως φορτώνονται
* `DYLD_PRINT_ENV`: Εκτύπωση περιβάλλοντος που βλέπει το dyld
* `DYLD_PRINT_INTERPOSTING`: Εκτύπωση λειτουργιών ενδιάθεσης
* `DYLD_PRINT_LIBRARIES`: Εκτύπωση φορτωμένων βιβλιοθηκών
* `DYLD_PRINT_OPTS`: Εκτύπωση επιλογών φόρτωσης
* `DYLD_REBASING`: Εκτύπωση λειτουργιών επαντοποίησης συμβόλων
* `DYLD_RPATHS`: Εκτύπωση επεκτάσεων @rpath
* `DYLD_PRINT_SEGMENTS`: Εκτύπωση αντιστοιχίσεων τμημάτων Mach-O
* `DYLD_PRINT_STATISTICS`: Εκτύπωση στατιστικών χρονομέτρησης
* `DYLD_PRINT_STATISTICS_DETAILS`: Εκτύπωση λεπτομερών στατιστικών χρονομέτρησης
* `DYLD_PRINT_WARNINGS`: Εκτύπωση μηνυμάτων προειδοποίησης
* `DYLD_SHARED_CACHE_DIR`: Διαδρομή για χρήση κοινής βιβλιοθήκης cache
* `DYLD_SHARED_REGION`: "χρήση", "ιδιωτικό", "αποφυγή"
* `DYLD_USE_CLOSURES`: Ενεργοποίηση κλεισιμάτων

Είναι δυνατόν να βρείτε περισσότερα με κάτι σαν:
```bash
strings /usr/lib/dyld | grep "^DYLD_" | sort -u
```
Ή κατεβάστε το έργο dyld από [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) και εκτελέστε μέσα στον φάκελο:
```bash
find . -type f | xargs grep strcmp| grep key,\ \" | cut -d'"' -f2 | sort -u
```
## Αναφορές

* [**\*OS Internals, Volume I: User Mode. Από τον Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του GitHub.

</details>
