# Εισαγωγή Βιβλιοθήκης στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

{% hint style="danger" %}
Ο κώδικας του **dyld είναι ανοικτού κώδικα** και μπορεί να βρεθεί στο [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) και μπορεί να ληφθεί ένα tar χρησιμοποιώντας μια **URL όπως** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **DYLD\_INSERT\_LIBRARIES**

Αυτό είναι παρόμοιο με το [**LD\_PRELOAD στο Linux**](../../../../linux-hardening/privilege-escalation#ld\_preload). Επιτρέπει να υποδείξετε σε ένα διεργασία που θα εκτελεστεί να φορτώσει μια συγκεκριμένη βιβλιοθήκη από ένα δρομολόγιο (εάν η μεταβλητή περιβάλλοντος είναι ενεργοποιημένη)

Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί ως τεχνική ASEP καθώς κάθε εγκατεστημένη εφαρμογή έχει ένα plist με το όνομα "Info.plist" που επιτρέπει την ανάθεση περιβαλλοντικών μεταβλητών χρησιμοποιώντας ένα κλειδί με το όνομα `LSEnvironmental`.

{% hint style="info" %}
Από το 2012, η Apple έχει μειώσει δραστικά την ισχύ του `DYLD_INSERT_LIBRARIES`.

Μεταβείτε στον κώδικα και ελέγξτε το `src/dyld.cpp`. Στη συνάρτηση `pruneEnvironmentVariables` μπορείτε να δείτε ότι οι μεταβλητές `DYLD_*` αφαιρούνται.

Στη συνάρτηση `processRestricted` ορίζεται ο λόγος του περιορισμού. Ελέγχοντας αυτόν τον κώδικα μπορείτε να δείτε ότι οι λόγοι είναι:

* Το δυαδικό είναι `setuid/setgid`
* Υπάρχει ενότητα `__RESTRICT/__restrict` στο δυαδικό macho.
* Το λογισμικό έχει εντοπισμούς (hardened runtime) χωρίς την εντολή [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Ελέγξτε τους εντοπισμούς ενός δυαδικού με: `codesign -dv --entitlements :- </path/to/bin>`

Σε πιο ενημερωμένες εκδόσεις μπορείτε να βρείτε αυτήν τη λογική στο δεύτερο μέρος της συνάρτησης `configureProcessRestrictions`. Ωστόσο, αυτό που εκτελείται σε νεότερες εκδόσεις είναι οι αρχικοί έλεγχοι της συνάρτησης (μπορείτε να αφαιρέσετε τα ifs που σχετίζοντ
* Εάν το **`LC_LOAD_DYLIB`** περιέχει `@rpath/library.dylib` και το **`LC_RPATH`** περιέχει `/application/app.app/Contents/Framework/v1/` και `/application/app.app/Contents/Framework/v2/`. Και οι δύο φάκελοι θα χρησιμοποιηθούν για να φορτωθεί το `library.dylib`**.** Εάν η βιβλιοθήκη δεν υπάρχει στον φάκελο `[...]/v1/` και ο επιτιθέμενος μπορεί να την τοποθετήσει εκεί για να αποκτήσει τον έλεγχο της φόρτωσης της βιβλιοθήκης στον φάκελο `[...]/v2/` καθώς ακολουθείται η σειρά των διαδρομών στο **`LC_LOAD_DYLIB`**.
* **Βρείτε τις διαδρομές rpath και τις βιβλιοθήκες** στα δυαδικά αρχεία με: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Είναι η **διαδρομή** προς τον φάκελο που περιέχει το **κύριο εκτελέσιμο αρχείο**.

**`@loader_path`**: Είναι η **διαδρομή** προς τον **φάκελο** που περιέχει το **Mach-O δυαδικό** που περιέχει την εντολή φόρτωσης.

* Όταν χρησιμοποιείται σε ένα εκτελέσιμο, το **`@loader_path`** είναι πρακτικά το **ίδιο** με το **`@executable_path`**.
* Όταν χρησιμοποιείται σε ένα **dylib**, το **`@loader_path`** δίνει την **διαδρομή** προς το **dylib**.
{% endhint %}

Ο τρόπος για να **αναβαθμίσετε τα δικαιώματα** καταχρώντας αυτήν τη λειτουργικότητα θα ήταν στη σπάνια περίπτωση που μια **εφαρμογή** που εκτελείται **από** τον **root** ψάχνει για μια **βιβλιοθήκη σε έναν φάκελο όπου ο επιτιθέμενος έχει δικαιώματα εγγραφής**.

{% hint style="success" %}
Ένα εξαιρετικό **εργαλείο σάρωσης** για να βρείτε **ελλιπείς βιβλιοθήκες** σε εφαρμογές είναι το [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ή μια [**έκδοση CLI**](https://github.com/pandazheng/DylibHijack).\
Μια ωραία **αναφορά με τεχνικές λεπτομέρειες** για αυτήν την τεχνική μπορεί να βρεθεί [**εδώ**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Παράδειγμα**

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Θυμηθείτε ότι ισχύουν και οι **προηγούμενοι περιορισμοί της Επικύρωσης Βιβλιοθήκης** για να πραγματοποιηθούν επιθέσεις Dlopen hijacking.
{% endhint %}

Από το **`man dlopen`**:

* Όταν η διαδρομή **δεν περιέχει τον χαρακτήρα κάθετος** (δηλαδή είναι απλά ένα όνομα φακέλου), το dlopen() θα κάνει αναζήτηση. Εάν το **`$DYLD_LIBRARY_PATH`** ήταν ορισμένο κατά την εκκίνηση, το dyld θα ψάξει πρώτα σε αυτόν τον φάκελο. Στη συνέχεια, εάν το καλούντα Mach-O αρχείο ή το κύριο εκτελέσιμο καθορίζουν ένα **`LC_RPATH`**, τότε το dyld θα ψάξει σε αυτούς τους φακέλους. Στη συνέχεια, εάν η διεργασία είναι **απεριόριστη**, το dyld θα αναζητήσει στον **τρέχοντα φάκελο εργασίας**. Τέλος, για παλαιότερα δυαδικά αρχεία, το dyld θα δοκιμάσει μερικές εναλλακτικές λύσεις. Εάν το **`$DYLD_FALLBACK_LIBRARY_PATH`** ήταν ορισμένο κατά την εκκίνηση, το dyld θα αναζητήσει σε αυτούς τους φακέλους, διαφορετικά, το dyld θα ψάξει στο **`/usr/local/lib/`** (εάν η διεργασία είναι απεριόριστη), και στη συνέχεια στο **`/usr/lib/`** (αυτές οι πληροφορίες προήλθαν από το **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(εάν είναι απεριόριστη)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (εάν είναι απεριό
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Εάν το μεταγλωττίσετε και το εκτελέσετε, μπορείτε να δείτε **πού αναζητήθηκε ανεπιτυχώς κάθε βιβλιοθήκη**. Επίσης, μπορείτε να **φιλτράρετε τα αρχεία καταγραφής του συστήματος αρχείων**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Απάτη με σχετική διαδρομή

Εάν ένα **προνομιούχο δυαδικό/εφαρμογή** (όπως ένα SUID ή κάποιο δυαδικό με ισχυρά entitlements) φορτώνει μια βιβλιοθήκη με **σχετική διαδρομή** (για παράδειγμα χρησιμοποιώντας `@executable_path` ή `@loader_path`) και έχει απενεργοποιημένο τον έλεγχο της βιβλιοθήκης, είναι δυνατόν να μετακινηθεί το δυαδικό σε μια τοποθεσία όπου ο επιτιθέμενος μπορεί να **τροποποιήσει τη φορτωμένη βιβλιοθήκη με τη σχετική διαδρομή** και να την καταχραστεί για να εισαγάγει κώδικα στη διεργασία.

## Αποκοπή των μεταβλητών περιβάλλοντος `DYLD_*` και `LD_LIBRARY_PATH`

Στο αρχείο `dyld-dyld-832.7.1/src/dyld2.cpp` είναι δυνατόν να βρεθεί η συνάρτηση **`pruneEnvironmentVariables`**, η οποία θα αφαιρέσει οποιαδήποτε μεταβλητή περιβάλλοντος που **αρχίζει με `DYLD_`** και **`LD_LIBRARY_PATH=`**.

Επίσης, θα ορίσει σε **null** ειδικά τις μεταβλητές περιβάλλοντος **`DYLD_FALLBACK_FRAMEWORK_PATH`** και **`DYLD_FALLBACK_LIBRARY_PATH`** για δυαδικά με **suid** και **sgid**.

Αυτή η συνάρτηση καλείται από τη συνάρτηση **`_main`** του ίδιου αρχείου εάν στοχεύει σε OSX ως εξής:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
και αυτές οι λογικές σημαίες ορίζονται στον ίδιο αρχείο στον κώδικα:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Αυτό σημαίνει ότι αν το δυαδικό αρχείο είναι **suid** ή **sgid**, ή έχει ένα τμήμα **RESTRICT** στις κεφαλίδες ή έχει υπογραφεί με τη σημαία **CS\_RESTRICT**, τότε το **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** είναι αληθές και οι μεταβλητές περιβάλλοντος αφαιρούνται.

Σημειώστε ότι αν το CS\_REQUIRE\_LV είναι αληθές, τότε οι μεταβλητές δεν θα αφαιρεθούν, αλλά ο έλεγχος επικύρωσης βιβλιοθήκης θα ελέγξει αν χρησιμοποιούν το ίδιο πιστοποιητικό με το αρχικό δυαδικό αρχείο.

## Έλεγχος Περιορισμών

### SUID & SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Ενότητα `__RESTRICT` με τον τομέα `__restrict`

The `__RESTRICT` section is a segment in macOS that is used to restrict access to certain libraries and prevent unauthorized code execution. This section is specifically designed to enhance the security of the operating system by limiting the privileges of processes.

When a library is placed in the `__RESTRICT` section, it means that only privileged processes can access and execute code from that library. This prevents malicious actors from injecting their own code into the library and gaining unauthorized access to sensitive system resources.

By utilizing the `__RESTRICT` section, macOS ensures that only trusted processes can interact with critical libraries, reducing the risk of privilege escalation and unauthorized access.

To summarize, the `__RESTRICT` section in macOS plays a crucial role in enhancing the security of the operating system by restricting access to certain libraries and preventing unauthorized code execution.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Ενισχυμένη εκτέλεση

Δημιουργήστε ένα νέο πιστοποιητικό στο Keychain και χρησιμοποιήστε το για να υπογράψετε το δυαδικό αρχείο:

{% code overflow="wrap" %}
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
{% endcode %}

{% hint style="danger" %}
Σημειώστε ότι ακόμα και αν υπάρχουν δυαδικά αρχεία με υπογραφή με σημαίες **`0x0(none)`**, μπορούν να αποκτήσουν δυναμικά τη σημαία **`CS_RESTRICT`** κατά την εκτέλεσή τους και, συνεπώς, αυτή η τεχνική δεν θα λειτουργήσει σε αυτά.

Μπορείτε να ελέγξετε αν ένα proc έχει αυτήν τη σημαία με (πάρτε [**εδώ το csops**](https://github.com/axelexic/CSOps)):&#x20;
```bash
csops -status <pid>
```
και στη συνέχεια ελέγξτε εάν η σημαία 0x800 είναι ενεργοποιημένη.
{% endhint %}

## Αναφορές
* [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
