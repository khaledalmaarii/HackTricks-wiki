# macOS Εισαγωγή Βιβλιοθήκης

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

{% hint style="danger" %}
Ο κώδικας του **dyld είναι ανοικτού κώδικα** και μπορεί να βρεθεί στο [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) και μπορεί να ληφθεί ως tar χρησιμοποιώντας μια **διεύθυνση URL όπως** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)
{% endhint %}

## **Διεργασία Dyld**

Ρίξτε μια ματιά στο πώς το Dyld φορτώνει βιβλιοθήκες μέσα σε δυαδικά αρχεία στο:

{% content-ref url="macos-dyld-process.md" %}
[macos-dyld-process.md](macos-dyld-process.md)
{% endcontent-ref %}

## **DYLD\_INSERT\_LIBRARIES**

Αυτό είναι σαν το [**LD\_PRELOAD στο Linux**](../../../../linux-hardening/privilege-escalation/#ld\_preload). Επιτρέπει να υποδείξετε σε μια διεργασία ότι θα τρέξει για να φορτώσει μια συγκεκριμένη βιβλιοθήκη από ένα διαδρομή (εάν η μεταβλητή περιβάλλοντος είναι ενεργοποιημένη)

Αυτή η τεχνική μπορεί επίσης **να χρησιμοποιηθεί ως τεχνική ASEP** καθώς κάθε εγκατεστημένη εφαρμογή έχει ένα plist που ονομάζεται "Info.plist" που επιτρέπει την **ανάθεση μεταβλητών περιβάλλοντος** χρησιμοποιώντας ένα κλειδί που ονομάζεται `LSEnvironmental`.

{% hint style="info" %}
Από το 2012 **η Apple έχει μειώσει δραστικά τη δύναμη** του **`DYLD_INSERT_LIBRARIES`**.

Πηγαίνετε στον κώδικα και **ελέγξτε το `src/dyld.cpp`**. Στη συνάρτηση **`pruneEnvironmentVariables`** μπορείτε να δείτε ότι οι μεταβλητές **`DYLD_*`** αφαιρούνται.

Στη συνάρτηση **`processRestricted`** ορίζεται ο λόγος του περιορισμού. Ελέγχοντας αυτόν τον κώδικα μπορείτε να δείτε ότι οι λόγοι είναι:

* Το δυαδικό είναι `setuid/setgid`
* Υπάρχει ενότητα `__RESTRICT/__restrict` στο δυαδικό macho.
* Το λογισμικό έχει εντοπιστικά (σκληρή εκτέλεση) χωρίς το εντοπιστικό [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables)
* Ελέγξτε τα **εντοπιστικά** ενός δυαδικού με: `codesign -dv --entitlements :- </path/to/bin>`

Σε πιο ενημερωμένες εκδόσεις μπορείτε να βρείτε αυτήν τη λογική στο δεύτερο μέρος της συνάρτησης **`configureProcessRestrictions`.** Ωστόσο, αυτό που εκτελείται σε νεότερες εκδόσεις είναι οι **έλεγχοι στην αρχή της συνάρτησης** (μπορείτε να αφαιρέσετε τα ifs που σχετίζονται με iOS ή προσομοίωση καθώς αυτά δεν θα χρησιμοποιηθούν σε macOS.
{% endhint %}

### Επικύρωση Βιβλιοθήκης

Ακόμη κι αν το δυαδικό επιτρέπει τη χρήση της **`DYLD_INSERT_LIBRARIES`** μεταβλητής περιβάλλοντος, αν το δυαδικό ελέγχει την υπογραφή της βιβλιοθήκης που θα φορτώσει, δεν θα φορτώσει μια προσαρμοσμένη βιβλιοθήκη.

Για να φορτώσετε μια προσαρμοσμένη βιβλιοθήκη, το δυαδικό πρέπει να έχει **ένα από τα ακόλουθα εντοπιστικά**:

* [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
* [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ή το δυαδικό **δεν πρέπει** να έχει τη σημαία **σκληρής εκτέλεσης** ή τη σημαία **επικύρωσης βιβλιοθήκης**.

Μπορείτε να ελέγξετε αν ένα δυαδικό έχει **σκληρή εκτέλεση** με `codesign --display --verbose <bin>` ελέγχοντας τη σημαία εκτέλεσης στο **`CodeDirectory`** όπως: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Μπορείτε επίσης να φορτώσετε μια βιβλιοθήκη αν είναι **υπογεγραμμένη με τον ίδιο πιστοποιητικό με το δυαδικό**.

Βρείτε ένα παράδειγμα πώς να (κατ)ασχοληθείτε με αυτό και ελέγξτε τους περιορισμούς στο:

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Απαγωγή Dylib

{% hint style="danger" %}
Θυμηθείτε ότι **ισχύουν επίσης οι προηγούμενοι περιορισμοί επικύρωσης βιβλιοθήκης** για την εκτέλεση επιθέσεων απαγωγής Dylib.
{% endhint %}

Όπως και στα Windows, στο MacOS μπορείτε επίσης **να απαγάγετε dylibs** για να κάνετε τις **εφαρμογές να εκτελούν** **αυθαίρετο** **κώδικα** (καλά, στην πραγματικότητα από έναν κανονικό χρήστη αυτό δεν θα ήταν δυνατό καθώς μπορεί να χρειαστείτε άδεια TCC για να γράψετε μέσα σε ένα `.app` πακέτο και να απαγάγετε μια βιβλιοθήκη).\
Ωστόσο, ο τρόπος με τον οποίο οι εφαρμογές **MacOS** φορτώνουν βιβλιοθήκες είναι **πιο περιορισμένος** από ό,τι στα Windows. Αυτό σημαίνει ότι οι **δημιουργοί malware** μπορούν ακόμη να χρησιμοποιήσουν αυτήν την τεχνική για την **κρυφή λειτουργία**, αλλά η πιθανότητα να μπορέσουν να **καταχραστούν αυτό για προνόμια είναι πολύ χαμηλή**.

Καταρχάς, είναι **πιο συνηθισμένο** να βρείτε ότι τα **δυαδικά MacOS υποδεικνύουν την πλήρη διαδρομή** προς τις βιβλιοθήκες που θα φορτώσουν. Και δεύτερο, το **MacOS ποτέ δεν αναζητά** στους φακέλους του **$PATH** για βιβλιοθήκες.

Η **κύρια** μέρος του **κώδικα** που σχετίζεται με αυτήν τη λειτουργικότητα βρίσκεται στο **`ImageLoader::recursiveLoadLibraries`** στο `ImageLoader.cpp`.

Υπάρχουν **4 διαφορετικές εντολές κεφαλίδας** που μπορεί να χρησιμοποιήσει ένα δυαδικό macho για τη φόρτωση βιβλιοθηκών:

* Η εντολή **`LC_LOAD_DYLIB`** είναι η κοινή εντολή για τη φόρτωσ
* **`LC_LOAD_DYLIB`** περιέχει το μονοπάτι προς συγκεκριμένες βιβλιοθήκες προς φόρτωση. Αυτά τα μονοπάτια μπορεί να περιέχουν το **`@rpath`**, το οποίο θα **αντικατασταθεί** από τις τιμές στο **`LC_RPATH`**. Αν υπάρχουν πολλά μονοπάτια στο **`LC_RPATH`** θα χρησιμοποιηθούν όλα για την αναζήτηση της βιβλιοθήκης προς φόρτωση. Παράδειγμα:
* Αν το **`LC_LOAD_DYLIB`** περιέχει `@rpath/library.dylib` και το **`LC_RPATH`** περιέχει `/application/app.app/Contents/Framework/v1/` και `/application/app.app/Contents/Framework/v2/`. Και τα δύο φακέλους θα χρησιμοποιηθούν για τη φόρτωση της `library.dylib`. Αν η βιβλιοθήκη δεν υπάρχει στο `[...]/v1/` και ο επιτιθέμενος μπορεί να την τοποθετήσει εκεί για να αποκτήσει τον έλεγχο της φόρτωσης της βιβλιοθήκης στο `[...]/v2/` καθώς ακολουθείται η σειρά των μονοπατιών στο **`LC_LOAD_DYLIB`**.
* **Βρείτε τα μονοπάτια rpath και τις βιβλιοθήκες** σε δυαδικά αρχεία με: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

{% hint style="info" %}
**`@executable_path`**: Είναι το **μονοπάτι** προς τον φάκελο που περιέχει το **κύριο εκτελέσιμο αρχείο**.

**`@loader_path`**: Είναι το **μονοπάτι** προς τον **φάκελο** που περιέχει το **Mach-O δυαδικό** που περιέχει την εντολή φόρτωσης.

* Όταν χρησιμοποιείται σε ένα εκτελέσιμο, το **`@loader_path`** είναι αποτελεσματικά το **ίδιο** με το **`@executable_path`**.
* Όταν χρησιμοποιείται σε ένα **dylib**, το **`@loader_path`** δίνει το **μονοπάτι** προς το **dylib**.
{% endhint %}

Ο τρόπος να **εξελιχθούν τα προνόμια** καταχρώντας αυτήν τη λειτουργικότητα θα ήταν στη σπάνια περίπτωση που μια **εφαρμογή** που εκτελείται **από** **root** ψάχνει για κάποια **βιβλιοθήκη σε κάποιο φάκελο όπου ο επιτιθέμενος έχει δικαιώματα εγγραφής.**

{% hint style="success" %}
Ένα εξαιρετικό **εργαλείο σάρωσης** για την εύρεση **λείπουσων βιβλιοθηκών** σε εφαρμογές είναι το [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ή μια [**εκδοχή γραμμής εντολών**](https://github.com/pandazheng/DylibHijack).\
Ένα ωραίο **αναφορά με τεχνικές λεπτομέρειες** σχετικά με αυτήν την τεχνική μπορεί να βρεθεί [**εδώ**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).
{% endhint %}

**Παράδειγμα**

{% content-ref url="macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

## Dlopen Hijacking

{% hint style="danger" %}
Να θυμάστε ότι **ισχύουν επίσης οι προηγούμενοι περιορισμοί Επικύρωσης Βιβλιοθήκης** για την εκτέλεση επιθέσεων Dlopen hijacking.
{% endhint %}

Από το **`man dlopen`**:

* Όταν το μονοπάτι **δεν περιέχει χαρακτήρα κάθετο** (δηλαδή είναι απλά ένα όνομα φακέλου), το **dlopen() θα κάνει αναζήτηση**. Αν το **`$DYLD_LIBRARY_PATH`** ήταν ορισμένο κατά την εκκίνηση, το dyld θα ψάξει πρώτα σε αυτόν τον φάκελο. Στη συνέχεια, αν το καλούντα Mach-O αρχείο ή το κύριο εκτελέσιμο καθορίζουν ένα **`LC_RPATH`**, τότε το dyld θα **ψάξει σε αυτούς** τους φακέλους. Στη συνέχεια, αν η διαδικασία είναι **ανεμπόδιστη**, το dyld θα αναζητήσει στον **τρέχοντα φάκελο εργασίας**. Τέλος, για παλιά δυαδικά αρχεία, το dyld θα δοκιμάσει κάποιες εναλλακτικές λύσεις. Αν το **`$DYLD_FALLBACK_LIBRARY_PATH`** ήταν ορισμένο κατά την εκκίνηση, το dyld θα αναζητήσει σε **αυτούς τους φακέλους**, διαφορετικά, το dyld θα ψάξει στο **`/usr/local/lib/`** (αν η διαδικασία είναι ανεμπόδιστη), και στη συνέχεια στο **`/usr/lib/`** (αυτές οι πληροφορίες προήχθησαν από το **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(αν είναι ανεμπόδιστη)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (αν είναι ανεμπόδιστη)
6. `/usr/lib/`

{% hint style="danger" %}
Αν δεν υπάρχουν κάθετοι στο όνομα, υπάρχουν 2 τρόποι για να γίνει μια απάτη:

* Αν κάποιο **`LC_RPATH`** είναι **εγγράψιμο** (αλλά ελέγχεται η υπογραφή, οπότε γι' αυτό χρειάζεστε επίσης το δυαδικό να είναι ανεμπόδιστο)
* Αν το δυαδικό είναι **ανεμπόδιστο** και στη συνέχεια είναι δυνατόν να φορτωθεί κάτι από το CWD (ή καταχρώντας κάποια από τις αναφερόμενες μεταβλητές περιβάλλοντος)
{% endhint %}

* Όταν το μονοπάτι **μοιάζει με μονοπάτι πλαισίου** (π.χ. `/stuff/foo.framework/foo`), αν το **`$DYLD_FRAMEWORK_PATH`** ήταν ορισμένο κατά την εκκίνηση, το dyld θα ψάξει πρώτα σε αυτόν τον φάκελο για το **μερικό μονοπάτι του πλαισίου** (π.χ. `foo.framework/foo`). Στη συνέχεια, το dyld θα δοκιμάσει το **παρεχόμενο μονοπάτι ως έχει** (χρησιμοποιώντας τον τρέχοντα φάκελο εργασίας για σχετικά μονοπάτια). Τέλος, για παλιά δυαδικά αρχεία, το dyld θα δοκιμάσει κάποιες εναλλακτικές λύσεις. Αν το **`$DYLD_FALLBACK_FRAMEWORK_PATH`** ήταν ορισμένο κατά την εκκίνηση, το dyld θα αναζητήσει σε **αυτούς τους φακέλους**. Διαφορετικά, θα αναζητήσει στο **`/Library/Frameworks`** (στο macOS αν η διαδικασία είναι ανεμπόδιστη), στη συνέχεια στο **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. παρεχόμενο μονοπάτι (χρησιμοποιώντας τον τρέχοντα φάκελο εργασίας για σχετικά μονοπάτια αν είναι ανεμπόδιστη η διαδικασία)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (αν η διαδικασία είναι ανεμπόδιστη)
5. `/System/Library/Frameworks`

{% hint style="danger" %}
Αν το μονοπάτι είναι πλαίσιο, ο τρόπος να το καταχραστείτε θα ήταν:

* Αν η διαδικασία είναι **ανεμπόδιστη**, καταχρώντας το **σχετικό μονοπάτι από το CWD** με τις αναφερόμενες μεταβλητές περιβάλλοντος (ακόμα κι αν δεν αναφέρεται στα έγγραφα αν η διαδικασία είναι περιορισμένη, οι μεταβλητές περιβάλλοντος DYLD\_\* αφαιρούνται)
{% endhint %}

* Όταν το μονοπάτι **περιέχει κάθετο αλλά δεν είναι μονοπάτι πλαισίου** (δηλαδή πλήρες μονοπάτι ή μερικό μονοπάτι προς ένα dylib), το dlopen() πρώτα ψάχνει (αν έχει οριστεί) στο **`$DYLD_LIBRARY_PATH`** (με το μέρος φύλλου από το μονοπάτι). Στη συνέχεια, το dyld **δοκιμάζει το παρεχόμενο μονοπάτι** (χρησιμοποιώντας τον τρέχοντα φάκελο εργασίας γ
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
Εάν το μεταγλωττίσετε και το εκτελέσετε, μπορείτε να δείτε **πού αναζητήθηκε ανεπιτυχώς κάθε βιβλιοθήκη**. Επίσης, θα μπορούσατε **να φιλτράρετε τα αρχεία καταγραφής του συστήματος αρχείων (FS logs)**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Απάτη με Σχετική Διαδρομή

Εάν ένα **προνομιούχο δυαδικό/εφαρμογή** (όπως ένα SUID ή κάποιο δυαδικό με ισχυρές άδειες) φορτώνει ένα βιβλιοθήκη με **σχετική διαδρομή** (για παράδειγμα χρησιμοποιώντας το `@executable_path` ή `@loader_path`) και έχει **απενεργοποιημένο τον Έλεγχο Βιβλιοθήκης**, θα μπορούσε να είναι δυνατόν να μετακινηθεί το δυαδικό σε μια τοποθεσία όπου ο επιτιθέμενος θα μπορούσε να **τροποποιήσει τη βιβλιοθήκη που φορτώνεται με σχετική διαδρομή**, και να την καταχραστεί για να εισάγει κώδικα στη διαδικασία.

## Καθαρισμός των μεταβλητών περιβάλλοντος `DYLD_*` και `LD_LIBRARY_PATH`

Στο αρχείο `dyld-dyld-832.7.1/src/dyld2.cpp` είναι δυνατόν να βρεθεί η συνάρτηση **`pruneEnvironmentVariables`**, η οποία θα αφαιρέσει οποιαδήποτε μεταβλητή περιβάλλοντος που **ξεκινά με `DYLD_`** και **`LD_LIBRARY_PATH=`**.

Επίσης, θα ορίσει σε **null** ειδικά τις μεταβλητές περιβάλλοντος **`DYLD_FALLBACK_FRAMEWORK_PATH`** και **`DYLD_FALLBACK_LIBRARY_PATH`** για δυαδικά με **suid** και **sgid**.

Αυτή η συνάρτηση καλείται από τη συνάρτηση **`_main`** του ίδιου αρχείου εάν στοχεύει σε OSX όπως εδώ:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
και αυτά τα boolean flags ορίζονται στον ίδιο φάκελο στον κώδικα:
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
Το οποίο σημαίνει βασικά ότι αν το δυαδικό είναι **suid** ή **sgid**, ή έχει ένα τμήμα **RESTRICT** στους κεφαλίδες ή έχει υπογραφεί με τη σημαία **CS\_RESTRICT**, τότε **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** είναι αληθές και οι μεταβλητές περιβάλλοντος αφαιρούνται.

Σημειώστε ότι αν το CS\_REQUIRE\_LV είναι αληθές, τότε οι μεταβλητές δεν θα αφαιρεθούν, αλλά η επαλήθευση βιβλιοθήκης θα ελέγξει αν χρησιμοποιούν το ίδιο πιστοποιητικό με το αρχικό δυαδικό.

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
### Ενότητα `__RESTRICT` με το τμήμα `__restrict`
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
Σημειώστε ότι ακόμα κι αν υπάρχουν δυαδικά αρχεία που έχουν υπογραφεί με σημαίες **`0x0(none)`**, μπορεί να λάβουν δυναμικά τη σημαία **`CS_RESTRICT`** κατά την εκτέλεσή τους και, συνεπώς, αυτή η τεχνική δεν θα λειτουργήσει σε αυτά.

Μπορείτε να ελέγξετε αν ένα proc έχει αυτήν τη σημαία με (κατεβάστε το [**εδώ το csops**](https://github.com/axelexic/CSOps)):
```bash
csops -status <pid>
```
και στη συνέχεια ελέγξτε εάν η σημαία 0x800 είναι ενεργοποιημένη.
{% endhint %}

## Αναφορές

* [https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/](https://theevilbit.github.io/posts/dyld\_insert\_libraries\_dylib\_injection\_in\_macos\_osx\_deep\_dive/)
* [**\*OS Internals, Volume I: User Mode. Από τον Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του GitHub.

</details>
