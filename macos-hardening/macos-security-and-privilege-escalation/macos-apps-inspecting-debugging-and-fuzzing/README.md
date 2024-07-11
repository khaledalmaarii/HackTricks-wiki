# macOS Εφαρμογές - Επιθεώρηση, εντοπισμός σφαλμάτων και Fuzzing

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αποκλεισμών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

***

## Στατική Ανάλυση

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
{% endcode %}
```bash
nm -m ./tccd # List of symbols
```
### jtool2 & Disarm

Μπορείτε να [**κατεβάσετε το disarm από εδώ**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Μπορείτε να [**κατεβάσετε το jtool2 εδώ**](http://www.newosxbook.com/tools/jtool.html) ή να το εγκαταστήσετε με το `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
{% hint style="danger" %}
**Το jtool έχει αποσυρθεί υπέρ του disarm**
{% endhint %}

### Codesign / ldid

{% hint style="success" %}
**`Codesign`** μπορεί να βρεθεί στο **macOS** ενώ το **`ldid`** μπορεί να βρεθεί στο **iOS**
{% endhint %}
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) είναι ένα εργαλείο χρήσιμο για να επιθεωρήσετε αρχεία **.pkg** (εγκαταστάτες) και να δείτε τι περιέχουν πριν την εγκατάστασή τους.\
Αυτοί οι εγκαταστάτες έχουν σενάρια bash `preinstall` και `postinstall` που οι δημιουργοί κακόβουλου λογισμικού συνήθως καταχρώνται για να **διατηρήσουν** το **κακόβουλο λογισμικό**.

### hdiutil

Αυτό το εργαλείο επιτρέπει τη **σύνδεση** των εικόνων δίσκου Apple (**.dmg**) για να τις επιθεωρήσετε πριν εκτελέσετε οτιδήποτε:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Θα τοποθετηθεί στο `/Volumes`

### Συσκευασμένα δυαδικά αρχεία

* Έλεγχος για υψηλή εντροπία
* Έλεγχος των συμβολοσειρών (αν υπάρχει σχεδόν καμία κατανοητή συμβολοσειρά, συσκευασμένο)
* Το εργαλείο UPX packer για MacOS δημιουργεί μια ενότητα που ονομάζεται "\_\_XHDR"

## Στατική ανάλυση Objective-C

### Μεταδεδομένα

{% hint style="danger" %}
Σημειώστε ότι τα προγράμματα που γράφονται σε Objective-C **διατηρούν** τις δηλώσεις των κλάσεών τους **κατά την** **μεταγλώττιση** σε [δυαδικά Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Τέτοιες δηλώσεις κλάσεων περιλαμβάνουν το όνομα και τον τύπο των:
{% endhint %}

* Οι διεπαφές που ορίζονται
* Οι μέθοδοι της διεπαφής
* Οι μεταβλητές παραδειγμάτων της διεπαφής
* Οι ορισμένες πρωτόκολλα

Σημειώστε ότι αυτά τα ονόματα μπορεί να είναι αποκρυπτογραφημένα για να δυσκολέψει η αντιστροφή του δυαδικού.

### Κλήση συνάρτησης

Όταν καλείται μια συνάρτηση σε ένα δυαδικό που χρησιμοποιεί Objective-C, ο μεταγλωττισμένος κώδικας αντί να καλεί αυτήν τη συνάρτηση, θα καλέσει το **`objc_msgSend`**. Το οποίο θα καλέσει την τελική συνάρτηση:

![](<../../../.gitbook/assets/image (305).png>)

Τα ορίσματα που αναμένει αυτή η συνάρτηση είναι:

* Το πρώτο όρισμα (**self**) είναι "ένας δείκτης που δείχνει στο **παράδειγμα της κλάσης που θα λάβει το μήνυμα**". Ή απλά, είναι το αντικείμενο στο οποίο καλείται η μέθοδος. Αν η μέθοδος είναι μια μέθοδος κλάσης, αυτό θα είναι ένα παράδειγμα του αντικειμένου της κλάσης (συνολικά), ενώ για μια μέθοδο παραδείγματος, το self θα δείχνει σε ένα παραδειγμένο παράδειγμα της κλάσης ως αντικείμενο.
* Το δεύτερο όρισμα, (**op**), είναι "ο επιλογέας της μεθόδου που χειρίζεται το μήνυμα". Και πάλι, απλούστερα, αυτό είναι απλά το **όνομα της μεθόδου.**
* Τα υπόλοιπα ορίσματα είναι οποιεσδήποτε **τιμές που απαιτούνται από τη μέθοδο** (op).

Δείτε πώς να **λάβετε αυτές τις πληροφορίες εύκολα με το `lldb` σε ARM64** σε αυτήν τη σελίδα:

{% content-ref url="arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](arm64-basic-assembly.md)
{% endcontent-ref %}

x64:

| **Ορισμός**      | **Καταχώρηση**                                                | **(για) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ο όρισμα**    | **rdi**                                                         | **self: αντικείμενο πάνω στο οποίο καλείται η μέθοδος** |
| **2ο όρισμα**    | **rsi**                                                         | **op: όνομα της μεθόδου**                            |
| **3ο όρισμα**    | **rdx**                                                         | **1ο όρισμα στη μέθοδο**                            |
| **4ο όρισμα**    | **rcx**                                                         | **2ο όρισμα στη μέθοδο**                            |
| **5ο όρισμα**    | **r8**                                                          | **3ο όρισμα στη μέθοδο**                            |
| **6ο όρισμα**    | **r9**                                                          | **4ο όρισμα στη μέθοδο**                            |
| **7ο+ όρισμα**   | <p><strong>rsp+</strong><br><strong>(στη στοίβα)</strong></p> | **5ο+ όρισμα στη μέθοδο**                           |

### Αποθήκευση μεταδεδομένων ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) είναι ένα εργαλείο για την ανάλυση Objective-C δυαδικών. Το github καθορίζει dylibs αλλά αυτό λειτουργεί επίσης με εκτελέσιμα.
```bash
./dynadump dump /path/to/bin
```
Προς το παρόν, αυτό **είναι το καλύτερο που λειτουργεί**.

#### Κανονικά εργαλεία
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) είναι το αρχικό εργαλείο που δημιουργεί δηλώσεις για τις κλάσεις, κατηγορίες και πρωτόκολλα σε κώδικα μορφοποιημένο σε ObjetiveC.

Είναι παλιό και δεν συντηρείται, οπότε πιθανόν να μη λειτουργεί σωστά.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) είναι ένα μοντέρνο και πολυπλατφορμικό dump κλάσεων Objective-C. Σε σύγκριση με τα υπάρχοντα εργαλεία, το iCDump μπορεί να τρέξει ανεξάρτητα από το οικοσύστημα της Apple και εκθέτει δεσμεύσεις Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Στατική ανάλυση Swift

Με τα δυαδικά αρχεία Swift, καθώς υπάρχει συμβατότητα με την Objective-C, μερικές φορές μπορείτε να εξάγετε δηλώσεις χρησιμοποιώντας το [class-dump](https://github.com/nygard/class-dump/), αλλά όχι πάντα.

Με τις γραμμές εντολών **`jtool -l`** ή **`otool -l`** είναι δυνατόν να βρείτε αρκετές ενότητες που ξεκινούν με το πρόθεμα **`__swift5`**:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Μπορείτε να βρείτε περισσότερες πληροφορίες σχετικά με τις [**πληροφορίες που αποθηκεύονται σε αυτές τις ενότητες σε αυτήν την ανάρτηση στο blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Επιπλέον, **τα δυαδικά αρχεία Swift μπορεί να έχουν σύμβολα** (για παράδειγμα, οι βιβλιοθήκες χρειάζονται να αποθηκεύουν σύμβολα ώστε οι λειτουργίες τους να μπορούν να κληθούν). Τα **σύμβολα συνήθως περιέχουν πληροφορίες σχετικά με το όνομα της λειτουργίας** και τα χαρακτηριστικά με έναν ασχημο τρόπο, οπότε είναι πολύ χρήσιμα και υπάρχουν "**αποκωδικοποιητές"** που μπορούν να ανακτήσουν το αρχικό όνομα:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Δυναμική Ανάλυση

{% hint style="warning" %}
Σημειώστε ότι για να εκτελέσετε αποσφαλμάτωση δυαδικών αρχείων, **πρέπει να απενεργοποιήσετε το SIP** (`csrutil disable` ή `csrutil enable --without debug`) ή να αντιγράψετε τα δυαδικά αρχεία σε έναν προσωρινό φάκελο και **να αφαιρέσετε την υπογραφή** με την εντολή `codesign --remove-signature <διαδρομή-δυαδικού>` ή να επιτρέψετε την αποσφαλμάτωση του δυαδικού (μπορείτε να χρησιμοποιήσετε [αυτό το σενάριο](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Σημειώστε ότι για να **εργαλεύεστε τα δυαδικά συστήματος**, (όπως το `cloudconfigurationd`) στο macOS, **πρέπει να είναι απενεργοποιημένο το SIP** (απλά η αφαίρεση της υπογραφής δεν λειτουργεί).
{% endhint %}

### APIs

Το macOS εκθέτει μερικά ενδιαφέροντα APIs που παρέχουν πληροφορίες σχετικά με τις διεργασίες:

* `proc_info`: Αυτό είναι το κύριο API που παρέχει πολλές πληροφορίες για κάθε διεργασία. Χρειάζεται να είστε ριζοχρήστης για να λάβετε πληροφορίες για άλλες διεργασίες, αλλά δεν χρειάζεστε ειδικά δικαιώματα ή mach ports.
* `libsysmon.dylib`: Επιτρέπει τη λήψη πληροφοριών σχετικά με τις διεργασίες μέσω εκτεθειμένων λειτουργιών XPC, ωστόσο, απαιτείται η έγκριση `com.apple.sysmond.client`.

### Stackshot & microstackshots

Η **Stackshotting** είναι μια τεχνική που χρησιμοποιείται για να καταγράψει την κατάσταση των διεργασιών, συμπεριλαμβανομένων των σωρών κλήσεων όλων των ενεργών νημάτων. Αυτό είναι ιδιαίτερα χρήσιμο για αποσφαλμάτωση, ανάλυση απόδοσης και κατανόηση της συμπεριφοράς του συστήματος σε ένα συγκεκριμένο σημείο στο χρόνο. Στα iOS και macOS, η Stackshotting μπορεί να πραγματοποιηθεί χρησιμοποιώντας διάφορα εργαλεία και μεθόδους όπως τα εργαλεία **`sample`** και **`spindump`**.

### Sysdiagnose

Αυτό το εργαλείο (`/usr/bini/ysdiagnose`) συλλέγει βασικές πληροφορίες από τον υπολογιστή σας εκτελώντας δεκάδες διαφορετικές εντολές όπως `ps`, `zprint`...

Πρέπει να εκτελείται ως **ριζοχρήστης** και το daemon `/usr/libexec/sysdiagnosed` έχει πολύ ενδιαφέρουσες άδειες όπως `com.apple.system-task-ports` και `get-task-allow`.

Το plist του βρίσκεται στην τοποθεσία `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` το οποίο δηλώνει 3 MachServices:

* `com.apple.sysdiagnose.CacheDelete`: Διαγράφει παλιά αρχεία στο /var/rmp
* `com.apple.sysdiagnose.kernel.ipc`: Ειδική θύρα 23 (πυρήνας)
* `com.apple.sysdiagnose.service.xpc`: Διεπαφή λειτουργίας χρήστη μέσω της κλάσης `Libsysdiagnose` Obj-C. Μπορούν να περαστούν τρία ορίσματα σε ένα λεξικό (`συμπίεση`, `εμφάνιση`, `εκτέλεση`)

### Ενοποιημένα Αρχεία Καταγραφής

Το macOS δημιουργεί πολλά αρχεία καταγραφής που μπορούν να είναι πολύ χρήσιμα κατά την εκτέλεση μιας εφαρμογής προσπαθώντας να κατανοήσει **τι κάνει**.

Επιπλέον, υπάρχουν κάποια αρχεία καταγραφής που θα περιέχουν την ετικέτα `<ιδιωτικό>` για **απόκρυψη** ορισμένων **προσδιορίσιμων** πληροφοριών **χρήστη** ή **υπολογιστή**. Ωστόσο, είναι δυνατόν να **εγκαταστήσετε ένα πιστοποιητικό για την αποκάλυψη αυτών των πληροφοριών**. Ακολουθήστε τις εξηγήσεις από [**εδώ**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Αριστερό πλαίσιο

Στο αριστερό πλαίσιο του hopper είναι δυνατό να δείτε τα σύμβολα (**Ετικέτες**) του δυαδικού, τη λίστα των διαδικασιών και συναρτήσεων (**Διαδικασίες**) και τις συμβολοσειρές (**Συμβολοσειρές**). Αυτές δεν είναι όλες οι συμβολοσειρές αλλά αυτές που έχουν οριστεί σε διάφορα μέρη του αρχείου Mac-O (όπως _cstring ή_ `objc_methname`).

#### Κεντρικό πλαίσιο

Στο κεντρικό πλαίσιο μπορείτε να δείτε το **κωδικό αποσυναρμολόγησης**. Και μπορείτε να το δείτε ως **ακατέργαστο** αποσυναρμολόγηση, ως **γράφημα**, ως **αποδιασυναρμολόγηση** και ως **δυαδικό** κάνοντας κλικ στο αντίστοιχο εικονίδιο:

<figure><img src="../../../.gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

Κάνοντας δεξί κλικ σε ένα αντικείμενο κώδικα μπορείτε να δείτε **αναφορές προς/από αυτό το αντικείμενο** ή ακόμα να αλλάξετε το όνομά του (αυτό δεν λειτουργεί στο αποδιασυναρμολογημένο ψευδοκώδικα):

<figure><img src="../../../.gitbook/assets/image (1117).png" alt=""><figcaption></figcaption></figure>

Επιπλέον, στο **κάτω μέρος μπορείτε να γράψετε εντολές python**.

#### Δεξί πλαίσιο

Στο δεξί πλαίσιο μπορείτε να δείτε ενδιαφέρουσες πληροφορίες όπως το **ιστορικό πλοήγησης** (ώστε να γνωρίζετε πώς φτάσατε στην τρέχουσα κατάσταση), το **γράφημα κλήσεων** όπου μπορείτε να δείτε όλες τις **συναρτήσεις που καλούν αυτή τη συνάρτηση** και όλες τις συναρτήσεις που **αυτή η συνάρτηση καλεί**, και πληροφορίες για τις **τοπικές μεταβλητές**.

### dtrace

Επιτρέπει στους χρήστες πρόσβαση σε εφαρμογές σε ένα εξαιρετικά **χαμηλό επίπεδο** και παρέχει έναν τρόπο στους χρήστες να **καταγράφουν** **προγράμματα** και ακόμα και να αλλάξουν τη ροή εκτέλεσής τους. Το Dtrace χρησιμοποιεί **σημεία παρακολούθησης (probes)** τα οποία τοποθετούνται σε όλο τον πυρήνα και βρίσκονται σε θέσεις όπως η αρχή και το τέλος των κλήσεων συστήματος.

Το DTrace χρησιμοποιεί τη λειτουργία **`dtrace_probe_create`** για να δημιουργήσει ένα σημείο παρακολούθησης για κάθε κλήση συστήματος. Αυτά τα σημεία παρακολούθησης μπορούν να ενεργοποιηθούν στο σημείο εισόδου και εξόδου κάθε κλήσης συστήματος. Η αλληλεπίδραση με το DTrace γίνεται μέσω του /dev/dtrace το οποίο είναι διαθέσιμο μόνο για το ριζοχρήστη.

{% hint style="success" %}
Για να ενεργοποιήσετε το Dtrace χωρίς να απενεργοποιήσετε πλήρως την προστασία SIP μπορείτε να εκτελέσετε σε λειτουργία ανάκαμψης: `csrutil enable --without dtrace`

Μπορείτε επίσης να **`dtrace`** ή **`dtruss`** δυαδικά που **έχετε συντάξει**.
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Το όνομα της έρευνας αποτελείται από τέσσερα μέρη: ο πάροχος, το module, η λειτουργία και το όνομα (`fbt:mach_kernel:ptrace:entry`). Εάν δεν καθορίσετε κάποιο μέρος του ονόματος, το Dtrace θα το εφαρμόσει ως μπαλαντέρ.

Για να ρυθμίσετε το DTrace για την ενεργοποίηση των ερευνών και για να καθορίσετε ποιες ενέργειες να εκτελεστούν όταν εκτοξεύονται, θα πρέπει να χρησιμοποιήσετε τη γλώσσα D.

Μια πιο λεπτομερής εξήγηση και περισσότερα παραδείγματα μπορούν να βρεθούν στο [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Παραδείγματα

Εκτελέστε `man -k dtrace` για να εμφανιστούν τα **διαθέσιμα scripts του DTrace**. Παράδειγμα: `sudo dtruss -n binary`

* Σειρά
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* σενάριο
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

Πρόκειται για ένα εργαλείο καταγραφής πυρήνα. Οι τεκμηριωμένοι κωδικοί μπορούν να βρεθούν στο **`/usr/share/misc/trace.codes`**.

Εργαλεία όπως `latency`, `sc_usage`, `fs_usage` και `trace` το χρησιμοποιούν εσωτερικά.

Για να αλληλεπιδράσετε με το `kdebug` χρησιμοποιείται το `sysctl` μέσω του namespace `kern.kdebug` και οι MIBs που πρέπει να χρησιμοποιηθούν μπορούν να βρεθούν στο `sys/sysctl.h` με τις λειτουργίες που υλοποιούνται στο `bsd/kern/kdebug.c`.

Για να αλληλεπιδράσετε με το kdebug με έναν προσαρμοσμένο πελάτη, συνήθως ακολουθούν αυτά τα βήματα:

* Αφαιρέστε τις υπάρχουσες ρυθμίσεις με το KERN\_KDSETREMOVE
* Ορίστε το ίχνος με το KERN\_KDSETBUF και το KERN\_KDSETUP
* Χρησιμοποιήστε το KERN\_KDGETBUF για να λάβετε τον αριθμό των καταχωρήσεων στο buffer
* Βρείτε τον δικό σας πελάτη από το ίχνος με το KERN\_KDPINDEX
* Ενεργοποιήστε την καταγραφή με το KERN\_KDENABLE
* Διαβάστε το buffer καλώντας το KERN\_KDREADTR
* Για να ταιριάξετε κάθε νήμα με τη διεργασία του καλέστε το KERN\_KDTHRMAP.

Για να λάβετε αυτές τις πληροφορίες είναι δυνατόν να χρησιμοποιήσετε το εργαλείο της Apple **`trace`** ή το προσαρμοσμένο εργαλείο [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Σημειώστε ότι το Kdebug είναι διαθέσιμο μόνο για 1 πελάτη τη φορά.** Έτσι, μόνο ένα εργαλείο που χρησιμοποιεί το k-debug μπορεί να εκτελεστεί ταυτόχρονα.

### ktrace

Οι `ktrace_*` APIs προέρχονται από το `libktrace.dylib` το οποίο τυλίγει αυτά του `Kdebug`. Έτσι, ένας πελάτης μπορεί απλά να καλέσει τις `ktrace_session_create` και `ktrace_events_[single/class]` για να ορίσει κλήσεις επιστροφής σε συγκεκριμένους κωδικούς και στη συνέχεια να το ξεκινήσει με το `ktrace_start`.

Μπορείτε να χρησιμοποιήσετε αυτό ακόμα και με το **SIP ενεργοποιημένο**

Μπορείτε να χρησιμοποιήσετε ως πελάτες το εργαλείο `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ή `tailspin`.

### kperf

Χρησιμοποιείται για προφίλινγκ σε επίπεδο πυρήνα και κατασκευάζεται χρησιμοποιώντας κλήσεις `Kdebug`.

Βασικά, ελέγχεται η καθολική μεταβλητή `kernel_debug_active` και αν είναι ορισμένη καλεί την `kperf_kdebug_handler` με τον κώδικα `Kdebug` και τη διεύθυνση του πυρήνα που καλεί. Αν ο κώδικας `Kdebug` ταιριάζει με έναν επιλεγμένο, αποκτά τις "ενέργειες" που έχουν διαμορφωθεί ως bitmap (ελέγξτε τις επιλογές στο `osfmk/kperf/action.h`).

Το Kperf έχει επίσης έναν πίνακα MIB sysctl: (ως ριζικός χρήστης) `sysctl kperf`. Αυτός ο κώδικας μπορεί να βρεθεί στο `osfmk/kperf/kperfbsd.c`.

Επιπλέον, ένα υποσύνολο της λειτουργικότητας του Kperf βρίσκεται στο `kpc`, το οποίο παρέχει πληροφορίες σχετικά με τους μετρητές απόδοσης της μηχανής.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) είναι ένα πολύ χρήσιμο εργαλείο για να ελέγξετε τις ενέργειες που σχετίζονται με τις διεργασίες που εκτελεί μια διεργασία (για παράδειγμα, να παρακολουθείτε ποιες νέες διεργασίες δημιουργεί μια διεργασία).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) είναι ένα εργαλείο που εκτυπώνει τις σχέσεις μεταξύ των διεργασιών.\
Χρειάζεται να παρακολουθείτε το Mac σας με έναν εντολή όπως **`sudo eslogger fork exec rename create > cap.json`** (η τερματική που εκκινεί αυτό απαιτεί FDA). Και στη συνέχεια μπορείτε να φορτώσετε το json σε αυτό το εργαλείο για να δείτε όλες τις σχέσεις:

<figure><img src="../../../.gitbook/assets/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) επιτρέπει την παρακολούθηση γεγονότων αρχείων (όπως δημιουργία, τροποποιήσεις και διαγραφές) παρέχοντας λεπτομερείς πληροφορίες για τέτοια γεγονότα.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) είναι ένα εργαλείο GUI με την εμφάνιση και την αίσθηση που οι χρήστες των Windows μπορεί να γνωρίζουν από το _Procmon_ της Microsoft Sysinternal. Αυτό το εργαλείο επιτρέπει την εγγραφή διαφόρων τύπων γεγονότων να ξεκινήσει και να σταματήσει, επιτρέπει το φιλτράρισμα αυτών των γεγονότων ανά κατηγορίες όπως αρχείο, διεργασία, δίκτυο κ.λπ., και παρέχει τη δυνατότητα να αποθηκεύσει τα καταγεγραμμένα γεγονότα σε μορφή json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) είναι μέρος των εργαλείων Ανάπτυξης του Xcode - χρησιμοποιούνται για την παρακολούθηση της απόδοσης εφαρμογών, την εντοπισμό διαρροών μνήμης και την παρακολούθηση της δραστηριότητας του συστήματος αρχείων.

![](<../../../.gitbook/assets/image (1138).png>)

### fs\_usage

Επιτρέπει να παρακολουθείτε τις ενέργειες που εκτελούνται από διεργασίες:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Το Taskexplorer**](https://objective-see.com/products/taskexplorer.html) είναι χρήσιμο για να δείτε τις **βιβλιοθήκες** που χρησιμοποιεί ένα δυαδικό αρχείο, τα **αρχεία** που χρησιμοποιεί και τις **δικτυακές** συνδέσεις.\
Επίσης ελέγχει τις διεργασίες του δυαδικού αρχείου εναντίον του **virustotal** και εμφανίζει πληροφορίες σχετικά με το δυαδικό αρχείο.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Σε [**αυτή την ανάρτηση στο blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) μπορείτε να βρείτε ένα παράδειγμα σχετικά με το πώς να **εκτελέσετε αποσφαλμάτωση σε έναν τρέχοντα daemon** που χρησιμοποιεί το **`PT_DENY_ATTACH`** για να αποτρέψει την αποσφαλμάτωση ακόμα κι αν το SIP ήταν απενεργοποιημένο.

### lldb

Το **lldb** είναι το εργαλείο **de facto** για την **αποσφαλμάτωση** δυαδικών αρχείων στο **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Μπορείτε να ορίσετε το intel flavor όταν χρησιμοποιείτε το lldb δημιουργώντας ένα αρχείο με το όνομα **`.lldbinit`** στον φάκελο του αρχικού σας χρήστη με την παρακάτω γραμμή:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Μέσα στο lldb, κάντε dump ενός διεργασίας με την εντολή `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Εντολή</strong></td><td><strong>Περιγραφή</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Έναρξη εκτέλεσης, η οποία θα συνεχιστεί μέχρι να εντοπιστεί ένα σημείο διακοπής ή να τερματιστεί η διεργασία.</td></tr><tr><td><strong>continue (c)</strong></td><td>Συνέχιση εκτέλεσης της διαγραφόμενης διεργασίας.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Εκτέλεση της επόμενης εντολής. Αυτή η εντολή θα παραλείψει τις κλήσεις συναρτήσεων.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Εκτέλεση της επόμενης εντολής. Αντίθετα με την εντολή nexti, αυτή η εντολή θα μπει στις κλήσεις συναρτήσεων.</td></tr><tr><td><strong>finish (f)</strong></td><td>Εκτέλεση των υπόλοιπων εντολών στην τρέχουσα συνάρτηση ("frame") επιστροφή και διακοπή.</td></tr><tr><td><strong>control + c</strong></td><td>Παύση εκτέλεσης. Αν η διεργασία έχει τρέξει (r) ή συνεχίσει (c), αυτό θα προκαλέσει τη διακοπή της διεργασίας ...όπου εκτελείται αυτή τη στιγμή.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Οποιαδήποτε συνάρτηση με το όνομα main</p><p>b &#x3C;binname>`main #Κύρια συνάρτηση του αρχείου</p><p>b set -n main --shlib &#x3C;lib_name> #Κύρια συνάρτηση του συγκεκριμένου αρχείου</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Λίστα σημείων διακοπής</p><p>br e/dis &#x3C;num> #Ενεργοποίηση/Απενεργοποίηση σημείου διακοπής</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Λήψη βοήθειας για την εντολή διακοπής</p><p>help memory write #Λήψη βοήθειας για εγγραφή στη μνήμη</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Εμφάνιση της μνήμης ως συμβολοσειρά που τερματίζεται με μηδενικό.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Εμφάνιση της μνήμης ως εντολή συναρμολόγησης.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Εμφάνιση της μνήμης ως byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Αυτό θα εκτυπώσει το αντικείμενο που αναφέρεται από την παράμετρο</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Σημειώστε ότι οι περισσότερες Objective-C APIs ή μέθοδοι της Apple επιστρέφουν αντικείμενα και έτσι θα πρέπει να εμφανίζονται μέσω της εντολής "εκτύπωση αντικειμένου" (po). Αν το po δεν παράγει ένα νόημα χρησιμοποιήστε <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Εγγραφή AAAA σε αυτή τη διεύθυνση<br>memory write -f s $rip+0x11f+7 "AAAA" #Εγγραφή AAAA στη διεύθυνση</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Αποσυναρμολόγηση της τρέχουσας συνάρτησης</p><p>dis -n &#x3C;funcname> #Αποσυναρμολόγηση συνάρτησης</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Αποσυναρμολόγηση συνάρτησης<br>dis -c 6 #Αποσυναρμολόγηση 6 γραμμών<br>dis -c 0x100003764 -e 0x100003768 # Από μια διεύθυνση μέχρι την άλλη<br>dis -p -c 4 # Έναρξη αποσυναρμολόγησης στην τρέχουσα διεύθυνση</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Έλεγχος πίνακα με 3 στοιχεία στο reg x1</td></tr></tbody></table>

{% hint style="info" %}
Κατά την κλήση της συνάρτησης **`objc_sendMsg`**, το register **rsi** κρατά το **όνομα της μεθόδου** ως συμβολοσειρά που τερματίζεται με μηδενικό ("C"). Για να εκτυπώσετε το όνομα μέσω του lldb:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Αντι-Δυναμική Ανάλυση

#### Ανίχνευση Εικονικών Μηχανών

* Η εντολή **`sysctl hw.model`** επιστρέφει "Mac" όταν ο **host είναι MacOS** αλλά κάτι διαφορετικό όταν είναι μια Εικονική Μηχανή.
* Παίζοντας με τις τιμές των **`hw.logicalcpu`** και **`hw.physicalcpu`** κάποια malware προσπαθούν να ανιχνεύσουν αν είναι μια Εικονική Μηχανή.
* Κάποια malware μπορεί επίσης να **ανιχνεύσει** αν η μηχανή είναι βασισμένη σε **VMware** βάσει της διεύθυνσης MAC (00:50:56).
* Είναι επίσης δυνατό να βρεθεί αν μια διεργασία βρίσκεται υπό αποσφαλμάτωση με έναν απλό κώδικα όπως:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //διεργασία υπό αποσφαλμάτωση }`
* Μπορεί επίσης να καλέσει την κλήση συστήματος **`ptrace`** με τη σημαία **`PT_DENY_ATTACH`**. Αυτό **εμποδίζει** έναν αποσφαλματωτή από το να συνδεθεί και να καταγράψει.
* Μπορείτε να ελέγξετε αν η συνάρτηση **`sysctl`** ή **`ptrace`** είναι **εισαγμένη** (αλλά το malware θα μπορούσε να την εισάγει δυναμικά)
* Όπως αναφέρεται σε αυτήν την ανάλυση, “[Νίκη εναντίον Αντι-Ανάλυσης: macOS παραλλαγές ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_Το μήνυμα Η Διεργασία # τερμάτισε με **κατάσταση = 45 (0x0000002d)** είναι συνήθως ένα σημάδι ότι ο στόχος αποσφαλμάτωσης χρησιμοποιεί το **PT\_DENY\_ATTACH**_”
## Core Dumps

Τα core dumps δημιουργούνται αν:

- Το `kern.coredump` sysctl έχει οριστεί σε 1 (από προεπιλογή)
- Αν η διαδικασία δεν ήταν suid/sgid ή το `kern.sugid_coredump` είναι 1 (από προεπιλογή είναι 0)
- Το όριο `AS_CORE` επιτρέπει τη λειτουργία. Είναι δυνατόν να ανασταλεί η δημιουργία core dumps καλώντας `ulimit -c 0` και να επαναφερθεί με `ulimit -c unlimited`.

Σε αυτές τις περιπτώσεις τα core dumps δημιουργούνται σύμφωνα με το `kern.corefile` sysctl και αποθηκεύονται συνήθως στο `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

Το ReportCrash **αναλύει διαδικασίες που καταρρέουν και αποθηκεύει ένα αναφοράς κατάρρευσης στο δίσκο**. Μια αναφορά κατάρρευσης περιέχει πληροφορίες που μπορούν **να βοηθήσουν έναν προγραμματιστή να διαγνώσει** τον λόγο της κατάρρευσης.\
Για εφαρμογές και άλλες διαδικασίες **που εκτελούνται στο πλαίσιο εκκίνησης ανά χρήστη**, το ReportCrash εκτελείται ως LaunchAgent και αποθηκεύει τις αναφορές κατάρρευσης στον φάκελο `~/Library/Logs/DiagnosticReports/` του χρήστη\
Για daemons, άλλες διαδικασίες **που εκτελούνται στο πλαίσιο εκκίνησης του συστήματος** και άλλες προνομιούχες διαδικασίες, το ReportCrash εκτελείται ως LaunchDaemon και αποθηκεύει τις αναφορές κατάρρευσης στον φάκελο `/Library/Logs/DiagnosticReports` του συστήματος

Αν ανησυχείτε για το γεγονός ότι οι αναφορές κατάρρευσης **στέλνονται στην Apple** μπορείτε να τις απενεργοποιήσετε. Διαφορετικά, οι αναφορές κατάρρευσης μπορούν να είναι χρήσιμες για **να καταλάβετε πώς κατέρρευσε ένας διακομιστής**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Υπνος

Κατά την εκτέλεση fuzzing σε ένα MacOS είναι σημαντικό να μην επιτραπεί στο Mac να μπει σε κατάσταση ύπνου:

* systemsetup -setsleep Never
* pmset, System Preferences
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Διακοπή SSH

Εάν εκτελείτε fuzzing μέσω μιας σύνδεσης SSH, είναι σημαντικό να βεβαιωθείτε ότι η συνεδρία δεν θα λήξει. Επομένως, αλλάξτε το αρχείο sshd\_config με:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Εσωτερικοί Χειριστές

**Ελέγξτε την ακόλουθη σελίδα** για να μάθετε πώς μπορείτε να βρείτε ποια εφαρμογή είναι υπεύθυνη για την **χειρισμό του συγκεκριμένου σχήματος ή πρωτοκόλλου:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Απαρίθμηση Δικτυακών Διεργασιών

Αυτό είναι ενδιαφέρον για να βρείτε διεργασίες που διαχειρίζονται δεδομένα δικτύου:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Ή χρησιμοποιήστε το `netstat` ή το `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Λειτουργεί για εργαλεία γραμμής εντολών

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Λειτουργεί με εργαλεία γραφικού περιβάλλοντος του macOS. Σημειώστε ότι μερικές εφαρμογές macOS έχουν συγκεκριμένες απαιτήσεις όπως μοναδικά ονόματα αρχείων, τη σωστή επέκταση, ανάγκη ανάγνωσης αρχείων από το χώρο ασφαλείας (`~/Library/Containers/com.apple.Safari/Data`)...

Μερικά παραδείγματα:

{% code overflow="wrap" %}
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
{% endcode %}

### Περισσότερες Πληροφορίες Fuzzing MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Αναφορές

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο βασικός στόχος του WhiteIntel είναι η καταπολέμηση των ληστειών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
