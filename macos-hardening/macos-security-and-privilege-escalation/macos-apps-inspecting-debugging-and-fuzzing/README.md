# macOS Apps - Επιθεώρηση, αποσφαλμάτωση και Fuzzing

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Στατική Ανάλυση

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

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

### jtool2

Το εργαλείο μπορεί να χρησιμοποιηθεί ως **αντικατάσταση** για τα **codesign**, **otool** και **objdump**, και παρέχει μερικές επιπλέον λειτουργίες. [**Κατεβάστε το εδώ**](http://www.newosxbook.com/tools/jtool.html) ή εγκαταστήστε το με την εντολή `brew`.
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
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** μπορεί να βρεθεί στο **macOS** ενώ **`ldid`** μπορεί να βρεθεί στο **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) είναι ένα εργαλείο που χρησιμοποιείται για να επιθεωρήσετε αρχεία **.pkg** (εγκαταστάτες) και να δείτε τι περιέχουν πριν την εγκατάστασή τους.\
Αυτοί οι εγκαταστάτες έχουν `preinstall` και `postinstall` bash scripts που οι δημιουργοί κακόβουλου λογισμικού συνήθως καταχρώνται για να **διατηρήσουν** το **κακόβουλο** λογισμικό.

### hdiutil

Αυτό το εργαλείο επιτρέπει την **προσάρτηση** αρχείων Apple disk images (**.dmg**) για να τα επιθεωρήσετε πριν εκτελέσετε οτιδήποτε:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Θα τοποθετηθεί στο `/Volumes`

### Objective-C

#### Μεταδεδομένα

{% hint style="danger" %}
Σημειώστε ότι τα προγράμματα που έχουν γραφτεί σε Objective-C **διατηρούν** τις δηλώσεις των κλάσεών τους **όταν** **μεταγλωττίζονται** σε [Mach-O δυαδικά αρχεία](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Αυτές οι δηλώσεις κλάσης περιλαμβάνουν το όνομα και τον τύπο των:
{% endhint %}

* Η κλάση
* Οι μέθοδοι της κλάσης
* Οι μεταβλητές περιπτώσεων της κλάσης

Μπορείτε να αποκτήσετε αυτές τις πληροφορίες χρησιμοποιώντας το [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
Σημείωση ότι αυτά τα ονόματα μπορεί να είναι κρυπτογραφημένα για να δυσκολέψει την αντιστροφή του δυαδικού αρχείου.

#### Κλήση συνάρτησης

Όταν μια συνάρτηση καλείται σε ένα δυαδικό αρχείο που χρησιμοποιεί Objective-C, ο μεταγλωττισμένος κώδικας αντί να καλέσει αυτήν τη συνάρτηση, θα καλέσει τη **`objc_msgSend`**. Αυτή θα καλέσει την τελική συνάρτηση:

![](<../../../.gitbook/assets/image (560).png>)

Τα ορίσματα που αναμένει αυτή η συνάρτηση είναι:

* Το πρώτο όρισμα (**self**) είναι "ένας δείκτης που δείχνει στη **έκδοση της κλάσης που θα λάβει το μήνυμα**". Ή απλούστερα, είναι το αντικείμενο στο οποίο καλείται η μέθοδος. Εάν η μέθοδος είναι μια μέθοδος κλάσης, αυτό θα είναι ένα αντικείμενο της κλάσης (συνολικά), ενώ για μια μέθοδο παραδείγματος, το self θα δείχνει σε ένα ενσωματωμένο παράδειγμα της κλάσης ως αντικείμενο.
* Το δεύτερο όρισμα (**op**) είναι "ο επιλογέας της μεθόδου που χειρίζεται το μήνυμα". Και πάλι, απλούστερα, αυτό είναι απλά το **όνομα της μεθόδου**.
* Τα υπόλοιπα ορίσματα είναι οποιεσδήποτε **τιμές που απαιτούνται από τη μέθοδο** (op).

| **Όρισμα**         | **Καταχώρηση**                                                 | **(για) objc\_msgSend**                              |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1ο όρισμα**     | **rdi**                                                         | **self: αντικείμενο στο οποίο καλείται η μέθοδος** |
| **2ο όρισμα**     | **rsi**                                                         | **op: όνομα της μεθόδου**                            |
| **3ο όρισμα**     | **rdx**                                                         | **1ο όρισμα της μεθόδου**                            |
| **4ο όρισμα**     | **rcx**                                                         | **2ο όρισμα της μεθόδου**                            |
| **5ο όρισμα**     | **r8**                                                          | **3ο όρισμα της μεθόδου**                            |
| **6ο όρισμα**     | **r9**                                                          | **4ο όρισμα της μεθόδου**                            |
| **7ο+ όρισμα**    | <p><strong>rsp+</strong><br><strong>(στη στοίβα)</strong></p> | **5ο+ όρισμα της μεθόδου**                           |

### Swift

Με δυαδικά αρχεία Swift, αφού υπάρχει συμβατότητα με Objective-C, μερικές φορές μπορείτε να εξάγετε δηλώσεις χρησιμοποιώντας το [class-dump](https://github.com/nygard/class-dump/), αλλά όχι πάντα.

Με τις εντολές γραμμής **`jtool -l`** ή **`otool -l`** είναι δυνατό να βρείτε αρκετές ενότητες που ξεκινούν με το πρόθεμα **`__swift5`**:
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
Μπορείτε να βρείτε περαιτέρω πληροφορίες σχετικά με τις [**πληροφορίες που αποθηκεύονται σε αυτές τις ενότητες σε αυτήν την ανάρτηση στο blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Επιπλέον, **οι δυαδικοί αρχείοι Swift μπορεί να έχουν σύμβολα** (για παράδειγμα, οι βιβλιοθήκες χρειάζονται να αποθηκεύουν σύμβολα ώστε να μπορούν να καλούνται οι λειτουργίες τους). Τα **σύμβολα συνήθως περιέχουν πληροφορίες σχετικά με το όνομα της συνάρτησης** και τα χαρακτηριστικά της με έναν ασυνάρτητο τρόπο, για αυτό είναι πολύ χρήσιμα και υπάρχουν "**αποκωδικοποιητές"** που μπορούν να ανακτήσουν το αρχικό όνομα:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Συμπιεσμένα δυαδικά αρχεία

* Ελέγξτε την υψηλή εντροπία
* Ελέγξτε τις συμβολοσειρές (αν υπάρχει σχεδόν καμία κατανοητή συμβολοσειρά, τότε είναι συμπιεσμένο)
* Ο συμπιεστής UPX για MacOS δημιουργεί μια ενότητα με το όνομα "\_\_XHDR"

## Δυναμική Ανάλυση

{% hint style="warning" %}
Σημειώστε ότι για να αποσφραγίσετε δυαδικά αρχεία, πρέπει να απενεργοποιήσετε το SIP (`csrutil disable` ή `csrutil enable --without debug`) ή να αντιγράψετε τα δυαδικά αρχεία σε έναν προσωρινό φάκελο και να αφαιρέσετε την υπογραφή με την εντολή `codesign --remove-signature <διαδρομή-δυαδικού>` ή να επιτρέψετε την αποσφράγιση του δυαδικού για αποσφράγιση (μπορείτε να χρησιμοποιήσετε [αυτό το σενάριο](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Σημειώστε ότι για να **εργαλειοθετήσετε συστημικά δυαδικά αρχεία** (όπως το `cloudconfigurationd`) στο macOS, πρέπει να απενεργοποιήσετε το SIP (απλή αφαίρεση της υπογραφής δεν λειτουργεί).
{% endhint %}

### Ενοποιημένα Αρχεία Καταγραφής

Το MacOS δημιουργεί πολλά αρχεία καταγραφής που μπορούν να είναι πολύ χρήσιμα κατά την εκτέλεση μιας εφαρμογής προσπαθώντας να κατανοήσει **τι κάνει**.

Επιπλέον, υπάρχουν ορισμένα αρχεία καταγραφής που θα περιέχουν την ετικέτα `<private>` για να **αποκρύψουν** ορισμένες πληροφορίες που μπορούν να αναγνωριστούν από τον **χρήστη** ή τον **υπολογιστή**. Ωστόσο, είναι δυνατόν να **εγκαταστήσετε ένα πιστοποιητικό για την αποκάλυψη αυτών των πληροφοριών**. Ακολουθήστε τις εξηγήσεις από [**εδώ**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Αριστερό πλαίσιο

Στο αριστερό πλαίσιο του hopper είναι δυνατόν να δείτε τα σύμβολα (**Ετικέτες**) του δυαδικού, τη λίστα των διαδικασιών και συναρτήσεων (**Proc**) και τις συμβολοσειρές (**Str**). Αυτές δεν είναι όλες οι συμβολοσειρές, αλλά αυτές που έχουν καθοριστεί σε διάφορα μέρη του αρχείου Mac-O (όπως _cstring ή_ `objc_methname`).

#### Κεντρικό πλαίσιο

Στο κεντρικό πλαίσιο μπορείτε να δείτε τον **αποσυναρμολογημένο κώδικα**. Και μπορείτε να τον δείτε ως **απλό** αποσυναρμολόγηση, ως **γράφο**, ως **αποδιασταλμένο** και ως **δυαδικό** κάνοντας κλικ στο αντίστοιχο εικονίδιο:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Κάνοντας δεξί κλικ σε ένα αντικείμενο κώδικα, μπορείτε να δείτε τις **αναφορές προς/από αυτό το αντικείμενο** ή ακόμα και να αλλάξετε το όνομά του (αυτό δεν λειτουργεί στον αποδιασταλμένο ψευδοκώδικα):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Επιπλέον, στο **κάτω μέρος του κεντρικού πλαισίου μπορείτε να γράψετε εντολές python**.

#### Δεξί πλαίσιο

Στο δεξί πλαίσιο μπορείτε να δείτε ενδιαφέρουσες πληροφορίες, όπως το **ιστορικό πλοήγησης** (ώστε να γνωρίζετε πώς φτάσατε στην τρέχουσα κατάσταση), τον **γράφο κλήσεων** όπου μπορείτε να δείτε όλες τις **συναρτήσεις που καλούν αυτήν τη συνάρτηση** και όλες τις συναρτήσεις που **αυτή η συνάρτηση καλεί**, και πληροφορίες για τις **τοπικές μεταβλητές**.

### dtrace

Επιτρέπει στους χρήστες να έχουν πρόσβαση σε εφαρμογές σε έναν ακραία **χαμηλό επίπεδο** και παρέχει έναν τρόπο για τους χρήστες να **καταγράφουν** προγράμματα και ακόμα και να αλλάξουν τη ροή εκτέλεσής τους. Το Dtrace χρησιμοποιεί **σημεία παρακολούθησης** που τοποθετούνται σε όλο τον πυρήνα και βρίσκονται σε θέσεις όπως η αρχή και το τέλος των συστημικών κλήσεων.

Το DTrace χρησιμοποιεί τη συνάρτηση **`dtrace_probe_create`** για να δημιουργήσει ένα σημείο παρακολούθησης για κάθε συστημική κλήση. Αυτά τα σημεία παρακολούθησης μπορούν να ενεργοποιηθούν στο σημείο εισόδου και εξόδου κάθε συστημικής κλήσης. Η αλληλεπίδραση με το DTrace γίνεται μέσω του /dev/dtrace που είναι διαθέσιμο μόνο για τον ριζικό χρήστη.

{% hint style="success" %}
Για να ενεργοποιήσετε το Dtrace χωρίς να απενεργοποιήσετε πλήρως την προστασία SIP, μπορείτε να εκτελέσετε στη λειτουργία ανάκτησης: `csrutil enable --without dtrace`

Μπορείτε επίσης να **εργαλειοθετήσετε** τα δυαδικά **`dtrace`** ή **`dtruss`** που **έχετε συντάξει**.
{% endhint %}

Οι διαθέσιμοι σημείοι παρακολούθησης του dtrace μπορ
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Το όνομα του αισθητήρα αποτελείται από τέσσερα μέρη: τον πάροχο, τον ενότητα, τη λειτουργία και το όνομα (`fbt:mach_kernel:ptrace:entry`). Εάν δεν καθορίσετε κάποιο μέρος του ονόματος, το Dtrace θα το εφαρμόσει ως μπαλαντέρ.

Για να ρυθμίσετε το DTrace για να ενεργοποιήσετε τους αισθητήρες και να καθορίσετε ποιες ενέργειες να εκτελεστούν όταν ενεργοποιηθούν, θα χρειαστεί να χρησιμοποιήσετε τη γλώσσα D.

Μια πιο λεπτομερής εξήγηση και περισσότερα παραδείγματα μπορούν να βρεθούν στο [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Παραδείγματα

Εκτελέστε `man -k dtrace` για να εμφανιστούν οι **διαθέσιμες εντολές DTrace**. Παράδειγμα: `sudo dtruss -n binary`

* Στη γραμμή
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

The `dtruss` command is a powerful tool for inspecting and debugging macOS applications. It allows you to trace system calls and signals made by a specific process, providing valuable insights into its behavior and potential vulnerabilities.

To use `dtruss`, simply run the command followed by the name or process ID of the target application. This will initiate the tracing process and display a detailed log of all system calls and signals generated by the application.

By analyzing the `dtruss` output, you can identify any suspicious or unexpected behavior that may indicate a security issue. This can include unauthorized file access, network communication, or privilege escalation attempts.

Additionally, `dtruss` can be used to monitor the performance of an application by tracking its system call activity. This can help identify bottlenecks or inefficiencies that may impact the overall performance of the application.

Overall, `dtruss` is a valuable tool for inspecting, debugging, and fuzzing macOS applications. It provides a comprehensive view of the system calls and signals generated by an application, allowing you to identify potential security vulnerabilities and performance issues.
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Μπορείτε να χρησιμοποιήσετε αυτό ακόμη και με το **SIP ενεργοποιημένο**.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) είναι ένα πολύ χρήσιμο εργαλείο για να ελέγξετε τις ενέργειες που σχετίζονται με τη διεργασία που εκτελείται (για παράδειγμα, να παρακολουθείτε ποιες νέες διεργασίες δημιουργεί μια διεργασία).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) είναι ένα εργαλείο που εκτυπώνει τις σχέσεις μεταξύ των διεργασιών.\
Πρέπει να παρακολουθείτε το Mac σας με έναν εντολή όπως **`sudo eslogger fork exec rename create > cap.json`** (η τερματική που εκτελεί αυτή την εντολή απαιτεί FDA). Και στη συνέχεια μπορείτε να φορτώσετε το json σε αυτό το εργαλείο για να δείτε όλες τις σχέσεις:

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) επιτρέπει την παρακολούθηση γεγονότων αρχείων (όπως δημιουργία, τροποποίηση και διαγραφή) παρέχοντας λεπτομερείς πληροφορίες για τέτοια γεγονότα.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) είναι ένα εργαλείο γραφικού περιβάλλοντος με την εμφάνιση και την αίσθηση που οι χρήστες των Windows μπορεί να γνωρίζουν από το _Procmon_ της Microsoft Sysinternal. Αυτό το εργαλείο επιτρέπει την εγγραφή διάφορων τύπων γεγονότων για να ξεκινήσετε και να σταματήσετε, επιτρέπει το φιλτράρισμα αυτών των γεγονότων ανά κατηγορίες όπως αρχείο, διεργασία, δίκτυο κ.λπ. και παρέχει τη δυνατότητα να αποθηκεύσετε τα καταγεγραμμένα γεγονότα σε μορφή json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) είναι μέρος των εργαλείων προγραμματιστή Xcode - χρησιμοποιούνται για την παρακολούθηση της απόδοσης των εφαρμογών, την εντοπισμό διαρροών μνήμης και την παρακολούθηση της δραστηριότητας του αρχείου συστήματος αρχείων.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Επιτρέπει να ακολουθήσετε τις ενέργειες που πραγματοποιούνται από διεργασίες:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) είναι χρήσιμο για να δείτε τις **βιβλιοθήκες** που χρησιμοποιεί ένα δυαδικό αρχείο, τα **αρχεία** που χρησιμοποιεί και τις **δικτυακές** συνδέσεις.\
Επίσης, ελέγχει τις διεργασίες του δυαδικού αρχείου έναντι του **virustotal** και εμφανίζει πληροφορίες για το δυαδικό αρχείο.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

Σε [**αυτήν την ανάρτηση στο blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) μπορείτε να βρείτε ένα παράδειγμα για το πώς να **αποσφαλματώσετε έναν τρέχοντα daemon** που χρησιμοποιεί το **`PT_DENY_ATTACH`** για να αποτρέψει τον αποσφαλματωτή ακόμα κι αν το SIP είναι απενεργοποιημένο.

### lldb

Το **lldb** είναι το εργαλείο **de facto** για το **αποσφαλμάτωση** δυαδικών αρχείων στο **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Μπορείτε να ορίσετε την εκδοχή intel όταν χρησιμοποιείτε το lldb δημιουργώντας ένα αρχείο με το όνομα **`.lldbinit`** στον φάκελο του αρχικού σας καταλόγου με την παρακάτω γραμμή:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Μέσα στο lldb, κάντε dump ενός διεργασίας με την εντολή `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Εντολή</strong></td><td><strong>Περιγραφή</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Έναρξη εκτέλεσης, η οποία θα συνεχιστεί μέχρι να εντοπιστεί ένα breakpoint ή να τερματίσει η διεργασία.</td></tr><tr><td><strong>continue (c)</strong></td><td>Συνέχιση εκτέλεσης της αποσφαλμάτωσης της διεργασίας.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Εκτέλεση της επόμενης εντολής. Αυτή η εντολή θα παραλείψει τις κλήσεις συνάρτησης.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Εκτέλεση της επόμενης εντολής. Αντίθετα με την εντολή nexti, αυτή η εντολή θα μπει στις κλήσεις συνάρτησης.</td></tr><tr><td><strong>finish (f)</strong></td><td>Εκτέλεση των υπόλοιπων εντολών στην τρέχουσα συνάρτηση ("frame") και διακοπή.</td></tr><tr><td><strong>control + c</strong></td><td>Παύση της εκτέλεσης. Αν η διεργασία έχει εκτελεστεί (r) ή συνεχίσει (c), αυτό θα οδηγήσει τη διεργασία να σταματήσει... όπου κι αν εκτελείται αυτή τη στιγμή.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Οποιαδήποτε συνάρτηση με όνομα main</p><p>b &#x3C;binname>`main #Κύρια συνάρτηση του αρχείου</p><p>b set -n main --shlib &#x3C;lib_name> #Κύρια συνάρτηση του καθορισμένου αρχείου</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Λίστα των breakpoints</p><p>br e/dis &#x3C;num> #Ενεργοποίηση/Απενεργοποίηση breakpoint</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Λήψη βοήθειας για την εντολή breakpoint</p><p>help memory write #Λήψη βοήθειας για την εγγραφή στη μνήμη</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/memory address></strong></td><td>Εμφάνιση της μνήμης ως αλφαριθμητικό που τερματίζεται με μηδενικό χαρακτήρα.</td></tr><tr><td><strong>x/i &#x3C;reg/memory address></strong></td><td>Εμφάνιση της μνήμης ως εντολή συναρτήσεων.</td></tr><tr><td><strong>x/b &#x3C;reg/memory address></strong></td><td>Εμφάνιση της μνήμης ως byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Αυτό θα εκτυπώσει το αντικείμενο που αναφέρεται από την παράμετρο</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Σημειώστε ότι οι περισσότερες από τις Objective-C APIs ή μεθόδους της Apple επιστρέφουν αντικείμενα και θα πρέπει να εμφανίζονται μέσω της εντολής "print object" (po). Εάν το po δεν παράγει ένα νόημα, χρησιμοποιήστε το <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Εγγραφή AAAA σε αυτήν τη διεύθυνση<br>memory write -f s $rip+0x11f+7 "AAAA" #Εγγραφή AAAA στη διεύθυνση</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Αποσυναρμολόγηση της τρέχουσας συνάρτησης</p><p>dis -n &#x3C;funcname> #Αποσυναρμολόγηση συνάρτησης</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Αποσυναρμολόγηση συνάρτησης<br>dis -c 6 #Αποσυναρμολόγηση 6 γραμμών<br>dis -c 0x100003764 -e 0x100003768 #Από μια διεύθυνση μέχρι την άλλη<br>dis -p -c 4 #Έναρξη αποσυναρμολόγησης από την τρέχουσα διεύθυνση</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 #Έλεγχος πίνακα 3 στοιχείων στον καταχωρητή x1</td></tr></tbody></table>

{% hint style="info" %}
Όταν καλείται η συνάρτηση **`objc_sendMsg`**, ο καταχωρητής **rsi** κρατά το **όνομα της μεθόδου
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

Το ReportCrash **αναλύει τις διεργασίες που καταρρέουν και αποθηκεύει ένα αναφορικό αρχείο κατάρρευσης στο δίσκο**. Ένα αναφορικό αρχείο κατάρρευσης περιέχει πληροφορίες που μπορούν **να βοηθήσουν έναν προγραμματιστή να διαγνώσει** τον ακριβή λόγο της κατάρρευσης.\
Για εφαρμογές και άλλες διεργασίες **που εκτελούνται στο πλαίσιο εκκίνησης ανά χρήστη**, το ReportCrash εκτελείται ως LaunchAgent και αποθηκεύει τα αναφορικά αρχεία κατάρρευσης στον φάκελο `~/Library/Logs/DiagnosticReports/` του χρήστη.\
Για δαίμονες, άλλες διεργασίες **που εκτελούνται στο πλαίσιο εκκίνησης του συστήματος** και άλλες προνομιούχες διεργασίες, το ReportCrash εκτελείται ως LaunchDaemon και αποθηκεύει τα αναφορικά αρχεία κατάρρευσης στον φάκελο `/Library/Logs/DiagnosticReports` του συστήματος.

Εάν ανησυχείτε για την αποστολή των αναφορικών αρχείων κατάρρευσης **στην Apple**, μπορείτε να τα απενεργοποιήσετε. Διαφορετικά, τα αναφορικά αρχεία κατάρρευσης μπορούν να είναι χρήσιμα για **να κατανοήσετε πώς κατέρρευσε ένας διακομιστής**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Αναστολή

Κατά τη διάρκεια του fuzzing σε ένα MacOS, είναι σημαντικό να μην επιτρέπετε στο Mac να μπει σε κατάσταση αναστολής:

* systemsetup -setsleep Never
* pmset, Προτιμήσεις Συστήματος
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Διακοπή SSH

Εάν κάνετε fuzzing μέσω μιας σύνδεσης SSH, είναι σημαντικό να βεβαιωθείτε ότι η συνεδρία δεν θα λήξει. Έτσι, αλλάξτε το αρχείο sshd\_config με τα παρακάτω:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Εσωτερικοί χειριστές

**Ελέγξτε την παρακάτω σελίδα** για να μάθετε πώς μπορείτε να βρείτε ποια εφαρμογή είναι υπεύθυνη για την **χειρισμό ενός συγκεκριμένου σχήματος ή πρωτοκόλλου:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Απαρίθμηση διεργασιών δικτύου

Αυτό είναι ενδιαφέρον για να βρείτε διεργασίες που διαχειρίζονται δεδομένα δικτύου:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
Ή χρησιμοποιήστε την εντολή `netstat` ή `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Λειτουργεί για εργαλεία γραμμής εντολών (CLI tools)

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Λειτουργεί "**απλά"** με εργαλεία γραφικού περιβάλλοντος (GUI tools) του macOS. Σημειώστε ότι ορισμένες εφαρμογές του macOS έχουν ορισμένες συγκεκριμένες απαιτήσεις, όπως μοναδικά ονόματα αρχείων, τη σωστή επέκταση, ανάγκη να διαβάζουν τα αρχεία από το sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Ορισμένα παραδείγματα:

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

### Περισσότερες πληροφορίες για το Fuzzing στο MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Αναφορές

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
