# macOS Kernel & System Extensions

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πυρήνας XNU

Η **καρδιά του macOS είναι ο XNU**, που σημαίνει "X is Not Unix". Αυτός ο πυρήνας αποτελείται θεμελιωτικά από τον **μικροπυρήνα Mach** (που θα συζητηθεί αργότερα), **και** στοιχεία από τη Διανομή Λογισμικού Berkeley (**BSD**). Ο XNU παρέχει επίσης μια πλατφόρμα για **οδηγούς πυρήνα μέσω ενός συστήματος που ονομάζεται I/O Kit**. Ο πυρήνας XNU είναι μέρος του ανοικτού κώδικα του έργου Darwin, που σημαίνει ότι **ο κώδικάς του είναι ελεύθερα προσβάσιμος**.

Από την άποψη ενός ερευνητή ασφάλειας ή ενός προγραμματιστή Unix, το **macOS** μπορεί να φανεί αρκετά **παρόμοιο** με ένα σύστημα **FreeBSD** με μια κομψή γραφική διεπαφή και μια σειρά προσαρμοσμένων εφαρμογών. Οι περισσότερες εφαρμογές που αναπτύσσονται για το BSD θα μεταγλωττιστούν και θα τρέξουν στο macOS χωρίς την ανάγκη τροποποιήσεων, καθώς τα εργαλεία γραμμής εντολών που είναι γνωστά στους χρήστες Unix είναι όλα παρόντα στο macOS. Ωστόσο, επειδή ο πυρήνας XNU ενσωματώνει το Mach, υπάρχουν ορισμένες σημαντικές διαφορές μεταξύ ενός παραδοσιακού συστήματος παρόμοιου με Unix και του macOS, και αυτές οι διαφορές μπορεί να προκαλέσουν προβλήματα ή να παρέχουν μοναδικά πλεονεκτήματα.

Ανοικτή έκδοση του XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Το Mach είναι ένας **μικροπυρήνας** σχεδιασμένος να είναι **συμβατός με το UNIX**. Ένας από τους βασικούς σχεδιαστικούς του αρχές ήταν να **ελαχιστοποιήσει** το ποσοστό του **κώδικα** που τρέχει στον **χώρο του πυρήνα** και αντ' αυτού να επιτρέψει σε πολλές τυπικές λειτουργίες πυρήνα, όπως σύστημα αρχείων, δικτύωση και I/O, να **τρέχουν ως εργασίες σε επίπεδο χρήστη**.

Στο XNU, το Mach είναι **υπεύθυνο για πολλές από τις κρίσιμες λειτουργίες χαμηλού επιπέδου** που ένας πυρήνας χειρίζεται τυπικά, όπως προγραμματισμός επεξεργαστή, πολυεργασία και διαχείριση εικονικής μνήμης.

### BSD

Ο πυρήνας XNU επίσης **ενσωματώνει** μια σημαντική ποσότητα κώδικα που προέρχεται από το έργο **FreeBSD**. Αυτός ο κώδικας **τρέχει ως μέρος του πυρήνα μαζί με το Mach**, στον ίδιο χώρο διεύθυνσης. Ωστόσο, ο κώδικας του FreeBSD μέσα στο XNU μπορεί να διαφέρει σημαντικά από τον αρχικό κώδικα του FreeBSD επειδή απαιτήθηκαν τροποποιήσεις για να εξασφαλιστεί η συμβατότητά του με το Mach. Το FreeBSD συμβάλλει σε πολλές λειτουργίες πυρήνα, συμπεριλαμβανομένων:

* Διαχείριση διεργασιών
* Χειρισμός σημάτων
* Βασικοί μηχανισμοί ασφαλείας, συμπεριλαμβανομένης της διαχείρισης χρηστών και ομάδων
* Δομή κλήσης συστήματος
* Στοίβα TCP/IP και sockets
* Τείχος προστασίας και φιλτράρισμα πακέτων

Η κατανόηση της αλληλεπίδρασης μεταξύ BSD και Mach μπορεί να είναι πολύπλοκη, λόγω των διαφορετικών θεωρητικών πλαισίων τους. Για παράδειγμα, το BSD χρησιμοποιεί διεργασίες ως τη βασική μονάδα εκτέλεσης του, ενώ το Mach λειτουργεί με βάση τις νήματα. Αυτή η αντίφαση συμβιβάζεται στο XNU με το **συσχετισμό κάθε διεργασίας BSD με μια εργασία Mach** που περιέχει ακριβώς ένα νήμα Mach. Όταν χρησιμοποιείται η κλήση συστήματος fork() του BSD, ο κώδικας BSD μέσα στον πυρήνα χρησιμοποιεί λειτουργίες Mach για να δημιουργήσει μια εργασία και μια δομή νήματος.

Επιπλέον, **το Mach και το BSD διατηρούν διαφορετικά μοντέλα ασφαλείας**: το μοντέλο ασφαλείας του Mach βασίζεται σε **δικαιώματα θύρας**, ενώ το μοντέλο ασφαλείας του BSD λειτουργεί βάσει της **ιδιοκτησίας διεργασίας**. Οι αντιφάσεις μεταξύ αυτών των δύο μοντέλων έχουν προκαλέσει περιστασιακά ευπάθειες προς ανόδο προνομίων σε τοπικό επίπεδο. Εκτός από τις τυπικές κλήσεις συστήματος, υπάρχουν επίσης **παγίδες Mach που επιτρέπουν σε προγράμματα χώρου χρήστη να αλληλεπιδρούν με τον πυρήνα**. Αυτά τα διαφορετικά στοιχεία σχηματίζουν μαζί την πολυδιάστατη, υβριδική αρχιτεκτονική του πυρήνα macOS.

### I/O Kit - Οδηγοί

Το I/O Kit είναι ένα ανοικτού κώδικα, αντικειμενοστραφές **πλαίσιο οδηγών συσκευών** στον πυρήνα XNU, χειρίζεται **δυναμικά φορτωμένους οδηγούς συσκευών**. Επιτρέπει την προσθήκη μοντουλαρισμένου κώδικα στον πυρήνα κατά τη διάρκεια της λειτουργίας, υποστηρίζοντας ποικίλες υλικές συσκευές.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Επικοινωνία Μεταξύ Διεργασιών

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Το **kernelcache** είναι μια \*\*προ-μεταγλωττισμένη και προ-συνδεδεμένη έκδοση του πυρήνα XNU

```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

#### Σύμβολα Kernelcache

Κάποιες φορές η Apple κυκλοφορεί **kernelcache** με **σύμβολα**. Μπορείτε να κατεβάσετε μερικά firmwares με σύμβολα ακολουθώντας τους συνδέσμους στο [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Αυτά είναι τα Apple **firmwares** που μπορείτε να κατεβάσετε από το [**https://ipsw.me/**](https://ipsw.me/). Μεταξύ άλλων αρχείων περιέχει το **kernelcache**.\
Για να **εξάγετε** τα αρχεία μπορείτε απλά να το **αποσυμπιέσετε**.

Μετά την εξαγωγή του firmware θα λάβετε ένα αρχείο όπως: **`kernelcache.release.iphone14`**. Είναι σε μορφή **IMG4**, μπορείτε να εξάγετε τις ενδιαφέρουσες πληροφορίες με:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

Μπορείτε να ελέγξετε τα σύμβολα που εξήχθησαν από τον πυρήνα με: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Με αυτό τώρα μπορούμε **να εξάγουμε όλες τις επεκτάσεις** ή τη **μία που σας ενδιαφέρει:**

```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```

## macOS Επεκτάσεις Πυρήνα

Το macOS είναι **υπερβολικά περιοριστικό στο να φορτώσει Επεκτάσεις Πυρήνα** (.kext) λόγω των υψηλών προνομίων που θα εκτελεστεί ο κώδικας. Πράγματι, από προεπιλογή είναι σχεδόν αδύνατο (εκτός αν βρεθεί ένας τρόπος παράκαμψης).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Επεκτάσεις Συστήματος macOS

Αντί να χρησιμοποιεί Επεκτάσεις Πυρήνα, το macOS δημιούργησε τις Επεκτάσεις Συστήματος, οι οποίες προσφέρουν APIs σε επίπεδο χρήστη για να αλληλεπιδράσουν με τον πυρήνα. Με αυτόν τον τρόπο, οι προγραμματιστές μπορούν να αποφύγουν τη χρήση επεκτάσεων πυρήνα.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Αναφορές

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
