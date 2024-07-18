# macOS Πυρήνας & Επεκτάσεις Συστήματος

{% hint style="success" %}
Μάθε & εξάσκησε το AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε το GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}

## Πυρήνας XNU

Ο **πυρήνας του macOS είναι ο XNU**, που σημαίνει "X is Not Unix". Αυτός ο πυρήνας αποτελείται θεμελιωδώς από τον **μικροπυρήνα Mach** (που θα συζητηθεί αργότερα), **και** στοιχεία από τη Διανομή Λογισμικού του Πανεπιστημίου του Μπέρκλεϊ (**BSD**). Ο XNU παρέχει επίσης μια πλατφόρμα για **οδηγούς πυρήνα μέσω ενός συστήματος που ονομάζεται I/O Kit**. Ο πυρήνας XNU είναι μέρος του έργου ανοικτού κώδικα Darwin, που σημαίνει ότι **ο κώδικας του είναι ελεύθερα προσβάσιμος**.

Από την άποψη ενός ερευνητή ασφάλειας ή ενός προγραμματιστή Unix, το **macOS** μπορεί να φανεί αρκετά **παρόμοιο** με ένα σύστημα **FreeBSD** με μια κομψή γραφική διεπαφή και μια σειρά προσαρμοσμένων εφαρμογών. Οι περισσότερες εφαρμογές που αναπτύσσονται για το BSD θα μεταγλωττιστούν και θα εκτελεστούν στο macOS χωρίς την ανάγκη τροποποιήσεων, καθώς τα εργαλεία γραμμής εντολών που είναι γνωστά στους χρήστες Unix είναι όλα παρόντα στο macOS. Ωστόσο, επειδή ο πυρήνας XNU ενσωματώνει το Mach, υπάρχουν ορισμένες σημαντικές διαφορές μεταξύ ενός παραδοσιακού συστήματος παρόμοιου με Unix και του macOS, και αυτές οι διαφορές μπορεί να προκαλέσουν προβλήματα ή να παρέχουν μοναδικά πλεονεκτήματα.

Πηγαίος κώδικας του XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Το Mach είναι ένας **μικροπυρήνας** σχεδιασμένος να είναι **συμβατός με το UNIX**. Ένας από τα βασικά αρχέτυπα σχεδιασμού του ήταν να **ελαχιστοποιήσει** το ποσοστό του **κώδικα** που εκτελείται στον **χώρο του πυρήνα** και αντ' αυτού να επιτρέψει σε πολλές τυπικές λειτουργίες πυρήνα, όπως σύστημα αρχείων, δικτύωση και I/O, να **εκτελούνται ως εργασίες σε επίπεδο χρήστη**.

Στο XNU, το Mach είναι **υπεύθυνο για πολλές από τις κρίσιμες λειτουργίες χαμηλού επιπέδου** που ένας πυρήνας χειρίζεται τυπικά, όπως προγραμματισμός επεξεργαστή, πολλαπλές εργασίες και διαχείριση εικονικής μνήμης.

### BSD

Ο πυρήνας XNU επίσης **ενσωματώνει** μια σημαντική ποσότητα κώδικα που προέρχεται από το έργο **FreeBSD**. Αυτός ο κώδικας **εκτελείται ως μέρος του πυρήνα μαζί με το Mach**, στον ίδιο χώρο διεύθυνσης. Ωστόσο, ο κώδικας του FreeBSD μέσα στο XNU μπορεί να διαφέρει σημαντικά από τον αρχικό κώδικα του FreeBSD επειδή απαιτήθηκαν τροποποιήσεις για να εξασφαλιστεί η συμβατότητά του με το Mach. Το FreeBSD συμβάλλει σε πολλές λειτουργίες πυρήνα, συμπεριλαμβανομένων:

* Διαχείριση διεργασιών
* Χειρισμός σημάτων
* Βασικοί μηχανισμοί ασφαλείας, συμπεριλαμβανομένης της διαχείρισης χρηστών και ομάδων
* Δομή κλήσης συστήματος
* Στοίβα TCP/IP και sockets
* Τείχος προστασίας και φιλτράρισμα πακέτων

Η κατανόηση της αλληλεπίδρασης μεταξύ BSD και Mach μπορεί να είναι πολύπλοκη, λόγω των διαφορετικών θεωρητικών πλαισίων τους. Για παράδειγμα, το BSD χρησιμοποιεί διεργασίες ως τη βασική μονάδα εκτέλεσης του, ενώ το Mach λειτουργεί με βάση τις νήματα. Αυτή η αντίφαση συμβιβάζεται στο XNU με το **συσχετισμό κάθε διεργασίας BSD με μια εργασία Mach** που περιέχει ακριβώς ένα νήμα Mach. Όταν χρησιμοποιείται η κλήση συστήματος fork() του BSD, ο κώδικας του BSD μέσα στον πυρήνα χρησιμοποιεί λειτουργίες Mach για να δημιουργήσει μια εργασία και μια δομή νήματος.

Επιπλέον, **ο Mach και το BSD διατηρούν διαφορετικά μοντέλα ασφαλείας**: το μοντέλο ασφαλείας του Mach βασίζεται σε **δικαιώματα θύρας**, ενώ το μοντέλο ασφαλείας του BSD λειτουργεί βάσει της **ιδιοκτησίας διεργασίας**. Οι αντιφάσεις μεταξύ αυτών των δύο μοντέλων έχουν προκαλέσει περιστασιακά ευπάθειες εκτίναξης προνομίων σε τοπικό επίπεδο. Εκτός από τις τυπικές κλήσεις συστήματος, υπάρχουν επίσης **παγίδες Mach που επιτρέπουν σε προγράμματα χώρου χρήστη να αλληλεπιδρούν με τον πυρήνα**. Αυτά τα διαφορετικά στοιχεία σχηματίζουν μαζί την πολυδιάστατη, υβριδική αρχιτεκτονική του πυρήνα macOS.

### I/O Kit - Οδηγοί

Το I/O Kit είναι ένα πλαίσιο **οδηγών συσκευών** ανοικτού κώδικα στον πυρήνα XNU, χειρίζεται **δυναμικά φορτωμένους οδηγούς συσκευών**. Επιτρέπει την προσθήκη μοντουλαρισμένου κώδικα στον πυρήνα κατά τη διάρκεια της λειτουργίας, υποστηρίζοντας ποικίλες υλικολογικές συσκευές.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Επικοινωνία Μεταξύ Διεργασιών

{% content-ref url="../macos-proces-abuse/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../macos-proces-abuse/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

Το **kernelcache** είναι μια **προ-μεταγλωττισμένη και προ-συνδεδεμένη έκδοση του πυρήνα XNU**, μαζί με τους απαραίτητους οδηγούς συσκευών και επεκτάσεις πυρήνα. Αποθηκεύεται σε μορφή **συμπιεσμένη** και αποσυμπιέ
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Σύμβολα Kernelcache

Κάποιες φορές η Apple κυκλοφορεί το **kernelcache** με **σύμβολα**. Μπορείτε να κατεβάσετε μερικά firmwares με σύμβολα ακολουθώντας τους συνδέσμους στο [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Αυτά είναι τα Apple **firmwares** που μπορείτε να κατεβάσετε από το [**https://ipsw.me/**](https://ipsw.me/). Μεταξύ άλλων αρχείων περιέχει το **kernelcache**.\
Για να **εξάγετε** τα αρχεία, απλά μπορείτε να το **αποσυμπιέσετε**.

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

Με αυτό τώρα μπορούμε να **εξάγουμε όλες τις επεκτάσεις** ή τη **μία που σας ενδιαφέρει:**
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

Το macOS είναι **υπερβολικά περιοριστικό στο να φορτώσει Επεκτάσεις Πυρήνα** (.kext) λόγω των υψηλών προνομίων που θα εκτελεί ο κώδικας. Πραγματικά, από προεπιλογή είναι σχεδόν αδύνατο (εκτός αν βρεθεί κάποιος τρόπος παράκαμψης).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Επεκτάσεις Συστήματος macOS

Αντί να χρησιμοποιεί Επεκτάσεις Πυρήνα, το macOS δημιούργησε τις Επεκτάσεις Συστήματος, οι οποίες προσφέρουν APIs σε επίπεδο χρήστη για αλληλεπίδραση με τον πυρήνα. Με αυτόν τον τρόπο, οι προγραμματιστές μπορούν να αποφύγουν τη χρήση επεκτάσεων πυρήνα.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Αναφορές

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
