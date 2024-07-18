# Κατάχρηση Εγκαταστάτη macOS

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Βασικές Πληροφορίες Pkg

Ένα **πακέτο εγκατάστασης macOS** (επίσης γνωστό ως αρχείο `.pkg`) είναι ένα μορφή αρχείου που χρησιμοποιείται από το macOS για τη **διανομή λογισμικού**. Αυτά τα αρχεία είναι σαν ένα **κουτί που περιέχει ό,τι χρειάζεται ένα κομμάτι λογισμικού** για να εγκατασταθεί και να λειτουργήσει σωστά.

Το ίδιο το αρχείο πακέτου είναι ένα αρχείο αρχειοθέτησης που κρατά μια **ιεραρχία αρχείων και καταλόγων που θα εγκατασταθούν στον στόχο** υπολογιστή. Μπορεί επίσης να περιλαμβάνει **σενάρια** για να εκτελέσει εργασίες πριν και μετά την εγκατάσταση, όπως η ρύθμιση αρχείων διαμόρφωσης ή η καθαρισμός παλαιότερων εκδόσεων του λογισμικού.

### Ιεραρχία

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Διανομή (xml)**: Προσαρμογές (τίτλος, κείμενο καλωσορίσματος...) και ελέγχοι σεναρίου/εγκατάστασης
* **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, διαδρομές για τα σενάρια που θα εκτελεστούν
* **Λογαριασμός υλικών (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση με δικαιώματα αρχείου
* **Φορτίο (CPIO αρχείο gzip συμπιεσμένο)**: Αρχεία προς εγκατάσταση στην `τοποθεσία-εγκατάστασης` από το PackageInfo
* **Σενάρια (CPIO αρχείο gzip συμπιεσμένο)**: Προεγκατάσταση και μεταεγκατάσταση σεναρίων και περισσότεροι πόροι εξάγονται σε έναν προσωρινό κατάλογο για εκτέλεση.

### Αποσυμπίεση
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Για να οπτικοποιήσετε τα περιεχόμενα του εγκαταστάτη χωρίς να το αποσυμπιέσετε χειροκίνητα, μπορείτε επίσης να χρησιμοποιήσετε το δωρεάν εργαλείο [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Βασικές Πληροφορίες DMG

Τα αρχεία DMG, ή Apple Disk Images, είναι ένα μορφή αρχείου που χρησιμοποιείται από το macOS της Apple για εικόνες δίσκου. Ένα αρχείο DMG είναι ουσιαστικά μια **εικόνα δίσκου που μπορεί να τοποθετηθεί** (περιέχει το δικό του σύστημα αρχείων) που περιέχει ωμά δεδομένα των τετραγωνικών του τομέων συνήθως συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγετε ένα αρχείο DMG, το macOS **τοποθετεί το ως να ήταν φυσικός δίσκος**, επιτρέποντάς σας να έχετε πρόσβαση στα περιεχόμενά του.

{% hint style="danger" %}
Σημειώστε ότι οι εγκαταστάτες **`.dmg`** υποστηρίζουν **τόσα πολλά μορφές** ώστε στο παρελθόν μερικοί από αυτούς που περιείχαν ευπάθειες καταχρηστικά χρησιμοποιήθηκαν για να αποκτηθεί **εκτέλεση κώδικα πυρήνα**.
{% endhint %}

### Ιεραρχία

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να είναι διαφορετική ανάλογα με το περιεχόμενο. Ωστόσο, για τα DMG εφαρμογών, συνήθως ακολουθεί αυτή τη δομή:

* Κορυφαίο Επίπεδο: Αυτό είναι το ριζικό της εικόνας δίσκου. Συνήθως περιέχει την εφαρμογή και πιθανώς ένα σύνδεσμο προς τον φάκελο Εφαρμογές.
* Εφαρμογή (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι τυπικά ένα πακέτο που περιέχει πολλά μεμονωμένα αρχεία και φακέλους που αποτελούν την εφαρμογή.
* Σύνδεσμος Εφαρμογών: Αυτός είναι ένας συντόμευση προς τον φάκελο Εφαρμογές στο macOS. Ο σκοπός αυτού είναι να σας διευκολύνει στην εγκατάσταση της εφαρμογής. Μπορείτε να σύρετε το αρχείο .app σε αυτόν τον συντόμευση για να εγκαταστήσετε την εφαρμογή.

## Ανύψωση προνομίων μέσω κατάχρησης pkg

### Εκτέλεση από δημόσιους καταλόγους

Αν ένα σενάριο πριν ή μετά την εγκατάσταση εκτελείται για παράδειγμα από το **`/var/tmp/Installerutil`**, και ένας επιτιθέμενος μπορεί να ελέγχει αυτό το σενάριο για να αναβαθμίσει τα προνόμια κάθε φορά που εκτελείται. Ή ένα άλλο παρόμοιο παράδειγμα:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [δημόσια συνάρτηση](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) που πολλοί εγκαταστάτες και ενημερωτές θα καλέσουν για να **εκτελέσουν κάτι ως ριζικός χρήστης**. Αυτή η συνάρτηση δέχεται τη **διαδρομή** του **αρχείου** που θα **εκτελεστεί** ως παράμετρο, ωστόσο, αν ένας επιτιθέμενος μπορούσε να **τροποποιήσει** αυτό το αρχείο, θα μπορούσε να **καταχραστεί** την εκτέλεσή του με ριζικά προνόμια για να **αναβαθμίσει τα προνόμια**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Εκτέλεση με την τοποθέτηση σε σημείο πρόσβασης

Εάν ένα πρόγραμμα εγκατάστασης γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατόν να **δημιουργήσετε ένα σημείο πρόσβασης** πάνω από το `/tmp/fixedname` χωρίς κάτοχους, έτσι ώστε να μπορείτε **να τροποποιήσετε οποιοδήποτε αρχείο κατά τη διάρκεια της εγκατάστασης** για να καταχραστείτε τη διαδικασία εγκατάστασης.

Ένα παράδειγμα αυτού είναι το **CVE-2021-26089** το οποίο κατάφερε να **αντικαταστήσει ένα περιοδικό script** για να εκτελέσει ως root. Για περισσότερες πληροφορίες, ρίξτε μια ματιά στην ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg ως κακόβουλο λογισμικό

### Κενό Φορτίο

Είναι δυνατόν απλά να δημιουργήσετε ένα αρχείο **`.pkg`** με **προεγκατεστημένα και μετα-εγκατάστασης scripts** χωρίς κανένα φορτίο.

### JS στο Distribution xml

Είναι δυνατόν να προσθέσετε ετικέτες **`<script>`** στο αρχείο **distribution xml** του πακέτου και αυτός ο κώδικας θα εκτελεστεί και μπορεί να **εκτελέσει εντολές** χρησιμοποιώντας το **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

* [**DEF CON 27 - Unpacking Pkgs Μια ματιά μέσα στα πακέτα εγκατάστασης του MacOS και συνηθισμένα ελαττώματα ασφαλείας**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "Ο Άγριος Κόσμος των Εγκαταστάσεων του macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs Μια ματιά μέσα στα πακέτα εγκατάστασης του MacOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
