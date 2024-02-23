# Κατάχρηση Εγκαταστάτη macOS

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

## Βασικές Πληροφορίες Pkg

Ένα **πακέτο εγκατάστασης macOS** (επίσης γνωστό ως αρχείο `.pkg`) είναι ένα μορφότυπο αρχείου που χρησιμοποιείται από το macOS για τη **διανομή λογισμικού**. Αυτά τα αρχεία είναι σαν ένα **κουτί που περιέχει ό,τι χρειάζεται ένα κομμάτι λογισμικού** για να εγκατασταθεί και να λειτουργήσει σωστά.

Το ίδιο το αρχείο πακέτου είναι ένα αρχείο αρχειοθήκης που κρατά μια **ιεραρχία αρχείων και καταλόγων που θα εγκατασταθούν στον στόχο** υπολογιστή. Μπορεί επίσης να περιλαμβάνει **σενάρια** για να εκτελέσει εργασίες πριν και μετά την εγκατάσταση, όπως η ρύθμιση αρχείων διαμόρφωσης ή η καθαρισμός παλαιών εκδόσεων του λογισμικού.

### Ιεραρχία

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Διανομή (xml)**: Προσαρμογές (τίτλος, κείμενο καλωσορίσματος...) και έλεγχοι σεναρίου/εγκατάστασης
* **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, διαδρομές για τα σενάρια που θα εκτελεστοώσν
* **Λογαριασμός υλικών (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση με δικαιώματα αρχείου
* **Φορτίο (CPIO αρχείο gzip συμπιεσμένο)**: Αρχεία προς εγκατάσταση στην `τοποθεσία-εγκατάστασης` από το PackageInfo
* **Σενάρια (CPIO αρχείο gzip συμπιεσμένο)**: Προεγκατάσταση και μεταεγκατάσταση σεναρίων και περισσότεροι πόροι που εξάγονται σε προσωρινό κατάλογο για εκτέλεση.

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

Τα αρχεία DMG, ή Apple Disk Images, είναι ένα μορφή αρχείου που χρησιμοποιείται από το macOS της Apple για εικόνες δίσκου. Ένα αρχείο DMG είναι ουσιαστικά μια **εικόνα δίσκου που μπορεί να τοποθετηθεί** (περιέχει το δικό του σύστημα αρχείων) που περιέχει ωμά δεδομένα των τετραγωνικών τύπων συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγετε ένα αρχείο DMG, το macOS **τοποθετεί το ως να ήταν φυσικός δίσκος**, επιτρέποντάς σας να έχετε πρόσβαση στα περιεχόμενά του.

### Ιεραρχία

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να είναι διαφορετική ανάλογα με το περιεχόμενο. Ωστόσο, για τα DMG εφαρμογών, συνήθως ακολουθεί αυτή τη δομή:

* Κορυφαίο Επίπεδο: Αυτό είναι το ριζικό επίπεδο της εικόνας δίσκου. Συνήθως περιέχει την εφαρμογή και πιθανώς ένα σύνδεσμο προς τον φάκελο Εφαρμογές.
* Εφαρμογή (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι τυπικά ένα πακέτο που περιέχει πολλά μεμονωμένα αρχεία και φακέλους που αποτελούν την εφαρμογή.
* Σύνδεσμος Εφαρμογών: Αυτός είναι ένας συντόμευση προς τον φάκελο Εφαρμογές στο macOS. Ο σκοπός αυτού είναι να σας διευκολύνει στην εγκατάσταση της εφαρμογής. Μπορείτε να σύρετε το αρχείο .app σε αυτόν το συντόμευση για να εγκαταστήσετε την εφαρμογή.

## Ανύψωση προνομίων μέσω κατάχρησης pkg

### Εκτέλεση από δημόσιους καταλόγους

Αν ένα σενάριο πριν ή μετά την εγκατάσταση εκτελείται για παράδειγμα από το **`/var/tmp/Installerutil`**, και ένας επιτιθέμενος μπορεί να ελέγχει αυτό το σενάριο για να αναβαθμίσει τα προνόμια κάθε φορά που εκτελείται. Ή ένα άλλο παρόμοιο παράδειγμα:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [δημόσια συνάρτηση](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) που πολλοί εγκαταστάτες και ενημερωτές θα καλέσουν για να **εκτελέσουν κάτι ως ριζικό χρήστη**. Αυτή η συνάρτηση δέχεται τη **διαδρομή** του **αρχείου** που θα **εκτελεστεί** ως παράμετρο, ωστόσο, αν ένας επιτιθέμενος μπορεί να **τροποποιήσει** αυτό το αρχείο, θα μπορεί να **καταχραστεί** την εκτέλεσή του με ρίζι για να **αναβαθμίσει τα προνόμια**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
### Εκτέλεση με την τοποθέτηση σε σημείο πρόσβασης

Αν ένα πρόγραμμα εγκατάστασης γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατόν να **δημιουργήσετε ένα σημείο πρόσβασης** πάνω από το `/tmp/fixedname` χωρίς κάτοχους, έτσι μπορείτε **να τροποποιήσετε οποιοδήποτε αρχείο κατά τη διάρκεια της εγκατάστασης** για να καταχραστείτε τη διαδικασία εγκατάστασης.

Ένα παράδειγμα αυτού είναι το **CVE-2021-26089** το οποίο κατάφερε να **αντικαταστήσει ένα περιοδικό script** για να λάβει εκτέλεση ως root. Για περισσότερες πληροφορίες ανατρέξτε στην ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg ως κακόβουλο λογισμικό

### Κενό Φορτίο

Είναι δυνατόν απλά να δημιουργήσετε ένα αρχείο **`.pkg`** με **προεγκατεστημένα και μετα-εγκατάστασης scripts** χωρίς κανένα φορτίο.

### JS στο Distribution xml

Είναι δυνατόν να προσθέσετε **`<script>`** tags στο αρχείο **distribution xml** του πακέτου και αυτός ο κώδικας θα εκτελεστεί και μπορεί **να εκτελέσει εντολές** χρησιμοποιώντας το **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
