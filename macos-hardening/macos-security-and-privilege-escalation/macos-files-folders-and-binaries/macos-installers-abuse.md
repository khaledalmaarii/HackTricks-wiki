# Κατάχρηση Εγκαταστάτη macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες Pkg

Ένα **πακέτο εγκατάστασης macOS** (επίσης γνωστό ως αρχείο `.pkg`) είναι ένα μορφότυπο αρχείου που χρησιμοποιείται από το macOS για τη **διανομή λογισμικού**. Αυτά τα αρχεία είναι σαν ένα **κουτί που περιέχει όλα όσα χρειάζεται ένα κομμάτι λογισμικού** για να εγκατασταθεί και να λειτουργήσει σωστά.

Το ίδιο το αρχείο πακέτου είναι ένα αρχείο αρχειοθήκης που περιέχει μια **ιεραρχία αρχείων και καταλόγων που θα εγκατασταθούν στον προορισμένο** υπολογιστή. Μπορεί επίσης να περιλαμβάνει **σενάρια** για να εκτελέσει εργασίες πριν και μετά την εγκατάσταση, όπως η ρύθμιση αρχείων διαμόρφωσης ή η εκκαθάριση παλαιών εκδόσεων του λογισμικού.

### Ιεραρχία

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Προσαρμογές (τίτλος, κείμενο καλωσορίσματος...) και έλεγχοι σεναρίου/εγκατάστασης
* **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, διαδρομές προς σενάρια που θα εκτελεστούν
* **Bill of materials (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση με δικαιώματα αρχείου
* **Payload (CPIO αρχείο gzip συμπιεσμένο)**: Αρχεία προς εγκατάσταση στην `install-location` από το PackageInfo
* **Scripts (CPIO αρχείο gzip συμπιεσμένο)**: Προεγκατάσταση και μεταγενέστερα σενάρια εγκατάστασης και περισσότεροι πόροι που εξάγονται σε έναν προσωρινό κατάλογο για εκτέλεση.
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
## Βασικές πληροφορίες για τα αρχεία DMG

Τα αρχεία DMG, ή Apple Disk Images, είναι ένα μορφότυπο αρχείου που χρησιμοποιείται από το macOS της Apple για εικόνες δίσκου. Ένα αρχείο DMG είναι ουσιαστικά μια **προσαρτήσιμη εικόνα δίσκου** (περιέχει το δικό της σύστημα αρχείων) που περιέχει ακατέργαστα δεδομένα των μπλοκ που συνήθως είναι συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγετε ένα αρχείο DMG, το macOS το προσαρτά ως να ήταν ένα φυσικό δίσκο, επιτρέποντάς σας να έχετε πρόσβαση στο περιεχόμενό του.

### Ιεραρχία

<figure><img src="../../../.gitbook/assets/image (12) (2).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να είναι διαφορετική ανάλογα με το περιεχόμενο. Ωστόσο, για τα αρχεία DMG εφαρμογών, συνήθως ακολουθεί αυτήν τη δομή:

* Επίπεδο κορυφής: Αυτό είναι το ριζικό επίπεδο της εικόνας δίσκου. Συνήθως περιέχει την εφαρμογή και πιθανώς ένα σύνδεσμο προς τον φάκελο Εφαρμογές.
* Εφαρμογή (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι συνήθως ένα πακέτο που περιέχει πολλά ατομικά αρχεία και φακέλους που αποτελούν την εφαρμογή.
* Σύνδεσμος Εφαρμογών: Αυτός είναι ένας συντόμευση προς τον φάκελο Εφαρμογές στο macOS. Ο σκοπός αυτού είναι να καταστήσει ευκολότερη την εγκατάσταση της εφαρμογής. Μπορείτε να σύρετε το αρχείο .app σε αυτήν τη συντόμευση για να εγκαταστήσετε την εφαρμογή.

## Απόκτηση προνομίων μέσω κατάχρησης του pkg

### Εκτέλεση από δημόσιους φακέλους

Αν ένα σενάριο προεγκατάστασης ή μεταγενέστερης εγκατάστασης εκτελείται, για παράδειγμα, από το **`/var/tmp/Installerutil`**, ένας επιτιθέμενος μπορεί να ελέγχει αυτό το σενάριο για να αποκτήσει προνόμια κατά την εκτέλεσή του. Ή ένα άλλο παρόμοιο παράδειγμα:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [δημόσια συνάρτηση](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) που πολλοί εγκαταστάτες και ενημερωτές καλούν για να **εκτελέσουν κάτι ως root**. Αυτή η συνάρτηση δέχεται ως παράμετρο το **μονοπάτι** του **αρχείου** που θα **εκτελεστεί**, ωστόσο, αν ένας επιτιθέμενος μπορεί να **τροποποιήσει** αυτό το αρχείο, θα μπορεί να **καταχραστεί** την εκτέλεσή του με προνόμια root για να αποκτήσει προνόμια.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Για περισσότερες πληροφορίες, ελέγξτε αυτήν την ομιλία: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Εκτέλεση με την προσάρτηση

Εάν ένα πρόγραμμα εγκατάστασης γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατόν να **δημιουργηθεί μια προσάρτηση** πάνω από το `/tmp/fixedname` χωρίς κατόχους, έτσι ώστε να μπορείτε να **τροποποιήσετε οποιοδήποτε αρχείο κατά τη διάρκεια της εγκατάστασης** για να καταχραστείτε τη διαδικασία εγκατάστασης.

Ένα παράδειγμα αυτού είναι το **CVE-2021-26089**, το οποίο κατάφερε να **αντικαταστήσει έναν περιοδικό σενάριο** για να εκτελέσει ως root. Για περισσότερες πληροφορίες, ρίξτε μια ματιά στην ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## Το pkg ως κακόβουλο λογισμικό

### Κενό φορτίο

Είναι δυνατόν απλά να δημιουργήσετε ένα αρχείο **`.pkg`** με **προεγκατεστημένα και μετα-εγκατάστασης σενάρια** χωρίς κανένα φορτίο.

### JS στο distribution xml

Είναι δυνατόν να προσθέσετε ετικέτες **`<script>`** στο αρχείο **distribution xml** του πακέτου και αυτός ο κώδικας θα εκτελεστεί και μπορεί να **εκτελέσει εντολές** χρησιμοποιώντας το **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
