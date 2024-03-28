# Δέσμες macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Οι δέσμες στο macOS λειτουργούν ως δοχεία για μια ποικιλία πόρων, συμπεριλαμβανομένων εφαρμογών, βιβλιοθηκών και άλλων απαραίτητων αρχείων, καθιστώντας τους ορατούς ως μοναδικά αντικείμενα στο Finder, όπως τα γνωστά αρχεία `*.app`. Η πιο συνηθισμένη δέσμη που συναντάται είναι η δέσμη `.app`, αν και άλλοι τύποι όπως `.framework`, `.systemextension` και `.kext` είναι επίσης διαδεδομένοι.

### Βασικά Στοιχεία μιας Δέσμης

Μέσα σε μια δέσμη, ειδικά μέσα στον κατάλογο `<εφαρμογή>.app/Contents/`, φιλοξενούνται μια ποικιλία σημαντικών πόρων:

* **\_CodeSignature**: Αυτός ο κατάλογος αποθηκεύει λεπτομέρειες υπογραφής κώδικα που είναι ζωτικές για τον έλεγχο της ακεραιότητας της εφαρμογής. Μπορείτε να ελέγξετε τις πληροφορίες υπογραφής κώδικα χρησιμοποιώντας εντολές όπως: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Περιέχει το εκτελέσιμο δυαδικό της εφαρμογής που εκτελείται κατά την αλληλεπίδραση του χρήστη.
* **Resources**: Ένα αποθήκευτικό χώρο για τα στοιχεία διεπαφής χρήστη της εφαρμογής, συμπεριλαμβανομένων εικόνων, εγγράφων και περιγραφών διεπαφής (αρχεία nib/xib).
* **Info.plist**: Δρα ως το κύριο αρχείο διαμόρφωσης της εφαρμογής, κρίσιμο για το σύστημα να αναγνωρίζει και να αλληλεπιδρά με την εφαρμογή κατάλληλα.

#### Σημαντικά Κλειδιά στο Info.plist

Το αρχείο `Info.plist` είναι ένας πυλώνας για τη διαμόρφωση της εφαρμογής, περιέχοντας κλειδιά όπως:

* **CFBundleExecutable**: Καθορίζει το όνομα του κύριου εκτελέσιμου αρχείου που βρίσκεται στον κατάλογο `Contents/MacOS`.
* **CFBundleIdentifier**: Παρέχει ένα παγκόσμιο αναγνωριστικό για την εφαρμογή, που χρησιμοποιείται εκτενώς από το macOS για τη διαχείριση της εφαρμογής.
* **LSMinimumSystemVersion**: Υποδεικνύει την ελάχιστη έκδοση του macOS που απαιτείται για την εκτέλεση της εφαρμογής.

### Εξερεύνηση Δεσμών

Για να εξερευνήσετε τα περιεχόμενα μιας δέσμης, όπως το `Safari.app`, μπορεί να χρησιμοποιηθεί η ακόλουθη εντολή: `bash ls -lR /Applications/Safari.app/Contents`

Αυτή η εξερεύνηση αποκαλύπτει καταλόγους όπως `_CodeSignature`, `MacOS`, `Resources`, και αρχεία όπως `Info.plist`, καθένας εξυπηρετώντας ένα μοναδικό σκοπό από την ασφάλεια της εφαρμογής μέχρι τον καθορισμό της διεπαφής χρήστη και των παραμέτρων λειτουργίας της.

#### Επιπλέον Κατάλογοι Δέσμης

Πέρα από τους κοινούς καταλόγους, οι δέσμες μπορεί να περιλαμβάνουν επίσης:

* **Πλαίσια (Frameworks)**: Περιέχει πλαισιωμένα πλαίσια που χρησιμοποιούνται από την εφαρμογή. Τα πλαίσια είναι σαν dylibs με επιπλέον πόρους.
* **Πρόσθετα (PlugIns)**: Ένας κατάλογος για πρόσθετα και επεκτάσεις που ενισχύουν τις δυνατότητες της εφαρμογής.
* **XPCServices**: Διαθέτει XPC υπηρεσίες που χρησιμοποιούνται από την εφαρμογή για επικοινωνία εκτός διεργασίας.

Αυτή η δομή εξασφαλίζει ότι όλα τα απαραίτητα στοιχεία είναι ενσωματωμένα μέσα στη δέσμη, διευκολύνοντας ένα περιβάλλον εφαρμογής που είναι μοντουλαρισμένο και ασφαλές.

Για περισσότερες λεπτομερείς πληροφορίες σχετικά με τα κλειδιά του `Info.plist` και τις σημασίες τους, η τεκμηρίωση προγραμματιστή της Apple παρέχει εκτενείς πόρους: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
