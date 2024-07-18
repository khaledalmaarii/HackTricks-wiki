# Δέσμες macOS

{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Βασικές Πληροφορίες

Οι δέσμες στο macOS λειτουργούν ως δοχεία για μια ποικιλία πόρων, συμπεριλαμβανομένων εφαρμογών, βιβλιοθηκών και άλλων απαραίτητων αρχείων, καθιστώντας τους ορατούς ως μοναδικά αντικείμενα στο Finder, όπως τα γνωστά αρχεία `*.app`. Η πιο συνηθισμένη δέσμη που συναντάται είναι η δέσμη `.app`, αν και άλλοι τύποι όπως `.framework`, `.systemextension` και `.kext` είναι επίσης διαδεδομένοι.

### Βασικά Στοιχεία μιας Δέσμης

Μέσα σε μια δέσμη, ειδικά μέσα στον κατάλογο `<εφαρμογή>.app/Contents/`, φιλοξενούνται ποικίλοι σημαντικοί πόροι:

* **\_CodeSignature**: Αυτός ο κατάλογος αποθηκεύει λεπτομέρειες υπογραφής κώδικα που είναι ζωτικές για τον έλεγχο της ακεραιότητας της εφαρμογής. Μπορείτε να ελέγξετε τις πληροφορίες υπογραφής κώδικα χρησιμοποιώντας εντολές όπως: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
* **MacOS**: Περιέχει το εκτελέσιμο δυαδικό της εφαρμογής που εκτελείται κατά την αλληλεπίδραση του χρήστη.
* **Resources**: Ένα αποθήκευτικό χώρο για τα στοιχεία διεπαφής χρήστη της εφαρμογής, συμπεριλαμβανομένων εικόνων, εγγράφων και περιγραφών διεπαφής (αρχεία nib/xib).
* **Info.plist**: Λειτουργεί ως το κύριο αρχείο διαμόρφωσης της εφαρμογής, κρίσιμο για το σύστημα να αναγνωρίζει και να αλληλεπιδρά με την εφαρμογή κατάλληλα.

#### Σημαντικά Κλειδιά στο Info.plist

Το αρχείο `Info.plist` είναι θεμέλιο για τη διαμόρφωση της εφαρμογής, περιέχοντας κλειδιά όπως:

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
* **XPCServices**: Κρατά υπηρεσίες XPC που χρησιμοποιούνται από την εφαρμογή για επικοινωνία εκτός διεργασίας.

Αυτή η δομή εξασφαλίζει ότι όλα τα απαραίτητα στοιχεία είναι ενσωματωμένα μέσα στη δέσμη, διευκολύνοντας ένα περιβάλλον εφαρμογής που είναι μοντουλάριο και ασφαλές.

Για περισσότερες λεπτομερείς πληροφορίες σχετικά με τα κλειδιά του `Info.plist` και τις σημασίες τους, η τεκμηρίωση προγραμματιστή της Apple παρέχει εκτενείς πόρους: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{% hint style="success" %}
Μάθε & εξάσκησε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθε & εξάσκησε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
