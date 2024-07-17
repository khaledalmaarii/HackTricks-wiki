# Επίθεση με Επέκταση Μήκους Hash

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο βασικός στόχος του WhiteIntel είναι η καταπολέμηση των αποκλεισμών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

***

## Σύνοψη της επίθεσης

Φανταστείτε ένα διακομιστή που **υπογράφει** κάποια **δεδομένα** με το **προσάρτημα** ενός **μυστικού** σε κάποια γνωστά δεδομένα και στη συνέχεια κατακερματίζει αυτά τα δεδομένα. Αν γνωρίζετε:

* **Το μήκος του μυστικού** (αυτό μπορεί επίσης να αναζητηθεί με βρόχο από ένα δεδομένο εύρος μήκους)
* **Τα καθαρά δεδομένα**
* **Τον αλγόριθμο (και την ευπάθειά του σε αυτήν την επίθεση)**
* **Η γέμιση είναι γνωστή**
* Συνήθως χρησιμοποιείται μια προεπιλεγμένη, οπότε αν πληρούνται τα άλλα 3 απαιτήσεις, αυτή επίσης είναι
* Η γέμιση ποικίλλει ανάλογα με το μήκος του μυστικού+δεδομένων, γι' αυτό χρειάζεται το μήκος του μυστικού

Τότε, είναι δυνατό για έναν **εισβολέα** να **προσαρτήσει** **δεδομένα** και να **δημιουργήσει** μια έγκυρη **υπογραφή** για τα **προηγούμενα δεδομένα + τα προσαρτημένα δεδομένα**.

### Πώς;

Βασικά, οι ευάλωτοι αλγόριθμοι δημιουργούν τα κατακερματισμένα δεδομένα αρχικά με το **κατακερματισμό ενός τμήματος δεδομένων**, και στη συνέχεια, **από** το **προηγουμένως** δημιουργημένο **κατακερματισμένο δεδομένο** (κατάσταση), **προσθέτουν το επόμενο τμήμα δεδομένων** και το **κατακερματίζουν**.

Στη συνέχεια, φανταστείτε ότι το μυστικό είναι "μυστικό" και τα δεδομένα είναι "δεδομένα", το MD5 του "μυστικόδεδομένα" είναι 6036708eba0d11f6ef52ad44e8b74d5b.\
Αν ένας εισβολέας θέλει να προσαρτήσει τη συμβολοσειρά "προσάρτηση" μπορεί:

* Να δημιουργήσει ένα MD5 από 64 "Α"
* Να αλλάξει την κατάσταση του προηγουμένως αρχικοποιημένου κατακερματισμένου σε 6036708eba0d11f6ef52ad44e8b74d5b
* Να προσαρτήσει τη συμβολοσειρά "προσάρτηση"
* Να ολοκληρώσει τον κατακερματισμό και το τελικό κατακερματισμένο θα είναι ένα **έγκυρο για το "μυστικό" + "δεδομένα" + "γέμισμα" + "προσάρτηση"**

### **Εργαλείο**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Αναφορές

Μπορείτε να βρείτε αυτήν την επίθεση καλά εξηγημένη στο [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

#### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο βασικός στόχος του WhiteIntel είναι η καταπολέμηση των αποκλεισμών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
