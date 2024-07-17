<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Σύνοψη της επίθεσης

Φανταστείτε ένα διακομιστή που **υπογράφει** κάποια **δεδομένα** με το **προσάρτημα** ενός **μυστικού** σε κάποια γνωστά καθαρά δεδομένα και στη συνέχεια κατακερματίζει αυτά τα δεδομένα. Αν γνωρίζετε:

* **Το μήκος του μυστικού** (αυτό μπορεί επίσης να αναζητηθεί με βρόχο από ένα δεδομένο εύρος μήκους)
* **Τα καθαρά δεδομένα**
* **Τον αλγόριθμο (και την ευπάθειά του σε αυτήν την επίθεση)**
* **Η γέμιση είναι γνωστή**
* Συνήθως χρησιμοποιείται μία προεπιλεγμένη, οπότε αν πληρούνται τα άλλα 3 απαιτήματα, αυτό επίσης ισχύει
* Η γέμιση ποικίλλει ανάλογα με το μήκος του μυστικού+δεδομένων, γι' αυτό χρειάζεται το μήκος του μυστικού

Τότε, είναι δυνατό για έναν **εισβολέα** να **προσαρτήσει** **δεδομένα** και να **δημιουργήσει** μια έγκυρη **υπογραφή** για τα **προηγούμενα δεδομένα + τα προσαρτημένα δεδομένα**.

## Πώς;

Βασικά, οι ευάλωτοι αλγόριθμοι δημιουργούν τα κατακερματισμένα δεδομένα αρχικά με το **κατακερματισμό ενός τμήματος δεδομένων**, και στη συνέχεια, **από** το **προηγουμένως** δημιουργημένο **κατακερματισμένο δεδομένο** (κατάσταση), **προσθέτουν το επόμενο τμήμα δεδομένων** και το **κατακερματίζουν**.

Έπειτα, φανταστείτε ότι το μυστικό είναι "μυστικό" και τα δεδομένα είναι "δεδομένα", το MD5 του "μυστικόδεδομένα" είναι 6036708eba0d11f6ef52ad44e8b74d5b.\
Αν ένας εισβολέας θέλει να προσαρτήσει τη συμβολοσειρά "προσάρτημα" μπορεί:

* Να δημιουργήσει ένα MD5 από 64 "Α"
* Να αλλάξει την κατάσταση του προηγουμένως αρχικοποιημένου κατακερματισμένου σε 6036708eba0d11f6ef52ad44e8b74d5b
* Να προσαρτήσει τη συμβολοσειρά "προσάρτημα"
* Να ολοκληρώσει τον κατακερματισμό και το τελικό κατακερματισμένο θα είναι ένα **έγκυρο για το "μυστικό" + "δεδομένα" + "γέμισμα" + "προσάρτημα"**

## **Εργαλείο**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Αναφορές

Μπορείτε να βρείτε αυτήν την επίθεση καλά εξηγημένη στο [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
