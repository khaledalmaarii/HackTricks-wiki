<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Περίληψη της επίθεσης

Φανταστείτε ένα διακομιστή που **υπογράφει** κάποια **δεδομένα** προσθέτοντας ένα **μυστικό** σε κάποια γνωστά καθαρά δεδομένα και στη συνέχεια κατακερματίζοντας αυτά τα δεδομένα. Εάν γνωρίζετε:

* **Το μήκος του μυστικού** (αυτό μπορεί επίσης να ανακαλυφθεί με βίαιη δοκιμή από έναν δεδομένο εύρος μήκους)
* **Τα καθαρά δεδομένα**
* **Τον αλγόριθμο (και τον ευάλωτο σε αυτήν την επίθεση)**
* **Το παραμόρφωμα είναι γνωστό**
* Συνήθως χρησιμοποιείται ένα προεπιλεγμένο, οπότε αν πληρούνται και οι άλλες 3 απαιτήσεις, αυτό επίσης ισχύει
* Το παραμόρφωμα διαφέρει ανάλογα με το μήκος του μυστικού+δεδομένων, γι' αυτό χρειάζεται το μήκος του μυστικού

Τότε, είναι δυνατό για έναν **επιτιθέμενο** να **προσθέσει** **δεδομένα** και να **δημιουργήσει** μια έγκυρη **υπογραφή** για τα **προηγούμενα δεδομένα + προσθεμένα δεδομένα**.

## Πώς;

Βασικά, οι ευάλωτοι αλγόριθμοι δημιουργούν τα κατακερματισμένα δεδομένα αρχικά κατακερματίζοντας ένα μπλοκ δεδομένων και στη συνέχεια, από το προηγούμενο δημιουργημένο κατακερματισμένο δεδομένο (κατάσταση), προσθέτουν το επόμενο μπλοκ δεδομένων και το κατακερματίζουν.

Έπειτα, φανταστείτε ότι το μυστικό είναι "μυστικό" και τα δεδομένα είναι "δεδομένα", το MD5 του "μυστικόδεδομένα" είναι 6036708eba0d11f6ef52ad44e8b74d5b.\
Εάν ένας επιτιθέμενος θέλει να προσθέσει τον χαρακτήρα "προσθήκη" μπορεί:

* Να δημιουργήσει ένα MD5 από 64 "Α"
* Να αλλάξει την κατάσταση του προηγουμένως αρχικοποιημένου κατακερματισμένου δεδομένου σε 6036708eba0d11f6ef52ad44e8b74d5b
* Να προσθέσει τον χαρακτήρα "προσθήκη"
* Να ολοκληρώσει τον κατακερματισμό και το αποτέλεσμα θα είναι μια **έγκυρη υπογραφή για το "μυστικό" + "δεδομένα" + "παραμόρφωμα" + "προσθήκη"**

## **Εργαλείο**

{% embed url="https://github.com/iagox86/hash_extender" %}

## Αναφορές

Μπορείτε να βρείτε αυτήν την επίθεση καλά εξηγημένη στο [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)


<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του
