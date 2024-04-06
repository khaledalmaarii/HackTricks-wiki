# FZ - 125kHz RFID

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Εισαγωγή

Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργούν οι ετικέτες 125kHz, ελέγξτε:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Ενέργειες

Για περισσότερες πληροφορίες σχετικά με αυτούς τους τύπους ετικετών [**διαβάστε αυτήν την εισαγωγή**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Ανάγνωση

Προσπαθεί να **διαβάσει** τις πληροφορίες της κάρτας. Στη συνέχεια, μπορεί να τις **εμούλευσει**.

{% hint style="warning" %}
Σημειώστε ότι ορισμένα συστήματα ασφαλείας προσπαθούν να προστατευθούν από την αντιγραφή κλειδιού αποστέλλοντας μια εντολή εγγραφής πριν από την ανάγνωση. Εάν η εγγραφή είναι επιτυχής, αυτή η ετικέτα θεωρείται ψεύτικη. Όταν το Flipper εμούλευσει RFID, δεν υπάρχει τρόπος για τον αναγνώστη να το διακρίνει από το αρχικό, οπότε δεν υπάρχουν τέτοια προβλήματα.
{% endhint %}

### Προσθήκη Χειροκίνητα

Μπορείτε να δημιουργήσετε **ψεύτικες κάρτες στο Flipper Zero δηλώνοντας τα δεδομένα** χειροκίνητα και στη συνέχεια να τις εμούλευσετε.

#### Αναγνωριστικά στις κάρτες

Μερικές φορές, όταν πάρετε μια κάρτα, θα βρείτε το αναγνωριστικό (ή μέρος του) γραμμένο στην ορατή πλευρά της κάρτας.

* **EM Marin**

Για παράδειγμα, σε αυτήν την κάρτα EM-Marin, στη φυσική κάρτα είναι δυνατόν να **διαβάσετε τα τελευταία 3 από τα 5 bytes καθαρά**.\
Τα άλλα 2 μπορούν να ανακτηθούν με βίαιο τρόπο εάν δεν μπορείτε να τα διαβάσετε από την κάρτα.

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

* **HID**

Το ίδιο συμβαίνει και σε αυτήν την κάρτα HID, όπου μόνο 2 από τα 3 bytes μπορούν να βρεθούν εκτυπωμένα στην κάρτα

<figure><img src="../../../.gitbook/assets/image (15) (3).png" alt=""><figcaption></figcaption></figure>

### Εμούλευση/Εγγραφή

Μετά την **αντιγραφή** μιας κάρτας ή την **εισαγωγή** του αναγνωριστικού **χειροκίνητα**, είναι δυνατόν να την **εμούλευσετε** με το Flipper Zero ή να την **εγγράψετε** σε μια πραγματική κάρτα.

## Αναφορές

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
