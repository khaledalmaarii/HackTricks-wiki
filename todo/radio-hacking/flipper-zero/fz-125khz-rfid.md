# FZ - 125kHz RFID

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρός Ομάδας AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Εισαγωγή

Για περισσότερες πληροφορίες σχετικά με το πώς λειτουργούν οι ετικέτες 125kHz, ελέγξτε:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Ενέργειες

Για περισσότερες πληροφορίες σχετικά με αυτούς τους τύπους ετικετών [**διαβάστε αυτήν την εισαγωγή**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Διάβασμα

Προσπαθεί να **διαβάσει** τις πληροφορίες της κάρτας. Στη συνέχεια μπορεί να τις **εξομοιώσει**.

{% hint style="warning" %}
Σημειώστε ότι μερικά κουδούνια προσπαθούν να προστατευτούν από την αντιγραφή κλειδιών με την αποστολή εντολής εγγραφής πριν την ανάγνωση. Αν η εγγραφή επιτύχει, αυτή η ετικέτα θεωρείται ψεύτικη. Όταν το Flipper εξομοιώνει RFID, δεν υπάρχει τρόπος για τον αναγνώστη να το διακρίνει από το πρωτότυπο, οπότε δεν υπάρχουν τέτοια προβλήματα.
{% endhint %}

### Προσθήκη Χειροκίνητα

Μπορείτε να δημιουργήσετε **ψεύτικες κάρτες στο Flipper Zero δείχνοντας τα δεδομένα** που εισάγετε χειροκίνητα και στη συνέχεια να τα εξομοιώσετε.

#### IDs στις κάρτες

Κάποιες φορές, όταν πάρετε μια κάρτα, θα βρείτε το ID (ή μέρος) του γραμμένο στην κάρτα ορατό.

* **EM Marin**

Για παράδειγμα, σε αυτήν την κάρτα EM-Marin στη φυσική κάρτα είναι δυνατόν να **διαβάσετε τα τελευταία 3 από τα 5 bytes καθαρά**.\
Τα άλλα 2 μπορούν να αναγνωριστούν με βία αν δεν μπορείτε να τα διαβάσετε από την κάρτα.

<figure><img src="../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

* **HID**

Το ίδιο συμβαίνει σε αυτήν την κάρτα HID όπου μόνο 2 από τα 3 bytes μπορούν να βρεθούν εκτυπωμένα στην κάρτα

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

### Εξομοίωση/Εγγραφή

Μετά το **αντιγράφο** μιας κάρτας ή την **εισαγωγή** του ID **χειροκίνητα**, είναι δυνατόν να την **εξομοιώσετε** με το Flipper Zero ή να την **εγγράψετε** σε μια πραγματική κάρτα.

## Αναφορές

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρός Ομάδας AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
