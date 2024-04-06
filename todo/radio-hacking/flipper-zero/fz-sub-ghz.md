# FZ - Sub-GHz

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>

**Try Hard Security Group**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/gr/todo/radio-hacking/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Εισαγωγή <a href="#kfpn7" id="kfpn7"></a>

Το Flipper Zero μπορεί **να λαμβάνει και να μεταδίδει ραδιοσυχνότητες στο εύρος 300-928 MHz** με το ενσωματωμένο του μοντούλο, ο οποίος μπορεί να διαβάσει, να αποθηκεύσει και να προσομοιώσει τηλεχειρισμούς. Αυτοί οι τηλεχειρισμοί χρησιμοποιούνται για την αλληλεπίδραση με πύλες, φράχτες, ραδιοκλειδαριές, διακόπτες τηλεχειρισμού, ασύρματα κουδούνια πορτών, έξυπνα φώτα και άλλα. Το Flipper Zero μπορεί να σας βοηθήσει να μάθετε αν η ασφάλειά σας έχει παραβιαστεί.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Υλικό Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Το Flipper Zero διαθέτει ενσωματωμένο υπο-1 GHz μοντούλο βασισμένο σε ένα [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿τσιπ CC1101]\(https://www.ti.com/lit/ds/symlink/cc1101.pdf) και μια ραδιοκεραία (η μέγιστη εμβέλεια είναι 50 μέτρα). Τόσο το τσιπ CC1101 όσο και η κεραία είναι σχεδιασμένα να λειτουργούν σε συχνότητες στα εύρη 300-348 MHz, 387-464 MHz και 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Αναλυτής Συχνοτήτων

{% hint style="info" %}
Πώς να βρείτε ποια συχνότητα χρησιμοποιεί το τηλεχειριστήριο
{% endhint %}

Κατά την ανάλυση, το Flipper Zero σαρώνει την ισχύ των σημάτων (RSSI) σε όλες τις διαθέσιμες συχνότητες στη ρύθμιση συχνοτήτων. Το Flipper Zero εμφανίζει τη συχνότητα με τη μεγαλύτερη τιμή RSSI, με ισχύ σήματος μεγαλύτερη από -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Για να προσδιορίσετε τη συχνότητα του τηλεχειριστηρίου, κάντε τα εξής:

1. Τοποθετήστε το τηλεχειριστήριο πολύ κοντά στα αριστερά του Flipper Zero.
2. Πηγαίνετε στο **Κύριο Μενού** **→ Sub-GHz**.
3. Επιλέξτε **Αναλυτής Συχνοτήτων**, στη συνέχεια πατήστε και κρατήστε πατημένο το κουμπί στο τηλεχειριστήριο που θέλετε να αναλύσετε.
4. Ελέγξτε την τιμή της συχνότητας στην οθόνη.

### Διάβασμα

{% hint style="info" %}
Βρείτε πληροφορίες σχετικά με τη χρησιμοποιούμενη συχνότητα (επίσης άλλος τρόπος να βρείτε ποια συχνότητα χρησιμοποιείται)
{% endhint %}

Η επιλογή **Διάβασμα** **ακούει στην ρυθμισμένη συχνότητα** στην καθορισμένη διαμόρφωση: 433.92 AM από προεπιλογή. Αν **βρεθεί κάτι** κατά τη διάρκεια της ανάγνωσης, **δίνονται πληροφορίες** στην οθόνη. Αυτές οι πληροφορίες μπορεί να χρησιμοποιηθούν για να αναπαραχθεί το σήμα στο μέλλον.

Κατά τη χρήση του Διαβάσματος, είναι δυνατόν να πατήσετε το **αριστερό κουμπί** και να το **ρυθμίσετε**.\
Αυτή τη στιγμή έχει **4 διαμορφώσεις** (AM270, AM650, FM328 και FM476), και **πολλές σχετικές συχνότητες** αποθηκευμένες:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να ορίσετε **οποιαδήποτε σας ενδιαφέρει**, ωστόσο, αν **δεν είστε σίγουροι ποια συχνότητα** μπορεί να είναι αυτή που χρησιμοποιείται από το τηλεχειριστήριο που έχετε, **ρυθμίστε το Hopping σε ON** (απενεργοποιημένο από προεπιλογή) και πατήστε το κουμπί αρκετές φορές μέχρι το Flipper να το αιχμαλωτίσει και να σας δώσει τις πληροφορίες που χρειάζεστε για να ρυθμίσετε τη συχνότητα.

{% hint style="danger" %}
Η μετάβαση μεταξύ συχνοτήτων απαιτεί κάποιο χρόνο, επομένως τα σήματα που μεταδίδονται κατά τη διάρκεια της μετάβασης μπορεί να χαθούν. Για καλύτερη λήψη σήματος, ορίστε μια σταθερή συχνότητα που καθορίζεται από τον Αναλυτή Συχνοτήτων.
{% endhint %}

### **Διάβασμα Raw**

{% hint style="info" %}
Κλέψτε (και επαναλάβετε) ένα σήμα στη ρυθμισμένη συχνότητα
{% endhint %}

Η επιλογή **Διάβασμα Raw** **καταγράφει τα σήματα** που στέλνονται στη συχνότητα ακρόασης. Αυτό μπορεί να χρησιμοποιηθεί για να **κλέψετε** ένα σήμα και να το **επαναλάβετε**.

Από προεπιλογή το **Διάβασμα Raw είναι επίσης στα 433.92 στο AM650**, αλλά αν με την επιλογή Διάβασμα βρήκατε ότι το σήμα που σας ενδιαφέρει είναι σε μια **διαφορετική συχνότητα/διαμόρφωση, μπορείτε επίσης να το τροποποιήσετε** πατώντας αριστερά (ενώ βρίσκεστε μέσα στην επιλογή Διάβασμα Raw).

### Βίαιη Δύναμη

Αν γνωρίζετε το πρωτόκολλο που χρησιμοποιείται για παράδειγμα από την πόρτα του γκαράζ, είναι δυνατόν να **δημιουργήσετε όλους τους κωδικούς και να τους στείλετε με το Flipper Zero.** Αυτό είναι ένα παράδειγμα που υποστηρίζει γενικά κοινούς τύπους γκαράζ: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Προσθήκη Χειροκίνητα

{% hint style="info" %}
Προσθέστε σήματα από μια ρυθμισμένη λίστα πρωτοκόλλων
{% endhint %}

#### Λίστα των [υποστηριζόμενων πρωτοκόλλων](https://docs.flipperzero.one/sub-ghz/add-new-remote) \<a href="#id-3iglu" id="id-3iglu

### Υποστηριζόμενοι προμηθευτές Sub-GHz

Ελέγξτε τη λίστα στο [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Υποστηριζόμενες συχνότητες ανά περιοχή

Ελέγξτε τη λίστα στο [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Τεστ

{% hint style="info" %}
Λάβετε τα dBms των αποθηκευμένων συχνοτήτων
{% endhint %}

## Αναφορά

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Try Hard Security Group**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/gr/todo/radio-hacking/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
