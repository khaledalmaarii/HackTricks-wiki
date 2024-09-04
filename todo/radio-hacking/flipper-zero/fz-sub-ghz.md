# FZ - Sub-GHz

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Εισαγωγή <a href="#kfpn7" id="kfpn7"></a>

Το Flipper Zero μπορεί να **λαμβάνει και να μεταδίδει ραδιοσυχνότητες στην περιοχή των 300-928 MHz** με το ενσωματωμένο του module, το οποίο μπορεί να διαβάσει, να αποθηκεύσει και να μιμηθεί τηλεχειριστήρια. Αυτά τα τηλεχειριστήρια χρησιμοποιούνται για αλληλεπίδραση με πύλες, φράγματα, ραδιοκλειδώματα, διακόπτες τηλεχειρισμού, ασύρματα κουδούνια, έξυπνα φώτα και άλλα. Το Flipper Zero μπορεί να σας βοηθήσει να μάθετε αν η ασφάλειά σας έχει παραβιαστεί.

<figure><img src="../../../.gitbook/assets/image (714).png" alt=""><figcaption></figcaption></figure>

## Υλικό Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Το Flipper Zero διαθέτει ένα ενσωματωμένο υπο-module 1 GHz βασισμένο σε [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[τσιπ CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) και μια ραδιοκεραία (η μέγιστη εμβέλεια είναι 50 μέτρα). Τanto το τσιπ CC1101 όσο και η κεραία έχουν σχεδιαστεί για να λειτουργούν σε συχνότητες στις ζώνες 300-348 MHz, 387-464 MHz και 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Αναλυτής Συχνότητας

{% hint style="info" %}
Πώς να βρείτε ποια συχνότητα χρησιμοποιεί το τηλεχειριστήριο
{% endhint %}

Κατά την ανάλυση, το Flipper Zero σαρώνει την ισχύ των σημάτων (RSSI) σε όλες τις διαθέσιμες συχνότητες στη ρύθμιση συχνότητας. Το Flipper Zero εμφανίζει τη συχνότητα με την υψηλότερη τιμή RSSI, με ισχύ σήματος μεγαλύτερη από -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Για να προσδιορίσετε τη συχνότητα του τηλεχειριστηρίου, κάντε τα εξής:

1. Τοποθετήστε το τηλεχειριστήριο πολύ κοντά στα αριστερά του Flipper Zero.
2. Μεταβείτε στο **Κύριο Μενού** **→ Sub-GHz**.
3. Επιλέξτε **Αναλυτής Συχνότητας**, στη συνέχεια πατήστε και κρατήστε το κουμπί στο τηλεχειριστήριο που θέλετε να αναλύσετε.
4. Ελέγξτε την τιμή της συχνότητας στην οθόνη.

### Ανάγνωση

{% hint style="info" %}
Βρείτε πληροφορίες σχετικά με τη συχνότητα που χρησιμοποιείται (επίσης ένας άλλος τρόπος για να βρείτε ποια συχνότητα χρησιμοποιείται)
{% endhint %}

Η επιλογή **Ανάγνωση** **ακούει στη ρυθμισμένη συχνότητα** στην υποδεικνυόμενη διαμόρφωση: 433.92 AM από προεπιλογή. Εάν **βρεθεί κάτι** κατά την ανάγνωση, **παρέχονται πληροφορίες** στην οθόνη. Αυτές οι πληροφορίες θα μπορούσαν να χρησιμοποιηθούν για να αναπαραχθεί το σήμα στο μέλλον.

Ενώ η Ανάγνωση είναι σε χρήση, είναι δυνατή η πίεση του **αριστερού κουμπιού** και **ρύθμισή του**.\
Αυτή τη στιγμή έχει **4 διαμορφώσεις** (AM270, AM650, FM328 και FM476), και **πολλές σχετικές συχνότητες** αποθηκευμένες:

<figure><img src="../../../.gitbook/assets/image (947).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να ρυθμίσετε **οποιαδήποτε σας ενδιαφέρει**, ωστόσο, αν **δεν είστε σίγουροι ποια συχνότητα** θα μπορούσε να είναι αυτή που χρησιμοποιεί το τηλεχειριστήριο που έχετε, **ρυθμίστε το Hopping σε ON** (Απενεργοποιημένο από προεπιλογή), και πατήστε το κουμπί αρκετές φορές μέχρι το Flipper να την καταγράψει και να σας δώσει τις πληροφορίες που χρειάζεστε για να ρυθμίσετε τη συχνότητα.

{% hint style="danger" %}
Η εναλλαγή μεταξύ συχνοτήτων απαιτεί κάποιο χρόνο, επομένως τα σήματα που μεταδίδονται κατά την εναλλαγή μπορεί να χαθούν. Για καλύτερη λήψη σήματος, ρυθμίστε μια σταθερή συχνότητα που καθορίζεται από τον Αναλυτή Συχνότητας.
{% endhint %}

### **Ανάγνωση Ακατέργαστου Σήματος**

{% hint style="info" %}
Κλέψτε (και επαναλάβετε) ένα σήμα στη ρυθμισμένη συχνότητα
{% endhint %}

Η επιλογή **Ανάγνωση Ακατέργαστου Σήματος** **καταγράφει σήματα** που αποστέλλονται στη συχνότητα λήψης. Αυτό μπορεί να χρησιμοποιηθεί για να **κλέψετε** ένα σήμα και να το **επαναλάβετε**.

Από προεπιλογή, η **Ανάγνωση Ακατέργαστου Σήματος είναι επίσης σε 433.92 AM650**, αλλά αν με την επιλογή Ανάγνωσης βρήκατε ότι το σήμα που σας ενδιαφέρει είναι σε **διαφορετική συχνότητα/διαμόρφωση, μπορείτε επίσης να το τροποποιήσετε** πατώντας αριστερά (εντός της επιλογής Ανάγνωσης Ακατέργαστου Σήματος).

### Βίαιη Δοκιμή

Εάν γνωρίζετε το πρωτόκολλο που χρησιμοποιείται για παράδειγμα από την πόρτα του γκαράζ, είναι δυνατό να **δημιουργήσετε όλους τους κωδικούς και να τους στείλετε με το Flipper Zero.** Αυτό είναι ένα παράδειγμα που υποστηρίζει γενικούς κοινούς τύπους γκαράζ: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Προσθήκη Χειροκίνητα

{% hint style="info" %}
Προσθέστε σήματα από μια ρυθμισμένη λίστα πρωτοκόλλων
{% endhint %}

#### Λίστα [υποστηριζόμενων πρωτοκόλλων](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433 (λειτουργεί με την πλειονότητα των στατικών συστημάτων κωδικών) | 433.92 | Στατικός  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Στατικός  |
| Nice Flo 24bit\_433                                             | 433.92 | Στατικός  |
| CAME 12bit\_433                                                 | 433.92 | Στατικός  |
| CAME 24bit\_433                                                 | 433.92 | Στατικός  |
| Linear\_300                                                     | 300.00 | Στατικός  |
| CAME TWEE                                                       | 433.92 | Στατικός  |
| Gate TX\_433                                                    | 433.92 | Στατικός  |
| DoorHan\_315                                                    | 315.00 | Δυναμικός |
| DoorHan\_433                                                    | 433.92 | Δυναμικός |
| LiftMaster\_315                                                 | 315.00 | Δυναμικός |
| LiftMaster\_390                                                 | 390.00 | Δυναμικός |
| Security+2.0\_310                                               | 310.00 | Δυναμικός |
| Security+2.0\_315                                               | 315.00 | Δυναμικός |
| Security+2.0\_390                                               | 390.00 | Δυναμικός |

### Υποστηριζόμενοι προμηθευτές Sub-GHz

Ελέγξτε τη λίστα στο [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Υποστηριζόμενες συχνότητες ανά περιοχή

Ελέγξτε τη λίστα στο [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Δοκιμή

{% hint style="info" %}
Λάβετε dBms των αποθηκευμένων συχνοτήτων
{% endhint %}

## Αναφορά

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
