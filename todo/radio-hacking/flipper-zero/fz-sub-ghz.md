# FZ - Sub-GHz

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από τις διεπαφές προς τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Εισαγωγή <a href="#kfpn7" id="kfpn7"></a>

Το Flipper Zero μπορεί να **λαμβάνει και να μεταδίδει ραδιοσυχνότητες στο εύρος 300-928 MHz** με το ενσωματωμένο του ενότητα, η οποία μπορεί να διαβάσει, να αποθηκεύσει και να προσομοιώσει απομακρυσμένους ελέγχους. Αυτοί οι ελέγχοι χρησιμοποιούνται για την αλληλεπίδραση με πύλες, φραγές, ραδιοκλειδαριές, διακόπτες απομακρυσμένου ελέγχου, ασύρματες κουδούνες, έξυπνα φώτα και άλλα. Το Flipper Zero μπορεί να σας βοηθήσει να μάθετε αν η ασφάλειά σας έχει παραβιαστεί.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Υλικό Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Το Flipper Zero διαθέτει ενσωματωμένη μονάδα sub-1 GHz βασισμένη σε ένα [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[τσιπ CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf) και μια ραδιοκεραία (η μέγιστη εμβέλεια είναι 50 μέτρα). Τόσο το τσιπ CC1101 όσο και η κεραία είναι σχεδιασμένα για να λειτουργούν σε συχνότητες στα εύρη 300-348 MHz, 387-464 MHz και 779-928 MHz.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Αναλυτής Συχνοτήτων

{% hint style="info" %}
Πώς να βρείτε ποια συχνότητα χρησιμοποιεί ο απομακρυσμένος ελεγκτής
{% endhint %}

Κατά την ανάλυση, το Flipper Zero σαρώνει την ισχύ των σημάτων (RSSI) σε όλες τις διαθέσιμες συχνότητες στη ρύθμιση της συχνότητας. Το Flipper Zero εμφανίζει τη συχνότητα με την υψηλότερη τιμή RSSI, με ισχύ σήματος μεγαλύτερη από -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Για να προσδιορίσετε τη συχνότητα του απομακρυσμένου ελεγκτή, ακολουθήστε τα παρακάτω βήματα:

1. Τοποθετήστε τον απομακρυσμένο ελεγκτή πολύ κοντά στα αρισ
### Υποστηριζόμενοι προμηθευτές Sub-GHz

Ελέγξτε τη λίστα στο [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Υποστηριζόμενες συχνότητες ανά περιοχή

Ελέγξτε τη λίστα στο [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Έλεγχος

{% hint style="info" %}
Πάρτε τα dBms των αποθηκευμένων συχνοτήτων
{% endhint %}

## Αναφορά

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από τις διεπαφές προς τις ιστοσελίδες και τα συστήματα cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm_source=referral&utm_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
