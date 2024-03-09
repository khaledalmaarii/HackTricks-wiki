# FZ - NFC

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε τη [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στη [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Εισαγωγή <a href="#9wrzi" id="9wrzi"></a>

Για πληροφορίες σχετικά με τα RFID και NFC ελέγξτε την ακόλουθη σελίδα:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Υποστηριζόμενες κάρτες NFC <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Εκτός από τις κάρτες NFC, το Flipper Zero υποστηρίζει **άλλους τύπους καρτών υψηλής συχνότητας** όπως διάφορες κάρτες **Mifare** Classic και Ultralight και **NTAG**.
{% endhint %}

Νέοι τύποι καρτών NFC θα προστεθούν στη λίστα των υποστηριζόμενων καρτών. Το Flipper Zero υποστηρίζει τις ακόλουθες **κάρτες NFC τύπου A** (ISO 14443A):

* ﻿**Τραπεζικές κάρτες (EMV)** — διαβάζει μόνο το UID, το SAK και το ATQA χωρίς αποθήκευση.
* ﻿**Άγνωστες κάρτες** — διαβάζει (UID, SAK, ATQA) και εμμονεύει ένα UID.

Για τις **κάρτες NFC τύπου B, τύπου F και τύπου V**, το Flipper Zero μπορεί να διαβάσει ένα UID χωρίς να το αποθηκεύσει.

### Κάρτες NFC τύπου A <a href="#uvusf" id="uvusf"></a>

#### Τραπεζική κάρτα (EMV) <a href="#kzmrp" id="kzmrp"></a>

Το Flipper Zero μπορεί μόνο να διαβάσει ένα UID, SAK, ATQA και αποθηκευμένα δεδομένα σε τραπεζικές κάρτες **χωρίς αποθήκευση**.

Οθόνη ανάγνωσης τραπεζικής κάρταςΓια τις τραπεζικές κάρτες, το Flipper Zero μπορεί μόνο να διαβάσει δεδομένα **χωρίς αποθήκευση και εμμονεύει τα**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Άγνωστες κάρτες <a href="#37eo8" id="37eo8"></a>

Όταν το Flipper Zero **δεν μπορεί να καθορίσει τον τύπο της κάρτας NFC**, τότε μόνο ένα **UID, SAK και ATQA** μπορούν να **διαβαστούν και αποθηκευτούν**.

Οθόνη ανάγνωσης άγνωστης κάρταςΓια άγνωστες κάρτες NFC, το Flipper Zero μπορεί να εμμονεύσει μόνο ένα UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Κάρτες NFC τύπων B, F και V <a href="#wyg51" id="wyg51"></a>

Για τις **κάρτες NFC τύπων B, F και V**, το Flipper Zero μπορεί μόνο να **διαβάσει και να εμφανίσει ένα UID** χωρίς να το αποθηκεύσει.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Ενέργειες

Για μια εισαγωγή σχετικά με τα NFC [**διαβάστε αυτήν τη σελίδα**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Διάβασμα

Το Flipper Zero μπορεί να **διαβάσει κάρτες NFC**, ωστόσο, **δεν κατανοεί όλα τα πρωτόκολλα** που βασίζονται στο ISO 14443. Ωστόσο, επειδή το **UID είναι ένα χαμηλού επιπέδου χαρακτηριστικό**, μπορείτε να βρεθείτε σε μια κατάσταση όπου το **UID έχει ήδη διαβαστεί, αλλά το πρωτόκολλο μεταφοράς δεδομένων υψηλού επιπέδου είναι ακόμα άγνωστο**. Μπορείτε να διαβάσετε, να εμμονεύσετε και να εισαγάγετε χειροκίνητα το UID χρησιμοποιώντας το Flipper για τους αρχέγονους αναγνώστες που χρησιμοποιούν το UID για την εξουσιοδότηση.

#### Διάβασμα του UID ΕΝΑΝΤΙ Διάβασμα των Δεδομένων Μέσα <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Στο Flipper, το διάβασμα ετικετών 13,56 MHz μπορεί να διαιρεθεί σε δύο μέρη:

* **Χαμηλού επιπέδου διάβασμα** — διαβάζει μόνο το UID, το SAK και το ATQA. Το Flipper προσπαθεί να μαντέψει το πρωτόκολλο υψηλού επιπέδου με βάση αυτά τα δεδομένα που διαβάζονται από την κάρτα. Δεν μπορείτε να είστε 100% σίγουροι με αυτό, καθώς είναι απλώς υπόθεση βασισμένη σε συγκεκριμένους παράγοντες.
* **Υψηλού επιπέδου διάβασμα** — διαβάζει τα δεδομένα από τη μνήμη της κάρτας χρησιμοποιώντας ένα συγκεκριμένο πρωτόκολλο υψηλού επιπέδου. Αυτό θα ήταν το διάβασμα των δεδομένων σε ένα Mifare Ultralight, το διάβασμα των τομέων από ένα Mifare Classic ή τα χαρακτηριστικά της κάρτας από PayPass/Apple Pay.

### Διάβασμα Συγκεκριμένου

Σε περίπτωση που το Flipper Zero δεν είναι ικανό να βρει τον τύπο της κάρτας από τα δεδομένα χαμηλού επιπέδου, στο `Επιπλέον Ενέργειες` μπορείτε να επιλέξετε `Διάβασμα Συγκεκριμένου Τύπου Κάρτας` και **να υποδείξετε χειροκίνητα τον τύπο κάρτας που θα θέλατε να διαβάσετε**.

#### Τραπεζικές Κάρτες EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Εκτός από το απλό διάβασμα του UID, μπορείτε να εξάγετε πολλά περισσότερα δεδομένα από μια τραπεζική κάρτα. Είναι δυνατόν να **πάρετε τον πλήρη αριθμό της κάρτας** (τα 16 ψηφία στο μπροστινό μέρος της κάρτας), την **ημερομηνία λήξης**, και σε κάποιες περιπτώσεις ακόμα και το **όνομα του ιδιοκτήτη** μαζί με μια λίστα των **πιο πρόσφατων συναλλαγών**.\
Ωστόσο, **δεν μπορείτε να διαβάσετε το CVV με αυτόν τον τρό
## Αναφορές

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρός Ομάδας HackTricks AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε τη **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στη **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγράφημα**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
