# FZ - NFC

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από APIs έως web εφαρμογές και συστήματα cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Εισαγωγή <a href="#9wrzi" id="9wrzi"></a>

Για πληροφορίες σχετικά με το RFID και το NFC, ελέγξτε την παρακάτω σελίδα:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Υποστηριζόμενες κάρτες NFC <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Εκτός από τις κάρτες NFC, το Flipper Zero υποστηρίζει **άλλους τύπους καρτών υψηλής συχνότητας** όπως ορισμένες κάρτες **Mifare** Classic και Ultralight και **NTAG**.
{% endhint %}

Νέοι τύποι καρτών NFC θα προστεθούν στη λίστα των υποστηριζόμενων καρτών. Το Flipper Zero υποστηρίζει τους ακόλουθους **τύπους καρτών NFC A** (ISO 14443A):

* ﻿**Τραπεζικές κάρτες (EMV)** - μόνο ανάγνωση UID, SAK και ATQA χωρίς αποθήκευση.
* ﻿**Άγνωστες κάρτες** - ανάγνωση (UID, SAK, ATQA) και εξομοίωση ενός UID.

Για τους **τύπους καρτών NFC B, F και V**, το Flipper Zero μπορεί να διαβάσει ένα UID χωρίς να το αποθηκεύσει.

### Τύπος καρτών NFC A <a href="#uvusf" id="uvusf"></a>

#### Τραπεζική κάρτα (EMV) <a href="#kzmrp" id="kzmrp"></a>

Το Flipper Zero μπορεί μόνο να διαβάσει ένα UID, SAK, ATQA και αποθηκευμένα δεδομένα σε τραπεζικές κάρτες **χωρίς αποθήκευση**.

Οθόνη ανάγνωσης τραπεζικής κάρταςΓια τις τραπεζικές κάρτες, το Flipper Zero μπορεί μόνο να διαβάσει δεδομένα **χωρίς αποθήκευση και εξομοίωση**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Άγνωστες κάρτες <a href="#37eo8" id="37eo8"></a>

Όταν το Flipper Zero είναι **αδύνατο να προσδιορίσει τον τύπο της κάρτας NFC**, τότε μόνο ένα **UID, SAK και ATQA** μπορούν να διαβαστούν και να αποθηκευτούν.

Οθόνη ανάγνωσης άγνωστης κάρταςΓια άγνωστες κάρτες NFC, το Flipper Zero μπορεί να εξομοιώσει μόνο ένα UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9
#### Κάρτες Τραπέζης EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Εκτός από το απλό διάβασμα του UID, μπορείτε να εξάγετε πολλά περισσότερα δεδομένα από μια τραπεζική κάρτα. Είναι δυνατόν να **πάρετε τον πλήρη αριθμό της κάρτας** (τα 16 ψηφία στο μπροστινό μέρος της κάρτας), τη **ημερομηνία λήξης** και σε ορισμένες περιπτώσεις ακόμα και το **όνομα του κατόχου** μαζί με μια λίστα των **πιο πρόσφατων συναλλαγών**.\
Ωστόσο, **δεν μπορείτε να διαβάσετε τον CVV με αυτόν τον τρόπο** (τα 3 ψηφία στο πίσω μέρος της κάρτας). Επίσης, οι **τραπεζικές κάρτες προστατεύονται από επαναληπτικές επιθέσεις**, οπότε η αντιγραφή τους με το Flipper και η προσπάθεια εξομοίωσής τους για πληρωμή δεν θα λειτουργήσει.

## Αναφορές

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν πραγματική σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από APIs έως ιστοσελίδες και συστήματα στον νέφος. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
