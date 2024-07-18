# FZ - NFC

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

## Εισαγωγή <a href="#id-9wrzi" id="id-9wrzi"></a>

Για πληροφορίες σχετικά με RFID και NFC, ελέγξτε την παρακάτω σελίδα:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Υποστηριζόμενες κάρτες NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Εκτός από τις κάρτες NFC, το Flipper Zero υποστηρίζει **άλλους τύπους καρτών Υψηλής συχνότητας** όπως αρκετές **Mifare** Classic και Ultralight και **NTAG**.
{% endhint %}

Νέοι τύποι καρτών NFC θα προστεθούν στη λίστα των υποστηριζόμενων καρτών. Το Flipper Zero υποστηρίζει τους εξής **τύπους καρτών NFC A** (ISO 14443A):

* ﻿**Κάρτες τραπέζης (EMV)** — διαβάζει μόνο UID, SAK και ATQA χωρίς αποθήκευση.
* ﻿**Άγνωστες κάρτες** — διαβάζει (UID, SAK, ATQA) και προσομοιώνει ένα UID.

Για **τύπους καρτών NFC B, F και V**, το Flipper Zero μπορεί να διαβάσει ένα UID χωρίς να το αποθηκεύσει.

### Τύποι καρτών NFC A <a href="#uvusf" id="uvusf"></a>

#### Κάρτα τραπέζης (EMV) <a href="#kzmrp" id="kzmrp"></a>

Το Flipper Zero μπορεί να διαβάσει μόνο ένα UID, SAK, ATQA και αποθηκευμένα δεδομένα σε κάρτες τραπέζης **χωρίς αποθήκευση**.

Οθόνη ανάγνωσης κάρτας τραπέζηςΓια τις κάρτες τραπέζης, το Flipper Zero μπορεί να διαβάσει μόνο δεδομένα **χωρίς αποθήκευση και προσομοίωση**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Άγνωστες κάρτες <a href="#id-37eo8" id="id-37eo8"></a>

Όταν το Flipper Zero είναι **ανίκανο να προσδιορίσει τον τύπο της κάρτας NFC**, τότε μόνο ένα **UID, SAK και ATQA** μπορούν να **διαβαστούν και να αποθηκευτούν**.

Οθόνη ανάγνωσης άγνωστης κάρταςΓια άγνωστες κάρτες NFC, το Flipper Zero μπορεί να προσομοιώσει μόνο ένα UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Τύποι καρτών NFC B, F και V <a href="#wyg51" id="wyg51"></a>

Για **τύπους καρτών NFC B, F και V**, το Flipper Zero μπορεί μόνο να **διαβάσει και να εμφανίσει ένα UID** χωρίς αποθήκευση.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Ενέργειες

Για μια εισαγωγή σχετικά με το NFC [**διαβάστε αυτή τη σελίδα**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Ανάγνωση

Το Flipper Zero μπορεί να **διαβάσει κάρτες NFC**, ωστόσο, **δεν κατανοεί όλα τα πρωτόκολλα** που βασίζονται στο ISO 14443. Ωστόσο, καθώς το **UID είναι μια χαμηλού επιπέδου ιδιότητα**, μπορεί να βρεθείτε σε μια κατάσταση όπου το **UID έχει ήδη διαβαστεί, αλλά το πρωτόκολλο μεταφοράς δεδομένων υψηλού επιπέδου είναι ακόμα άγνωστο**. Μπορείτε να διαβάσετε, να προσομοιώσετε και να εισάγετε χειροκίνητα το UID χρησιμοποιώντας το Flipper για τους πρωτόγονους αναγνώστες που χρησιμοποιούν το UID για εξουσιοδότηση.

#### Ανάγνωση του UID VS Ανάγνωση των Δεδομένων Μέσα <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

Στο Flipper, η ανάγνωση ετικετών 13.56 MHz μπορεί να χωριστεί σε δύο μέρη:

* **Χαμηλού επιπέδου ανάγνωση** — διαβάζει μόνο το UID, SAK και ATQA. Το Flipper προσπαθεί να μαντέψει το πρωτόκολλο υψηλού επιπέδου με βάση αυτά τα δεδομένα που διαβάστηκαν από την κάρτα. Δεν μπορείτε να είστε 100% σίγουροι με αυτό, καθώς είναι απλώς μια υπόθεση βασισμένη σε ορισμένους παράγοντες.
* **Υψηλού επιπέδου ανάγνωση** — διαβάζει τα δεδομένα από τη μνήμη της κάρτας χρησιμοποιώντας ένα συγκεκριμένο πρωτόκολλο υψηλού επιπέδου. Αυτό θα ήταν η ανάγνωση των δεδομένων σε μια Mifare Ultralight, η ανάγνωση των τομέων από μια Mifare Classic ή η ανάγνωση των χαρακτηριστικών της κάρτας από PayPass/Apple Pay.

### Ανάγνωση Συγκεκριμένου Τύπου

Σε περίπτωση που το Flipper Zero δεν είναι ικανό να βρει τον τύπο της κάρτας από τα δεδομένα χαμηλού επιπέδου, στην `Επιπλέον Ενέργειες` μπορείτε να επιλέξετε `Ανάγνωση Συγκεκριμένου Τύπου Κάρτας` και **χειροκίνητα** **να υποδείξετε τον τύπο της κάρτας που θα θέλατε να διαβάσετε**.

#### Κάρτες Τραπεζών EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Εκτός από την απλή ανάγνωση του UID, μπορείτε να εξάγετε πολύ περισσότερα δεδομένα από μια κάρτα τραπέζης. Είναι δυνατό να **λάβετε τον πλήρη αριθμό της κάρτας** (τους 16 ψηφίους στην μπροστινή πλευρά της κάρτας), **ημερομηνία λήξης**, και σε ορισμένες περιπτώσεις ακόμη και το **όνομα του κατόχου** μαζί με μια λίστα με τις **πιο πρόσφατες συναλλαγές**.\
Ωστόσο, δεν μπορείτε να διαβάσετε το CVV με αυτόν τον τρόπο (τους 3 ψηφίους στην πίσω πλευρά της κάρτας). Επίσης, **οι κάρτες τραπέζης προστατεύονται από επιθέσεις επανάληψης**, οπότε η αντιγραφή τους με το Flipper και στη συνέχεια η προσπάθεια προσομοίωσής τους για να πληρώσετε κάτι δεν θα λειτουργήσει.

## Αναφορές

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

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
