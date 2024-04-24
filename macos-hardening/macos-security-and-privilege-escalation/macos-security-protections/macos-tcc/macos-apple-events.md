# macOS Apple Events

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

**Τα Apple Events** είναι μια λειτουργία στο macOS της Apple που επιτρέπει σε εφαρμογές να επικοινωνούν μεταξύ τους. Αυτά αποτελούν μέρος του **Apple Event Manager**, το οποίο είναι ένα στοιχείο του λειτουργικού συστήματος macOS που είναι υπεύθυνο για την χειρισμό της διαδικασίας επικοινωνίας μεταξύ διεργασιών. Αυτό το σύστημα επιτρέπει σε μια εφαρμογή να στείλει ένα μήνυμα σε μια άλλη εφαρμογή για να ζητήσει να εκτελέσει μια συγκεκριμένη λειτουργία, όπως το άνοιγμα ενός αρχείου, την ανάκτηση δεδομένων ή την εκτέλεση ενός εντολής.

Το δαίμονα mina είναι το `/System/Library/CoreServices/appleeventsd` το οποίο εγγράφει την υπηρεσία `com.apple.coreservices.appleevents`.

Κάθε εφαρμογή που μπορεί να λαμβάνει events θα ελέγχει με αυτό το δαίμονα παρέχοντας την Apple Event Mach Port της. Και όταν μια εφαρμογή θέλει να στείλει ένα event σε αυτό, η εφαρμογή θα ζητήσει αυτή τη θύρα από το δαίμονα.

Οι εφαρμογές που έχουν τεθεί σε αμμοβολίο απαιτούν προνόμια όπως το `allow appleevent-send` και `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` για να μπορούν να στέλνουν events. Σημειώστε ότι τα entitlements όπως το `com.apple.security.temporary-exception.apple-events` μπορεί να περιορίσουν ποιος έχει πρόσβαση για να στέλνει events, τα οποία θα χρειαστούν entitlements όπως το `com.apple.private.appleevents`.

{% hint style="success" %}
Είναι δυνατόν να χρησιμοποιηθεί η μεταβλητή περιβάλλοντος **`AEDebugSends`** για να καταγράφει πληροφορίες σχετικά με το μήνυμα που στάλθηκε:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
