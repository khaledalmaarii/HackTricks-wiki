# macOS Ενσωμάτωση στο Chromium

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Οι περιηγητές βασισμένοι στο Chromium όπως το Google Chrome, το Microsoft Edge, το Brave και άλλοι. Αυτοί οι περιηγητές είναι χτισμένοι πάνω στο έργο ανοικτού κώδικα του Chromium, που σημαίνει ότι μοιράζονται ένα κοινό βασικό και, συνεπώς, έχουν παρόμοιες λειτουργίες και επιλογές προγραμματιστή.

#### Σημαία `--load-extension`

Η σημαία `--load-extension` χρησιμοποιείται κατά την εκκίνηση ενός περιηγητή βασισμένου στο Chromium από τη γραμμή εντολών ή ένα σενάριο. Αυτή η σημαία επιτρέπει τη **αυτόματη φόρτωση ενός ή περισσότερων επεκτάσεων** στον περιηγητή κατά την εκκίνηση.

#### Σημαία `--use-fake-ui-for-media-stream`

Η σημαία `--use-fake-ui-for-media-stream` είναι μια άλλη επιλογή γραμμής εντολών που μπορεί να χρησιμοποιηθεί για την εκκίνηση περιηγητών βασισμένων στο Chromium. Αυτή η σημαία είναι σχεδιασμένη για να **παρακάμψει τις κανονικές προτροπές χρήστη που ζητούν άδεια πρόσβασης σε ροές πολυμέσων από την κάμερα και το μικρόφωνο**. Όταν χρησιμοποιείται αυτή η σημαία, ο περιηγητής χορηγεί αυτόματα άδεια σε οποιονδήποτε ιστότοπο ή εφαρμογή ζητά πρόσβαση στην κάμερα ή το μικρόφωνο.

### Εργαλεία

* [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
* [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Παράδειγμα
```bash
# Intercept traffic
voodoo intercept -b chrome
```
## Αναφορές

* [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του GitHub.

</details>
