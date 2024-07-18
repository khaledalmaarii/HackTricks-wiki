# macOS Εισαγωγή Chromium

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ κάνοντας υποβολή PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Βασικές Πληροφορίες

Οι περιηγητές βασισμένοι στο Chromium όπως το Google Chrome, το Microsoft Edge, το Brave και άλλοι. Αυτοί οι περιηγητές είναι χτισμένοι πάνω στο έργο ανοικτού κώδικα του Chromium, που σημαίνει ότι μοιράζονται ένα κοινό βασικό και, συνεπώς, έχουν παρόμοιες λειτουργίες και επιλογές προγραμματιστή.

#### Σημαία `--load-extension`

Η σημαία `--load-extension` χρησιμοποιείται κατά την εκκίνηση ενός περιηγητή βασισμένου στο Chromium από τη γραμμή εντολών ή ένα σενάριο. Αυτή η σημαία επιτρέπει την **αυτόματη φόρτωση ενός ή περισσότερων επεκτάσεων** στον περιηγητή κατά την εκκίνηση.

#### Σημαία `--use-fake-ui-for-media-stream`

Η σημαία `--use-fake-ui-for-media-stream` είναι μια άλλη επιλογή γραμμής εντολών που μπορεί να χρησιμοποιηθεί για την εκκίνηση περιηγητών βασισμένων στο Chromium. Αυτή η σημαία είναι σχεδιασμένη για την **παράκαμψη των κανονικών προτροπών χρήστη που ζητούν άδεια πρόσβασης σε ροές πολυμέσων από την κάμερα και το μικρόφωνο**. Όταν χρησιμοποιείται αυτή η σημαία, ο περιηγητής χορηγεί αυτόματα άδεια σε οποιονδήποτε ιστότοπο ή εφαρμογή ζητά πρόσβαση στην κάμερα ή το μικρόφωνο.

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

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
