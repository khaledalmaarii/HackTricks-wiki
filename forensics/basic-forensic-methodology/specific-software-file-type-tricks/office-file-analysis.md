# Ανάλυση αρχείων Office

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

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Για περισσότερες πληροφορίες, ελέγξτε το [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτό είναι απλώς μια περίληψη:

Η Microsoft έχει δημιουργήσει πολλούς τύπους εγγράφων office, με δύο κύριους τύπους να είναι οι **μορφές OLE** (όπως RTF, DOC, XLS, PPT) και οι **μορφές Office Open XML (OOXML)** (όπως DOCX, XLSX, PPTX). Αυτές οι μορφές μπορούν να περιλαμβάνουν μακροεντολές, καθιστώντας τις στόχους για phishing και κακόβουλο λογισμικό. Τα αρχεία OOXML είναι δομημένα ως zip containers, επιτρέποντας την επιθεώρηση μέσω αποσυμπίεσης, αποκαλύπτοντας τη δομή αρχείων και φακέλων και το περιεχόμενο αρχείων XML.

Για να εξερευνήσετε τις δομές αρχείων OOXML, παρέχονται η εντολή για την αποσυμπίεση ενός εγγράφου και η δομή εξόδου. Τεχνικές για την απόκρυψη δεδομένων σε αυτά τα αρχεία έχουν τεκμηριωθεί, υποδεικνύοντας συνεχιζόμενη καινοτομία στην απόκρυψη δεδομένων εντός προκλήσεων CTF.

Για ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα εργαλεία για την εξέταση τόσο των εγγράφων OLE όσο και των OOXML. Αυτά τα εργαλεία βοηθούν στην αναγνώριση και ανάλυση ενσωματωμένων μακροεντολών, οι οποίες συχνά χρησιμεύουν ως διαδρομές για την παράδοση κακόβουλου λογισμικού, συνήθως κατεβάζοντας και εκτελώντας επιπλέον κακόβουλα φορτία. Η ανάλυση των VBA μακροεντολών μπορεί να διεξαχθεί χωρίς Microsoft Office χρησιμοποιώντας το Libre Office, το οποίο επιτρέπει την αποσφαλμάτωση με σημεία διακοπής και παρακολουθούμενες μεταβλητές.

Η εγκατάσταση και η χρήση των **oletools** είναι απλή, με εντολές που παρέχονται για την εγκατάσταση μέσω pip και την εξαγωγή μακροεντολών από έγγραφα. Η αυτόματη εκτέλεση μακροεντολών ενεργοποιείται από συναρτήσεις όπως `AutoOpen`, `AutoExec` ή `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
