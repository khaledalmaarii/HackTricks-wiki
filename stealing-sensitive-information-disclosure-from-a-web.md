# Κλοπή Αποκάλυψης Ευαίσθητων Πληροφοριών από μια Ιστοσελίδα

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε hacking tricks υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
{% endhint %}

Αν σε κάποιο σημείο βρείτε μια **ιστοσελίδα που παρουσιάζει ευαίσθητες πληροφορίες βασισμένες στη συνεδρία σας**: Ίσως αντανακλά cookies, ή εκτυπώνει ή λεπτομέρειες πιστωτικής κάρτας ή οποιεσδήποτε άλλες ευαίσθητες πληροφορίες, μπορείτε να προσπαθήσετε να τις κλέψετε.\
Εδώ σας παρουσιάζω τους κύριους τρόπους που μπορείτε να δοκιμάσετε να το επιτύχετε:

* [**Παράκαμψη CORS**](pentesting-web/cors-bypass.md): Αν μπορείτε να παρακάμψετε τους κεφαλίδες CORS θα μπορείτε να κλέψετε τις πληροφορίες εκτελώντας αίτηση Ajax για μια κακόβουλη σελίδα.
* [**XSS**](pentesting-web/xss-cross-site-scripting/): Αν βρείτε μια ευπάθεια XSS στη σελίδα μπορείτε να την εκμεταλλευτείτε για να κλέψετε τις πληροφορίες.
* [**Κρεμαστή Σήμανση**](pentesting-web/dangling-markup-html-scriptless-injection/): Αν δεν μπορείτε να εισάγετε ετικέτες XSS ενδέχεται ακόμα να μπορείτε να κλέψετε τις πληροφορίες χρησιμοποιώντας άλλες κανονικές ετικέτες HTML.
* [**Clickjaking**](pentesting-web/clickjacking.md): Αν δεν υπάρχει προστασία ενάντια σε αυτήν την επίθεση, μπορείτε να εξαπατήσετε τον χρήστη ώστε να σας στείλει τα ευαίσθητα δεδομένα (ένα παράδειγμα [εδώ](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε hacking tricks υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
{% endhint %}
