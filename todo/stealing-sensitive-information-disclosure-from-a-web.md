# Κλοπή Ευαίσθητης Πληροφορίας από μια Ιστοσελίδα

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

Αν σε κάποια στιγμή βρείτε μια **ιστοσελίδα που σας παρουσιάζει ευαίσθητες πληροφορίες με βάση τη συνεδρία σας**: Ίσως να αντικατοπτρίζει cookies, ή να εκτυπώνει ή λεπτομέρειες CC ή οποιαδήποτε άλλη ευαίσθητη πληροφορία, μπορείτε να προσπαθήσετε να την κλέψετε.\
Εδώ σας παρουσιάζω τους κύριους τρόπους που μπορείτε να προσπαθήσετε να το πετύχετε:

* [**CORS bypass**](../pentesting-web/cors-bypass.md): Αν μπορείτε να παρακάμψετε τις κεφαλίδες CORS, θα είστε σε θέση να κλέψετε τις πληροφορίες εκτελώντας Ajax αίτημα για μια κακόβουλη σελίδα.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Αν βρείτε μια ευπάθεια XSS στη σελίδα, μπορεί να είστε σε θέση να την εκμεταλλευτείτε για να κλέψετε τις πληροφορίες.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Αν δεν μπορείτε να εισάγετε XSS tags, μπορεί ακόμα να είστε σε θέση να κλέψετε τις πληροφορίες χρησιμοποιώντας άλλες κανονικές HTML tags.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Αν δεν υπάρχει προστασία κατά αυτής της επίθεσης, μπορεί να είστε σε θέση να παραπλανήσετε τον χρήστη να σας στείλει τα ευαίσθητα δεδομένα (ένα παράδειγμα [εδώ](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

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
