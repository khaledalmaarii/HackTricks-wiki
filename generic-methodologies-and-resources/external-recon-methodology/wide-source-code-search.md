# Ευρετήριο Ευρεσης Κώδικα

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
{% endhint %}

**Ομάδα Ασφαλείας Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

Ο στόχος αυτής της σελίδας είναι να καταγράψει **πλατφόρμες που επιτρέπουν την αναζήτηση κώδικα** (κυριολεκτικά ή με regex) σε χιλιάδες/εκατομμύρια αποθετήρια σε μία ή περισσότερες πλατφόρμες.

Αυτό βοηθάει σε πολλές περιπτώσεις να **αναζητήσετε διαρροές πληροφοριών** ή πρότυπα **ευπαθειών**.

* [**SourceGraph**](https://sourcegraph.com/search): Αναζήτηση σε εκατομμύρια αποθετήρια. Υπάρχει μια δωρεάν έκδοση και μια επιχειρησιακή έκδοση (με 15 ημέρες δωρεάν). Υποστηρίζει τα regexes.
* [**Αναζήτηση Github**](https://github.com/search): Αναζήτηση στο Github. Υποστηρίζει τα regexes.
* Ίσως είναι χρήσιμο να ελέγξετε επίσης την [**Αναζήτηση Κώδικα του Github**](https://cs.github.com/).
* [**Προηγμένη Αναζήτηση Gitlab**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Αναζήτηση σε έργα Gitlab. Υποστηρίζει τα regexes.
* [**SearchCode**](https://searchcode.com/): Αναζήτηση κώδικα σε εκατομμύρια έργα.

{% hint style="warning" %}
Όταν αναζητάτε διαρροές σε ένα αποθετήριο και εκτελείτε κάτι σαν `git log -p` μην ξεχνάτε ότι μπορεί να υπάρχουν **άλλα κλαδιά με άλλες καταχωρήσεις** που περιέχουν μυστικά!
{% endhint %}

**Ομάδα Ασφαλείας Try Hard**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
{% endhint %}
