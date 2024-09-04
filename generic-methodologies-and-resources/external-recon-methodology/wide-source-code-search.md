# Wide Source Code Search

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

Ο στόχος αυτής της σελίδας είναι να απαριθμήσει **πλατφόρμες που επιτρέπουν την αναζήτηση κώδικα** (κυριολεκτικά ή regex) σε χιλιάδες/εκατομμύρια αποθετήρια σε μία ή περισσότερες πλατφόρμες.

Αυτό βοηθά σε πολλές περιπτώσεις να **αναζητήσετε διαρροές πληροφοριών** ή για **παραδείγματα ευπαθειών**.

* [**SourceGraph**](https://sourcegraph.com/search): Αναζητήστε σε εκατομμύρια αποθετήρια. Υπάρχει μια δωρεάν έκδοση και μια έκδοση επιχείρησης (με 15 ημέρες δωρεάν). Υποστηρίζει regexes.
* [**Github Search**](https://github.com/search): Αναζητήστε σε όλο το Github. Υποστηρίζει regexes.
* Ίσως είναι επίσης χρήσιμο να ελέγξετε και το [**Github Code Search**](https://cs.github.com/).
* [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Αναζητήστε σε έργα Gitlab. Υποστηρίζει regexes.
* [**SearchCode**](https://searchcode.com/): Αναζητήστε κώδικα σε εκατομμύρια έργα.

{% hint style="warning" %}
Όταν αναζητάτε διαρροές σε ένα αποθετήριο και εκτελείτε κάτι όπως `git log -p`, μην ξεχάσετε ότι μπορεί να υπάρχουν **άλλες κλάδοι με άλλες δεσμεύσεις** που περιέχουν μυστικά!
{% endhint %}

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
