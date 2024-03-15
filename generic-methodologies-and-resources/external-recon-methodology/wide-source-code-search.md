# Ευρεία Αναζήτηση Πηγαίου Κώδικα

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Ομάδα Ασφαλείας Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

Ο στόχος αυτής της σελίδας είναι να καταγράψει **πλατφόρμες που επιτρέπουν την αναζήτηση κώδικα** (κυριολεκτικού ή με regex) σε χιλιάδες/εκατομμύρια αποθετήρια σε μία ή περισσότερες πλατφόρμες.

Αυτό βοηθάει σε πολλές περιπτώσεις να **αναζητήσετε διαρροές πληροφοριών** ή πρότυπα **ευπαθειών**.

* [**SourceGraph**](https://sourcegraph.com/search): Αναζήτηση σε εκατομμύρια αποθετήρια. Υπάρχει μια δωρεάν έκδοση και μια επιχειρησιακή έκδοση (με 15 ημέρες δωρεάν). Υποστηρίζει regexes.
* [**Github Search**](https://github.com/search): Αναζήτηση σε όλο το Github. Υποστηρίζει regexes.
* Ίσως είναι χρήσιμο να ελέγξετε επίσης το [**Github Code Search**](https://cs.github.com/).
* [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced\_search.html): Αναζήτηση σε έργα Gitlab. Υποστηρίζει regexes.
* [**SearchCode**](https://searchcode.com/): Αναζήτηση κώδικα σε εκατομμύρια έργα.

{% hint style="warning" %}
Όταν αναζητάτε διαρροές σε ένα αποθετήριο και εκτελείτε κάτι σαν `git log -p` μην ξεχνάτε ότι μπορεί να υπάρχουν **άλλα κλαδιά με άλλες δεσμεύσεις** που περιέχουν μυστικά!
{% endhint %}

**Ομάδα Ασφαλείας Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
