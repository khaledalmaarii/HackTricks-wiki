# Stealing Sensitive Information Disclosure from a Web

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

Εάν σε κάποιο σημείο βρείτε μια **ιστοσελίδα που σας παρουσιάζει ευαίσθητες πληροφορίες βάσει της συνεδρίας σας**: Ίσως αντανακλά τα cookies, ή εκτυπώνει ή λεπτομέρειες πιστωτικής κάρτας ή οποιεσδήποτε άλλες ευαίσθητες πληροφορίες, μπορείτε να προσπαθήσετε να τις κλέψετε.\
Εδώ σας παρουσιάζω τους κύριους τρόπους που μπορείτε να δοκιμάσετε να το επιτύχετε:

* [**Παράκαμψη CORS**](../pentesting-web/cors-bypass.md): Εάν μπορείτε να παρακάμψετε τους κεφαλίδες CORS, θα μπορείτε να κλέψετε τις πληροφορίες εκτελώντας αίτηση Ajax για μια κακόβουλη σελίδα.
* [**XSS**](../pentesting-web/xss-cross-site-scripting/): Εάν βρείτε μια ευπάθεια XSS στη σελίδα, μπορείτε να την καταχραστείτε για να κλέψετε τις πληροφορίες.
* [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): Εάν δεν μπορείτε να εισαγάγετε ετικέτες XSS, εξακολουθείτε να μπορείτε να κλέψετε τις πληροφορίες χρησιμοποιώντας άλλες κανονικές ετικέτες HTML.
* [**Clickjaking**](../pentesting-web/clickjacking.md): Εάν δεν υπάρχει προστασία κατά αυτής της επίθεσης, μπορείτε να καταφέρετε να εξαπατήσετε τον χρήστη να σας στείλει τα ευαίσθητα δεδομένα (ένα παράδειγμα [εδώ](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
