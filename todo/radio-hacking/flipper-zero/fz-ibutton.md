# FZ - iButton

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Εισαγωγή

Για περισσότερες πληροφορίες σχετικά με το τι είναι ένα iButton, ανατρέξτε στο:

{% content-ref url="../ibutton.md" %}
[ibutton.md](../ibutton.md)
{% endcontent-ref %}

## Σχεδίαση

Το **μπλε** μέρος της παρακάτω εικόνας είναι ο τρόπος με τον οποίο θα πρέπει να **τοποθετήσετε το πραγματικό iButton** ώστε το Flipper να το **διαβάσει**. Το **πράσινο** μέρος είναι ο τρόπος με τον οποίο θα πρέπει να **αγγίξετε τον αναγνώστη** με το Flipper zero για να **εμμοντεύσετε σωστά ένα iButton**.

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Διάβασμα

Στη λειτουργία Διάβασμα, το Flipper περιμένει να αγγίξει το κλειδί iButton και είναι σε θέση να επεξεργαστεί οποιοδήποτε από τα τρία είδη κλειδιών: **Dallas, Cyfral και Metakom**. Το Flipper θα **αναγνωρίσει αυτόματα τον τύπο του κλειδιού**. Το όνομα του πρωτοκόλλου του κλειδιού θα εμφανιστεί στην οθόνη πάνω από τον αριθμό ταυτότητας.

### Προσθήκη χειροκίνητα

Είναι δυνατή η **χειροκίνητη προσθήκη** ενός iButton τύπου: **Dallas, Cyfral και Metakom**

### Εμμοντεύστε

Είναι δυνατό να **εμμοντεύσετε** αποθηκευμένα iButtons (διαβασμένα ή προσθέτως χειροκίνητα).

{% hint style="info" %}
Εάν δεν μπορείτε να κάνετε τις αναμενόμενες επαφές του Flipper Zero να αγγίξουν τον αναγνώστη, μπορείτε να **χρησιμοποιήσετε τον εξωτερικό GPIO:**
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (24) (1).png" alt=""><figcaption></figcaption></figure>

## Αναφορές

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
