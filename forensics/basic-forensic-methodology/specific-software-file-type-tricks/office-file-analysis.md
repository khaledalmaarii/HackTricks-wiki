# Ανάλυση αρχείων γραφείου

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

Για περαιτέρω πληροφορίες ελέγξτε το [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτό είναι απλώς ένα σύνοψη:

Η Microsoft έχει δημιουργήσει πολλές μορφές εγγράφων γραφείου, με δύο κύριους τύπους να είναι τα **μορφότυπα OLE** (όπως RTF, DOC, XLS, PPT) και τα **μορφότυπα Office Open XML (OOXML)** (όπως DOCX, XLSX, PPTX). Αυτά τα μορφότυπα μπορούν να περιλαμβάνουν μακρότυπα, καθιστώντας τα στόχους για phishing και κακόβουλο λογισμικό. Τα αρχεία OOXML είναι δομημένα ως αρχεία zip, επιτρέποντας την επιθεώρηση μέσω αποσυμπίεσης, αποκαλύπτοντας τη δομή του αρχείου και του φακέλου και τα περιεχόμενα του αρχείου XML.

Για να εξερευνήσετε τις δομές αρχείων OOXML, δίνεται η εντολή για αποσυμπίεση ενός εγγράφου και η δομή εξόδου. Έχουν καταγραφεί τεχνικές για την κρυψοκάλυψη δεδομένων σε αυτά τα αρχεία, υποδεικνύοντας συνεχή καινοτομία στην κρυψοκάλυψη δεδομένων στις προκλήσεις CTF.

Για ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν πλήρεις συλλογές εργαλείων για την εξέταση τόσο των εγγράφων OLE όσο και των εγγράφων OOXML. Αυτά τα εργαλεία βοηθούν στην αναγνώριση και ανάλυση ενσωματωμένων μακροεντολών, οι οποίες συχνά λειτουργούν ως διανομείς κακόβουλου λογισμικού, κατά κανόνα λήψη και εκτέλεση επιπλέον κακόβουλων φορτίων. Η ανάλυση των μακροεντολών VBA μπορεί να πραγματοποιηθεί χωρίς το Microsoft Office χρησιμοποιώντας το Libre Office, το οποίο επιτρέπει την αποσφαλμάτωση με σημεία διακοπής και μεταβλητές παρακολούθησης.

Η εγκατάσταση και η χρήση των **oletools** είναι απλές, με εντολές που παρέχονται για την εγκατάσταση μέσω pip και την εξαγωγή μακροεντολών από εγγράφα. Η αυτόματη εκτέλεση μακροεντολών ενεργοποιείται από λειτουργίες όπως `AutoOpen`, `AutoExec` ή `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
