# Ανάλυση αρχείων Office

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}


Για περαιτέρω πληροφορίες ελέγξτε το [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτό είναι απλώς ένα σύνοψη:


Η Microsoft έχει δημιουργήσει πολλές μορφές εγγράφων γραφείου, με δύο κύριους τύπους να είναι οι **μορφές OLE** (όπως RTF, DOC, XLS, PPT) και οι **μορφές Office Open XML (OOXML)** (όπως DOCX, XLSX, PPTX). Αυτές οι μορφές μπορούν να περιλαμβάνουν μακρός, καθιστώντας τα στόχους για φισινγκ και κακόβουλο λογισμικό. Τα αρχεία OOXML είναι δομημένα ως αρχεία zip, επιτρέποντας την επιθεώρηση μέσω αποσυμπίεσης, αποκαλύπτοντας την ιεραρχία αρχείων και φακέλων και το περιεχόμενο των αρχείων XML.

Για να εξερευνήσετε τις δομές αρχείων OOXML, δίνεται η εντολή για αποσυμπίεση ενός εγγράφου και η δομή εξόδου. Έχουν καταγραφεί τεχνικές για την απόκρυψη δεδομένων σε αυτά τα αρχεία, που υποδεικνύουν συνεχή καινοτομία στην κρυπτογράφηση δεδομένων μέσα σε προκλήσεις CTF.

Για την ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα εργαλεία για την εξέταση τόσο των εγγράφων OLE όσο και των εγγράφων OOXML. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων μακρό, τα οποία συχνά λειτουργούν ως διανομείς κακόβουλου λογισμικού, συνήθως λήψη και εκτέλεση επιπλέον κακόβουλων φορτίων. Η ανάλυση των μακρό VBA μπορεί να γίνει χωρίς το Microsoft Office χρησιμοποιώντας το Libre Office, το οποίο επιτρέπει τον εντοπισμό σφαλμάτων με διακοπές και παρακολούθηση μεταβλητών.

Η εγκατάσταση και η χρήση των **oletools** είναι απλές, με παρεχόμενες εντολές για την εγκατάσταση μέσω του pip και την εξαγωγή μακρό από εγγράφα. Η αυτόματη εκτέλεση των μακρό ενεργοποιείται από λειτουργίες όπως `AutoOpen`, `AutoExec` ή `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε εργασιακές διαδικασίες με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
