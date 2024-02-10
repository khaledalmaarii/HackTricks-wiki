# Τοπική Αποθήκευση Νέφους

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

## OneDrive

Στα Windows, μπορείτε να βρείτε τον φάκελο του OneDrive στον δρόμο `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Και μέσα στον φάκελο `logs\Personal` είναι δυνατόν να βρείτε το αρχείο `SyncDiagnostics.log` που περιέχει μερικά ενδιαφέροντα δεδομένα σχετικά με τα συγχρονισμένα αρχεία:

* Μέγεθος σε bytes
* Ημερομηνία δημιουργίας
* Ημερομηνία τροποποίησης
* Αριθμός αρχείων στο νέφος
* Αριθμός αρχείων στον φάκελο
* **CID**: Μοναδικό αναγνωριστικό του χρήστη του OneDrive
* Χρόνος δημιουργίας αναφοράς
* Μέγεθος του σκληρού δίσκου του λειτουργικού συστήματος

Αφού βρείτε το CID, συνίσταται να **αναζητήσετε αρχεία που περιέχουν αυτό το αναγνωριστικό**. Μπορείτε να βρείτε αρχεία με τα ονόματα: _**\<CID>.ini**_ και _**\<CID>.dat**_ που μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες όπως τα ονόματα των αρχείων που συγχρονίζονται με το OneDrive.

## Google Drive

Στα Windows, μπορείτε να βρείτε τον κύριο φάκελο του Google Drive στον δρόμο `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Αυτός ο φάκελος περιέχει ένα αρχείο με το όνομα Sync\_log.log με πληροφορίες όπως η διεύθυνση email του λογαριασμού, τα ονόματα αρχείων, οι χρονοσφραγίδες, τα MD5 hashes των αρχείων, κλπ. Ακόμα και τα διαγραμμένα αρχεία εμφανίζονται σε αυτό το αρχείο καταγραφής με το αντίστοιχο MD5 τους.

Το αρχείο **`Cloud_graph\Cloud_graph.db`** είναι μια βάση δεδομένων sqlite που περιέχει τον πίνακα **`cloud_graph_entry`**. Σε αυτόν τον πίνακα μπορείτε να βρείτε το **όνομα** των **συγχρονισμένων** **αρχείων**, την τροποποιημένη ώρα, το μέγεθος και το MD5 checksum των αρχείων.

Τα δεδομένα του πίνακα της βάσης δεδομένων **`Sync_config.db`** περιέχουν τη διεύθυνση email του λογαριασμού, τη διαδρομή των κοινόχρηστων φακέλων και την έκδοση του Google Drive.

## Dropbox

Η Dropbox χρησιμοποιεί **βάσεις δεδομένων SQLite** για τη διαχείριση των αρχείων. Σε αυτόν\
Μπορείτε να βρείτε τις βάσεις δεδομένων στους φακέλους:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Και οι κύριες βάσεις δεδομένων είναι:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Η επέκταση ".dbx" σημαίνει ότι οι **βάσεις δεδομένων** είναι **κρυπτογραφημένες**. Η Dropbox χρησιμοποιεί το **DPAPI** ([https://docs.microsoft.com
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Η βάση δεδομένων **`config.dbx`** περιέχει:

* **Email**: Το email του χρήστη
* **usernamedisplayname**: Το όνομα του χρήστη
* **dropbox\_path**: Η διαδρομή όπου βρίσκεται ο φάκελος του Dropbox
* **Host\_id: Hash**: Χρησιμοποιείται για την πιστοποίηση στο cloud. Μπορεί να ανακληθεί μόνο από τον ιστό.
* **Root\_ns**: Αναγνωριστικό χρήστη

Η βάση δεδομένων **`filecache.db`** περιέχει πληροφορίες για όλα τα αρχεία και φακέλους που συγχρονίζονται με το Dropbox. Ο πίνακας `File_journal` είναι αυτός με τις περισσότερες χρήσιμες πληροφορίες:

* **Server\_path**: Διαδρομή όπου βρίσκεται το αρχείο μέσα στον διακομιστή (αυτή η διαδρομή προηγείται από το `host_id` του πελάτη).
* **local\_sjid**: Έκδοση του αρχείου
* **local\_mtime**: Ημερομηνία τροποποίησης
* **local\_ctime**: Ημερομηνία δημιουργίας

Άλλοι πίνακες μέσα σε αυτήν τη βάση δεδομένων περιέχουν περισσότερες ενδιαφέρουσες πληροφορίες:

* **block\_cache**: hash όλων των αρχείων και φακέλων του Dropbox
* **block\_ref**: Σχετίζει το αναγνωριστικό hash του πίνακα `block_cache` με το αναγνωριστικό αρχείου στον πίνακα `file_journal`
* **mount\_table**: Κοινόχρηστοι φάκελοι του Dropbox
* **deleted\_fields**: Διαγραμμένα αρχεία του Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε εργασιακές διαδικασίες με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>
