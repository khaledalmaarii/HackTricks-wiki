# Τοπική Αποθήκευση Στο Cloud

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε Πρόσβαση Σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

Στα Windows, μπορείτε να βρείτε το φάκελο του OneDrive στο `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Και μέσα στον φάκελο `logs\Personal` είναι δυνατόν να βρείτε το αρχείο `SyncDiagnostics.log` το οποίο περιέχει μερικά ενδιαφέροντα δεδομένα σχετικά με τα συγχρονισμένα αρχεία:

* Μέγεθος σε bytes
* Ημερομηνία δημιουργίας
* Ημερομηνία τροποποίησης
* Αριθμός αρχείων στο cloud
* Αριθμός αρχείων στον φάκελο
* **CID**: Μοναδικό ID του χρήστη του OneDrive
* Χρόνος δημιουργίας αναφοράς
* Μέγεθος του σκληρού δίσκου του λειτουργικού συστήματος

Αφού βρείτε το CID συνιστάται να **αναζητήσετε αρχεία που περιέχουν αυτό το ID**. Μπορείτε να βρείτε αρχεία με τα ονόματα: _**\<CID>.ini**_ και _**\<CID>.dat**_ που μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες όπως τα ονόματα των αρχείων που συγχρονίζονται με το OneDrive.

## Google Drive

Στα Windows, μπορείτε να βρείτε τον κύριο φάκελο του Google Drive στο `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Αυτός ο φάκελος περιέχει ένα αρχείο με το όνομα Sync\_log.log με πληροφορίες όπως η διεύθυνση email του λογαριασμού, ονόματα αρχείων, χρονικά σημεία, MD5 hashes των αρχείων, κλπ. Ακόμα και τα διαγραμμένα αρχεία εμφανίζονται σε αυτό το αρχείο καταγραφής με το αντίστοιχο MD5 τους.

Το αρχείο **`Cloud_graph\Cloud_graph.db`** είναι μια βάση δεδομένων sqlite που περιέχει τον πίνακα **`cloud_graph_entry`**. Σε αυτόν τον πίνακα μπορείτε να βρείτε το **όνομα** των **συγχρονισμένων** **αρχείων**, την τροποποίηση του χρόνου, το μέγεθος και το MD5 checksum των αρχείων.

Τα δεδομένα του πίνακα της βάσης δεδομένων **`Sync_config.db`** περιέχουν τη διεύθυνση email του λογαριασμού, τη διαδρομή των κοινόχρηστων φακέλων και την έκδοση του Google Drive.

## Dropbox

Η Dropbox χρησιμοποιεί **βάσεις δεδομένων SQLite** για τη διαχείριση των αρχείων. Σε αυτήν\
Μπορείτε να βρείτε τις βάσεις δεδομένων στους φακέλους:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Και οι κύριες βάσεις δεδομένων είναι:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Η επέκταση ".dbx" σημαίνει ότι οι **βάσεις δεδομένων** είναι **κρυπτογραφημένες**. Η Dropbox χρησιμοποιεί το **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Για να καταλάβετε καλύτερα την κρυπτογράφηση που χρησιμοποιεί η Dropbox μπορείτε να διαβάσετε [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Ωστόσο, οι κύριες πληροφορίες είναι:

* **Εντροπία**: d114a55212655f74bd772e37e64aee9b
* **Αλάτι**: 0D638C092E8B82FC452883F95F355B8E
* **Αλγόριθμος**: PBKDF2
* **Επαναλήψεις**: 1066

Εκτός από αυτές τις πληροφορίες, για να αποκρυπτογραφήσετε τις βάσεις δεδομένων χρειάζεστε ακόμα:

* Το **κρυπτογραφημένο κλειδί DPAPI**: Μπορείτε να το βρείτε στο μητρώο μέσα στο `NTUSER.DAT\Software\Dropbox\ks\client` (εξαγάγετε αυτά τα δεδομένα ως δυαδικά)
* Τα **`SYSTEM`** και **`SECURITY`** hives
* Τα **κλειδιά μετατροπής DPAPI**: Τα οποία μπορείτε να βρείτε στον φάκελο `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* Το **όνομα χρήστη** και **κωδικό πρόσβασης** του χρήστη των Windows

Στη συνέχεια μπορείτε να χρησιμοποιήσετε το εργαλείο [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Αν όλα πάνε όπως αναμένεται, το εργαλείο θα υποδείξει το **κύριο κλειδί** που χρειάζεστε για να **χρησιμοποιήσετε για την ανάκτηση του αρχικού**. Για να ανακτήσετε τον αρχικό, απλά χρησιμοποιήστε αυτό το [cyber\_chef receipt](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) βάζοντας το κύριο κλειδί ως "passphrase" μέσα στο receipt.

Το αποτέλεσμα σε hex είναι το τελικό κλειδί που χρησιμοποιείται για την κρυπτογράφηση των βάσεων δεδομένων τα οποία μπορούν να αποκρυπτογραφηθούν με:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Η βάση δεδομένων **`config.dbx`** περιέχει:

* **Email**: Το email του χρήστη
* **usernamedisplayname**: Το όνομα του χρήστη
* **dropbox\_path**: Διαδρομή όπου βρίσκεται ο φάκελος του dropbox
* **Host\_id: Hash** που χρησιμοποιείται για πιστοποίηση στο cloud. Αυτό μπορεί να ανακληθεί μόνο από το web.
* **Root\_ns**: Αναγνωριστικό χρήστη

Η βάση δεδομένων **`filecache.db`** περιέχει πληροφορίες για όλα τα αρχεία και φακέλους που συγχρονίζονται με το Dropbox. Ο πίνακας `File_journal` είναι αυτός που περιέχει τις περισσότερες χρήσιμες πληροφορίες:

* **Server\_path**: Διαδρομή όπου βρίσκεται το αρχείο μέσα στον διακομιστή (αυτή η διαδρομή προηγείται από το `host_id` του πελάτη).
* **local\_sjid**: Έκδοση του αρχείου
* **local\_mtime**: Ημερομηνία τροποποίησης
* **local\_ctime**: Ημερομηνία δημιουργίας

Άλλοι πίνακες μέσα σε αυτή τη βάση δεδομένων περιέχουν περισσότερες ενδιαφέρουσες πληροφορίες:

* **block\_cache**: hash όλων των αρχείων και φακέλων του Dropbox
* **block\_ref**: Σχετίζει το hash ID του πίνακα `block_cache` με το αναγνωριστικό αρχείου στον πίνακα `file_journal`
* **mount\_table**: Κοινοποιημένοι φάκελοι του Dropbox
* **deleted\_fields**: Διαγραμμένα αρχεία του Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
