# Τοπική Αποθήκευση Cloud

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τη βοήθεια των **πιο προηγμένων** εργαλείων της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

Στα Windows, μπορείτε να βρείτε τον φάκελο OneDrive στο `\Users\<username>\AppData\Local\Microsoft\OneDrive`. Και μέσα στο `logs\Personal` είναι δυνατόν να βρείτε το αρχείο `SyncDiagnostics.log` το οποίο περιέχει ορισμένα ενδιαφέροντα δεδομένα σχετικά με τα συγχρονισμένα αρχεία:

* Μέγεθος σε bytes
* Ημερομηνία δημιουργίας
* Ημερομηνία τροποποίησης
* Αριθμός αρχείων στο cloud
* Αριθμός αρχείων στον φάκελο
* **CID**: Μοναδικό ID του χρήστη OneDrive
* Χρόνος δημιουργίας αναφοράς
* Μέγεθος του HD του OS

Αφού βρείτε το CID, συνιστάται να **αναζητήσετε αρχεία που περιέχουν αυτό το ID**. Μπορείτε να βρείτε αρχεία με το όνομα: _**\<CID>.ini**_ και _**\<CID>.dat**_ που μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες όπως τα ονόματα των αρχείων που συγχρονίστηκαν με το OneDrive.

## Google Drive

Στα Windows, μπορείτε να βρείτε τον κύριο φάκελο Google Drive στο `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Αυτός ο φάκελος περιέχει ένα αρχείο που ονομάζεται Sync\_log.log με πληροφορίες όπως τη διεύθυνση email του λογαριασμού, ονόματα αρχείων, χρονικές σφραγίδες, MD5 hashes των αρχείων, κ.λπ. Ακόμα και τα διαγραμμένα αρχεία εμφανίζονται σε αυτό το αρχείο καταγραφής με το αντίστοιχο MD5.

Το αρχείο **`Cloud_graph\Cloud_graph.db`** είναι μια βάση δεδομένων sqlite που περιέχει τον πίνακα **`cloud_graph_entry`**. Σε αυτόν τον πίνακα μπορείτε να βρείτε το **όνομα** των **συγχρονισμένων** **αρχείων**, τον χρόνο τροποποίησης, το μέγεθος και το MD5 checksum των αρχείων.

Τα δεδομένα του πίνακα της βάσης δεδομένων **`Sync_config.db`** περιέχουν τη διεύθυνση email του λογαριασμού, τη διαδρομή των κοινών φακέλων και την έκδοση του Google Drive.

## Dropbox

Το Dropbox χρησιμοποιεί **βάσεις δεδομένων SQLite** για να διαχειρίζεται τα αρχεία. Σε αυτό\
Μπορείτε να βρείτε τις βάσεις δεδομένων στους φακέλους:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

Και οι κύριες βάσεις δεδομένων είναι:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Η επέκταση ".dbx" σημαίνει ότι οι **βάσεις δεδομένων** είναι **κρυπτογραφημένες**. Το Dropbox χρησιμοποιεί **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Για να κατανοήσετε καλύτερα την κρυπτογράφηση που χρησιμοποιεί το Dropbox, μπορείτε να διαβάσετε [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Ωστόσο, οι κύριες πληροφορίες είναι:

* **Entropy**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algorithm**: PBKDF2
* **Iterations**: 1066

Εκτός από αυτές τις πληροφορίες, για να αποκρυπτογραφήσετε τις βάσεις δεδομένων χρειάζεστε επίσης:

* Το **κρυπτογραφημένο κλειδί DPAPI**: Μπορείτε να το βρείτε στο μητρώο μέσα στο `NTUSER.DAT\Software\Dropbox\ks\client` (εξάγετε αυτά τα δεδομένα ως δυαδικά)
* Τις **hives** **`SYSTEM`** και **`SECURITY`**
* Τα **master keys DPAPI**: Τα οποία μπορούν να βρεθούν στο `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* Το **όνομα χρήστη** και τον **κωδικό πρόσβασης** του χρήστη Windows

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Αν όλα πάνε όπως αναμένεται, το εργαλείο θα υποδείξει το **κύριο κλειδί** που χρειάζεστε για να **χρησιμοποιήσετε για να ανακτήσετε το αρχικό**. Για να ανακτήσετε το αρχικό, απλώς χρησιμοποιήστε αυτή τη [συνταγή cyber\_chef](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) βάζοντας το κύριο κλειδί ως την "passphrase" μέσα στη συνταγή.

Το προκύπτον hex είναι το τελικό κλειδί που χρησιμοποιείται για την κρυπτογράφηση των βάσεων δεδομένων που μπορεί να αποκρυπτογραφηθεί με:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** database contains:

* **Email**: Η διεύθυνση email του χρήστη
* **usernamedisplayname**: Το όνομα του χρήστη
* **dropbox\_path**: Διαδρομή όπου βρίσκεται ο φάκελος dropbox
* **Host\_id: Hash** που χρησιμοποιείται για την αυθεντικοποίηση στο cloud. Αυτό μπορεί να ανακληθεί μόνο από το διαδίκτυο.
* **Root\_ns**: Αναγνωριστικό χρήστη

The **`filecache.db`** database contains information about all the files and folders synchronized with Dropbox. The table `File_journal` is the one with more useful information:

* **Server\_path**: Διαδρομή όπου βρίσκεται το αρχείο μέσα στον διακομιστή (αυτή η διαδρομή προηγείται από το `host_id` του πελάτη).
* **local\_sjid**: Έκδοση του αρχείου
* **local\_mtime**: Ημερομηνία τροποποίησης
* **local\_ctime**: Ημερομηνία δημιουργίας

Other tables inside this database contain more interesting information:

* **block\_cache**: hash όλων των αρχείων και φακέλων του Dropbox
* **block\_ref**: Σχετίζει το hash ID του πίνακα `block_cache` με το ID του αρχείου στον πίνακα `file_journal`
* **mount\_table**: Κοινόχρηστοι φάκελοι του dropbox
* **deleted\_fields**: Διαγραμμένα αρχεία του Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

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
