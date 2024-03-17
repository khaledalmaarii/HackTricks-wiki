# macOS Επεκτάσεις Πυρήνα

<details>

<summary><strong>Μάθετε AWS χάκινγκ από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΥΝΔΡΟΜΗΣ ΣΧΕΔΙΑ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), την αποκλειστική μας συλλογή [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο swag του PEASS και του HackTricks**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) **ομάδα Discord** ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Μοιραστείτε τα χάκινγκ κόλπα σας στέλνοντας PR στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Βασικές Πληροφορίες

Οι επεκτάσεις πυρήνα (Kexts) είναι **πακέτα** με **επέκταση `.kext`** που φορτώνονται απευθείας στον χώρο πυρήνα του macOS, παρέχοντας επιπλέον λειτουργικότητα στον κύριο λειτουργικό σύστημα.

### Απαιτήσεις

Φυσικά, αυτό είναι τόσο ισχυρό που είναι **περίπλοκο να φορτωθεί μια επέκταση πυρήνα**. Αυτές είναι οι **απαιτήσεις** που πρέπει να πληροί μια επέκταση πυρήνα για να φορτωθεί:

* Κατά την **είσοδο σε λειτουργία ανάκαμψης**, οι επεκτάσεις πυρήνα πρέπει να επιτρέπεται να φορτωθούν:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Η επέκταση πυρήνα πρέπει να είναι **υπογεγραμμένη με πιστοποιητικό υπογραφής κώδικα πυρήνα**, το οποίο μπορεί να χορηγηθεί μόνο από την Apple. Ποιος θα εξετάσει λεπτομερώς την εταιρεία και τους λόγους για τους οποίους απαιτείται.
* Η επέκταση πυρήνα πρέπει επίσης να είναι **επικυρωμένη**, ώστε η Apple να μπορεί να την ελέγξει για κακόβουλο λογισμικό.
* Στη συνέχεια, ο **χρήστης root** είναι αυτός που μπορεί να **φορτώσει την επέκταση πυρήνα** και τα αρχεία μέσα στο πακέτο πρέπει να **ανήκουν στο root**.
* Κατά τη διαδικασία φόρτωσης, το πακέτο πρέπει να προετοιμαστεί σε μια **προστατευμένη μη-ριζική τοποθεσία**: `/Library/StagedExtensions` (απαιτεί τη χορήγηση `com.apple.rootless.storage.KernelExtensionManagement`).
* Τέλος, κατά την προσπάθεια φόρτωσής της, ο χρήστης θα [**λάβει αίτημα επιβεβαίωσης**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) και, εάν γίνει αποδεκτό, ο υπολογιστής πρέπει να **επανεκκινηθεί** για να τη φορτώσει.

### Διαδικασία Φόρτωσης

Στο Catalina ήταν ως εξής: Είναι ενδιαφέρον να σημειωθεί ότι η διαδικασία **επαλήθευσης** συμβαίνει στο **userland**. Ωστόσο, μόνο εφαρμογές με τη χορήγηση **`com.apple.private.security.kext-management`** μπορούν να **ζητήσουν από τον πυρήνα να φορτώσει μια επέκταση**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. Το **`kextutil`** cli **ξεκινά** τη διαδικασία **επαλήθευσης** για τη φόρτωση μιας επέκτασης
* Θα επικοινωνήσει με το **`kextd`** στέλνοντας χρησιμοποιώντας ένα **Mach service**.
2. Το **`kextd`** θα ελέγξει διάφορα πράγματα, όπως η **υπογραφή**
* Θα επικοινωνήσει με το **`syspolicyd`** για να **ελέγξει** αν η επέκταση μπορεί να **φορτωθεί**.
3. Το **`syspolicyd`** θα **ζητήσει** το **αίτημα επιβεβαίωσης** από τον **χρήστη** αν η επέκταση δεν έχει φορτωθεί προηγουμένως.
* Το **`syspolicyd`** θα αναφέρει το αποτέλεσμα στο **`kextd`**
4. Το **`kextd`** θα μπορεί εν τέλει να **πει στον πυρήνα να φορτώσει** την επέκταση

Αν το **`kextd`** δεν είναι διαθέσιμο, το **`kextutil`** μπορεί να πραγματοποιήσει τις ίδιες ελέγχους.

## Αναφορές

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Μάθετε AWS χάκινγκ από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΥΝΔΡΟΜΗΣ ΣΧΕΔΙΑ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), την αποκλειστική μας συλλογή [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο swag του PEASS και του HackTricks**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) **ομάδα Discord** ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Μοιραστείτε τα χάκινγκ κόλπα σας στέλνοντας PR στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
