<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


**Η αρχική ανάρτηση είναι** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Περίληψη

Βρέθηκαν δύο κλειδιά του μητρώου που μπορούν να εγγραφούν από τον τρέχοντα χρήστη:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Προτάθηκε να ελεγχθούν οι άδειες του υπηρεσίας **RpcEptMapper** χρησιμοποιώντας το **regedit GUI**, ειδικά το παράθυρο **Advanced Security Settings** και την καρτέλα **Effective Permissions**. Αυτή η προσέγγιση επιτρέπει την αξιολόγηση των χορηγημένων δικαιωμάτων σε συγκεκριμένους χρήστες ή ομάδες χωρίς την ανάγκη να εξετάζονται ξεχωριστά κάθε Access Control Entry (ACE).

Παρουσιάστηκε μια στιγμιότυπη εικόνα με τις δικαιώματα που έχει ένας χρήστης με χαμηλά προνόμια, μεταξύ των οποίων ξεχώριζε το δικαίωμα **Create Subkey**. Αυτό το δικαίωμα, που αναφέρεται επίσης ως **AppendData/AddSubdirectory**, αντιστοιχεί με τα ευρήματα του σεναρίου.

Σημειώθηκε η αδυναμία να τροποποιηθούν ορισμένες τιμές απευθείας, αλλά η δυνατότητα δημιουργίας νέων υποκλειδιών. Ένα παράδειγμα που τονίστηκε ήταν η προσπάθεια να αλλάξει η τιμή **ImagePath**, η οποία οδήγησε σε ένα μήνυμα απόρριψης πρόσβασης.

Παρά τους περιορισμούς αυτούς, εντοπίστηκε η δυνατότητα ανόδου προνομίων μέσω της δυνατότητας εκμετάλλευσης του υποκλειδιού **Performance** εντός της δομής του μητρώου της υπηρεσίας **RpcEptMapper**, ένα υποκλειδί που δεν υπάρχει από προεπιλογή. Αυτό θα μπορούσε να επιτρέψει την εγγραφή DLL και την παρακολούθηση της απόδοσης.

Συμβουλευτήκαμε την τεκμηρίωση για το υποκλειδί **Performance** και τη χρήση του για την παρακολούθηση της απόδοσης, με αποτέλεσμα την ανάπτυξη ενός DLL προσχεδίου. Αυτό το DLL, που δείχνει την υλοποίηση των συναρτήσεων **OpenPerfData**, **CollectPerfData** και **ClosePerfData**, δοκιμάστηκε μέσω του **rundll32**, επιβεβαιώνοντας τη λειτουργική του επιτυχία.

Ο στόχος ήταν να αναγκαστεί η υπηρεσία **RPC Endpoint Mapper** να φορτώσει το δημιουργημένο DLL της Απόδοσης. Παρατηρήσεις έδειξαν ότι η εκτέλεση ερωτημάτων κλάσης WMI που σχετίζονται με τα δεδομένα απόδοσης μέσω του PowerShell οδηγούσε στη δημιουργία ενός αρχείου καταγραφής, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα υπό το πλαίσιο του **LOCAL SYSTEM**, παρέχοντας έτσι αυξημένα προνόμια.

Επισημάνθηκε η μόνιμη ύπαρξη και οι δυνητικές επιπτώσεις αυτής της ευπάθειας, τονίζοντας τη σημασία της για στρατηγικές μετά-εκμετάλλευσης, πλευρικής κίνησης και αποφυγής συστημάτων αντιιικών/EDR.

Παρόλο που η ευπάθεια αποκαλύφθηκε αρχικά ακούσια μέσω του σεναρίου, τονίστηκε ότι η εκμετάλλευσή της περιορίζεται σε παλαιές εκδόσεις των Windows (π.χ. **Windows 7 / Server 2008 R2**) και απαιτεί τοπική πρόσβαση.

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong
