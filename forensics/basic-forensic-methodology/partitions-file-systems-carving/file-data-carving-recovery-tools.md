# Εργαλεία Ανάκτησης & Ανάλυσης Δεδομένων Αρχείων

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

## Εργαλεία Ανάκτησης & Ανάλυσης

Περισσότερα εργαλεία στο [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Το πιο κοινό εργαλείο που χρησιμοποιείται στην ανάκριση για την εξαγωγή αρχείων από εικόνες είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και κάντε το να αναλύσει το αρχείο για να βρεί "κρυμμένα" αρχεία. Σημειώστε ότι το Autopsy είναι σχεδιασμένο για να υποστηρίζει εικόνες δίσκων και άλλους τύπους εικόνων, αλλά όχι απλά αρχεία.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** είναι ένα εργαλείο για την ανάλυση δυαδικών αρχείων για την εύρεση ενσωματωμένου περιεχομένου. Μπορεί να εγκατασταθεί μέσω `apt` και ο πηγαίος κώδικάς του βρίσκεται στο [GitHub](https://github.com/ReFirmLabs/binwalk).

**Χρήσιμες εντολές**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Ένα άλλο κοινό εργαλείο για την εύρεση κρυφών αρχείων είναι το **foremost**. Μπορείτε να βρείτε το αρχείο ρύθμισης του foremost στο `/etc/foremost.conf`. Αν θέλετε απλά να αναζητήσετε κάποια συγκεκριμένα αρχεία, κάντε σχόλιο την αντίστοιχη γραμμή. Αν δεν κάνετε σχόλιο σε κάτι, το foremost θα αναζητήσει τους τύπους αρχείων που έχουν προκαθοριστεί.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** είναι ένα άλλο εργαλείο που μπορεί να χρησιμοποιηθεί για να βρεί και να εξάγει **αρχεία που έχουν ενσωματωθεί σε ένα αρχείο**. Σε αυτήν την περίπτωση, θα χρειαστεί να καταργήσετε τα σχόλια από το αρχείο ρυθμίσεων (_/etc/scalpel/scalpel.conf_) των τύπων αρχείων που θέλετε να εξάγει.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Αυτό το εργαλείο περιλαμβάνεται στο Kali αλλά μπορείτε να το βρείτε εδώ: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Αυτό το εργαλείο μπορεί να σαρώσει μια εικόνα και θα **εξάγει pcaps** μέσα σε αυτή, **πληροφορίες δικτύου (URLs, domains, IPs, MACs, emails)** και περισσότερα **αρχεία**. Θα πρέπει μόνο να:
```
bulk_extractor memory.img -o out_folder
```
### PhotoRec

Μπορείτε να το βρείτε στο [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Έρχεται με εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τα **τύποι αρχείων** που θέλετε το PhotoRec να αναζητήσει.

![](<../../../.gitbook/assets/image (524).png>)

### binvis

Ελέγξτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και το [εργαλείο στην ιστοσελίδα](https://binvis.io/#/).

#### Χαρακτηριστικά του BinVis

* Οπτικός και ενεργός **δομικός προβολέας**
* Πολλαπλά γραφήματα για διαφορετικά σημεία εστίασης
* Εστίαση σε τμήματα ενός δείγματος
* **Προβολή συμβόλων και πόρων**, σε εκτελέσιμα PE ή ELF, κ.λπ.
* Λήψη **μοτίβων** για κρυπτανάλυση αρχείων
* **Εντοπισμός** αλγορίθμων συμπιεστή ή κωδικοποιητή
* **Αναγνώριση** Στεγανογραφίας με βάση τα μοτίβα
* **Οπτική** διαφοροποίηση δυαδικών

Το BinVis είναι ένα εξαιρετικό **σημείο εκκίνησης για να εξοικειωθείτε με έναν άγνωστο στόχο** σε ένα σενάριο μαύρου κουτιού.

## Εργαλεία Ανάκτησης Συγκεκριμένων Δεδομένων

### FindAES

Αναζητά κλειδιά AES αναζητώντας τα προγράμματα κλειδιών τους. Μπορεί να βρει κλειδιά 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από το TrueCrypt και το BitLocker.

Λήψη [εδώ](https://sourceforge.net/projects/findaes/).

## Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu)για να δείτε εικόνες από το τερματικό.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών του Linux **pdftotext** για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.
