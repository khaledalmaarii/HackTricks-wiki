<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Εργαλεία ανάκτησης δεδομένων

## Autopsy

Το πιο κοινό εργαλείο που χρησιμοποιείται στην ανάκτηση δεδομένων για την εξαγωγή αρχείων από εικόνες είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και κάντε το να αναλύσει το αρχείο για να βρει "κρυφά" αρχεία. Σημειώστε ότι το Autopsy είναι σχεδιασμένο για να υποστηρίζει εικόνες δίσκων και άλλου είδους εικόνες, αλλά όχι απλά αρχεία.

## Binwalk <a id="binwalk"></a>

Το **Binwalk** είναι ένα εργαλείο για την αναζήτηση δυαδικών αρχείων όπως εικόνες και αρχεία ήχου για ενσωματωμένα αρχεία και δεδομένα.
Μπορεί να εγκατασταθεί με την εντολή `apt`, ωστόσο η [πηγή](https://github.com/ReFirmLabs/binwalk) μπορεί να βρεθεί στο github.
**Χρήσιμες εντολές**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Ένα άλλο κοινό εργαλείο για την εύρεση κρυφών αρχείων είναι το **foremost**. Μπορείτε να βρείτε το αρχείο ρυθμίσεων του foremost στη διαδρομή `/etc/foremost.conf`. Αν θέλετε απλά να αναζητήσετε κάποια συγκεκριμένα αρχεία, κάντε σχόλιο στις αντίστοιχες γραμμές. Αν δεν κάνετε σχόλιο σε κάτι, το foremost θα αναζητήσει τους τύπους αρχείων που έχουν προκαθοριστεί.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** είναι ένα άλλο εργαλείο που μπορεί να χρησιμοποιηθεί για να βρει και να εξάγει **αρχεία που έχουν ενσωματωθεί σε ένα αρχείο**. Σε αυτήν την περίπτωση, θα πρέπει να καταργήσετε το σχόλιο από το αρχείο ρυθμίσεων \(_/etc/scalpel/scalpel.conf_\) τους τύπους αρχείων που θέλετε να εξάγει.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Αυτό το εργαλείο περιλαμβάνεται στο kali αλλά μπορείτε να το βρείτε εδώ: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Αυτό το εργαλείο μπορεί να σαρώσει μια εικόνα και θα **εξάγει pcaps** μέσα σε αυτήν, **πληροφορίες δικτύου (URLs, domains, IPs, MACs, mails)** και περισσότερα **αρχεία**. Απλά πρέπει να κάνετε:
```text
bulk_extractor memory.img -o out_folder
```
Περιηγηθείτε μέσα από **όλες τις πληροφορίες** που έχει συγκεντρώσει το εργαλείο \(κωδικοί πρόσβασης;\), **αναλύστε** τα **πακέτα** \(διαβάστε [**ανάλυση Pcaps**](../pcap-inspection/)\), αναζητήστε **περίεργους τομείς** \(τομείς που σχετίζονται με **κακόβουλο λογισμικό** ή **μη υπαρκτούς\).

## PhotoRec

Μπορείτε να το βρείτε στο [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Έρχεται με GUI και CLI έκδοση. Μπορείτε να επιλέξετε τους **τύπους αρχείων** που θέλετε το PhotoRec να αναζητήσει.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Εργαλεία Ανάκτησης Συγκεκριμένων Δεδομένων

## FindAES

Αναζητά για κλειδιά AES αναζητώντας τα προγράμματα κλειδιού τους. Μπορεί να βρει κλειδιά 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από το TrueCrypt και το BitLocker.

Κατεβάστε το [εδώ](https://sourceforge.net/projects/findaes/).

# Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu)για να δείτε εικόνες από το τερματικό.
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών του Linux **pdftotext** για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.



<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
