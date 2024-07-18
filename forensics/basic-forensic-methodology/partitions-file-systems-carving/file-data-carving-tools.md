{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}


# Εργαλεία Carving

## Autopsy

Το πιο κοινό εργαλείο που χρησιμοποιείται στην ανάκτηση αρχείων από εικόνες είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και κάντε το να εξάγει αρχεία για να βρεί "κρυμμένα" αρχεία. Σημειώστε ότι το Autopsy είναι σχεδιασμένο για να υποστηρίζει εικόνες δίσκων και άλλου είδους εικόνες, αλλά όχι απλά αρχεία.

## Binwalk <a id="binwalk"></a>

**Binwalk** είναι ένα εργαλείο για την αναζήτηση δυαδικών αρχείων όπως εικόνες και αρχεία ήχου για ενσωματωμένα αρχεία και δεδομένα.
Μπορεί να εγκατασταθεί με την εντολή `apt`, ωστόσο η [πηγή](https://github.com/ReFirmLabs/binwalk) μπορεί να βρεθεί στο github.
**Χρήσιμες εντολές**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Ένα άλλο κοινό εργαλείο για την εύρεση κρυφών αρχείων είναι το **foremost**. Μπορείτε να βρείτε το αρχείο ρύθμισης του foremost στο `/etc/foremost.conf`. Αν θέλετε απλώς να αναζητήσετε κάποια συγκεκριμένα αρχεία, κάντε σχόλιο τη γραμμή τους. Αν δεν κάνετε σχόλιο σε τίποτα, το foremost θα αναζητήσει τους τύπους αρχείων που έχουν ρυθμιστεί από προεπιλογή.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** είναι ένα ακόμα εργαλείο που μπορεί να χρησιμοποιηθεί για την εύρεση και εξαγωγή **αρχείων που έχουν ενσωματωθεί σε ένα αρχείο**. Σε αυτήν την περίπτωση, θα χρειαστεί να καταργήσετε τα σχόλια από το αρχείο ρυθμίσεων \(_/etc/scalpel/scalpel.conf_\) των τύπων αρχείων που θέλετε να εξάγετε.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Αυτό το εργαλείο περιλαμβάνεται στο Kali αλλά μπορείτε να το βρείτε εδώ: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk_extractor)

Αυτό το εργαλείο μπορεί να σαρώσει μια εικόνα και θα **εξάγει pcaps** μέσα σε αυτή, **πληροφορίες δικτύου (URLs, domains, IPs, MACs, emails)** και περισσότερα **αρχεία**. Απλά πρέπει να:
```text
bulk_extractor memory.img -o out_folder
```
Πλοηγηθείτε μέσω **όλων των πληροφοριών** που έχει συγκεντρώσει το εργαλείο \(κωδικοί πρόσβασης;\), **αναλύστε** τα **πακέτα** \(διαβάστε [**Ανάλυση Pcaps**](../pcap-inspection/)\), αναζητήστε **περίεργους τομείς** \(τομείς που σχετίζονται με **κακόβουλο λογισμικό** ή **μη υπαρκτούς**\).

## PhotoRec

Μπορείτε να το βρείτε στο [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Διατίθεται σε έκδοση με γραφικό περιβάλλον χρήστη και γραμμή εντολών. Μπορείτε να επιλέξετε τους **τύπους αρχείων** που θέλετε το PhotoRec να αναζητήσει.

![](../../../.gitbook/assets/image%20%28524%29.png)

# Εργαλεία Ανάκτησης Συγκεκριμένων Δεδομένων

## FindAES

Αναζητά κλειδιά AES αναζητώντας τα προγράμματα κλειδιών τους. Μπορεί να βρει κλειδιά 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από το TrueCrypt και το BitLocker.

Λήψη [εδώ](https://sourceforge.net/projects/findaes/).

# Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu)για να δείτε εικόνες από το τερματικό.
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών του Linux **pdftotext** για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.
