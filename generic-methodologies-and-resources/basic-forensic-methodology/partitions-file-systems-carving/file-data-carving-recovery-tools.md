# File/Data Carving & Recovery Tools

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

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Το πιο κοινό εργαλείο που χρησιμοποιείται στην ψηφιακή εγκληματολογία για την εξαγωγή αρχείων από εικόνες είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και κάντε το να επεξεργαστεί το αρχείο για να βρείτε "κρυφά" αρχεία. Σημειώστε ότι το Autopsy έχει σχεδιαστεί για να υποστηρίζει εικόνες δίσκων και άλλους τύπους εικόνων, αλλά όχι απλά αρχεία.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** είναι ένα εργαλείο για την ανάλυση δυαδικών αρχείων για να βρείτε ενσωματωμένο περιεχόμενο. Είναι εγκαταστάσιμο μέσω του `apt` και η πηγή του είναι στο [GitHub](https://github.com/ReFirmLabs/binwalk).

**Useful commands**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Ένα άλλο κοινό εργαλείο για να βρείτε κρυφά αρχεία είναι το **foremost**. Μπορείτε να βρείτε το αρχείο ρύθμισης του foremost στο `/etc/foremost.conf`. Αν θέλετε να αναζητήσετε συγκεκριμένα αρχεία, αποσχολιάστε τα. Αν δεν αποσχολιάσετε τίποτα, το foremost θα αναζητήσει τους προεπιλεγμένους τύπους αρχείων που είναι ρυθμισμένοι.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** είναι ένα άλλο εργαλείο που μπορεί να χρησιμοποιηθεί για να βρει και να εξάγει **αρχεία ενσωματωμένα σε ένα αρχείο**. Σε αυτή την περίπτωση, θα χρειαστεί να αφαιρέσετε το σχόλιο από το αρχείο ρυθμίσεων (_/etc/scalpel/scalpel.conf_) τους τύπους αρχείων που θέλετε να εξάγει.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Αυτό το εργαλείο έρχεται μέσα στο kali αλλά μπορείτε να το βρείτε εδώ: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Αυτό το εργαλείο μπορεί να σαρώσει μια εικόνα και θα **εξάγει pcaps** μέσα σε αυτή, **πληροφορίες δικτύου (URLs, τομείς, IPs, MACs, emails)** και περισσότερα **αρχεία**. Πρέπει απλώς να κάνετε:
```
bulk_extractor memory.img -o out_folder
```
Πλοηγηθείτε μέσα από **όλες τις πληροφορίες** που έχει συγκεντρώσει το εργαλείο (κωδικοί πρόσβασης;), **αναλύστε** τα **πακέτα** (διαβάστε [**ανάλυση Pcaps**](../pcap-inspection/)), αναζητήστε **παράξενους τομείς** (τομείς σχετικούς με **malware** ή **μη υπάρχοντες**).

### PhotoRec

Μπορείτε να το βρείτε στο [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Έρχεται με εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους **τύπους αρχείων** που θέλετε να αναζητήσει το PhotoRec.

![](<../../../.gitbook/assets/image (242).png>)

### binvis

Ελέγξτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και την [ιστοσελίδα εργαλείου](https://binvis.io/#/).

#### Χαρακτηριστικά του BinVis

* Οπτικός και ενεργός **θεατής δομής**
* Πολλαπλά διαγράμματα για διαφορετικά σημεία εστίασης
* Εστίαση σε τμήματα ενός δείγματος
* **Βλέποντας αλυσίδες και πόρους**, σε εκτελέσιμα PE ή ELF π.χ.
* Λήψη **μοτίβων** για κρυπτοανάλυση σε αρχεία
* **Εντοπισμός** αλγορίθμων συμπίεσης ή κωδικοποίησης
* **Αναγνώριση** Στεγανότητας μέσω μοτίβων
* **Οπτική** διαφορά δυαδικών αρχείων

Το BinVis είναι ένα εξαιρετικό **σημείο εκκίνησης για να εξοικειωθείτε με έναν άγνωστο στόχο** σε ένα σενάριο black-boxing.

## Ειδικά Εργαλεία Κατασκευής Δεδομένων

### FindAES

Αναζητά κλειδιά AES αναζητώντας τα χρονοδιαγράμματα κλειδιών τους. Ικανό να βρει κλειδιά 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από το TrueCrypt και το BitLocker.

Κατεβάστε [εδώ](https://sourceforge.net/projects/findaes/).

## Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu) για να δείτε εικόνες από το τερματικό.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών linux **pdftotext** για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
