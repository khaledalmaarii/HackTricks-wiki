<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από APIs έως web εφαρμογές και συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

# Εργαλεία Carving & Recovery

Περισσότερα εργαλεία στο [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

## Autopsy

Το πιο κοινό εργαλείο που χρησιμοποιείται στην αντιμετώπιση παραβιάσεων για την εξαγωγή αρχείων από εικόνες είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και κάντε το να επεξεργαστεί το αρχείο για να βρει "κρυφά" αρχεία. Σημειώστε ότι το Autopsy είναι σχεδιασμένο για να υποστηρίζει εικόνες δίσκων και άλλους τύπους εικόνων, αλλά όχι απλά αρχεία.

## Binwalk <a href="#binwalk" id="binwalk"></a>

Το **Binwalk** είναι ένα εργαλείο για την ανάλυση δυαδικών αρχείων για την εύρεση ενσωματωμένου περιεχομένου. Μπορεί να εγκατασταθεί μέσω `apt` και ο πηγαίος κώδικας του βρίσκεται στο [GitHub](https://github.com/ReFirmLabs/binwalk).

**Χρήσιμες εντολές**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
## Foremost

Ένα άλλο κοινό εργαλείο για την εύρεση κρυφών αρχείων είναι το **foremost**. Μπορείτε να βρείτε το αρχείο ρυθμίσεων του foremost στη διαδρομή `/etc/foremost.conf`. Εάν θέλετε απλά να αναζητήσετε κάποια συγκεκριμένα αρχεία, κάντε σχόλιο στις αντίστοιχες γραμμές. Εάν δεν κάνετε σχόλιο σε κάτι, το foremost θα αναζητήσει τους τύπους αρχείων που έχουν προκαθοριστεί ως προεπιλογή.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
## **Scalpel**

**Scalpel** είναι ένα άλλο εργαλείο που μπορεί να χρησιμοποιηθεί για να βρει και να εξάγει **αρχεία που έχουν ενσωματωθεί σε ένα αρχείο**. Σε αυτήν την περίπτωση, θα πρέπει να καταργήσετε το σχόλιο από το αρχείο ρυθμίσεων (_/etc/scalpel/scalpel.conf_) τους τύπους αρχείων που θέλετε να εξάγει.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
## Bulk Extractor

Αυτό το εργαλείο περιλαμβάνεται στο kali αλλά μπορείτε να το βρείτε εδώ: [https://github.com/simsong/bulk\_extractor](https://github.com/simsong/bulk\_extractor)

Αυτό το εργαλείο μπορεί να σαρώσει μια εικόνα και θα **εξάγει pcaps** μέσα σε αυτήν, **πληροφορίες δικτύου (URLs, domains, IPs, MACs, mails)** και περισσότερα **αρχεία**. Απλά πρέπει να κάνετε:
```
bulk_extractor memory.img -o out_folder
```
Περιηγηθείτε μέσα από **όλες τις πληροφορίες** που έχει συγκεντρώσει το εργαλείο (κωδικοί πρόσβασης;), **αναλύστε** τα **πακέτα** (διαβάστε [**Ανάλυση Pcaps**](../pcap-inspection/)), αναζητήστε **περίεργους τομείς** (τομείς που σχετίζονται με **κακόβουλο λογισμικό** ή **μη υπαρκτούς**).

## PhotoRec

Μπορείτε να το βρείτε στο [https://www.cgsecurity.org/wiki/TestDisk\_Download](https://www.cgsecurity.org/wiki/TestDisk\_Download)

Έρχεται με εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους **τύπους αρχείων** που θέλετε το PhotoRec να αναζητήσει.

![](<../../../.gitbook/assets/image (524).png>)

## binvis

Ελέγξτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και το [εργαλείο στην ιστοσελίδα](https://binvis.io/#/).

### Χαρακτηριστικά του BinVis

* Οπτικός και ενεργός **προβολέας δομής**
* Πολλαπλά γραφήματα για διάφορα σημεία εστίασης
* Εστίαση σε μέρη ενός δείγματος
* **Προβολή συμβολοσειρών και πόρων**, σε εκτελέσιμα αρχεία PE ή ELF, για παράδειγμα
* Λήψη **μοτίβων** για κρυπτοανάλυση αρχείων
* **Εντοπισμός** αλγορίθμων συμπίεσης ή κωδικοποίησης
* **Αναγνώριση** κρυπτογραφίας με βάση μοτίβα
* **Οπτική** σύγκριση δυαδικών αρχείων

Το BinVis είναι ένα εξαιρετικό **σημείο εκκίνησης για να γνωρίσετε έναν άγνωστο στόχο** σε ένα σενάριο μαύρου κουτιού.

# Εργαλεία Ανάκτησης Συγκεκριμένων Δεδομένων

## FindAES

Αναζητά κλειδιά AES αναζητώντας τα προγράμματα προγραμματισμού τους. Μπορεί να βρει κλειδιά 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από το TrueCrypt και το BitLocker.

Κατεβάστε το [εδώ](https://sourceforge.net/projects/findaes/).

# Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu**](https://github.com/atanunq/viu) για να δείτε εικόνες από το τερματικό.\
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών του Linux **pdftotext** για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνειά σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από τις διεπαφές προς τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
