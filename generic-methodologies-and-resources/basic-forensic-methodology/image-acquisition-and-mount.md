# Απόκτηση Εικόνας & Προσάρτηση

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Απόκτηση

### DD
```bash
#This will generate a raw copy of the disk
dd if=/dev/sdb of=disk.img
```
### dcfldd

Το **dcfldd** είναι ένα εργαλείο που χρησιμοποιείται για την αντιγραφή εικόνων δίσκου. Αυτό το εργαλείο είναι μια εναλλακτική λύση στο dd, μερικές φορές προτιμάται για την ακρίβεια της αντιγραφής. Οι εντολές και οι παράμετροι του dcfldd είναι παρόμοιες με αυτές του dd, μερικές φορές με μερικές επιπλέον δυνατότητες. Μπορεί να χρησιμοποιηθεί για την αντιγραφή εικόνων δίσκου, την αντιγραφή μόνο των μηχανικών τμημάτων ενός δίσκου, την αντιγραφή με συμπίεση και πολλά άλλα.
```bash
#Raw copy with hashes along the way (more secur as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### FTK Imager

Μπορείτε να [**κατεβάσετε το FTK imager από εδώ**](https://accessdata.com/product-download/debian-and-ubuntu-x64-3-1-1).
```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 --description 'A description' --examiner 'Your name'
```
### EWF

Μπορείτε να δημιουργήσετε μια εικόνα δίσκου χρησιμοποιώντας τα [**εργαλεία ewf**](https://github.com/libyal/libewf).
```bash
ewfacquire /dev/sdb
#Name: evidence
#Case number: 1
#Description: A description for the case
#Evidence number: 1
#Examiner Name: Your name
#Media type: fixed
#Media characteristics: physical
#File format: encase6
#Compression method: deflate
#Compression level: fast

#Then use default values
#It will generate the disk image in the current directory
```
## Τοποθέτηση

### Πολλαπλοί τύποι

Στα **Windows** μπορείτε να δοκιμάσετε να χρησιμοποιήσετε τη δωρεάν έκδοση του Arsenal Image Mounter ([https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)) για να **τοποθετήσετε την εικόνα ανάκτησης**.

### Raw
```bash
#Get file type
file evidence.img
evidence.img: Linux rev 1.0 ext4 filesystem data, UUID=1031571c-f398-4bfb-a414-b82b280cf299 (extents) (64bit) (large files) (huge files)

#Mount it
mount evidence.img /mnt
```
### EWF

Το EWF (EnCase Evidence File) είναι ένα αρχείο εικόνας που χρησιμοποιείται από το λογισμικό EnCase για την αποθήκευση αντιγράφων ασφαλείας των αποδεικτικών στοιχείων. Το EWF αποτελείται από έναν κύριο αρχείο (.E01) και πολλά επιπλέον αρχεία (.EX01) που περιέχουν τα δεδομένα της εικόνας.

Για να αποκτήσετε μια εικόνα EWF, μπορείτε να χρησιμοποιήσετε το λογισμικό EnCase ή άλλα εργαλεία όπως το FTK Imager. Αυτά τα εργαλεία σάς επιτρέπουν να αποκτήσετε μια ακριβή αντιγραφή του περιεχομένου του σκληρού δίσκου ή του μέσου αποθήκευσης και να το αποθηκεύσετε σε ένα αρχείο EWF.

Για να προσπελάσετε τα δεδομένα μιας εικόνας EWF, πρέπει να την προσαρτήσετε σε έναν εικονικό δίσκο. Αυτό μπορεί να γίνει χρησιμοποιώντας το εργαλείο ewfmount ή άλλα εργαλεία που υποστηρίζουν το EWF format. Μετά την προσάρτηση, μπορείτε να εξερευνήσετε τα δεδομένα της εικόνας όπως θα κάνατε με έναν συνηθισμένο δίσκο.

Η απόκτηση και η προσάρτηση εικόνων EWF είναι σημαντικά εργαλεία στην ψηφιακή διαφθορά και την ανάκτηση αποδεικτικών στοιχείων. Με τη χρήση αυτών των μεθόδων, μπορείτε να διερευνήσετε και να ανακτήσετε σημαντικά δεδομένα από εικόνες EWF.
```bash
#Get file type
file evidence.E01
evidence.E01: EWF/Expert Witness/EnCase image file format

#Transform to raw
mkdir output
ewfmount evidence.E01 output/
file output/ewf1
output/ewf1: Linux rev 1.0 ext4 filesystem data, UUID=05acca66-d042-4ab2-9e9c-be813be09b24 (needs journal recovery) (extents) (64bit) (large files) (huge files)

#Mount
mount output/ewf1 -o ro,norecovery /mnt
```
### ArsenalImageMounter

Είναι μια εφαρμογή για τα Windows που χρησιμοποιείται για την προσάρτηση τόμων. Μπορείτε να την κατεβάσετε από εδώ [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

### Σφάλματα

* **`cannot mount /dev/loop0 read-only`** σε αυτήν την περίπτωση χρειάζεται να χρησιμοποιήσετε τις σημαίες **`-o ro,norecovery`**
* **`wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.`** σε αυτήν την περίπτωση η προσάρτηση απέτυχε επειδή η μετατόπιση του συστήματος αρχείων είναι διαφορετική από αυτήν της εικόνας του δίσκου. Πρέπει να βρείτε το μέγεθος του τομέα (Sector size) και τον αρχικό τομέα (Start sector):
```bash
fdisk -l disk.img
Disk disk.img: 102 MiB, 106954648 bytes, 208896 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00495395

Device        Boot Start    End Sectors  Size Id Type
disk.img1       2048 208895  206848  101M  1 FAT12
```
Σημειώστε ότι το μέγεθος του τομέα είναι **512** και η αρχή είναι **2048**. Στη συνέχεια, τοποθετήστε την εικόνα ως εξής:
```bash
mount disk.img /mnt -o ro,offset=$((2048*512))
```
<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
