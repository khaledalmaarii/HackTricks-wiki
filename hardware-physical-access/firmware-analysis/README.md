# Ανάλυση Firmware

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ καταθέτοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
{% endhint %}

## **Εισαγωγή**

Το Firmware είναι το ουσιαστικό λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των υλικών συστατικών και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, εξασφαλίζοντας ότι η συσκευή μπορεί να έχει πρόσβαση σε ζωτικές οδηγίες από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του firmware είναι ένα κρίσιμο βήμα για την εντοπισμό ευπαθειών ασφαλείας.

## **Συλλογή Πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της δομής μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων για:

* Την αρχιτεκτονική της CPU και το λειτουργικό σύστημα που εκτελεί
* Συγκεκριμένες πληροφορίες για τον εκκινητή
* Τη διάταξη του υλικού και τις φύλλα τεκμηρίωσης
* Μετρήσεις κώδικα και τοποθεσίες πηγαίου κώδικα
* Εξωτερικές βιβλιοθήκες και τύπους αδειών
* Ιστορικά ενημερώσεων και πιστοποιήσεις ρυθμίσεων
* Αρχιτεκτονικά και διαγράμματα ροής
* Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για αυτόν τον σκοπό, τα εργαλεία **ανοικτής πηγής πληροφορίας (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων συστατικών λογισμικού ανοικτού κώδικα μέσω μηχανικών ελέγχων χειροκίνητων και αυτοματοποιημένων. Εργαλεία όπως το [Coverity Scan](https://scan.coverity.com) και το [LGTM της Semmle](https://lgtm.com/#explore) προσφέρουν δωρεάν στατική ανάλυση που μπορεί να αξιοποιηθεί για την εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση του firmware μπορεί να γίνει μέσω διαφόρων μέσων, καθένα με το δικό του επίπεδο πολυπλοκότητας:

* **Απευθείας** από την πηγή (προγραμματιστές, κατασκευαστές)
* **Κατασκευάζοντάς το** ακολουθώντας τις παρεχόμενες οδηγίες
* **Λήψη** από επίσημους ιστότοπους υποστήριξης
* Χρήση **ερωτημάτων Google dork** για την εύρεση φιλοξενούμενων αρχείων firmware
* Πρόσβαση στην **αποθήκευση στο cloud** απευθείας, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Παρεμβολή σε **ενημερώσεις** μέσω τεχνικών man-in-the-middle
* **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG**, ή **PICit**
* **Καταγραφή** αιτημάτων ενημέρωσης εντός της επικοινωνίας της συσκευής
* Αναγνώριση και χρήση **σκληροκωδικοποιημένων σημείων ενημέρωσης**
* **Ανάκτηση** από τον εκκινητή ή το δίκτυο
* **Αφαίρεση και ανάγνωση** του επιτραπέζιου τσιπ, όταν τίποτα άλλο αποτύχει, χρησιμοποιώντας κατάλληλα εργαλεία υλικού
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Εάν δε βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε την **εντροπία** της εικόνας με την εντολή `binwalk -E <bin>`. Αν η εντροπία είναι χαμηλή, τότε πιθανότατα δεν είναι κρυπτογραφημένη. Αν η εντροπία είναι υψηλή, είναι πιθανό να είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξάγετε **αρχεία που έχουν ενσωματωθεί μέσα στο firmware**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Ή το [**binvis.io**](https://binvis.io/#/) ([κώδικας](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Απόκτηση του Συστήματος Αρχείων

Με τα προηγούμενα εργαλεία όπως `binwalk -ev <bin>` θα πρέπει να έχετε καταφέρει να **εξάγετε το σύστημα αρχείων**.\
Το Binwalk συνήθως το εξάγει μέσα σε ένα **φάκελο με το όνομα του τύπου του συστήματος αρχείων**, το οποίο συνήθως είναι ένα από τα παρακάτω: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη Εξαγωγή Συστήματος Αρχείων

Μερικές φορές, το binwalk **δεν έχει το μαγικό byte του συστήματος αρχείων στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε τη θέση του συστήματος αρχείων και να αναγνωρίσετε το συμπιεσμένο σύστημα αρχείων** από το δυαδικό αρχείο και **εξάγετε χειροκίνητα** το σύστημα αρχείων σύμφωνα με τον τύπο του χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την ακόλουθη εντολή **dd** για να ανακτήσετε το σύστημα αρχείων Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Εναλλακτικά, μπορεί να εκτελεστεί και η παρακάτω εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Για το squashfs (που χρησιμοποιείται στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται στον κατάλογο "`squashfs-root`" μετά.

* Αρχεία αρχείων CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

* Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Αφού αποκτηθεί το firmware, είναι ουσιώδες να αναλυθεί για την κατανόηση της δομής του και των πιθανών ευπαθειών του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και εξαγωγή αξιόλογων δεδομένων από την εικόνα του firmware.

### Εργαλεία Αρχικής Ανάλυσης

Παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του δυαδικού αρχείου (αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στην αναγνώριση τύπων αρχείων, την εξαγωγή συμβολοσειρών, την ανάλυση δυαδικών δεδομένων και την κατανόηση των λεπτομερειών των διαμερισμάτων και του συστήματος αρχείων:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να αξιολογήσετε την κατάσταση της κρυπτογράφησης της εικόνας, ο έλεγχος γίνεται με την εντολή `binwalk -E <bin>`. Η χαμηλή εντροπία υποδηλώνει έλλειψη κρυπτογράφησης, ενώ η υψηλή εντροπία υποδηλώνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **ενσωματωμένων αρχείων**, συνιστώνται εργαλεία και πόροι όπως το έγγραφο **file-data-carving-recovery-tools** και το **binvis.io** για τον έλεγχο αρχείων.

### Εξαγωγή του Συστήματος Αρχείων

Χρησιμοποιώντας την εντολή `binwalk -ev <bin>`, μπορεί κανείς συνήθως να εξάγει το σύστημα αρχείων, συχνά σε έναν κατάλογο που ονομάζεται μετά τον τύπο του συστήματος αρχείων (π.χ., squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτυγχάνει να αναγνωρίσει τον τύπο του συστήματος αρχείων λόγω λείπουντος μαγικού byte, είναι απαραίτητη η χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό της μετατόπισης του συστήματος αρχείων, ακολουθούμενο από την εντολή `dd` για την ανάγλυψη του συστήματος αρχείων:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Ανάλυση Συστήματος Αρχείων

Με το σύστημα αρχείων εξαγμένο, ξεκινά η αναζήτηση ευπαθειών ασφάλειας. Προσέχετε τους ανασφαλείς δαίμονες δικτύου, σκληρούς κωδικούς πρόσβασης, σημεία API, λειτουργίες ενημέρωσης διακομιστή, μη μεταγλωττισμένο κώδικα, scripts εκκίνησης και μεταγλωττισμένα δυαδικά για ανάλυση εκτός σύνδεσης.

**Κύριες τοποθεσίες** και **στοιχεία** προς έλεγχο περιλαμβάνουν:

- **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά SSL και κλειδιά στο **etc/ssl**
- Αρχεία ρυθμίσεων και scripts για πιθανές ευπάθειες
- Ενσωματωμένα δυαδικά για περαιτέρω ανάλυση
- Κοινοί διακομιστές ιστοσελίδων και δυαδικά συσκευών IoT

Πολλά εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών εντός του συστήματος αρχείων:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- [**Το Εργαλείο Ανάλυσης και Σύγκρισης Firmware (FACT)**](https://github.com/fkie-cad/FACT\_core) για σφαιρική ανάλυση firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για στατική και δυναμική ανάλυση

### Έλεγχοι Ασφάλειας σε Μεταγλωττισμένα Δυαδικά

Τόσο ο πηγαίος κώδικας όσο και τα μεταγλωττισμένα δυαδικά που βρίσκονται στο σύστημα αρχείων πρέπει να εξεταστούν προσεκτικά για ευπαθείς ευπαθείς. Εργαλεία όπως το **checksec.sh** για δυαδικά Unix και το **PESecurity** για δυαδικά Windows βοηθούν στον εντοπισμό μη προστατευμένων δυαδικών που θα μπορούσαν να εκμεταλλευτούνται.

## Εξομοίωση Firmware για Δυναμική Ανάλυση

Η διαδικασία εξομοίωσης firmware επιτρέπει τη **δυναμική ανάλυση** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις με εξαρτήσεις υλικού ή αρχιτεκτονικής, αλλά η μεταφορά του ριζικού συστήματος αρχείων ή συγκεκριμένων δυαδικών σε μια συσκευή με την ίδια αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια προεγκατεστημένη εικονική μηχανή, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Εξομοίωση Μεμονωμένων Δυαδικών

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να αναγνωριστεί η endianness και η αρχιτεκτονική CPU του προγράμματος.

#### Παράδειγμα με Αρχιτεκτονική MIPS

Για να εξομοιώσετε ένα δυαδικό αρχιτεκτονικής MIPS, μπορείτε να χρησιμοποιήσετε την εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία προσομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### Εξομοίωση Αρχιτεκτονικής ARM

Για δυαδικά αρχιτεκτονικής ARM, η διαδικασία είναι παρόμοια, με τον εξομοιωτή `qemu-arm` να χρησιμοποιείται για την εξομοίωση.

### Πλήρης Εξομοίωση Συστήματος

Εργαλεία όπως το [Firmadyne](https://github.com/firmadyne/firmadyne), το [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), και άλλα, διευκολύνουν την πλήρη εξομοίωση firmware, αυτοματοποιώντας τη διαδικασία και βοηθώντας στη δυναμική ανάλυση.

## Δυναμική Ανάλυση στην Πράξη

Σε αυτό το στάδιο, χρησιμοποιείται είτε ένα πραγματικό είτε εξομοιωμένο περιβάλλον συσκευής για ανάλυση. Είναι ουσιώδες να διατηρείτε πρόσβαση στο κέλυφος του λειτουργικού συστήματος και το σύστημα αρχείων. Η εξομοίωση ενδέχεται να μην αντικατοπτρίζει τέλεια τις αλληλεπιδράσεις με το υλικό, επομένως ενδέχεται να απαιτούνται περιοδικές επανεκκινήσεις της εξομοίωσης. Η ανάλυση θα πρέπει να επανεξετάζει το σύστημα αρχείων, να εκμεταλλεύεται τις αποκαλυφθείσες ιστοσελίδες και υπηρεσίες δικτύου, και να εξετάζει τις ευπάθειες του bootloader. Οι δοκιμές ακεραιότητας του firmware είναι κρίσιμες για την αναγνώριση πιθανών ευπαθειών πίσω πόρτας.

## Τεχνικές Ανάλυσης Χρόνου Εκτέλεσης

Η ανάλυση χρόνου εκτέλεσης περιλαμβάνει την αλληλεπίδραση με ένα διεργασία ή δυαδικό στο περιβάλλον λειτουργίας του, χρησιμοποιώντας εργαλεία όπως το gdb-multiarch, το Frida, και το Ghidra για τον καθορισμό σημείων ανακοπής και την αναγνώριση ευπαθειών μέσω της τεχνικής του fuzzing και άλλων τεχνικών.

## Εκμετάλλευση Δυαδικών και Απόδειξης-Προς-Τούτο

Η ανάπτυξη μιας απόδειξης-προς-τούτο για εντοπισμένες ευπαθείες απαιτεί μια βαθιά κατανόηση της στόχευσης αρχιτεκτονικής και την προγραμματισμό σε γλώσσες χαμηλού επιπέδου. Οι προστασίες χρόνου εκτέλεσης δυαδικών συστημάτων ενσωματωμένων συστημάτων είναι σπάνιες, αλλά όταν υπάρχουν, τεχνικές όπως το Return Oriented Programming (ROP) ενδέχεται να είναι απαραίτητες.

## Προετοιμασμένα Λειτουργικά Συστήματα για Ανάλυση Firmware

Λειτουργικά συστήματα όπως το [AttifyOS](https://github.com/adi0x90/attifyos) και το [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προ-διαμορφωμένα περιβάλλοντα για τον έλεγχο ασφάλειας του firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Προετοιμασμένα ΛΣ για Ανάλυση Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια διανομή που σκοπό έχει να σας βοηθήσει να πραγματοποιήσετε αξιολόγηση ασφάλειας και δοκιμές διείσδυσης συσκευών Internet of Things (IoT). Σας εξοικονομεί πολύτιμο χρόνο παρέχοντας ένα προ-διαμορφωμένο περιβάλλον με όλα τα απαραίτητα εργαλεία φορτωμένα.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Λειτουργικό σύστημα δοκιμών ασφάλειας ενσωματωμένο στο Ubuntu 18.04 προφορτωμένο με εργαλεία ελέγχου ασφαλείας firmware.

## Ευπαθή Firmware για Πρακτική

Για να πρακτικά ανακαλύψετε ευπαθείες σε firmware, χρησιμοποιήστε τα παρακάτω ευπαθή έργα firmware ως αφετηρία.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Αναφορές

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Εκπαίδευση και Πιστοποίηση

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
