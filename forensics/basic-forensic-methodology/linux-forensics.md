# Ανάλυση Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε ροές εργασίας με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Αρχική Συλλογή Πληροφοριών

### Βασικές Πληροφορίες

Καταρχήν, συνιστάται να έχετε ένα **USB** με **γνωστά καλά δυαδικά αρχεία και βιβλιοθήκες** (μπορείτε απλά να πάρετε το ubuntu και να αντιγράψετε τους φακέλους _/bin_, _/sbin_, _/lib_ και _/lib64_), στη συνέχεια να προσαρτήσετε το USB και να τροποποιήσετε τις μεταβλητές περιβάλλοντος για να χρησιμοποιήσετε αυτά τα δυαδικά αρχεία:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Αφού έχετε ρυθμίσει το σύστημα να χρησιμοποιεί καλά και γνωστά δυαδικά αρχεία, μπορείτε να ξεκινήσετε την **εξαγωγή ορισμένων βασικών πληροφοριών**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Υποψίασμα για ύποπτες πληροφορίες

Κατά την απόκτηση των βασικών πληροφοριών, θα πρέπει να ελέγξετε για παράξενα πράγματα όπως:

* Οι **διεργασίες root** συνήθως εκτελούνται με χαμηλά PIDS, οπότε αν βρείτε μια διεργασία root με ένα μεγάλο PID μπορεί να υπάρχει υποψία
* Ελέγξτε τις **εγγεγραμμένες συνδέσεις** χρηστών χωρίς κέλυφος μέσα στο `/etc/passwd`
* Ελέγξτε για **κατακερματισμένους κωδικούς πρόσβασης** μέσα στο `/etc/shadow` για χρήστες χωρίς κέλυφος

### Αντιγραφή μνήμης

Για να αποκτήσετε τη μνήμη του εκτελούμενου συστήματος, συνίσταται να χρησιμοποιήσετε το [**LiME**](https://github.com/504ensicsLabs/LiME).\
Για να το **μεταγλωττίσετε**, πρέπει να χρησιμοποιήσετε το **ίδιο πυρήνα** που χρησιμοποιεί η μηχανή θύμα.

{% hint style="info" %}
Θυμηθείτε ότι **δεν μπορείτε να εγκαταστήσετε το LiME ή οτιδήποτε άλλο** στη μηχανή θύμα, καθώς θα προκαλέσει αλλαγές σε αυτήν.
{% endhint %}

Έτσι, αν έχετε μια πανομοιότυπη έκδοση του Ubuntu, μπορείτε να χρησιμοποιήσετε την εντολή `apt-get install lime-forensics-dkms`\
Σε άλλες περιπτώσεις, πρέπει να κατεβάσετε το [**LiME**](https://github.com/504ensicsLabs/LiME) από το github και να το μεταγλωττίσετε με τις σωστές κεφαλίδες του πυρήνα. Για να **αποκτήσετε τις ακριβείς κεφαλίδες του πυρήνα** της μηχανής θύματος, απλά **αντιγράψτε τον φάκελο** `/lib/modules/<έκδοση πυρήνα>` στη μηχανή σας και στη συνέχεια **μεταγλωττίστε** το LiME χρησιμοποιώντας αυτές.
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
Το LiME υποστηρίζει 3 **μορφές**:

* Raw (κάθε τμήμα ενωμένο μαζί)
* Padded (ίδιο με το raw, αλλά με μηδενικά στα δεξιά bits)
* Lime (συνιστώμενη μορφή με μεταδεδομένα)

Το LiME μπορεί επίσης να χρησιμοποιηθεί για να **στείλει το dump μέσω δικτύου** αντί να το αποθηκεύσει στο σύστημα χρησιμοποιώντας κάτι όπως: `path=tcp:4444`

### Δημιουργία εικόνας δίσκου

#### Απενεργοποίηση

Καταρχάς, θα πρέπει να **απενεργοποιήσετε το σύστημα**. Αυτό δεν είναι πάντα μια επιλογή, καθώς μερικές φορές το σύστημα θα είναι ένας παραγωγικός διακομιστής που η εταιρεία δεν μπορεί να τον απενεργοποιήσει.\
Υπάρχουν **2 τρόποι** απενεργοποίησης του συστήματος, μια **κανονική απενεργοποίηση** και μια **απενεργοποίηση "τραβώντας το φις"**. Ο πρώτος θα επιτρέψει στις **διεργασίες να τερματίσουν κανονικά** και το **σύστημα αρχείων** να **συγχρονιστεί**, αλλά θα επιτρέψει επίσης στον πιθανό **κακόβουλο κώδικα** να **καταστρέψει τα αποδεικτικά στοιχεία**. Η προσέγγιση "τραβώντας το φις" μπορεί να οδηγήσει σε **απώλεια ορισμένων πληροφοριών** (δεν θα χαθεί πολλή πληροφορία καθώς ήδη πήραμε μια εικόνα της μνήμης) και ο **κακόβουλος κώδικας δεν θα έχει καμία ευκαιρία** να κάνει κάτι γι' αυτό. Επομένως, αν **υποψιάζεστε** ότι μπορεί να υπάρχει **κακόβουλος κώδικας**, απλά εκτελέστε την εντολή **`sync`** στο σύστημα και τραβήξτε το φις.

#### Δημιουργία εικόνας του δίσκου

Είναι σημαντικό να σημειώσουμε ότι **πριν συνδέσετε τον υπολογιστή σας με οτιδήποτε σχετίζεται με την υπόθεση**, πρέπει να είστε σίγουροι ότι θα γίνει **προσάρτηση με ανάγνωση μόνο** για να αποφευχθεί οποιαδήποτε τροποποίηση πληροφοριών.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Προ-ανάλυση εικόνας δίσκου

Δημιουργία εικόνας δίσκου χωρίς περισσότερα δεδομένα.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε εργασιακές διαδικασίες με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Αναζήτηση για γνωστό κακόβουλο λογισμικό

### Τροποποιημένα αρχεία συστήματος

Το Linux προσφέρει εργαλεία για τη διασφάλιση της ακεραιότητας των συστατικών του συστήματος, το οποίο είναι κρίσιμο για τον εντοπισμό πιθανών προβληματικών αρχείων.

- **Συστήματα βασισμένα σε RedHat**: Χρησιμοποιήστε την εντολή `rpm -Va` για μια συνολική έλεγχο.
- **Συστήματα βασισμένα σε Debian**: Χρησιμοποιήστε την εντολή `dpkg --verify` για αρχικό έλεγχο, ακολουθούμενη από την εντολή `debsums | grep -v "OK$"` (μετά την εγκατάσταση του `debsums` με την εντολή `apt-get install debsums`) για τον εντοπισμό οποιουδήποτε προβλήματος.

### Εργαλεία ανίχνευσης κακόβουλου λογισμικού/Rootkit

Διαβάστε την παρακάτω σελίδα για να μάθετε για εργαλεία που μπορούν να είναι χρήσιμα για τον εντοπισμό κακόβουλου λογισμικού:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Αναζήτηση εγκατεστημένων προγραμμάτων

Για να αναζητήσετε αποτελεσματικά εγκατεστημένα προγράμματα τόσο σε συστήματα Debian όσο και σε συστήματα RedHat, εξετάστε τα αρχεία καταγραφής και τις βάσεις δεδομένων του συστήματος, σε συνδυασμό με χειροκίνητους ελέγχους σε κοινά καταλόγους.

- Για το Debian, εξετάστε τα αρχεία **_`/var/lib/dpkg/status`_** και **_`/var/log/dpkg.log`_** για να λάβετε λεπτομέρειες σχετικά με τις εγκαταστάσεις πακέτων, χρησιμοποιώντας την εντολή `grep` για να φιλτράρετε συγκεκριμένες πληροφορίες.

- Οι χρήστες του RedHat μπορούν να ερωτήσουν τη βάση δεδομένων RPM με την εντολή `rpm -qa --root=/mntpath/var/lib/rpm` για να εμφανίσουν τα εγκατεστημένα πακέτα.

Για να ανακαλύψετε λογισμικό που έχει εγκατασταθεί χειροκίνητα ή εκτός αυτών των διαχειριστών πακέτων, εξερευνήστε καταλόγους όπως **_`/usr/local`_**, **_`/opt`_**, **_`/usr/sbin`_**, **_`/usr/bin`_**, **_`/bin`_**, και **_`/sbin`_**. Συνδυάστε τη λίστα των καταλόγων με εντολές που είναι συγκεκριμένες για το σύστημα για να εντοπίσετε εκτελέσιμα που δεν σχετίζονται με γνωστά πακέτα, βελτιώνοντας έτσι την αναζήτησή σας για όλα τα εγκατεστημένα προγράμματα.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε εύκολα ροές εργασίας με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ανάκτηση Διαγραμμένων Εκτελέσιμων Αρχείων

Φανταστείτε ένα διεργασία που εκτελέστηκε από το /tmp/exec και διαγράφηκε. Είναι δυνατή η εξαγωγή του
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Επιθεώρηση τοποθεσιών αυτόματης εκκίνησης

### Προγραμματισμένες εργασίες
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### Υπηρεσίες

Διαδρομές όπου μπορεί να εγκατασταθεί κακόβουλο λογισμικό ως υπηρεσία:

- **/etc/inittab**: Καλεί σενάρια αρχικοποίησης όπως το rc.sysinit, καθοδηγώντας περαιτέρω σε σενάρια εκκίνησης.
- **/etc/rc.d/** και **/etc/rc.boot/**: Περιέχουν σενάρια για την εκκίνηση των υπηρεσιών, με το δεύτερο να βρίσκεται σε παλαιότερες εκδόσεις του Linux.
- **/etc/init.d/**: Χρησιμοποιείται σε ορισμένες εκδόσεις του Linux, όπως το Debian, για την αποθήκευση σεναρίων εκκίνησης.
- Οι υπηρεσίες μπορεί επίσης να ενεργοποιηθούν μέσω των **/etc/inetd.conf** ή **/etc/xinetd/**, ανάλογα με την παραλλαγή του Linux.
- **/etc/systemd/system**: Ένας κατάλογος για σενάρια συστήματος και διαχείρισης υπηρεσιών.
- **/etc/systemd/system/multi-user.target.wants/**: Περιέχει συνδέσμους προς υπηρεσίες που πρέπει να ξεκινήσουν σε ένα επίπεδο εκτέλεσης πολλαπλών χρηστών.
- **/usr/local/etc/rc.d/**: Για προσαρμοσμένες ή υπηρεσίες τρίτων.
- **~/.config/autostart/**: Για εφαρμογές εκκίνησης αυτόματης εκκίνησης που είναι συγκεκριμένες για τον χρήστη, η οποία μπορεί να είναι ένα κρυψώνα για κακόβουλο λογισμικό που στοχεύει τον χρήστη.
- **/lib/systemd/system/**: Παγκόσμια προεπιλεγμένα αρχεία μονάδας που παρέχονται από εγκατεστημένα πακέτα.


### Πυρήνας Ενοτήτων

Οι ενότητες πυρήνα Linux, που συχνά χρησιμοποιούνται από κακόβουλο λογισμικό ως στοιχεία rootkit, φορτώνονται κατά την εκκίνηση του συστήματος. Οι κατάλογοι και τα αρχεία που είναι κρίσιμα για αυτές τις ενότητες περιλαμβάνουν:

- **/lib/modules/$(uname -r)**: Περιέχει ενότητες για την τρέχουσα έκδοση του πυρήνα.
- **/etc/modprobe.d**: Περιέχει αρχεία ρύθμισης για τον έλεγχο της φόρτωσης των ενοτήτων.
- **/etc/modprobe** και **/etc/modprobe.conf**: Αρχεία για τις γενικές ρυθμίσεις των ενοτήτων.

### Άλλες Τοποθεσίες Αυτόματης Εκκίνησης

Το Linux χρησιμοποιεί διάφορα αρχεία για την αυτόματη εκτέλεση προγραμμάτων κατά την σύνδεση του χρήστη, πιθανώς κρύβοντας κακόβουλο λογισμικό:

- **/etc/profile.d/***, **/etc/profile** και **/etc/bash.bashrc**: Εκτελούνται για κάθε σύνδεση χρήστη.
- **~/.bashrc**, **~/.bash_profile**, **~/.profile** και **~/.config/autostart**: Αρχεία που αφορούν συγκεκριμένους χρήστες και εκτελούνται κατά την σύνδεσή τους.
- **/etc/rc.local**: Εκτελείται μετά την εκκίνηση όλων των υπηρεσιών του συστήματος, σηματοδοτώντας το τέλος της μετάβασης σε ένα πολλαπλών χρηστών περιβάλλον.

## Εξέταση Αρχείων Καταγραφής

Τα συστήματα Linux καταγράφουν τις δραστηριότητες των χρηστών και τα γεγονότα του συστήματος μέσω διάφορων αρχείων καταγραφής. Αυτά τα αρχεία καταγραφής είναι κρίσιμα για την αναγνώριση μη εξουσιοδοτημένης πρόσβασης, μολύνσεων από κακόβουλο λογισμικό και άλλων περιστατικών ασφαλείας. Τα κύρια αρχεία καταγραφής περιλαμβάνουν:

- **/var/log/syslog** (Debian) ή **/var/log/messages** (RedHat): Καταγράφουν μηνύματα και δραστηριότητες σε όλο το σύστημα.
- **/var/log/auth.log** (Debian) ή **/var/log/secure** (RedHat): Καταγράφουν προσπάθειες πιστοποίησης, επιτυχείς και αποτυχημένες συνδέσεις.
- Χρησιμοποιήστε την εντολή `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` για να φιλτράρετε σχετικά γεγονότα πιστοποίησης.
- **/var/log/boot.log**: Περιέχει μηνύματα εκκίνησης του συστήματος.
- **/var/log/maillog** ή **/var/log/mail.log**: Καταγράφουν δραστηριότητες του διακομιστή ηλεκτρονικού ταχυδρομείου, χρήσιμες για την παρακολούθηση υπηρεσιών που σχετίζονται με το ηλεκτρονικό ταχυδρομείο.
- **/var/log/kern.log**: Αποθηκεύει μη
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Παραδείγματα

#### Εύρεση αρχείων

Για να εντοπίσετε αρχεία σε ένα σύστημα Linux, μπορείτε να χρησιμοποιήσετε την εντολή `find`. Για παράδειγμα, για να βρείτε όλα τα αρχεία με κατάληξη `.txt` στον κατάλογο `/home/user`, μπορείτε να εκτελέσετε την εξής εντολή:

```bash
find /home/user -name "*.txt"
```

#### Ανάλυση αρχείων καταγραφής

Για να αναλύσετε ένα αρχείο καταγραφής σε ένα σύστημα Linux, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το `grep` ή το `awk`. Για παράδειγμα, για να βρείτε όλες τις εμφανίσεις της λέξης "error" σε ένα αρχείο καταγραφής με όνομα `logfile.txt`, μπορείτε να εκτελέσετε την εξής εντολή:

```bash
grep "error" logfile.txt
```

#### Ανάκτηση διαγραμμένων αρχείων

Για να ανακτήσετε διαγραμμένα αρχεία σε ένα σύστημα Linux, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το `extundelete` ή το `foremost`. Για παράδειγμα, για να ανακτήσετε όλα τα διαγραμμένα αρχεία από τον κατάλογο `/home/user`, μπορείτε να εκτελέσετε την εξής εντολή:

```bash
extundelete /dev/sda1 --restore-all
```

#### Ανάλυση μνήμης

Για να αναλύσετε τη μνήμη ενός συστήματος Linux, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το `Volatility` ή το `LiME`. Για παράδειγμα, για να εκτελέσετε μια ανάλυση μνήμης σε ένα αντίγραφο ασφαλείας της μνήμης με όνομα `memory.dump`, μπορείτε να εκτελέσετε την εξής εντολή:

```bash
volatility -f memory.dump imageinfo
```
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Περισσότερα παραδείγματα και πληροφορίες μπορείτε να βρείτε στο GitHub: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)



<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε εργασιακές διαδικασίες με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}



## Αναθεώρηση Λογαριασμών Χρηστών και Δραστηριοτήτων Σύνδεσης

Εξετάστε τα αρχεία _**/etc/passwd**_, _**/etc/shadow**_ και τα **αρχεία καταγραφής ασφαλείας** για ασυνήθιστα ονόματα ή λογαριασμούς που δημιουργήθηκαν ή χρησιμοποιήθηκαν κοντά σε γνωστά μη εξουσιοδοτημένα γεγονότα. Επίσης, ελέγξτε πιθανές επιθέσεις brute-force στο sudo.\
Επιπλέον, ελέγξτε αρχεία όπως το _**/etc/sudoers**_ και το _**/etc/groups**_ για απροσδόκητα προνόμια που έχουν δοθεί σε χρήστες.\
Τέλος, αναζητήστε λογαριασμούς χωρίς κωδικούς πρόσβασης ή με εύκολα μαντεψιάματα κωδικούς.

## Εξέταση Συστήματος Αρχείων

### Ανάλυση Δομών Συστήματος Αρχείων σε Έρευνα Κακόβουλου Λογισμικού

Κατά την έρευνα κακόβουλων περιστατικών, η δομή του συστήματος αρχείων είναι μια κρίσιμη πηγή πληροφοριών, αποκαλύπτοντας τόσο την ακολουθία των γεγονότων όσο και το περιεχόμενο του κακόβουλου λογισμικού. Ωστόσο, οι συγγραφείς κακόβουλου λογισμικού αναπτύσσουν τεχνικές για να δυσκολέψουν αυτήν την ανάλυση, όπως η τροποποίηση των χρονοσημάτων των αρχείων ή η αποφυγή του συστήματος αρχείων για την αποθήκευση δεδομένων.

Για να αντιμετωπίσετε αυτές τις αντι-δικαστικές μεθόδους, είναι απαραίτητο:

- **Να διεξάγετε μια λεπτομερή ανάλυση χρονολογίας** χρησιμοποιώντας εργαλεία όπως το **Autopsy** για την οπτικοποίηση της χρονολογίας των γεγονότων ή το `mactime` του **Sleuth Kit** για λεπτομερείς χρονολογικές πληροφορίες.
- **Να ερευνήσετε απροσδόκητα scripts** στον $PATH του συστήματος, τα οποία μπορεί να περιλαμβάνουν shell ή PHP scripts που χρησιμοποιούνται από επιτιθέμενους.
- **Να εξετάσετε τον φάκελο `/dev` για ατυπα αρχεία**, καθώς παραδοσιακά περιέχει ειδικά αρχεία, αλλά μπορεί να περιέχει και αρχεία που σχετίζονται με κακόβουλο λογισμικό.
- **Να αναζητήσετε κρυφά αρχεία ή φακέλους** με ονόματα όπως ".. " (τελεία τελεία κενό) ή "..^G" (τελεία τελεία control-G), τα οποία μπορεί να κρύβουν κακόβουλο περιεχόμενο.
- **Να εντοπίσετε αρχεία setuid root** χρησιμοποιώντας την εντολή:
```find / -user root -perm -04000 -print```
Αυτό εντοπίζει αρχεία με αυξημένα δικαιώματα, τα οποία μπορεί να καταχραστούν οι επιτιθέμενοι.
- **Να ελέγξετε τα χρονοσήματα διαγραφής** στους πίνακες inode για να εντοπίσετε μαζικές διαγραφές αρχείων, που μπορεί να υποδηλώνουν την παρουσία rootkits ή τροϊανών.
- **Να επιθεωρήσετε συνεχόμενα inodes** για κοντινά κακόβουλα αρχεία μετά τον εντοπισμό ενός, καθώς μπορεί να έχουν τοποθετηθεί μαζί.
- **Να ελέγξετε κοινούς δυαδικούς φακέλους** (_/bin_, _/sbin_) για πρόσφατα τροποποιημένα αρχεία, καθώς αυτά μπορεί να έχουν τροποποιηθεί από κακόβουλο λογισμικό.
```bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
```
{% hint style="info" %}
Σημείωση ότι ένας **επιτιθέμενος** μπορεί να **τροποποιήσει** την **ώρα** για να κάνει τα **αρχεία να φαίνονται νόμιμα**, αλλά δεν μπορεί να τροποποιήσει το **inode**. Εάν διαπιστώσετε ότι ένα **αρχείο** υποδεικνύει ότι δημιουργήθηκε και τροποποιήθηκε την **ίδια ώρα** με τα υπόλοιπα αρχεία στον ίδιο φάκελο, αλλά το **inode** είναι **απροσδόκητα μεγαλύτερο**, τότε οι **χρονοσφραγίδες του αρχείου αυτού τροποποιήθηκαν**.
{% endhint %}

## Σύγκριση αρχείων διαφορετικών εκδόσεων συστήματος αρχείων

### Περίληψη σύγκρισης εκδόσεων συστήματος αρχείων

Για να συγκρίνουμε τις εκδόσεις του συστήματος αρχείων και να εντοπίσουμε τις αλλαγές, χρησιμοποιούμε απλοποιημένες εντολές `git diff`:

- **Για να βρούμε νέα αρχεία**, συγκρίνουμε δύο φακέλους:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Για τροποποιημένο περιεχόμενο**, αναφέρετε τις αλλαγές αγνοώντας συγκεκριμένες γραμμές:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Για τον εντοπισμό διαγραμμένων αρχείων**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Επιλογές φίλτρου** (`--diff-filter`) βοηθούν στον περιορισμό σε συγκεκριμένες αλλαγές όπως προστιθέμενα (`A`), διαγραμμένα (`D`) ή τροποποιημένα (`M`) αρχεία.
- `A`: Προστιθέμενα αρχεία
- `C`: Αντιγραμμένα αρχεία
- `D`: Διαγραμμένα αρχεία
- `M`: Τροποποιημένα αρχεία
- `R`: Μετονομασμένα αρχεία
- `T`: Αλλαγές τύπου (π.χ. αρχείο σε σύνδεσμο)
- `U`: Μη συγχωνευμένα αρχεία
- `X`: Άγνωστα αρχεία
- `B`: Κατεστραμμένα αρχεία

## Αναφορές

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Βιβλίο: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!

* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
