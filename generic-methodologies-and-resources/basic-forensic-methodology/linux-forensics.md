# Ψηφιακή Διαφθορά σε Linux

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

## Αρχική Συλλογή Πληροφοριών

### Βασικές Πληροφορίες

Καταρχάς, συνιστάται να έχετε ένα **USB** με **καλά γνωστά δυαδικά και βιβλιοθήκες** (μπορείτε απλά να πάρετε το Ubuntu και να αντιγράψετε τους φακέλους _/bin_, _/sbin_, _/lib_ και _/lib64_), στη συνέχεια να τοποθετήσετε το USB και να τροποποιήσετε τις μεταβλητές περιβάλλοντος για να χρησιμοποιήσετε αυτά τα δυαδικά:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Αφού έχετε ρυθμίσει το σύστημα να χρησιμοποιεί καλά και γνωστά δυαδικά αρχεία, μπορείτε να ξεκινήσετε την **εξαγωγή μερικών βασικών πληροφοριών**:
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
#### Υπούλη πληροφορία

Κατά την απόκτηση των βασικών πληροφοριών, πρέπει να ελέγξετε για περίεργα πράγματα όπως:

- **Διεργασίες ρίζας** συνήθως τρέχουν με χαμηλά PIDS, οπότε αν βρείτε μια διεργασία ρίζας με ένα μεγάλο PID μπορείτε να υποψιαστείτε
- Ελέγξτε τις **εγγεγραμμένες συνδέσεις** χρηστών χωρίς κέλυφος μέσα στο `/etc/passwd`
- Ελέγξτε τις **κατακερματισμένες κωδικοποιήσεις** μέσα στο `/etc/shadow` για χρήστες χωρίς κέλυφος

### Ανάκτηση Αναμνηστικού

Για να αποκτήσετε τη μνήμη του τρέχοντος συστήματος, συνιστάται να χρησιμοποιήσετε το [**LiME**](https://github.com/504ensicsLabs/LiME).\
Για να το **μεταγλωτίσετε**, πρέπει να χρησιμοποιήσετε το **ίδιο πυρήνα** που χρησιμοποιεί η μηχανή θύματος.

{% hint style="info" %}
Να θυμάστε ότι **δεν μπορείτε να εγκαταστήσετε το LiME ή οτιδήποτε άλλο** στη μηχανή θύματος καθώς θα προκαλέσει πολλές αλλαγές σε αυτήν
{% endhint %}

Έτσι, αν έχετε μια ταυτόσημη έκδοση του Ubuntu μπορείτε να χρησιμοποιήσετε `apt-get install lime-forensics-dkms`\
Σε άλλες περιπτώσεις, πρέπει να κατεβάσετε το [**LiME**](https://github.com/504ensicsLabs/LiME) από το github και να το μεταγλωτίσετε με τις σωστές κεφαλίδες πυρήνα. Για να **ανακτήσετε τις ακριβείς κεφαλίδες πυρήνα** της μηχανής θύματος, μπορείτε απλά να **αντιγράψετε τον κατάλογο** `/lib/modules/<έκδοση πυρήνα>` στη μηχανή σας, και στη συνέχεια να **μεταγλωτίσετε** το LiME χρησιμοποιώντας αυτές.
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
Το LiME υποστηρίζει 3 **μορφές**:

* Raw (κάθε τμήμα συνενωμένο μαζί)
* Padded (ίδιο με το raw, αλλά με μηδενικά στα δεξιά bits)
* Lime (συνιστώμενη μορφή με μεταδεδομένα)

Το LiME μπορεί επίσης να χρησιμοποιηθεί για να **στείλει την αντιγραφή μέσω δικτύου** αντί να την αποθηκεύσει στο σύστημα χρησιμοποιώντας κάτι σαν: `path=tcp:4444`

### Εικονική αντιγραφή δίσκου

#### Απενεργοποίηση

Καταρχάς, θα πρέπει να **απενεργοποιήσετε το σύστημα**. Αυτό δεν είναι πάντα μια επιλογή καθώς μερικές φορές το σύστημα θα είναι ένας παραγωγικός διακομιστής που η εταιρεία δεν μπορεί να επιτρέψει να απενεργοποιηθεί.\
Υπάρχουν **2 τρόποι** απενεργοποίησης του συστήματος, μια **κανονική απενεργοποίηση** και μια **απενεργοποίηση "τραβώντας το φις"**. Η πρώτη θα επιτρέψει στις **διεργασίες να τερματιστούν όπως συνήθως** και το **σύστημα αρχείων** να **συγχρονιστεί**, αλλά θα επιτρέψει επίσης στο πιθανό **κακόβουλο λογισμικό** να **καταστρέψει αποδεικτικά στοιχεία**. Η προσέγγιση "τραβώντας το φις" μπορεί να έχει **κάποια απώλεια πληροφοριών** (δεν θα χαθεί πολύ από τις πληροφορίες καθώς έχουμε ήδη πάρει μια εικόνα της μνήμης) και το **κακόβουλο λογισμικό δεν θα έχει καμία ευκαιρία** να κάνει κάτι γι' αυτό. Επομένως, αν υποψιάζεστε ότι μπορεί να υπάρχει **κακόβουλο λογισμικό**, απλά εκτελέστε την εντολή **`sync`** στο σύστημα και τραβήξτε το φις.

#### Λήψη εικόνας του δίσκου

Είναι σημαντικό να σημειώσετε ότι **πριν συνδέσετε τον υπολογιστή σας σε οτιδήποτε σχετίζεται με την υπόθεση**, πρέπει να είστε σίγουροι ότι θα **είναι προσαρτημένος ως μόνο για ανάγνωση** για να αποφύγετε την τροποποίηση οποιασδήποτε πληροφορίας.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Προανάλυση εικόνας δίσκου

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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Αναζήτηση γνωστού Malware

### Τροποποιημένα Αρχεία Συστήματος

Το Linux προσφέρει εργαλεία για τη διασφάλιση της ακεραιότητας των συστατικών του συστήματος, το οποίο είναι κρίσιμο για τον εντοπισμό ενδεχόμενα προβληματικών αρχείων.

* **Συστήματα βασισμένα σε RedHat**: Χρησιμοποιήστε την εντολή `rpm -Va` για μια συνολική έλεγχο.
* **Συστήματα βασισμένα σε Debian**: `dpkg --verify` για αρχικό έλεγχο, ακολουθούμενο από `debsums | grep -v "OK$"` (μετά την εγκατάσταση του `debsums` με `apt-get install debsums`) για την εντοπισμό οποιωνδήποτε προβλημάτων.

### Εργαλεία Εντοπισμού Malware/Rootkit

Διαβάστε την παρακάτω σελίδα για να μάθετε για εργαλεία που μπορεί να είναι χρήσιμα για τον εντοπισμό malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Αναζήτηση εγκατεστημένων προγραμμάτων

Για να αναζητήσετε αποτελεσματικά εγκατεστημένα προγράμματα τόσο σε συστήματα Debian όσο και RedHat, σκεφτείτε να εκμεταλλευτείτε τα αρχεία καταγραφής συστήματος και τις βάσεις δεδομένων σε συνδυασμό με χειροκίνητους ελέγχους σε κοινούς καταλόγους.

* Για το Debian, ελέγξτε τα _**`/var/lib/dpkg/status`**_ και _**`/var/log/dpkg.log`**_ για λεπτομέρειες σχετικά με τις εγκαταστάσεις πακέτων, χρησιμοποιώντας το `grep` για να φιλτράρετε συγκεκριμένες πληροφορίες.
* Οι χρήστες RedHat μπορούν να ερευνήσουν τη βάση δεδομένων RPM με την εντολή `rpm -qa --root=/mntpath/var/lib/rpm` για να καταχωρίσουν τα εγκατεστημένα πακέτα.

Για να ανακαλύψετε λογισμικό που έχει εγκατασταθεί χειροκίνητα ή εκτός αυτών των διαχειριστών πακέτων, εξετάστε καταλόγους όπως _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ και _**`/sbin`**_. Συνδυάστε τις λίστες καταλόγων με εντολές ειδικές για το σύστημα για να εντοπίσετε εκτελέσιμα που δεν σχετίζονται με γνωστά πακέτα, βελτιώνοντας έτσι την αναζήτησή σας για όλα τα εγκατεστημένα προγράμματα.
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της παγκόσμιας κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ανάκτηση Διαγραμμένων Εκτελέσιμων Αρχείων

Φανταστείτε ένα διεργασία που εκτελέστηκε από το /tmp/exec και στη συνέχεια διαγράφηκε. Είναι δυνατόν να το εξάγετε
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Επιθεώρηση τοποθεσιών εκκίνησης αυτόματης εκκίνησης

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

- **/etc/inittab**: Καλεί σενάρια εκκίνησης όπως το rc.sysinit, καθοδηγώντας προς περαιτέρω σενάρια εκκίνησης.
- **/etc/rc.d/** και **/etc/rc.boot/**: Περιέχουν σενάρια για την εκκίνηση υπηρεσιών, με το δεύτερο να βρίσκεται σε παλαιότερες εκδόσεις Linux.
- **/etc/init.d/**: Χρησιμοποιείται σε συγκεκριμένες εκδόσεις Linux όπως το Debian για την αποθήκευση σεναρίων εκκίνησης.
- Οι υπηρεσίες μπορεί επίσης να ενεργοποιηθούν μέσω **/etc/inetd.conf** ή **/etc/xinetd/**, ανάλογα με την εκδοχή του Linux.
- **/etc/systemd/system**: Ένας κατάλογος για σενάρια συστήματος και διαχείρισης υπηρεσιών.
- **/etc/systemd/system/multi-user.target.wants/**: Περιέχει συνδέσμους προς υπηρεσίες που πρέπει να ξεκινήσουν σε ένα επίπεδο εκτέλεσης πολλαπλών χρηστών.
- **/usr/local/etc/rc.d/**: Για προσαρμοσμένες ή υπηρεσίες τρίτων.
- **\~/.config/autostart/**: Για εφαρμογές εκκίνησης αυτόματα που είναι συγκεκριμένες για τον χρήστη, μπορεί να είναι ένα μέρος κρυψώνας για κακόβουλο λογισμικό που στοχεύει τον χρήστη.
- **/lib/systemd/system/**: Αρχεία μονάδας προεπιλογής για ολόκληρο το σύστημα που παρέχονται από εγκατεστημένα πακέτα.

### Μονάδες πυρήνα

Οι μονάδες πυρήνα Linux, συχνά χρησιμοποιούμενες από κακόβουλο λογισμικό ως στοιχεία rootkit, φορτώνονται κατά την εκκίνηση του συστήματος. Οι κατάλογοι και τα αρχεία που είναι κρίσιμα για αυτές τις μονάδες περιλαμβάνουν:

- **/lib/modules/$(uname -r)**: Κρατά μονάδες για την τρέχουσα έκδοση του πυρήνα.
- **/etc/modprobe.d**: Περιέχει αρχεία ρύθμισης για τον έλεγχο της φόρτωσης μονάδων.
- **/etc/modprobe** και **/etc/modprobe.conf**: Αρχεία για γενικές ρυθμίσεις μονάδων.

### Άλλες Τοποθεσίες Αυτόματης Εκκίνησης

Το Linux χρησιμοποιεί διάφορα αρχεία για την αυτόματη εκτέλεση προγραμμάτων κατά την σύνδεση του χρήστη, πιθανώς κρύβοντας κακόβουλο λογισμικό:

- **/etc/profile.d/**\*, **/etc/profile**, και **/etc/bash.bashrc**: Εκτελούνται για οποιαδήποτε σύνδεση χρήστη.
- **\~/.bashrc**, **\~/.bash\_profile**, **\~/.profile**, και **\~/.config/autostart**: Αρχεία συγκεκριμένα για τον χρήστη που εκτελούνται κατά τη σύνδεσή τους.
- **/etc/rc.local**: Εκτελείται μετά την εκκίνηση όλων των υπηρεσιών συστήματος, σηματοδοτώντας το τέλος της μετάβασης σε ένα πολλαπλών χρηστών περιβάλλον.

## Εξέταση Αρχείων Καταγραφής

Τα συστήματα Linux καταγράφουν τις δραστηριότητες των χρηστών και τα συμβάντα του συστήματος μέσω διαφόρων αρχείων καταγραφής. Αυτά τα αρχεία καταγραφής είναι ζωτικής σημασίας για την αναγνώριση μη εξουσιοδοτημένης πρόσβασης, μολύνσεις από κακόβουλο λογισμικό και άλλα περιστατικά ασφάλειας. Κύρια αρχεία καταγραφής περιλαμβάνουν:

- **/var/log/syslog** (Debian) ή **/var/log/messages** (RedHat): Καταγράφουν μηνύματα και δραστηριότητες σε ολόκληρο το σύστημα.
- **/var/log/auth.log** (Debian) ή **/var/log/secure** (RedHat): Καταγράφουν προσπάθειες πιστοποίησης, επιτυχείς και αποτυχημένες συνδέσεις.
- Χρησιμοποιήστε την εντολή `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` για να φιλτράρετε σχετικά γεγονότα πιστοποίησης.
- **/var/log/boot.log**: Περιέχει μηνύματα εκκίνησης του συστήματος.
- **/var/log/maillog** ή **/var/log/mail.log**: Καταγράφουν δραστηριότητες του διακομιστή email, χρήσιμα για την παρακολούθηση υπηρεσιών σχετικών με email.
- **/var/log/kern.log**: Αποθηκεύει μηνύματα πυρήνα, συμπεριλαμβανομένων σφαλμάτων και προειδοποιήσεων.
- **/var/log/dmesg**: Κρατά μηνύματα οδηγών συσκευών.
- **/var/log/faillog**: Καταγράφει αποτυχημένες προσπάθειες σύνδεσης, βοηθώντας στην έρευνα παραβίασης ασφάλειας.
- **/var/log/cron**: Καταγράφει τις εκτελέσεις των εργασιών cron.
- **/var/log/daemon.log**: Καταγράφει τις δραστηριότητες υπηρεσιών φόντου.
- **/var/log/btmp**: Τεκμηριώνει αποτυχημένες προσπάθειες σύνδεσης.
- **/var/log/httpd/**: Περιέχει αρχεία καταγραφής σφαλμάτων και πρόσβασης του Apache HTTPD.
- **/var/log/mysqld.log** ή **/var/log/mysql.log**: Καταγράφουν δραστηριότητες της βάσης δεδομένων MySQL.
- **/var/log/xferlog**: Καταγράφει μεταφορές αρχείων FTP.
- **/var/log/**: Πάντα ελέγξτε για απροσδόκητα αρχεία καταγραφής εδώ.

{% hint style="info" %}
Τα αρχεία καταγραφής συστήματος Linux και τα υποσυστήματα ελέγχου ενδέχεται να είναι απενεργοποιημένα ή διαγραμμένα σε περίπτωση διείσδυσης ή περιστατικού κακόβουλου λογισμικού. Διότι τα αρχεία καταγραφής σε συστήματα Linux συνήθως περιέχουν μερικές από τις πιο χρήσιμες πληροφορίες σχετικά με κακόβουλες δραστηριότητες, οι εισβολείς τα διαγράφουν συστηματικά. Επομένως, κατά την εξέταση των διαθέσιμων αρχείων καταγραφής, είναι σημαντικό να εξετάζετε για κενά ή μη σειριακές καταχωρήσεις που μπορεί να υποδεικνύουν διαγραφή ή παρεμβολή.
{% endhint %}

**Το Linux διατηρεί μια ιστορία εντολών για κάθε χρήστη**, αποθηκευμένη σε:

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

Επιπλέον, η εντολή `last -Faiwx` παρέχει μια λίστα με τις συνδέσεις χρηστών. Ελέγξτε την για άγνωστες ή απροσδόκητες συνδέσεις.

Ελέγξτε αρχεία που μπορούν να παραχωρήσουν επιπλέον δικαιώματα:

- Εξετάστε το `/etc/sudoers` για απροσδόκητα δικαιώματα χρήστη που ενδεχομένως έχουν χορηγηθεί.
- Εξετάστε το `/etc/sudoers.d/` για απροσδόκητα δικαιώματα χρήστη που ενδεχομένως έχουν χορηγηθεί.
- Εξετάστε το `/etc/groups` για την αναγνώριση οποιωνδήποτε ασυνήθιστων μελών ομάδας ή δικαιωμάτων.
- Εξετάστε το `/etc/passwd` για την αναγνώριση οποιωνδήπο
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Παραδείγματα
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
## Εξέταση Λογαριασμών Χρηστών και Δραστηριοτήτων Σύνδεσης

Εξετάστε τα _**/etc/passwd**_, _**/etc/shadow**_ και **αρχεία καταγραφής ασφαλείας** για ασυνήθιστα ονόματα ή λογαριασμούς που δημιουργήθηκαν ή χρησιμοποιήθηκαν κοντά σε γνωστά μη εξουσιοδοτημένα συμβάντα. Επίσης, ελέγξτε πιθανές επιθέσεις sudo brute-force.\
Επιπλέον, ελέγξτε αρχεία όπως το _**/etc/sudoers**_ και το _**/etc/groups**_ για απροσδόκητα προνόμια που δίνονται σε χρήστες.\
Τέλος, αναζητήστε λογαριασμούς με **καμία κωδικό** ή **εύκολα μαντεψιάρικους** κωδικούς.

## Εξέταση Συστήματος Αρχείων

### Ανάλυση Δομών Αρχείων στην Έρευνα Κακόβουλου Λογισμικού

Κατά την έρευνα περιστατικών κακόβουλου λογισμικού, η δομή του συστήματος αρχείων είναι μια κρίσιμη πηγή πληροφοριών, αποκαλύπτοντας τόσο την ακολουθία των γεγονότων όσο και το περιεχόμενο του κακόβουλου λογισμικού. Ωστόσο, οι συγγραφείς κακόβουλου λογισμικού αναπτύσσουν τεχνικές για να δυσκολέψουν αυτήν την ανάλυση, όπως η τροποποίηση των χρονοσημάτων αρχείων ή η αποφυγή του συστήματος αρχείων για αποθήκευση δεδομένων.

Για να αντιμετωπίσετε αυτές τις αντι-δανειστικές μεθόδους, είναι ουσιώδες:

* **Διεξάγετε μια λεπτομερή ανάλυση χρονολογίου** χρησιμοποιώντας εργαλεία όπως το **Autopsy** για οπτικοποίηση των χρονολογιών συμβάντων ή το `mactime` του **Sleuth Kit** για λεπτομερείς πληροφορίες χρονολογίου.
* **Εξετάστε απροσδόκητα scripts** στο $PATH του συστήματος, τα οποία ενδέχεται να περιλαμβάνουν scripts κελύφους ή PHP που χρησιμοποιούν οι επιτιθέμενοι.
* **Εξετάστε τον κατάλογο `/dev` για ατυπικά αρχεία**, καθώς συνήθως περιέχει ειδικά αρχεία, αλλά μπορεί να περιέχει και αρχεία που σχετίζονται με κακόβουλο λογισμικό.
* **Αναζητήστε κρυφά αρχεία ή καταλόγους** με ονόματα όπως ".. " (τελεία τελεία κενό) ή "..^G" (τελεία τελεία ελέγχου-G), τα οποία μπορεί να κρύβουν κακόβουλο περιεχόμενο.
* **Αναγνωρίστε αρχεία setuid root** χρησιμοποιώντας την εντολή: `find / -user root -perm -04000 -print` Αυτό εντοπίζει αρχεία με υψηλά δικαιώματα, τα οποία θα μπορούσαν να καταχραστούνται από επιτιθέμενους.
* **Ελέγξτε τα χρονοσήματα διαγραφής** στους πίνακες inode για να εντοπίσετε μαζικές διαγραφές αρχείων, που ενδέχεται να υποδηλώνουν την παρουσία rootkits ή τροϊανών.
* **Ελέγξτε συνεχόμενα inodes** για κοντινά κακόβουλα αρχεία μετά την εντοπισμό ενός, καθώς ενδέχεται να έχουν τοποθετηθεί μαζί.
* **Ελέγξτε κοινούς καταλόγους δυαδικών αρχείων** (_/bin_, _/sbin_) για πρόσφατα τροποποιημένα αρχεία, καθώς αυτά θα μπορούσαν να έχουν τροποποιηθεί από κακόβουλο λογισμικό.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
Σημειώστε ότι ένας **εισβολέας** μπορεί να **τροποποιήσει** τη **χρονική σήμανση** για να κάνει τα **αρχεία να φαίνονται** **νόμιμα**, αλλά δεν μπορεί να τροποποιήσει το **inode**. Εάν ανακαλύψετε ότι ένα **αρχείο** υποδηλώνει ότι δημιουργήθηκε και τροποποιήθηκε την **ίδια ώρα** με τα υπόλοιπα αρχεία στον ίδιο φάκελο, αλλά το **inode** είναι **απροσδόκητα μεγαλύτερο**, τότε οι **χρονικές σημάνσεις του αρχείου αυτού τροποποιήθηκαν**.
{% endhint %}

## Σύγκριση αρχείων διαφορετικών εκδόσεων συστήματος αρχείων

### Περίληψη Σύγκρισης Εκδόσεων Συστήματος Αρχείων

Για να συγκρίνουμε εκδόσεις συστημάτων αρχείων και να εντοπίσουμε τις αλλαγές, χρησιμοποιούμε απλοποιημένες εντολές `git diff`:

* **Για να βρείτε νέα αρχεία**, συγκρίνετε δύο καταλόγους:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **Για τροποποιημένο περιεχόμενο**, καταγράψτε τις αλλαγές αγνοώντας συγκεκριμένες γραμμές:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **Ανίχνευση διαγραμμένων αρχείων**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **Επιλογές φίλτρου** (`--diff-filter`) βοηθούν στον περιορισμό σε συγκεκριμένες αλλαγές όπως προστιθέμενα (`A`), διαγραμμένα (`D`), ή τροποποιημένα (`M`) αρχεία.
* `A`: Προστιθέμενα αρχεία
* `C`: Αντιγραμμένα αρχεία
* `D`: Διαγραμμένα αρχεία
* `M`: Τροποποιημένα αρχεία
* `R`: Μετονομασμένα αρχεία
* `T`: Αλλαγές τύπου (π.χ., αρχείο σε σύμβολο συνδέσμου)
* `U`: Μη συγχωνευμένα αρχεία
* `X`: Άγνωστα αρχεία
* `B`: Κατεστραμμένα αρχεία

## Αναφορές

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **Βιβλίο: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!

* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
