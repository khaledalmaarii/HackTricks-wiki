# Μεταβλητές Περιβάλλοντος του Linux

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα κληρονομηθούν** από **παιδικές διεργασίες**.

Μπορείτε να δημιουργήσετε μια καθολική μεταβλητή για την τρέχουσα συνεδρία σας κάνοντας:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Αυτή η μεταβλητή θα είναι προσβάσιμη από τις τρέχουσες συνεδρίες σας και τις διεργασίες παιδιά τους.

Μπορείτε **να αφαιρέσετε** μια μεταβλητή κάνοντας:
```bash
unset MYGLOBAL
```
## Τοπικές μεταβλητές

Οι **τοπικές μεταβλητές** μπορούν να **προσπελαστούν** μόνο από το **τρέχον κέλυφος/σενάριο**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Λίστα τρέχουσων μεταβλητών

To list the current environment variables in Linux, you can use the `env` command. This command will display a list of all the variables and their values. 

```bash
$ env
```

Alternatively, you can use the `printenv` command to achieve the same result:

```bash
$ printenv
```

Both commands will provide you with the current environment variables set in your Linux system.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Κοινές μεταβλητές

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** - η οθόνη που χρησιμοποιείται από το **X**. Αυτή η μεταβλητή συνήθως έχει την τιμή **:0.0**, που σημαίνει η πρώτη οθόνη στον τρέχοντα υπολογιστή.
* **EDITOR** - ο προτιμώμενος κειμενογράφος του χρήστη.
* **HISTFILESIZE** - το μέγιστο πλήθος γραμμών που περιέχονται στο αρχείο ιστορικού.
* **HISTSIZE** - Αριθμός γραμμών που προστίθενται στο αρχείο ιστορικού όταν ο χρήστης τερματίζει τη συνεδρία του.
* **HOME** - ο κατάλογος του χρήστη.
* **HOSTNAME** - το όνομα του υπολογιστή.
* **LANG** - η τρέχουσα γλώσσα.
* **MAIL** - η τοποθεσία του αρχείου αλληλογραφίας του χρήστη. Συνήθως **/var/spool/mail/USER**.
* **MANPATH** - η λίστα των καταλόγων που αναζητούνται για εγχειρίδια χρήσης.
* **OSTYPE** - ο τύπος του λειτουργικού συστήματος.
* **PS1** - η προεπιλεγμένη εντολή στο bash.
* **PATH** - αποθηκεύει τη διαδρομή όλων των καταλόγων που περιέχουν δυαδικά αρχεία που θέλετε να εκτελείτε απλά αναφέροντας το όνομα του αρχείου και όχι τη σχετική ή απόλυτη διαδρομή.
* **PWD** - ο τρέχων κατάλογος εργασίας.
* **SHELL** - η διαδρομή προς το τρέχον κέλυφος εντολών (για παράδειγμα, **/bin/bash**).
* **TERM** - ο τρέχων τύπος τερματικού (για παράδειγμα, **xterm**).
* **TZ** - η ζώνη ώρας σας.
* **USER** - το τρέχον όνομα χρήστη.

## Ενδιαφέρουσες μεταβλητές για χακινγκ

### **HISTFILESIZE**

Αλλάξτε τη **τιμή αυτής της μεταβλητής σε 0**, έτσι όταν **τερματίζετε τη συνεδρία** σας το **αρχείο ιστορικού** (\~/.bash\_history) **θα διαγραφεί**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε τη **τιμή αυτής της μεταβλητής σε 0**, έτσι ώστε όταν **τερματίσετε τη συνεδρία** σας, καμία εντολή δεν θα προστεθεί στο **αρχείο ιστορικού** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Οι διεργασίες θα χρησιμοποιήσουν τον **proxy** που έχει καθοριστεί εδώ για να συνδεθούν στο διαδίκτυο μέσω **http ή https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Οι διεργασίες θα εμπιστεύονται τα πιστοποιητικά που δηλώνονται στις **μεταβλητές περιβάλλοντος αυτές**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Αλλάξτε τον τρόπο που εμφανίζεται η γραμμή εντολών σας.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

Κανονικός χρήστης:

![](<../.gitbook/assets/image (88).png>)

Ένα, δύο και τρία φόνταρισμένα jobs:

![](<../.gitbook/assets/image (89).png>)

Ένα φόνταρισμένο job, ένα παύση και η τελευταία εντολή δεν ολοκληρώθηκε σωστά:

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
