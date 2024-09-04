# Linux Environment Variables

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Global variables

Οι παγκόσμιες μεταβλητές **θα κληρονομηθούν** από **διεργασίες παιδιών**.

Μπορείτε να δημιουργήσετε μια παγκόσμια μεταβλητή για την τρέχουσα συνεδρία σας κάνοντας:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Αυτή η μεταβλητή θα είναι προσβάσιμη από τις τρέχουσες συνεδρίες σας και τις διεργασίες παιδιών της.

Μπορείτε να **αφαιρέσετε** μια μεταβλητή κάνοντας:
```bash
unset MYGLOBAL
```
## Τοπικές μεταβλητές

Οι **τοπικές μεταβλητές** μπορούν να **προσεγγιστούν** μόνο από το **τρέχον shell/script**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Λίστα τρεχουσών μεταβλητών
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – η οθόνη που χρησιμοποιείται από **X**. Αυτή η μεταβλητή συνήθως ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη στον τρέχοντα υπολογιστή.
* **EDITOR** – ο προτιμώμενος επεξεργαστής κειμένου του χρήστη.
* **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχονται στο αρχείο ιστορικού.
* **HISTSIZE** – Αριθμός γραμμών που προστίθενται στο αρχείο ιστορικού όταν ο χρήστης ολοκληρώνει τη συνεδρία του.
* **HOME** – ο κατάλογος του σπιτιού σας.
* **HOSTNAME** – το όνομα του υπολογιστή.
* **LANG** – η τρέχουσα γλώσσα σας.
* **MAIL** – η τοποθεσία του ταχυδρομικού σπιτιού του χρήστη. Συνήθως **/var/spool/mail/USER**.
* **MANPATH** – η λίστα των καταλόγων για αναζήτηση σε σελίδες εγχειριδίων.
* **OSTYPE** – ο τύπος του λειτουργικού συστήματος.
* **PS1** – η προεπιλεγμένη προτροπή στο bash.
* **PATH** – αποθηκεύει τη διαδρομή όλων των καταλόγων που περιέχουν δυαδικά αρχεία που θέλετε να εκτελέσετε απλά καθορίζοντας το όνομα του αρχείου και όχι με σχετική ή απόλυτη διαδρομή.
* **PWD** – ο τρέχων κατάλογος εργασίας.
* **SHELL** – η διαδρομή προς την τρέχουσα εντολή shell (για παράδειγμα, **/bin/bash**).
* **TERM** – ο τρέχων τύπος τερματικού (για παράδειγμα, **xterm**).
* **TZ** – η ζώνη ώρας σας.
* **USER** – το τρέχον όνομα χρήστη σας.

## Interesting variables for hacking

### **HISTFILESIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **τερματίσετε τη συνεδρία σας** το **αρχείο ιστορικού** (\~/.bash\_history) **να διαγραφεί**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, έτσι ώστε όταν **τερματίσετε τη συνεδρία σας** οποιαδήποτε εντολή να προστεθεί στο **αρχείο ιστορικού** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Οι διαδικασίες θα χρησιμοποιήσουν τον **proxy** που δηλώνεται εδώ για να συνδεθούν στο διαδίκτυο μέσω **http ή https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Οι διαδικασίες θα εμπιστεύονται τα πιστοποιητικά που υποδεικνύονται σε **αυτές τις μεταβλητές περιβάλλοντος**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Αλλάξτε πώς φαίνεται η προτροπή σας.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Κανονικός χρήστης:

![](<../.gitbook/assets/image (740).png>)

Ένας, δύο και τρεις εργασίες στο παρασκήνιο:

![](<../.gitbook/assets/image (145).png>)

Μία εργασία στο παρασκήνιο, μία σταματημένη και η τελευταία εντολή δεν ολοκληρώθηκε σωστά:

![](<../.gitbook/assets/image (715).png>)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
