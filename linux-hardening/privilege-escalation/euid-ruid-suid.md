# euid, ruid, suid

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

### Μεταβλητές Αναγνώρισης Χρήστη

- **`ruid`**: Το **πραγματικό ID χρήστη** υποδεικνύει τον χρήστη που ξεκίνησε τη διεργασία.
- **`euid`**: Επίσης γνωστό ως **αποτελεσματικό ID χρήστη**, αντιπροσωπεύει την ταυτότητα του χρήστη που χρησιμοποιείται από το σύστημα για να καθορίσει τα δικαιώματα της διεργασίας. Γενικά, το `euid` αντικατοπτρίζει το `ruid`, εκτός από περιπτώσεις όπως η εκτέλεση ενός δυαδικού αρχείου SetUID, όπου το `euid` παίρνει την ταυτότητα του ιδιοκτήτη του αρχείου, παρέχοντας έτσι συγκεκριμένα δικαιώματα λειτουργίας.
- **`suid`**: Αυτό το **αποθηκευμένο ID χρήστη** είναι κρίσιμο όταν μια διεργασία υψηλών προνομίων (συνήθως εκτελούμενη ως root) χρειάζεται να αποδώσει προσωρινά τα προνόμιά της για να εκτελέσει ορισμένες εργασίες, μόνο για να ανακτήσει αργότερα την αρχική της αυξημένη κατάσταση.

#### Σημαντική Σημείωση
Μια διεργασία που δεν λειτουργεί ως root μπορεί να τροποποιήσει μόνο το `euid` της για να ταιριάζει με το τρέχον `ruid`, `euid` ή `suid`.

### Κατανόηση των Συναρτήσεων set*uid

- **`setuid`**: Αντίθετα με τις αρχικές υποθέσεις, το `setuid` τροποποιεί κυρίως το `euid` αντί του `ruid`. Συγκεκριμένα, για διεργασίες με προνόμια, ευθυγραμμίζει τα `ruid`, `euid` και `suid` με τον καθορισμένο χρήστη, συνήθως το root, ενισχύοντας αποτελεσματικά αυτά τα αναγνωριστικά λόγω του αντικαθιστώντος `suid`. Λεπτομερείς πληροφορίες μπορούν να βρεθούν στη [σελίδα του εγχειριδίου του setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** και **`setresuid`**: Αυτές οι συναρτήσεις επιτρέπουν τη λεπτομερή προσαρμογή των `ruid`, `euid` και `suid`. Ωστόσο, οι δυνατότητές τους εξαρτώνται από το επίπεδο προνομίων της διεργασίας. Για μη-ριζικές διεργασίες, οι τροποποιήσεις περιορίζονται στις τρέχουσες τιμές των `ruid`, `euid` και `suid`. Αντίθετα, οι διεργασίες root ή αυτές με δυνατότητα `CAP_SETUID` μπορούν να αναθέσουν αυθαίρετες τιμές σε αυτά τα αναγνωριστικά. Περισσότερες πληροφορίες μπορούν να αντληθούν από τη [σελίδα του εγχειριδίου του setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) και τη [σελίδα του εγχειριδίου του setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Αυτές οι λειτουργίες σχ
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Συλλογή και Δικαιώματα:**

Όταν μιλάμε για συλλογή και δικαιώματα στο Linux, αναφερόμαστε στη διαδικασία της ανάθεσης δικαιωμάτων σε αρχεία και φακέλους. Τα δικαιώματα καθορίζουν ποιος έχει πρόσβαση σε ένα αρχείο ή φάκελο και ποιες ενέργειες μπορεί να εκτελέσει.

Στο Linux, κάθε αρχείο και φάκελος έχει τρία βασικά δικαιώματα: ανάγνωση (r), εγγραφή (w) και εκτέλεση (x). Αυτά τα δικαιώματα μπορούν να ανατεθούν σε τρεις διαφορετικές ομάδες: τον ιδιοκτήτη του αρχείου, την ομάδα του αρχείου και τους υπόλοιπους χρήστες.

Οι διαδικασίες που εκτελούνται στο Linux έχουν έναν πραγματικό αριθμό χρήστη (RUID) και έναν αριθμό χρήστη αποτελέσματος (EUID). Ο RUID αντιπροσωπεύει τον πραγματικό χρήστη που εκτελεί τη διεργασία, ενώ ο EUID αντιπροσωπεύει τον χρήστη που χρησιμοποιείται για την εκτέλεση της διεργασίας.

Οι διαδικασίες μπορούν να αλλάξουν τον EUID τους σε έναν άλλο χρήστη, αρκεί να έχουν τα ανάλογα δικαιώματα. Αυτή η δυνατότητα μπορεί να χρησιμοποιηθεί για την απόκτηση προνομίων και την ανόρθωση της διαδικασίας.

Επιπλέον, οι αρχειοθέτες στο Linux μπορούν να ανατεθούν με το δικαίωμα SUID (Set User ID), το οποίο επιτρέπει σε ένα αρχείο να εκτελείται με τα δικαιώματα του ιδιοκτήτη του αρχείου, ανεξάρτητα από τον χρήστη που το εκτελεί.

Κατά την ανάπτυξη μιας εφαρμογής ή την ρύθμιση ενός συστήματος Linux, είναι σημαντικό να λαμβάνονται υπόψη οι σωστές διαδικασίες συλλογής και τα δικαιώματα των αρχείων και των φακέλων, καθώς αυτά μπορούν να επηρεάσουν την ασφάλεια του συστήματος.
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* Οι `ruid` και `euid` ξεκινούν ως 99 (nobody) και 1000 (frank) αντίστοιχα.
* Η `setuid` ευθυγραμμίζει και τους δύο στο 1000.
* Η `system` εκτελεί την εντολή `/bin/bash -c id` λόγω του symlink από το sh στο bash.
* Το `bash`, χωρίς την επιλογή `-p`, προσαρμόζει το `euid` για να ταιριάζει με το `ruid`, με αποτέλεσμα και οι δύο να είναι 99 (nobody).

#### Περίπτωση 2: Χρήση της setreuid με την system

**Κώδικας C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Συλλογή και Δικαιώματα:**

Όταν μιλάμε για συλλογή και δικαιώματα στο Linux, αναφερόμαστε στη διαδικασία της ανάθεσης δικαιωμάτων σε αρχεία και φακέλους. Τα δικαιώματα καθορίζουν ποιος έχει πρόσβαση σε ένα αρχείο ή φάκελο και ποιες ενέργειες μπορεί να εκτελέσει.

Στο Linux, κάθε αρχείο και φάκελος έχει τρία βασικά δικαιώματα: ανάγνωση (read), εγγραφή (write) και εκτέλεση (execute). Αυτά τα δικαιώματα μπορούν να ανατεθούν σε τρεις κατηγορίες χρηστών: τον ιδιοκτήτη του αρχείου, την ομάδα του αρχείου και τους υπόλοιπους χρήστες.

Οι διαχειριστές συστήματος μπορούν να αλλάξουν τα δικαιώματα ενός αρχείου ή φακέλου χρησιμοποιώντας την εντολή `chmod`. Επιπλέον, μπορούν να αλλάξουν τον ιδιοκτήτη ενός αρχείου ή φακέλου χρησιμοποιώντας την εντολή `chown`.

Η σωστή διαχείριση των δικαιωμάτων είναι σημαντική για την ασφάλεια του συστήματος, καθώς μπορεί να περιορίσει την πρόσβαση των χρηστών σε ευαίσθητα αρχεία και να αποτρέψει την ανεξουσιότητα.
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Εκτέλεση και Αποτέλεσμα:**

To εκτελέσεις και τα αποτελέσματα:
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* Το `setreuid` ορίζει τόσο το ruid όσο και το euid σε 1000.
* Το `system` καλεί το bash, το οποίο διατηρεί τα αναγνωριστικά χρήστη λόγω της ισότητάς τους, λειτουργώντας αποτελεσματικά ως frank.

#### Περίπτωση 3: Χρήση του setuid με το execve
Στόχος: Εξερεύνηση της αλληλεπίδρασης μεταξύ του setuid και του execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**

To εκτελέσεις και τα αποτελέσματα:
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* Το `ruid` παραμένει 99, αλλά το `euid` ορίζεται σε 1000, σύμφωνα με το αποτέλεσμα του `setuid`.

**Παράδειγμα Κώδικα C 2 (Κλήση του Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**

To εκτελέσεις και τα αποτελέσματα:
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

* Παρόλο που το `euid` ορίζεται σε 1000 από το `setuid`, το `bash` επαναφέρει το `euid` στο `ruid` (99) λόγω της απουσίας της επιλογής `-p`.

**Παράδειγμα Κώδικα C 3 (Χρήση του bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**

To εκτελέσεις και τα αποτελέσματα:
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Αναφορές
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
