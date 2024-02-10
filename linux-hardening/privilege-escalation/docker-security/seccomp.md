# Seccomp

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Το **Seccomp**, που σημαίνει Secure Computing mode, είναι μια λειτουργία ασφαλείας του **πυρήνα του Linux που σχεδιάστηκε για το φιλτράρισμα των κλήσεων συστήματος**. Περιορίζει τις διεργασίες σε έναν περιορισμένο σύνολο κλήσεων συστήματος (`exit()`, `sigreturn()`, `read()` και `write()`) για ήδη ανοιχτά περιγραφέα αρχείων. Εάν μια διεργασία προσπαθήσει να καλέσει οτιδήποτε άλλο, τότε τερματίζεται από τον πυρήνα χρησιμοποιώντας το SIGKILL ή το SIGSYS. Αυτός ο μηχανισμός δεν εικονοποιεί τους πόρους αλλά απομονώνει τη διεργασία από αυτούς.

Υπάρχουν δύο τρόποι για να ενεργοποιηθεί το seccomp: μέσω της κλήσης συστήματος `prctl(2)` με το `PR_SET_SECCOMP`, ή για πυρήνες Linux 3.17 και νεότερους, μέσω της κλήσης συστήματος `seccomp(2)`. Η παλαιότερη μέθοδος ενεργοποίησης του seccomp με την εγγραφή στο `/proc/self/seccomp` έχει αποσυρθεί υπέρ της `prctl()`.

Μια βελτίωση, το **seccomp-bpf**, προσθέτει τη δυνατότητα φιλτραρίσματος των κλήσεων συστήματος με ένα προσαρμόσιμο πολιτική, χρησιμοποιώντας κανόνες Berkeley Packet Filter (BPF). Αυτή η επέκταση χρησιμοποιείται από λογισμικό όπως το OpenSSH, το vsftpd και οι περιηγητές Chrome/Chromium σε Chrome OS και Linux για ευέλικτο και αποδοτικό φιλτράρισμα κλήσεων συστήματος, προσφέροντας μια εναλλακτική λύση στο πλέον μη υποστηριζόμενο systrace για το Linux.

### **Αρχική/Αυστηρή Λειτουργία**

Σε αυτή τη λειτουργία, το Seccomp **επιτρέπει μόνο τις κλήσεις συστήματος** `exit()`, `sigreturn()`, `read()` και `write()` για ήδη ανοιχτά περιγραφέα αρχείων. Εάν γίνει οποιαδήποτε άλλη κλήση συστήματος, η διεργασία τερματίζεται χρησιμοποιώντας το SIGKILL.
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
{% endcode %}

### Seccomp-bpf

Αυτή η λειτουργία επιτρέπει το **φιλτράρισμα των κλήσεων συστήματος χρησιμοποιώντας μια παραμετροποιήσιμη πολιτική** που υλοποιείται χρησιμοποιώντας κανόνες Berkeley Packet Filter. 

{% code title="seccomp_bpf.c" %}
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
{% endcode %}

## Seccomp στο Docker

Το **Seccomp-bpf** υποστηρίζεται από το **Docker** για να περιορίσει τις **syscalls** από τα containers, μειώνοντας αποτελεσματικά το επιθετικό πεδίο. Μπορείτε να βρείτε τις **syscalls που αποκλείονται** από **προεπιλογή** στη διεύθυνση [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) και το **προφίλ seccomp προεπιλογής** μπορεί να βρεθεί εδώ [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Μπορείτε να εκτελέσετε ένα container docker με μια **διαφορετική πολιτική seccomp** με:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Αν θέλετε για παράδειγμα να **απαγορεύσετε** σε ένα container να εκτελεί κάποια **syscall** όπως το `uname`, μπορείτε να κατεβάσετε το προφίλ προεπιλογής από [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) και απλά **αφαιρέστε το string `uname` από τη λίστα**.\
Αν θέλετε να βεβαιωθείτε ότι **κάποιο δυαδικό αρχείο δεν λειτουργεί μέσα σε ένα docker container**, μπορείτε να χρησιμοποιήσετε το strace για να εμφανίσετε τις syscalls που χρησιμοποιεί το δυαδικό αρχείο και στη συνέχεια να τις απαγορεύσετε.\
Στο παρακάτω παράδειγμα ανακαλύπτονται οι **syscalls** του `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Εάν χρησιμοποιείτε το **Docker απλά για να εκτελέσετε μια εφαρμογή**, μπορείτε να την **προφίλαρετε** με το **`strace`** και να επιτρέψετε μόνο τις συσκευές που χρειάζεται.
{% endhint %}

### Παράδειγμα πολιτικής Seccomp

[Παράδειγμα από εδώ](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Για να επιδείξουμε το χαρακτηριστικό Seccomp, ας δημιουργήσουμε ένα προφίλ Seccomp που απενεργοποιεί την κλήση συστήματος "chmod" όπως παρακάτω.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Στο παραπάνω προφίλ, έχουμε ορίσει την προεπιλεγμένη ενέργεια σε "επιτρέπεται" και έχουμε δημιουργήσει μια μαύρη λίστα για να απενεργοποιήσουμε την εντολή "chmod". Για να είμαστε ακόμα πιο ασφαλείς, μπορούμε να ορίσουμε την προεπιλεγμένη ενέργεια σε απόρριψη και να δημιουργήσουμε μια λευκή λίστα για να ενεργοποιήσουμε εκλεκτικά κλήσεις συστήματος.\
Το παρακάτω αποτέλεσμα δείχνει την κλήση "chmod" να επιστρέφει σφάλμα επειδή είναι απενεργοποιημένη στο προφίλ seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Το παρακάτω αποτέλεσμα δείχνει την εντολή "docker inspect" που εμφανίζει το προφίλ:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Απενεργοποίηση στο Docker

Ξεκινήστε ένα container με τη σημαία: **`--security-opt seccomp=unconfined`**

Από την έκδοση Kubernetes 1.19, το **seccomp είναι ενεργοποιημένο από προεπιλογή για όλα τα Pods**. Ωστόσο, το προφίλ seccomp που εφαρμόζεται προεπιλεγμένα στα Pods είναι το προφίλ "**RuntimeDefault**", το οποίο **παρέχεται από τον container runtime** (π.χ. Docker, containerd). Το προφίλ "RuntimeDefault" επιτρέπει τις περισσότερες κλήσεις συστήματος ενώ αποκλείει μερικές που θεωρούνται επικίνδυνες ή δεν απαιτούνται γενικά από τα containers.
