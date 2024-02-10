# IPC Ονοματοχώρος

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Ο IPC (Inter-Process Communication) ονοματοχώρος είναι μια δυνατότητα του πυρήνα του Linux που παρέχει **απομόνωση** των αντικειμένων του System V IPC, όπως ουρές μηνυμάτων, κοινόχρηστα τμήματα μνήμης και σημαφόρους. Αυτή η απομόνωση εξασφαλίζει ότι οι διεργασίες σε **διαφορετικούς IPC ονοματοχώρους δεν μπορούν να έχουν άμεση πρόσβαση ή να τροποποιήσουν τα αντικείμενα IPC ο οποίος ανήκει σε άλλες ονοματοχώρους**, παρέχοντας έτσι ένα επιπλέον επίπεδο ασφάλειας και ιδιωτικότητας μεταξύ των ομάδων διεργασιών.

### Πώς λειτουργεί:

1. Όταν δημιουργείται ένας νέος IPC ονοματοχώρος, ξεκινά με ένα **πλήρως απομονωμένο σύνολο αντικειμένων του System V IPC**. Αυτό σημαίνει ότι οι διεργασίες που εκτελούνται στον νέο IPC ονοματοχώρο δεν μπορούν να έχουν πρόσβαση ή να παρεμβαίνουν στα αντικείμενα IPC σε άλλους ονοματοχώρους ή στο σύστημα του κεντρικού υπολογιστή από προεπιλογή.
2. Τα αντικείμενα IPC που δημιουργούνται εντός ενός ονοματοχώρου είναι ορατά και **προσβάσιμα μόνο από διεργασίες εντός αυτού του ονοματοχώρου**. Κάθε αντικείμενο IPC αναγνωρίζεται από ένα μοναδικό κλειδί εντός του ονοματοχώρου του. Αν και το κλειδί μπορεί να είναι ίδιο σε διάφορους ονοματοχώρους, τα ίδια τα αντικείμενα είναι απομονωμένα και δεν μπορούν να προσπελαστούν από διαφορετικούς ονοματοχώρους.
3. Οι διεργασίες μπορούν να μετακινηθούν μεταξύ ονοματοχώρων χρησιμοποιώντας την κλήση συστήματος `setns()` ή να δημιουργήσουν νέους ονοματοχώρους χρησιμοποιώντας τις κλήσεις συστήματος `unshare()` ή `clone()` με τη σημαία `CLONE_NEWIPC`. Όταν μια διεργασία μετακινείται σε έναν νέο ονοματοχώρο ή δημιουργεί έναν νέο, θα αρχίσει να χρησιμοποιεί τα αντικείμενα IPC που σχετίζονται με αυτόν τον ονοματοχώρο.

## Εργαστήριο:

### Δημιουργία διαφορετικών Ονοματοχώρων

#### Εντολική γραμμή
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
Με την προσάρτηση μιας νέας περίπτωσης του συστήματος αρχείων `/proc` χρησιμοποιώντας την παράμετρο `--mount-proc`, εξασφαλίζετε ότι ο νέος χώρος ονομάτων περιέχει μια **ακριβή και απομονωμένη προβολή των πληροφοριών διεργασιών που είναι συγκεκριμένες για αυτόν τον χώρο ονομάτων**.

<details>

<summary>Σφάλμα: bash: fork: Δεν είναι δυνατή η δέσμευση μνήμης</summary>

Όταν το `unshare` εκτελείται χωρίς την επιλογή `-f`, συναντάται ένα σφάλμα λόγω του τρόπου με τον οποίο το Linux χειρίζεται τους νέους χώρους ονομάτων PID (Process ID). Τα κύρια στοιχεία και η λύση παρουσιάζονται παρακάτω:

1. **Εξήγηση του προβλήματος**:
- Ο πυρήνας του Linux επιτρέπει σε μια διεργασία να δημιουργεί νέους χώρους ονομάτων χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διεργασία που προκαλεί τη δημιουργία ενός νέου χώρου ονομάτων PID (αναφέρεται ως "διεργασία unshare") δεν εισέρχεται στον νέο χώρο ονομάτων, μόνο οι υποδιεργασίες της το κάνουν.
- Η εκτέλεση της εντολής `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διεργασία με το `unshare`. Ως αποτέλεσμα, το `/bin/bash` και οι υποδιεργασίες του βρίσκονται στον αρχικό χώρο ονομάτων PID.
- Η πρώτη υποδιεργασία του `/bin/bash` στον νέο χώρο ονομάτων γίνεται PID 1. Όταν αυτή η διεργασία τερματίζει, ενεργοποιείται η εκκαθάριση του χώρου ονομάτων αν δεν υπάρχουν άλλες διεργασίες, καθώς η PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διεργασιών. Ο πυρήνας του Linux θα απενεργοποιήσει στη συνέχεια την εκχώρηση PID σε αυτόν τον χώρο ονομάτων.

2. **Συνέπεια**:
- Η έξοδος της PID 1 σε έναν νέο χώρο ονομάτων οδηγεί στην απενεργοποίηση της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα την αποτυχία της συνάρτησης `alloc_pid` να εκχωρήσει ένα νέο PID κατά τη δημιουργία μιας νέας διεργασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει ένα νέο διεργασία μετά τη δημιουργία του νέου χώρου ονομάτων PID.
- Εκτελώντας `%unshare -fp /bin/bash%` εξασφαλίζεται ότι η εντολή `unshare` ίδια γίνεται PID 1 στον νέο χώρο ονομάτων. Το `/bin/bash` και οι υποδιεργασίες του περιορίζονται στον νέο αυτόν χώρο ονομάτων, αποτρέποντας την πρόωρη έξοδο της PID 1 και επιτρέποντας την κανονική εκχώρηση PID.

Εξασφαλίζοντας ότι το `unshare` εκτελείται με τη σημαία `-f`, ο νέος χώρος ονομάτων PID διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και στις υποδιεργασίες του να λειτουργούν χωρίς να αντιμετωπίζουν το σφάλμα δέσμευσης μνήμης.
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ελέγξτε σε ποιο namespace βρίσκεται η διεργασία σας

To check which namespace your process is in, you can use the following command:

```bash
cat /proc/$$/ns/ipc
```

This will display the inode number of the IPC namespace that your process is currently in.
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### Βρείτε όλους τους IPC namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Εισέλθετε μέσα σε ένα IPC namespace

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
Επίσης, μπορείτε να **εισέλθετε σε ένα άλλο namespace διεργασίας μόνο αν είστε root**. Και **δεν μπορείτε** να **εισέλθετε** σε άλλο namespace **χωρίς έναν περιγραφέα** που να δείχνει προς αυτό (όπως `/proc/self/ns/net`).

### Δημιουργία αντικειμένου IPC
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## Αναφορές
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
