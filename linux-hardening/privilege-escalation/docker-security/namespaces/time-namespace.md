# Χώρος ονομάτων χρόνου

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο χάκινγκ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές πληροφορίες

Ο χώρος ονομάτων χρόνου στο Linux επιτρέπει την ανάθεση ανεξάρτητων αποκλίσεων στους χρονομετρητές του συστήματος και του χρόνου εκκίνησης ανά ονοματοχώρο. Χρησιμοποιείται συχνά σε εφαρμογές Linux για να αλλάξει η ημερομηνία/ώρα μέσα σε έναν χώρο ονομάτων και να προσαρμόσει τους χρονομετρητές μετά από αποκατάσταση από ένα σημείο ελέγχου ή αντίγραφο ασφαλείας.

## Εργαστήριο:

### Δημιουργία διαφορετικών ονομάτων χώρου

#### Εντολική γραμμή
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Με την προσάρτηση μιας νέας περίπτωσης του συστήματος αρχείων `/proc` χρησιμοποιώντας την παράμετρο `--mount-proc`, εξασφαλίζετε ότι ο νέος χώρος ονομάτων περιέχει μια **ακριβή και απομονωμένη προβολή των πληροφοριών διεργασιών που είναι συγκεκριμένες για αυτόν τον χώρο ονομάτων**.

<details>

<summary>Σφάλμα: bash: fork: Δεν είναι δυνατή η δέσμευση μνήμης</summary>

Όταν το `unshare` εκτελείται χωρίς την επιλογή `-f`, συναντάται ένα σφάλμα λόγω του τρόπου που ο πυρήνας Linux χειρίζεται τους νέους χώρους ονομάτων PID (Process ID). Τα κύρια στοιχεία και η λύση παρουσιάζονται παρακάτω:

1. **Εξήγηση του προβλήματος**:
- Ο πυρήνας Linux επιτρέπει σε μια διεργασία να δημιουργεί νέους χώρους ονομάτων χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διεργασία που προκαλεί τη δημιουργία ενός νέου χώρου ονομάτων PID (που αναφέρεται ως "διαδικασία unshare") δεν εισέρχεται στον νέο χώρο ονομάτων, μόνο οι υποδιεργασίες της το κάνουν.
- Η εκτέλεση της εντολής `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διεργασία με το `unshare`. Ως αποτέλεσμα, το `/bin/bash` και οι υποδιεργασίες του βρίσκονται στον αρχικό χώρο ονομάτων PID.
- Η πρώτη υποδιεργασία του `/bin/bash` στον νέο χώρο ονομάτων γίνεται PID 1. Όταν αυτή η διεργασία τερματίζει, ενεργοποιείται η εκκαθάριση του χώρου ονομάτων αν δεν υπάρχουν άλλες διεργασίες, καθώς η PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διεργασιών. Ο πυρήνας Linux θα απενεργοποιήσει στη συνέχεια την εκχώρηση PID σε αυτόν τον χώρο ονομάτων.

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
cat /proc/$$/ns/pid
```

This will display the inode number of the namespace that your process is currently in.
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Βρείτε όλα τα Time namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Εισέλθετε σε ένα χώρο ονομάτων χρόνου

{% endcode %}
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
Επίσης, μπορείτε να **εισέλθετε σε ένα άλλο namespace διεργασίας μόνο αν είστε root**. Και **δεν μπορείτε** να **εισέλθετε** σε άλλο namespace **χωρίς έναν δείκτη** που να τον δείχνει (όπως `/proc/self/ns/net`).

## Αναφορές
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
* [https://www.phoronix.com/news/Linux-Time-Namespace-Coming](https://www.phoronix.com/news/Linux-Time-Namespace-Coming)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
