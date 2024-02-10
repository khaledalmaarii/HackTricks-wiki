# Περιβάλλον PID

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Το PID (Process IDentifier) namespace είναι μια λειτουργία στον πυρήνα του Linux που παρέχει απομόνωση διεργασιών επιτρέποντας σε μια ομάδα διεργασιών να έχει το δικό της σύνολο μοναδικών PIDs, ξεχωριστά από τα PIDs σε άλλα namespaces. Αυτό είναι ιδιαίτερα χρήσιμο στην ενθυλάκωση, όπου η απομόνωση διεργασιών είναι απαραίτητη για την ασφάλεια και τη διαχείριση πόρων.

Όταν δημιουργείται ένα νέο PID namespace, η πρώτη διεργασία σε αυτό το namespace αντιστοιχίζεται στο PID 1. Αυτή η διεργασία γίνεται η διεργασία "init" του νέου namespace και είναι υπεύθυνη για τη διαχείριση άλλων διεργασιών μέσα στο namespace. Κάθε επόμενη διεργασία που δημιουργείται μέσα στο namespace θα έχει ένα μοναδικό PID μέσα σε αυτό το namespace και αυτά τα PIDs θα είναι ανεξάρτητα από τα PIDs σε άλλα namespaces.

Από την οπτική γωνία μιας διεργασίας μέσα σε ένα PID namespace, μπορεί να βλέπει μόνο άλλες διεργασίες στο ίδιο namespace. Δεν είναι ενήμερη για διεργασίες σε άλλα namespaces και δεν μπορεί να αλληλεπιδράσει με αυτές χρησιμοποιώντας παραδοσιακά εργαλεία διαχείρισης διεργασιών (π.χ. `kill`, `wait`, κλπ.). Αυτό παρέχει ένα επίπεδο απομόνωσης που βοηθά στην αποτροπή των διεργασιών να παρεμβαίνουν μεταξύ τους.

### Πώς λειτουργεί:

1. Όταν δημιουργείται μια νέα διεργασία (π.χ. χρησιμοποιώντας τη συστημική κλήση `clone()`), η διεργασία μπορεί να αντιστοιχιστεί σε ένα νέο ή υπάρχον PID namespace. **Εάν δημιουργείται ένα νέο namespace, η διεργασία γίνεται η διεργασία "init" αυτού του namespace**.
2. Ο **πυρήνας** διατηρεί μια **αντιστοίχιση μεταξύ των PIDs στο νέο namespace και των αντίστοιχων PIDs** στο γονικό namespace (δηλαδή το namespace από το οποίο δημιουργήθηκε το νέο namespace). Αυτή η αντιστοίχιση **επιτρέπει στον πυρήνα να μεταφράζει τα PIDs όταν είναι απαραίτητο**, όπως όταν στέλνει σήματα μεταξύ διεργασιών σε διαφορετικά namespaces.
3. **Οι διεργασίες μέσα σε ένα PID namespace μπορούν να βλέπουν και να αλληλεπιδρούν με άλλες διεργασίες στο ίδιο namespace**. Δεν είναι ενήμερες για διεργασίες σε άλλα namespaces και τα PIDs τους είναι μοναδικά μέσα στο namespace τους.
4. Όταν ένα **PID namespace καταστρέφεται** (π.χ. όταν η διεργασία "init" του namespace εξέρχεται), **όλες οι διεργασίες μέσα σε αυτό το namespace τερματίζονται**. Αυτό εξασφαλίζει ότι όλοι οι πόροι που σχετίζονται με το namespace καθαρίζονται σωστά.

## Εργαστήριο:

### Δημιουργία διαφορετικών Namespaces

#### Εντολή CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Σφάλμα: bash: fork: Δεν είναι δυνατή η δέσμευση μνήμης</summary>

Όταν το `unshare` εκτελείται χωρίς την επιλογή `-f`, συναντάται ένα σφάλμα λόγω του τρόπου που ο πυρήνας Linux χειρίζεται τα νέα namespaces PID (Process ID). Τα κύρια στοιχεία και η λύση παρουσιάζονται παρακάτω:

1. **Εξήγηση του προβλήματος**:
- Ο πυρήνας Linux επιτρέπει σε ένα διεργασία να δημιουργεί νέα namespaces χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διεργασία που εκκινεί τη δημιουργία ενός νέου PID namespace (αναφέρεται ως "διεργασία unshare") δεν εισέρχεται στο νέο namespace, μόνο οι παιδικές διεργασίες της.
- Η εκτέλεση `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διεργασία με το `unshare`. Ως αποτέλεσμα, το `/bin/bash` και οι παιδικές διεργασίες του βρίσκονται στο αρχικό PID namespace.
- Η πρώτη παιδική διεργασία του `/bin/bash` στο νέο namespace γίνεται PID 1. Όταν αυτή η διεργασία τερματίζει, ενεργοποιείται η εκκαθάριση του namespace αν δεν υπάρχουν άλλες διεργασίες, καθώς η PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διεργασιών. Ο πυρήνας Linux απενεργοποιεί στη συνέχεια την εκχώρηση PID σε αυτό το namespace.

2. **Συνέπεια**:
- Η έξοδος της PID 1 σε ένα νέο namespace οδηγεί στην απενεργοποίηση της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα την αποτυχία της συνάρτησης `alloc_pid` να δεσμεύσει ένα νέο PID κατά τη δημιουργία μιας νέας διεργασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει μια νέα διεργασία μετά τη δημιουργία του νέου PID namespace.
- Εκτελώντας `%unshare -fp /bin/bash%` εξασφαλίζεται ότι η εντολή `unshare` ίδια γίνεται PID 1 στο νέο namespace. Το `/bin/bash` και οι παιδικές διεργασίες του περιέχονται ασφαλώς μέσα σε αυτό το νέο namespace, αποτρέποντας την πρόωρη έξοδο της PID 1 και επιτρέποντας την κανονική εκχώρηση PID.

Εξασφαλίζοντας ότι το `unshare` εκτελείται με τη σημαία `-f`, το νέο PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και στις υποδιεργασίες του να λειτουργούν χωρίς να αντιμετωπίζουν το σφάλμα δέσμευσης μνήμης.

</details>

Με την προσάρτηση μιας νέας περίπτωσης του αρχείου συστήματος `/proc` εάν χρησιμοποιείτε την παράμετρο `--mount-proc`, εξασφαλίζετε ότι το νέο namespace περιέχει μια **ακριβή και απομονωμένη προβολή των πληροφοριών διεργασίας που είναι συγκεκριμένες για αυτό το namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ελέγξτε σε ποιο namespace βρίσκεται η διεργασία σας

To check which namespace your process is in, you can use the following command:

```bash
cat /proc/$$/status | grep NSpid
```

This command will display the PID (Process ID) of your process along with the namespace it belongs to.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Βρείτε όλα τα PID namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Να σημειωθεί ότι ο ριζικός χρήστης από το αρχικό (προεπιλεγμένο) PID namespace μπορεί να δει όλες τις διεργασίες, ακόμη και αυτές στα νέα PID namespaces, γι' αυτό μπορούμε να δούμε όλα τα PID namespaces.

### Εισέλθετε μέσα σε ένα PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Όταν εισέρχεστε σε ένα PID namespace από το προεπιλεγμένο namespace, θα εξακολουθείτε να βλέπετε όλες τις διεργασίες. Και η διεργασία από αυτό το PID ns θα μπορεί να δει το νέο bash στο PID ns.

Επίσης, μπορείτε να **εισέλθετε σε ένα άλλο PID namespace μόνο αν είστε root**. Και **δεν μπορείτε** να **εισέλθετε** σε άλλο namespace **χωρίς έναν δείκτη** που να δείχνει σε αυτό (όπως `/proc/self/ns/pid`)

## Αναφορές
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
