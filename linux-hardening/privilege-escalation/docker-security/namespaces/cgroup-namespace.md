# CGroup Namespace

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

Ένα cgroup namespace είναι μια δυνατότητα του πυρήνα του Linux που παρέχει **απομόνωση των ιεραρχιών cgroup για διεργασίες που εκτελούνται μέσα σε ένα namespace**. Τα cgroups, συντομευμένα για **control groups**, είναι μια δυνατότητα του πυρήνα που επιτρέπει την οργάνωση των διεργασιών σε ιεραρχικές ομάδες για τη διαχείριση και επιβολή **όριων στους πόρους του συστήματος** όπως η CPU, η μνήμη και η I/O.

Αν και τα cgroup namespaces δεν είναι ένας ξεχωριστός τύπος namespace όπως αυτοί που συζητήσαμε προηγουμένως (PID, mount, network, κλπ.), σχετίζονται με την έννοια της απομόνωσης των namespaces. **Τα cgroup namespaces εικονικοποιούν την προβολή της ιεραρχίας cgroup**, έτσι ώστε οι διεργασίες που εκτελούνται μέσα σε ένα cgroup namespace να έχουν μια διαφορετική προβολή της ιεραρχίας σε σύγκριση με τις διεργασίες που εκτελούνται στον κεντρικό υπολογιστή ή σε άλλα namespaces.

### Πώς λειτουργεί:

1. Όταν δημιουργείται ένα νέο cgroup namespace, **ξεκινά με μια προβολή της ιεραρχίας cgroup βασισμένη στο cgroup της δημιουργούσας διεργασίας**. Αυτό σημαίνει ότι οι διεργασίες που εκτελούνται στο νέο cgroup namespace θα βλέπουν μόνο ένα υποσύνολο της ολόκληρης ιεραρχίας cgroup, περιορισμένο στο υποδέντρο cgroup που έχει ρίζα το cgroup της δημιουργούσας διεργασίας.
2. Οι διεργασίες μέσα σε ένα cgroup namespace θα **βλέπουν το δικό τους cgroup ως τη ρίζα της ιεραρχίας**. Αυτό σημαίνει ότι, από την οπτική γωνία των διεργασιών μέσα στο namespace, το δικό τους cgroup εμφανίζεται ως η ρίζα και δεν μπορούν να δουν ή να έχουν πρόσβαση σε cgroups εκτός του δικού τους υποδέντρου.
3. Τα cgroup namespaces δεν παρέχουν απευθείας απομόνωση των πόρων. **Παρέχουν μόνο απομόνωση της προβολής της ιεραρχίας cgroup**. **Ο έλεγχος και η απομόνωση των πόρων εξακολουθούν να επιβάλλονται από τα υποσυστήματα cgroup** (π.χ. cpu, μνήμη, κλπ.) οι ίδια.

Για περισσότερες πληροφορίες σχετικά με τα CGroups, ελέγξτε:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Εργαστήριο:

### Δημιουργία διαφορετικών Namespaces

#### Εντολή CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Με την προσάρτηση μιας νέας περίπτωσης του αρχείου `/proc` εάν χρησιμοποιήσετε την παράμετρο `--mount-proc`, εξασφαλίζετε ότι ο νέος χώρος ονομάτων περιέχει μια **ακριβή και απομονωμένη προβολή των πληροφοριών διεργασιών που είναι συγκεκριμένες για αυτόν τον χώρο ονομάτων**.

<details>

<summary>Σφάλμα: bash: fork: Δεν είναι δυνατή η δέσμευση μνήμης</summary>

Όταν το `unshare` εκτελείται χωρίς την επιλογή `-f`, συναντάται ένα σφάλμα λόγω του τρόπου με τον οποίο το Linux χειρίζεται τους νέους χώρους ονομάτων PID (Process ID). Τα κύρια στοιχεία και η λύση παρουσιάζονται παρακάτω:

1. **Εξήγηση του προβλήματος**:
- Ο πυρήνας του Linux επιτρέπει σε μια διεργασία να δημιουργεί νέους χώρους ονομάτων χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διεργασία που προκαλεί τη δημιουργία ενός νέου χώρου ονομάτων PID (αναφέρεται ως "διεργασία unshare") δεν εισέρχεται στον νέο χώρο ονομάτων, μόνο οι υποδιεργασίες της το κάνουν.
- Η εκτέλεση `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διεργασία με το `unshare`. Ως αποτέλεσμα, το `/bin/bash` και οι υποδιεργασίες του βρίσκονται στον αρχικό χώρο ονομάτων PID.
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
cat /proc/$$/cgroup | grep "name=systemd" | cut -d: -f3
```

This command will display the namespace ID of your process. If the output is empty, it means that your process is not in any namespace.
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Βρείτε όλους τους CGroup namespaces

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### Εισέρχονται μέσα σε ένα CGroup namespace

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Επίσης, μπορείτε να **εισέλθετε σε ένα άλλο namespace διεργασίας μόνο αν είστε root**. Και **δεν μπορείτε** να **εισέλθετε** σε άλλο namespace **χωρίς έναν δείκτη** που να τον δείχνει (όπως `/proc/self/ns/cgroup`).

## Αναφορές
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
