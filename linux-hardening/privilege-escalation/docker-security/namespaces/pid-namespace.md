# PID Namespace

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}

## Basic Information

Ο χώρος ονομάτων PID (Process IDentifier) είναι μια δυνατότητα στον πυρήνα του Linux που παρέχει απομόνωση διαδικασιών επιτρέποντας σε μια ομάδα διαδικασιών να έχει το δικό της σύνολο μοναδικών PIDs, ξεχωριστό από τα PIDs σε άλλους χώρους ονομάτων. Αυτό είναι ιδιαίτερα χρήσιμο στην κοντεντοποίηση, όπου η απομόνωση διαδικασιών είναι απαραίτητη για την ασφάλεια και τη διαχείριση πόρων.

Όταν δημιουργείται ένας νέος χώρος ονομάτων PID, η πρώτη διαδικασία σε αυτόν τον χώρο ονομάτων ανατίθεται PID 1. Αυτή η διαδικασία γίνεται η διαδικασία "init" του νέου χώρου ονομάτων και είναι υπεύθυνη για τη διαχείριση άλλων διαδικασιών εντός του χώρου ονομάτων. Κάθε επόμενη διαδικασία που δημιουργείται εντός του χώρου ονομάτων θα έχει έναν μοναδικό PID εντός αυτού του χώρου ονομάτων, και αυτοί οι PIDs θα είναι ανεξάρτητοι από τους PIDs σε άλλους χώρους ονομάτων.

Από την προοπτική μιας διαδικασίας εντός ενός χώρου ονομάτων PID, μπορεί να δει μόνο άλλες διαδικασίες στον ίδιο χώρο ονομάτων. Δεν είναι ενήμερη για διαδικασίες σε άλλους χώρους ονομάτων και δεν μπορεί να αλληλεπιδράσει μαζί τους χρησιμοποιώντας παραδοσιακά εργαλεία διαχείρισης διαδικασιών (π.χ., `kill`, `wait`, κ.λπ.). Αυτό παρέχει ένα επίπεδο απομόνωσης που βοηθά στην αποφυγή παρεμβολών μεταξύ διαδικασιών.

### How it works:

1. Όταν δημιουργείται μια νέα διαδικασία (π.χ., χρησιμοποιώντας την κλήση συστήματος `clone()`), η διαδικασία μπορεί να ανατεθεί σε έναν νέο ή υπάρχοντα χώρο ονομάτων PID. **Εάν δημιουργηθεί ένας νέος χώρος ονομάτων, η διαδικασία γίνεται η διαδικασία "init" αυτού του χώρου ονομάτων**.
2. Ο **πυρήνας** διατηρεί μια **χαρτογράφηση μεταξύ των PIDs στον νέο χώρο ονομάτων και των αντίστοιχων PIDs** στον γονικό χώρο ονομάτων (δηλαδή, τον χώρο ονομάτων από τον οποίο δημιουργήθηκε ο νέος χώρος ονομάτων). Αυτή η χαρτογράφηση **επιτρέπει στον πυρήνα να μεταφράσει τους PIDs όταν είναι απαραίτητο**, όπως όταν στέλνει σήματα μεταξύ διαδικασιών σε διαφορετικούς χώρους ονομάτων.
3. **Οι διαδικασίες εντός ενός χώρου ονομάτων PID μπορούν να βλέπουν και να αλληλεπιδρούν μόνο με άλλες διαδικασίες στον ίδιο χώρο ονομάτων**. Δεν είναι ενήμερες για διαδικασίες σε άλλους χώρους ονομάτων και οι PIDs τους είναι μοναδικοί εντός του χώρου ονομάτων τους.
4. Όταν **καταστραφεί ένας χώρος ονομάτων PID** (π.χ., όταν η διαδικασία "init" του χώρου ονομάτων τερματιστεί), **όλες οι διαδικασίες εντός αυτού του χώρου ονομάτων τερματίζονται**. Αυτό διασφαλίζει ότι όλοι οι πόροι που σχετίζονται με τον χώρο ονομάτων καθαρίζονται σωστά.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Σφάλμα: bash: fork: Cannot allocate memory</summary>

Όταν εκτελείται το `unshare` χωρίς την επιλογή `-f`, προκύπτει ένα σφάλμα λόγω του τρόπου που διαχειρίζεται το Linux τις νέες PID (Process ID) namespaces. Οι βασικές λεπτομέρειες και η λύση παρατίθενται παρακάτω:

1. **Εξήγηση Προβλήματος**:
- Ο πυρήνας του Linux επιτρέπει σε μια διαδικασία να δημιουργεί νέες namespaces χρησιμοποιώντας την κλήση συστήματος `unshare`. Ωστόσο, η διαδικασία που ξεκινά τη δημιουργία μιας νέας PID namespace (αναφερόμενη ως η διαδικασία "unshare") δεν εισέρχεται στη νέα namespace; μόνο οι παιδικές της διαδικασίες το κάνουν.
- Η εκτέλεση του `%unshare -p /bin/bash%` ξεκινά το `/bin/bash` στην ίδια διαδικασία με το `unshare`. Ως εκ τούτου, το `/bin/bash` και οι παιδικές του διαδικασίες βρίσκονται στην αρχική PID namespace.
- Η πρώτη παιδική διαδικασία του `/bin/bash` στη νέα namespace γίνεται PID 1. Όταν αυτή η διαδικασία τερματίσει, ενεργοποιεί την καθαριότητα της namespace αν δεν υπάρχουν άλλες διαδικασίες, καθώς το PID 1 έχει τον ειδικό ρόλο της υιοθέτησης ορφανών διαδικασιών. Ο πυρήνας του Linux θα απενεργοποιήσει στη συνέχεια την κατανομή PID σε αυτή τη namespace.

2. **Συνέπεια**:
- Η έξοδος του PID 1 σε μια νέα namespace οδηγεί στον καθαρισμό της σημαίας `PIDNS_HASH_ADDING`. Αυτό έχει ως αποτέλεσμα η συνάρτηση `alloc_pid` να αποτυγχάνει να κατανοήσει ένα νέο PID κατά τη δημιουργία μιας νέας διαδικασίας, παράγοντας το σφάλμα "Cannot allocate memory".

3. **Λύση**:
- Το πρόβλημα μπορεί να επιλυθεί χρησιμοποιώντας την επιλογή `-f` με το `unshare`. Αυτή η επιλογή κάνει το `unshare` να δημιουργήσει μια νέα διαδικασία μετά τη δημιουργία της νέας PID namespace.
- Η εκτέλεση του `%unshare -fp /bin/bash%` διασφαλίζει ότι η εντολή `unshare` γίνεται PID 1 στη νέα namespace. Το `/bin/bash` και οι παιδικές του διαδικασίες περιέχονται στη νέα αυτή namespace, αποτρέποντας την πρόωρη έξοδο του PID 1 και επιτρέποντας την κανονική κατανομή PID.

Διασφαλίζοντας ότι το `unshare` εκτελείται με την επιλογή `-f`, η νέα PID namespace διατηρείται σωστά, επιτρέποντας στο `/bin/bash` και τις υπο-διαδικασίες του να λειτουργούν χωρίς να συναντούν το σφάλμα κατανομής μνήμης.

</details>

Με την τοποθέτηση μιας νέας παρουσίας του συστήματος αρχείων `/proc` αν χρησιμοποιήσετε την παράμετρο `--mount-proc`, διασφαλίζετε ότι η νέα mount namespace έχει μια **ακριβή και απομονωμένη άποψη των πληροφοριών διαδικασίας που είναι συγκεκριμένες για αυτή τη namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Ελέγξτε σε ποιο namespace βρίσκονται οι διαδικασίες σας
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

Σημειώστε ότι ο χρήστης root από το αρχικό (προεπιλεγμένο) PID namespace μπορεί να δει όλες τις διεργασίες, ακόμη και αυτές σε νέα PID namespaces, γι' αυτό μπορούμε να δούμε όλα τα PID namespaces.

### Είσοδος σε ένα PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Όταν εισέλθετε σε ένα PID namespace από το προεπιλεγμένο namespace, θα μπορείτε ακόμα να δείτε όλες τις διεργασίες. Και η διεργασία από αυτό το PID ns θα μπορεί να δει το νέο bash στο PID ns.

Επίσης, μπορείτε μόνο **να εισέλθετε σε άλλο PID namespace αν είστε root**. Και **δεν μπορείτε** **να εισέλθετε** σε άλλο namespace **χωρίς έναν περιγραφέα** που να δείχνει σε αυτό (όπως το `/proc/self/ns/pid`)

## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
