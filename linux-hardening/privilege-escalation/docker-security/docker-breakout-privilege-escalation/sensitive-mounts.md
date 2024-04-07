# Ευαίσθητα Mounts

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

Η εκθεσιοποίηση του `/proc` και `/sys` χωρίς κατάλληλη απομόνωση του namespace εισάγει σημαντικούς κινδύνους ασφάλειας, συμπεριλαμβανομένης της αύξησης της επιφάνειας επίθεσης και της αποκάλυψης πληροφοριών. Αυτοί οι κατάλογοι περιέχουν ευαίσθητα αρχεία που, εάν δεν ρυθμιστούν σωστά ή αν έχουν πρόσβαση από μη εξουσιοδοτημένο χρήστη, μπορεί να οδηγήσουν σε διαφυγή του container, τροποποίηση του host ή παροχή πληροφοριών που βοηθούν σε περαιτέρω επιθέσεις. Για παράδειγμα, η εσφαλμένη προσάρτηση `-v /proc:/host/proc` μπορεί να παρακάμψει την προστασία AppArmor λόγω της φύσης του βασισμένη σε διαδρομή, αφήνοντας το `/host/proc` ανεπτυγμένο.

**Μπορείτε να βρείτε περισσότερες λεπτομέρειες για κάθε δυνητική ευπάθεια στο** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Ευπάθειες procfs

### `/proc/sys`

Αυτός ο κατάλογος επιτρέπει την πρόσβαση για τροποποίηση μεταβλητών πυρήνα, συνήθως μέσω `sysctl(2)`, και περιέχει αρκετούς υποκαταλόγους που αφορούν:

#### **`/proc/sys/kernel/core_pattern`**

* Περιγράφεται στο [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
* Επιτρέπει τον καθορισμό ενός προγράμματος για εκτέλεση κατά τη δημιουργία αρχείου πυρήνα με τα πρώτα 128 bytes ως ορίσματα. Αυτό μπορεί να οδηγήσει σε εκτέλεση κώδικα εάν το αρχείο ξεκινά με ένα pipe `|`.
*   **Παράδειγμα Δοκιμής και Εκμετάλλευσης**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Δοκιμή πρόσβασης εγγραφής
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Ορισμός προσαρμοσμένου χειριστή
sleep 5 && ./crash & # Ενεργοποίηση χειριστή
```

#### **`/proc/sys/kernel/modprobe`**

* Λεπτομερείς πληροφορίες στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Περιέχει τη διαδρομή προς τον φορτωτή πυρήνα module, καλείται για τη φόρτωση πυρήνα modules.
*   **Παράδειγμα Έλεγχου Πρόσβασης**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Έλεγχος πρόσβασης στο modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

* Αναφέρεται στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
* Ένα γενικό σημαία που ελέγχει εάν ο πυρήνας κάνει panic ή καλεί τον OOM killer όταν συμβεί μια κατάσταση OOM.

#### **`/proc/sys/fs`**

* Σύμφωνα με το [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), περιέχει επιλογές και πληροφορίες σχετικά με το σύστημα αρχείων.
* Η εγγραφή μπορεί να ενεργοποιήσει διάφορες επιθέσεις αρνητικής υπηρεσίας κατά του host.

#### **`/proc/sys/fs/binfmt_misc`**

* Επιτρέπει την εγγραφή ερμηνευτών για μη-φυσικές μορφές δεδομένων βασισμένες στο μαγικό τους νούμερο.
* Μπορεί να οδηγήσει σε ανόδου προνομίων ή πρόσβαση σε root shell αν το `/proc/sys/fs/binfmt_misc/register` είναι εγγράψιμο.
* Σχετική εκμετάλλευση και εξήγηση:
* [Φτωχό rootkit μέσω binfmt\_misc](https://github.com/toffan/binfmt\_misc)
* Αναλυτικός οδηγός: [Σύνδεσμος βίντεο](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Άλλα στο `/proc`

#### **`/proc/config.gz`**

* Μπορεί να αποκαλύψει τη διαμόρφωση του πυρήνα αν το `CONFIG_IKCONFIG_PROC` είναι ενεργοποιημένο.
* Χρήσιμο για τους επιτιθέμενους για την εντοπισμό ευπαθειών στον τρέχοντα πυρήνα.

#### **`/proc/sysrq-trigger`**

* Επιτρέπει την εκκίνηση εντολών Sysrq, προκαλώντας πιθανώς άμεσες επανεκκινήσεις συστήματος ή άλλες κρίσιμες ενέργειες.
*   **Παράδειγμα Επανεκκίνησης Φιλοξενητή**:

```bash
echo b > /proc/sysrq-trigger # Επανεκκίνηση του φιλοξενητή
```

#### **`/proc/kmsg`**

* Εκθέτει μηνύματα πυρήνα στον κύκλο.
* Μπορεί να βοηθήσει σε εκμετάλλευση πυρήνα, διαρροές διευθύνσεων και παροχή ευαίσθητων πληροφοριών συστήματος.

#### **`/proc/kallsyms`**

* Καταχωρεί σύμβολα πυρήνα και τις διευθύνσεις τους.
* Βασικό για την ανάπτυξη εκμετάλλευσης πυρήνα, ειδικά για την υπέρβαση του KASLR.
* Οι πληροφορίες διεύθυνσης περιορίζονται με το `kptr_restrict` ορισμένο σε `1` ή `2`.
* Λεπτομέρειες στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

* Επικοινωνεί με τη συσκευή μνήμης πυρήνα `/dev/mem`.
* Ιστορικά ευάλωτο σε επιθέσεις ανόδου προνομίων.
* Περισσότερα στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

* Αντιπροσωπεύει τη φυσική μνήμη του συστήματος σε μορφή πυρήνα ELF.
* Η ανάγνωση μπορεί να διαρρεύσει τα περιεχόμενα μνήμης του φιλοξενητή και άλλων containers.
* Το μεγάλο μέγεθος αρχείου μπορεί να οδηγήσει σε προβλήματα ανάγνωσης ή καταρρεύσεις λογισμικού.
* Λεπτομερής χρήση στο [Απορρόφηση /proc/kcore το 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

* Εναλλακτική διεπαφή για το `/dev/kmem`, αντιπροσωπεύοντας την εικονική μνήμη πυρήνα.
* Επιτρέπει ανάγνωση και εγγραφή, επομένως άμεση τροποποίηση της μνήμης πυρήνα.

#### **`/proc/mem`**

* Εναλλακτική διεπαφή για το `/dev/mem`, αντιπροσωπεύοντας τη φυσική μνήμη.
* Ε
#### **`/sys/class/thermal`**

* Ελέγχει τις ρυθμίσεις θερμοκρασίας, προκαλώντας ενδεχομένως επιθέσεις DoS ή φυσικές ζημιές.

#### **`/sys/kernel/vmcoreinfo`**

* Διαρρέει διευθύνσεις πυρήνα, ενδεχομένως διακινδυνεύοντας το KASLR.

#### **`/sys/kernel/security`**

* Περιέχει τη διεπαφή `securityfs`, επιτρέποντας τη διαμόρφωση των Linux Security Modules όπως το AppArmor.
* Η πρόσβαση μπορεί να επιτρέψει σε ένα container να απενεργοποιήσει το σύστημα του MAC.

#### **`/sys/firmware/efi/vars` και `/sys/firmware/efi/efivars`**

* Εκθέτει διεπαφές για την αλληλεπίδραση με μεταβλητές EFI στη μνήμη NVRAM.
* Η εσφαλμένη ρύθμιση ή εκμετάλλευση μπορεί να οδηγήσει σε υπολογιστές φορητούς που δεν εκκινούν ή σε μη εκκινήσιμες μηχανές φιλοξενίας.

#### **`/sys/kernel/debug`**

* Το `debugfs` προσφέρει μια διεπαφή αποσφαλμάτωσης "χωρίς κανόνες" στον πυρήνα.
* Ιστορικό προβλημάτων ασφάλειας λόγω της μη περιορισμένης φύσης του.

### Αναφορές

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Κατανόηση και Ενίσχυση των Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Κατάχρηση Προνομιούχων και Μη Προνομιούχων Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
