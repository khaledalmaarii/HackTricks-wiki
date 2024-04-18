# macOS Απορρόφηση Μνήμης

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλου λογισμικού**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κλοπή πληροφοριών.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

---

## Αρτεφάκτα Μνήμης

### Αρχεία Swap

Τα αρχεία swap, όπως το `/private/var/vm/swapfile0`, λειτουργούν ως **μνήμες cache όταν η φυσική μνήμη είναι γεμάτη**. Όταν δεν υπάρχει άλλος χώρος στη φυσική μνήμη, τα δεδομένα μεταφέρονται σε ένα αρχείο swap και στη συνέχεια επαναφέρονται στη φυσική μνήμη όποτε χρειάζεται. Μπορεί να υπάρχουν πολλά αρχεία swap, με ονόματα όπως swapfile0, swapfile1 κλπ.

### Εικόνα Hibernation

Το αρχείο που βρίσκεται στο `/private/var/vm/sleepimage` είναι κρίσιμο κατά τη διάρκεια της **λειτουργίας υπνώσεως**. **Τα δεδομένα από τη μνήμη αποθηκεύονται σε αυτό το αρχείο όταν το OS X κάνει υπνώση**. Κατά την αφύπνιση του υπολογιστή, το σύστημα ανακτά τα δεδομένα μνήμης από αυτό το αρχείο, επιτρέποντας στον χρήστη να συνεχίσει από το σημείο που σταμάτησε.

Αξίζει να σημειωθεί ότι σε μοντέρνα συστήματα MacOS, αυτό το αρχείο είναι συνήθως κρυπτογραφημένο για λόγους ασφαλείας, κάτι που δυσκολεύει την ανάκτηση.

* Για να ελέγξετε αν η κρυπτογράφηση είναι ενεργοποιημένη για το sleepimage, μπορείτε να εκτελέσετε την εντολή `sysctl vm.swapusage`. Αυτό θα δείξει αν το αρχείο είναι κρυπτογραφημένο.

### Καταγραφές Πίεσης Μνήμης

Ένα άλλο σημαντικό αρχείο σχετικό με τη μνήμη στα συστήματα MacOS είναι το **αρχείο καταγραφής πίεσης μνήμης**. Αυτά τα αρχεία καταγραφής βρίσκονται στο `/var/log` και περιέχουν λεπτομερείς πληροφορίες σχετικά με τη χρήση μνήμης του συστήματος και τα γεγονότα πίεσης. Μπορούν να είναι ιδιαίτερα χρήσιμα για τη διάγνωση θεμάτων που σχετίζονται με τη μνήμη ή την κατανόηση του τρόπου με τον οποίο το σύστημα διαχειρίζεται τη μνήμη με τον χρόνο.

## Απορρόφηση μνήμης με το osxpmem

Για να απορροφήσετε τη μνήμη σε μια μηχανή MacOS, μπορείτε να χρησιμοποιήσετε το [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Σημείωση**: Οι παρακάτω οδηγίες θα λειτουργήσουν μόνο για Mac με αρχιτεκτονική Intel. Αυτό το εργαλείο είναι τώρα αρχειοθετημένο και η τελευταία έκδοση ήταν το 2017. Το δυαδικό που κατεβάζετε χρησιμοποιώντας τις παρακάτω οδηγίες στοχεύει σε Intel chips καθώς το Apple Silicon δεν υπήρχε το 2017. Μπορεί να είναι δυνατόν να μεταγλωττίσετε το δυαδικό για αρχιτεκτονική arm64 αλλά θα πρέπει να το δοκιμάσετε μόνοι σας.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Αν βρείτε αυτό το σφάλμα: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Μπορείτε να το διορθώσετε κάνοντας:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Άλλα σφάλματα** μπορεί να διορθωθούν επιτρέποντας τη φόρτωση του kext στο "Ασφάλεια & Απορρήτου --> Γενικά", απλά **επιτρέψτε** το.

Μπορείτε επίσης να χρησιμοποιήσετε αυτό το **oneliner** για να κατεβάσετε την εφαρμογή, να φορτώσετε το kext και να κάνετε dump τη μνήμη:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι ένας μηχανισμός αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες malware**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αρπαγών λογαριασμών και των επιθέσεων ransomware που προκύπτουν από malware που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τον μηχανισμό τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφή**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
