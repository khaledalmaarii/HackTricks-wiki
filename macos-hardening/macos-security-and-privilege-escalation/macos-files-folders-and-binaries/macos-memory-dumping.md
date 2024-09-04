# macOS Memory Dumping

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


## Memory Artifacts

### Swap Files

Τα αρχεία swap, όπως το `/private/var/vm/swapfile0`, λειτουργούν ως **cache όταν η φυσική μνήμη είναι γεμάτη**. Όταν δεν υπάρχει άλλος χώρος στη φυσική μνήμη, τα δεδομένα της μεταφέρονται σε ένα αρχείο swap και στη συνέχεια επιστρέφονται στη φυσική μνήμη όταν χρειάζεται. Μπορεί να υπάρχουν πολλά αρχεία swap, με ονόματα όπως swapfile0, swapfile1, και ούτω καθεξής.

### Hibernate Image

Το αρχείο που βρίσκεται στο `/private/var/vm/sleepimage` είναι κρίσιμο κατά τη διάρκεια της **λειτουργίας αδρανοποίησης**. **Δεδομένα από τη μνήμη αποθηκεύονται σε αυτό το αρχείο όταν το OS X αδρανοποιείται**. Όταν ξυπνά ο υπολογιστής, το σύστημα ανακτά τα δεδομένα μνήμης από αυτό το αρχείο, επιτρέποντας στον χρήστη να συνεχίσει από εκεί που σταμάτησε.

Αξίζει να σημειωθεί ότι σε σύγχρονα συστήματα MacOS, αυτό το αρχείο είναι συνήθως κρυπτογραφημένο για λόγους ασφαλείας, καθιστώντας την ανάκτηση δύσκολη.

* Για να ελέγξετε αν η κρυπτογράφηση είναι ενεργοποιημένη για το sleepimage, μπορείτε να εκτελέσετε την εντολή `sysctl vm.swapusage`. Αυτό θα δείξει αν το αρχείο είναι κρυπτογραφημένο.

### Memory Pressure Logs

Ένα άλλο σημαντικό αρχείο που σχετίζεται με τη μνήμη στα συστήματα MacOS είναι το **log πίεσης μνήμης**. Αυτά τα logs βρίσκονται στο `/var/log` και περιέχουν λεπτομερείς πληροφορίες σχετικά με τη χρήση μνήμης του συστήματος και τα γεγονότα πίεσης. Μπορούν να είναι ιδιαίτερα χρήσιμα για τη διάγνωση προβλημάτων που σχετίζονται με τη μνήμη ή για την κατανόηση του τρόπου διαχείρισης της μνήμης από το σύστημα με την πάροδο του χρόνου.

## Dumping memory with osxpmem

Για να κάνετε dump τη μνήμη σε μια μηχανή MacOS μπορείτε να χρησιμοποιήσετε το [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Σημείωση**: Οι παρακάτω οδηγίες θα λειτουργήσουν μόνο για Macs με αρχιτεκτονική Intel. Αυτό το εργαλείο είναι πλέον αρχειοθετημένο και η τελευταία έκδοση ήταν το 2017. Το δυαδικό αρχείο που κατεβάζεται χρησιμοποιώντας τις παρακάτω οδηγίες στοχεύει σε επεξεργαστές Intel καθώς η Apple Silicon δεν υπήρχε το 2017. Είναι πιθανό να μπορείτε να συντάξετε το δυαδικό αρχείο για αρχιτεκτονική arm64, αλλά θα πρέπει να το δοκιμάσετε μόνοι σας.
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
**Άλλα σφάλματα** μπορεί να διορθωθούν **επιτρέποντας τη φόρτωση του kext** στο "Ασφάλεια & Ιδιωτικότητα --> Γενικά", απλά **επιτρέψτε** το.

Μπορείτε επίσης να χρησιμοποιήσετε αυτήν την **εντολή** για να κατεβάσετε την εφαρμογή, να φορτώσετε το kext και να κάνετε dump τη μνήμη:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
