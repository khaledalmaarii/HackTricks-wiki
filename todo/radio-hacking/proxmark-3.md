# Proxmark 3

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που έχουν μεγαλύτερη σημασία, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από διεπαφές προς ιστοσελίδες και συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Επίθεση σε συστήματα RFID με το Proxmark3

Το πρώτο πράγμα που χρειάζεστε είναι να έχετε ένα [**Proxmark3**](https://proxmark.com) και [**να εγκαταστήσετε το λογισμικό και τις εξαρτήσεις του**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Επίθεση σε MIFARE Classic 1KB

Έχει **16 τομείς**, καθένας από αυτούς έχει **4 μπλοκ** και κάθε μπλοκ περιέχει **16B**. Το UID βρίσκεται στον τομέα 0 μπλοκ 0 (και δεν μπορεί να αλλοιωθεί).\
Για να έχετε πρόσβαση σε κάθε τομέα, χρειάζεστε **2 κλειδιά** (**Α** και **Β**) τα οποία αποθηκεύονται στο **μπλοκ 3 κάθε τομέα** (τελευταίος τομέας). Ο τελευταίος τομέας αποθηκεύει επίσης τα **bits πρόσβασης** που δίνουν τις άδειες **ανάγνωσης και εγγραφής** σε **κάθε μπλοκ** χρησιμοποιώντας τα 2 κλειδιά.\
Τα 2 κλειδιά είναι χρήσιμα για να δώσουν άδειες ανάγνωσης αν γνωρίζετε το πρώτο και άδειες εγγραφής αν γνωρίζετε το δεύτερο (για παράδειγμα).

Μπορούν να πραγματοποιηθούν πολλές επιθέσεις
```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```
Το Proxmark3 επιτρέπει να εκτελείτε και άλλες ενέργειες όπως το **ακροατήριο** μιας **επικοινωνίας από ετικέτα προς αναγνώστη** για να προσπαθήσετε να βρείτε ευαίσθητα δεδομένα. Σε αυτήν την κάρτα, μπορείτε απλώς να καταγράψετε την επικοινωνία και να υπολογίσετε το χρησιμοποιούμενο κλειδί επειδή οι **κρυπτογραφικές λειτουργίες που χρησιμοποιούνται είναι αδύναμες** και γνωρίζοντας το καθαρό και το κρυπτογραφημένο κείμενο μπορείτε να το υπολογίσετε (εργαλείο `mfkey64`).

### Ακατέργαστες Εντολές

Οι συστήματα IoT μερικές φορές χρησιμοποιούν **μη εμπορικές ετικέτες**. Σε αυτήν την περίπτωση, μπορείτε να χρησιμοποιήσετε το Proxmark3 για να στείλετε προσαρμοσμένες **ακατέργαστες εντολές στις ετικέτες**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Με αυτές τις πληροφορίες μπορείτε να προσπαθήσετε να αναζητήσετε πληροφορίες σχετικά με την κάρτα και τον τρόπο επικοινωνίας μαζί της. Το Proxmark3 επιτρέπει την αποστολή ακατέργαστων εντολών όπως: `hf 14a raw -p -b 7 26`

### Σενάρια

Το λογισμικό Proxmark3 διαθέτει μια προεγκατεστημένη λίστα **σεναρίων αυτοματισμού** που μπορείτε να χρησιμοποιήσετε για να εκτελέσετε απλές εργασίες. Για να ανακτήσετε την πλήρη λίστα, χρησιμοποιήστε την εντολή `script list`. Στη συνέχεια, χρησιμοποιήστε την εντολή `script run`, ακολουθούμενη από το όνομα του σεναρίου:
```
proxmark3> script run mfkeys
```
Μπορείτε να δημιουργήσετε ένα σενάριο για να **δοκιμάσετε την ανθεκτικότητα των αναγνωστών ετικετών**, έτσι ώστε να αντιγράψετε τα δεδομένα ενός **έγκυρου καρτών**. Απλά γράψτε ένα **Lua script** που θα **τυχαιοποιεί** ένα ή περισσότερα **τυχαία bytes** και θα ελέγχει αν ο αναγνώστης καταρρέει με οποιαδήποτε επανάληψη.

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε τις πιο σημαντικές ευπάθειες, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τις διεπαφές προς τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Δουλεύετε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
