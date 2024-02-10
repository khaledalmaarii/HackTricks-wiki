# Προστασία διαπιστευτηρίων στα Windows

## Προστασία διαπιστευτηρίων

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## WDigest

Το πρωτόκολλο [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396), που εισήχθη με τα Windows XP, είναι σχεδιασμένο για την πιστοποίηση μέσω του πρωτοκόλλου HTTP και **είναι ενεργοποιημένο από προεπιλογή στα Windows XP έως Windows 8.0 και Windows Server 2003 έως Windows Server 2012**. Αυτή η προεπιλεγμένη ρύθμιση οδηγεί στην **αποθήκευση των κωδικών πρόσβασης σε απλό κείμενο στο LSASS** (Local Security Authority Subsystem Service). Ένας επιτιθέμενος μπορεί να χρησιμοποιήσει το Mimikatz για να **εξάγει αυτά τα διαπιστευτήρια** εκτελώντας:
```bash
sekurlsa::wdigest
```
Για να **απενεργοποιήσετε ή ενεργοποιήσετε αυτήν τη λειτουργία**, οι κλειδιά καταχώρησης _**UseLogonCredential**_ και _**Negotiate**_ εντός του _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ πρέπει να οριστούν σε "1". Εάν αυτά τα κλειδιά είναι **απών ή ορισμένα σε "0"**, το WDigest είναι **απενεργοποιημένο**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Προστασία LSA

Από την έκδοση **Windows 8.1** και μετά, η Microsoft ενισχύει την ασφάλεια του LSA για να **αποτρέπει την μη εξουσιοδοτημένη ανάγνωση μνήμης ή εισαγωγή κώδικα από μη αξιόπιστες διεργασίες**. Αυτή η βελτίωση δυσκολεύει την κανονική λειτουργία εντολών όπως `mimikatz.exe sekurlsa:logonpasswords`. Για να **ενεργοποιήσετε αυτήν τη βελτιωμένη προστασία**, η τιμή _**RunAsPPL**_ στο μονοπάτι _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ πρέπει να ρυθμιστεί σε 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Παράκαμψη

Είναι δυνατόν να παρακαμφθεί αυτή η προστασία χρησιμοποιώντας τον οδηγό Mimikatz mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Προστασία διαπιστευτηρίων

Το **Credential Guard**, μια λειτουργία αποκλειστική για τα **Windows 10 (Enterprise και Education εκδόσεις)**, ενισχύει την ασφάλεια των διαπιστευτηρίων της μηχανής χρησιμοποιώντας το **Virtual Secure Mode (VSM)** και το **Virtualization Based Security (VBS)**. Χρησιμοποιεί επεκτάσεις εικονικοποίησης της CPU για να απομονώσει βασικές διεργασίες εντός ενός προστατευμένου χώρου μνήμης, μακριά από την πρόσβαση του κύριου λειτουργικού συστήματος. Αυτή η απομόνωση εξασφαλίζει ότι ακόμα και το πυρήνας δεν μπορεί να έχει πρόσβαση στη μνήμη του VSM, προστατεύοντας αποτελεσματικά τα διαπιστευτήρια από επιθέσεις όπως το **pass-the-hash**. Ο **Local Security Authority (LSA)** λειτουργεί μέσα σε αυτό το ασφαλές περιβάλλον ως ένα trustlet, ενώ η διεργασία **LSASS** στο κύριο λειτουργικό σύστημα λειτουργεί απλώς ως επικοινωνητής με το LSA του VSM.

Από προεπιλογή, το **Credential Guard** δεν είναι ενεργό και απαιτεί χειροκίνητη ενεργοποίηση εντός μιας οργάνωσης. Είναι κρίσιμο για την ενίσχυση της ασφάλειας έναντι εργαλείων όπως το **Mimikatz**, τα οποία περιορίζονται στην ικανότητά τους να εξάγουν διαπιστευτήρια. Ωστόσο, ευπάθειες μπορούν ακόμα να εκμεταλλευτούνται μέσω της προσθήκης προσαρμοσμένων **Security Support Providers (SSP)** για την καταγραφή διαπιστευτηρίων σε καθαρό κείμενο κατά τη διάρκεια προσπαθειών σύνδεσης.

Για να επαληθευτεί η κατάσταση ενεργοποίησης του **Credential Guard**, μπορεί να ελεγχθεί το κλειδί μητρώου **_LsaCfgFlags_** κάτω από **_HKLM\System\CurrentControlSet\Control\LSA_**. Μια τιμή "**1**" υποδηλώνει ενεργοποίηση με **UEFI lock**, "**2**" χωρίς κλείδωμα και "**0**" υποδηλώνει ότι δεν είναι ενεργοποιημένο. Αυτός ο έλεγχος του μητρώου, ενώ είναι ένα ισχυρό ένδειξη, δεν είναι το μόνο βήμα για την ενεργοποίηση του Credential Guard. Λεπτομερείς οδηγίες και ένα σενάριο PowerShell για την ενεργοποίηση αυτής της λειτουργίας είναι διαθέσιμα στο διαδίκτυο.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Για μια συνεπή κατανόηση και οδηγίες για την ενεργοποίηση του **Credential Guard** στα Windows 10 και την αυτόματη ενεργοποίησή του σε συμβατά συστήματα των **Windows 11 Enterprise και Education (έκδοση 22H2)**, επισκεφθείτε την [τεκμηρίωση της Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Περαιτέρω λεπτομέρειες για την εφαρμογή προσαρμοσμένων SSPs για την καταγραφή διαπιστευτηρίων παρέχονται στο [ακόλουθο εγχειρίδιο](../active-directory-methodology/custom-ssp.md).


## Λειτουργία RestrictedAdmin για το RDP

Τα **Windows 8.1 και Windows Server 2012 R2** εισήγαγαν αρκετά νέα χαρακτηριστικά ασφαλείας, συμπεριλαμβανομένης της **_Restricted Admin mode για το RDP_**. Αυτή η λειτουργία σχεδιάστηκε για να ενισχύσει την ασφάλεια μειώνοντας τους κινδύνους που συνδέονται με επιθέσεις **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)**.

Παραδοσιακά, κατά τη σύνδεση σε έναν απομακρυσμένο υπολογιστή μέσω RDP, τα διαπιστευτήριά σας αποθηκεύονται στον στόχο. Αυτό αποτελεί σημαντικό κίνδυνο για την ασφάλεια, ειδικά όταν χρησιμοποιούνται λογαριασμοί με αυξημένα προνόμια. Ωστόσο, με την εισαγωγή της **_Restricted Admin mode_**, αυτός ο κίνδυνος μειώνεται σημαντικά.

Όταν πραγματοποιείτε μια σύνδεση RDP χρησιμοποιώντας την εντολή **mstsc.exe /RestrictedAdmin**, η πιστοποίηση στον απομακρυσμένο υπολογιστή πραγματοποιείται χωρίς να αποθηκεύονται τα διαπιστευτήριά σας σε αυτόν. Με αυτήν την προσέγγιση, διασφαλίζεται ότι, σε περίπτωση μόλυνσης από κακόβουλο λογισμικό ή αν κακόβουλος χρήστης αποκτήσει πρόσβαση στον απομακρυσμένο διακομιστή, τα διαπιστευτήριά σας δεν κινδυνεύουν, καθώς δεν αποθηκεύονται στον διακομιστή.

Σημαντικό είναι να σημειωθεί ότι στην **Restricted Admin mode**, οι προσπάθειες πρόσβασης σε πόρους του δικτύου από τη συνεδρία RDP δεν θα χρησιμοποιήσουν τα προσωπικά σας διαπιστευτήρια, αλλά θα χρησιμοποιήσουν την **ταυτότητα της μηχανής**.

Αυτό το χαρακτηριστικό αποτελεί ένα σημαντικό βήμα προόδου στην ασφάλεια των απομακρυσμένων συνδέσεων επιφάνειας εργασίας και στην προστασία ευαίσθητων πληροφοριών από αποκάλυψη σε περίπτωση παραβίασης της ασφάλειας.

![](../../.gitbook/assets/ram.png)

Για περισσότερες λεπτομερείς πληροφορίες, επισκεφθείτε την [πηγή αυτή](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Κρυφά διαπιστευτήρια

Τα Windows ασφαλίζουν τα **διαπιστευτήρια του τομέα** μέσω της **Τοπικής Αρχής Ασφαλείας (LSA)**, υποστηρίζοντας διαδικασίες σύνδεσης με πρωτόκολλα ασφαλείας όπως το **Kerberos** και το **NTLM**. Ένα βασικό χαρακτηριστικό των Windows είναι η δυνατότητά τους να αποθηκεύουν τις **τελευταίες δέκα συνδέσεις στον τομέα** για να εξασφαλίζουν ότι οι χρήστες μπορούν ακόμα να έχουν πρόσβαση στους υπολογιστές τους ακόμα και αν ο **ελεγκτής τομέα είναι εκτός σύνδεσης** - μια ευκαιρία για τους χρήστες φορητών υπολογιστών που συχνά βρίσκονται μακριά από το δίκτυο της εταιρείας τους.

Ο αριθμός των κρυφών συνδέσεων μπορεί να προσαρμοστεί μέσω ενός συγκεκριμένου **κλειδιού μητρώου ή πολιτικής ομάδας**. Για να δείτε ή να αλλάξετε αυτήν τη ρύθμιση, χρησιμοποιείται η ακόλουθη εντολή:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Η πρόσβαση σε αυτές τις κρυφές πιστοποιητικές πληροφορίες ελέγχεται αυστηρά, με μόνο τον λογαριασμό **SYSTEM** να έχει τις απαραίτητες άδειες για να τις προβάλει. Οι διαχειριστές που χρειάζονται πρόσβαση σε αυτές τις πληροφορίες πρέπει να το κάνουν με τα δικαιώματα χρήστη SYSTEM. Τα πιστοποιητικά αποθηκεύονται στη διεύθυνση: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

Το **Mimikatz** μπορεί να χρησιμοποιηθεί για να εξαχθούν αυτά τα κρυφά πιστοποιητικά χρησιμοποιώντας την εντολή `lsadump::cache`.

Για περισσότερες λεπτομέρειες, η αρχική [πηγή](http://juggernaut.wikidot.com/cached-credentials) παρέχει πλήρεις πληροφορίες.


## Προστατευμένοι Χρήστες

Η συμμετοχή στην ομάδα **Προστατευμένοι Χρήστες** εισάγει αρκετές ενισχύσεις ασφαλείας για τους χρήστες, εξασφαλίζοντας υψηλότερα επίπεδα προστασίας από κλοπή και κατάχρηση διαπιστευτηρίων:

- **Αναθέσεις Διαπιστευτηρίων (CredSSP)**: Ακόμα κι αν η ρύθμιση ομάδας πολιτικής για το **Επιτρέπεται η ανάθεση προεπιλεγμένων διαπιστευτηρίων** είναι ενεργοποιημένη, τα καθαρά κείμενα διαπιστευτήρια των Προστατευμένων Χρηστών δεν θα αποθηκευτούν στην μνήμη cache.
- **Windows Digest**: Από τα **Windows 8.1 και Windows Server 2012 R2** και μετά, το σύστημα δεν θα αποθηκεύει στην μνήμη cache τα καθαρά κείμενα διαπιστευτήρια των Προστατευμένων Χρηστών, ανεξάρτητα από την κατάσταση του Windows Digest.
- **NTLM**: Το σύστημα δεν θα αποθηκεύει στην μνήμη cache τα καθαρά κείμενα διαπιστευτήρια ή τις μονοδρομικές συναρτήσεις NT (NTOWF) των Προστατευμένων Χρηστών.
- **Kerberos**: Για τους Προστατευμένους Χρήστες, η πιστοποίηση Kerberos δεν θα δημιουργήσει κλειδιά **DES** ή **RC4**, ούτε θα αποθηκεύσει καθαρά κείμενα διαπιστευτήρια ή μακροπρόθεσμα κλειδιά πέρα ​​από την αρχική απόκτηση του Ticket-Granting Ticket (TGT).
- **Είσοδος εκτός σύνδεσης**: Οι Προστατευμένοι Χρήστες δεν θα έχουν έναν διαθέσιμο επαληθευτή που θα δημιουργείται κατά την είσοδο ή το ξεκλείδωμα, πράγμα που σημαίνει ότι η είσοδος εκτός σύνδεσης δεν υποστηρίζεται για αυτούς τους λογαριασμούς.

Αυτές οι προστασίες ενεργοποιούνται από τη στιγμή που ένας χρήστης, που είναι μέλος της ομάδας **Προστατευμένοι Χρήστες**, συνδέεται στη συσκευή. Αυτό εξασφαλίζει ότι υπάρχουν κρίσιμα μέτρα ασφαλείας για την προστασία από διάφορες μεθόδους κλοπής διαπιστευτηρίων.

Για περισσότερες λεπτομερείς πληροφορίες, ανατρέξτε στην επίσημη [τεκμηρίωση](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Πίνακας από** [**τα έγγραφα**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον επαγγελματία με</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας
