# Κατάχρηση Δικαιωμάτων

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Διακριτικά

Αν **δεν γνωρίζετε τι είναι τα Διακριτικά Πρόσβασης των Windows**, διαβάστε αυτήν τη σελίδα πριν συνεχίσετε:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Ίσως να μπορείτε να αναβαθμίσετε τα δικαιώματά σας καταχρώμενοι τα διακριτικά που ήδη έχετε**

### SeImpersonatePrivilege

Αυτό είναι ένα δικαίωμα που κατέχεται από οποιαδήποτε διεργασία επιτρέπει την προσωποποίηση (αλλά όχι τη δημιουργία) οποιουδήποτε διακριτικού, εφόσον μπορεί να αποκτηθεί ένα χειριστήριο για αυτό. Ένα δικαιωματικό διακριτικό μπορεί να αποκτηθεί από ένα υπηρεσία των Windows (DCOM) προκαλώντας τη να πραγματοποιήσει ελέγχους ταυτότητας NTLM έναντι μιας εκμετάλλευσης, επιτρέποντας στη συνέχεια την εκτέλεση μιας διεργασίας με δικαιώματα SYSTEM. Αυτή η ευπάθεια μπορεί να εκμεταλλευτεί χρησιμοποιώντας διάφορα εργαλεία, όπως το [juicy-potato](https://github.com/ohpe/juicy-potato), το [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί την απενεργοποίηση του winrm), το [SweetPotato](https://github.com/CCob/SweetPotato) και το [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, θα χρησιμοποιήσει την **ίδια μέθοδο** για να αποκτήσει ένα δικαιωματικό διακριτικό.\
Στη συνέχεια, αυτό το δικαίωμα επιτρέπει **την ανάθεση ενός πρωτεύοντος διακριτικού** σε μια νέα/ανενεργή διεργασία. Με το δικαιωματικό διακριτικό προσωποποίησης μπορείτε να παράγετε ένα πρωτεύον διακριτικό (DuplicateTokenEx).\
Με το διακριτικό, μπορείτε να δημιουργήσετε μια **νέα διεργασία** με την 'CreateProcessAsUser' ή να δημιουργήσετε μια διεργασία ανενεργή και να **ορίσετε το διακριτικό** (γενικά, δεν μπορείτε να τροποποιήσετε το πρωτεύον διακριτικό μιας εκτελούμενης διεργασίας).

### Se
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Περισσότεροι τρόποι για την κατάχρηση αυτού του προνομίου στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε ένα διεργασία να αναλάβει την ιδιοκτησία ενός αντικειμένου, παρακάμπτοντας την απαίτηση για έμμεση δικαιοδοσία μέσω της παροχής δικαιωμάτων πρόσβασης WRITE_OWNER. Η διαδικασία περιλαμβάνει πρώτα την ασφάλιση της ιδιοκτησίας του επιθυμητού κλειδιού του μητρώου για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL για να επιτραπούν οι εγγραφές.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Αυτό το προνόμιο επιτρέπει το **αποσφαλμάτωση άλλων διεργασιών**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Με αυτό το προνόμιο μπορούν να χρησιμοποιηθούν διάφορες στρατηγικές για την εισχώρηση στη μνήμη, ικανές να αποφύγουν τις περισσότερες λύσεις αντιιντροπίας και πρόληψης εισβολής του οικοδεσπότη.

#### Αποθήκευση μνήμης

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Ειδικότερα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, η οποία είναι υπεύθυνη για την αποθήκευση των διαπιστευτηρίων των χρηστών μετά από επιτυχημένη σύνδεση σε ένα σύστημα.

Στη συνέχεια, μπορείτε να φορτώσετε αυτήν την αποθήκευση στο mimikatz για να αποκτήσετε κωδικούς πρόσβασης:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Εάν θέλετε να αποκτήσετε ένα κέλυφος `NT SYSTEM`, μπορείτε να χρησιμοποιήσετε:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Έλεγχος δικαιωμάτων

To check the privileges of a user, you can use the following methods:

### 1. Whoami

The `whoami` command displays the username and group information of the current user.

```plaintext
whoami
```

### 2. Net user

The `net user` command provides detailed information about a user account, including the group memberships and privileges.

```plaintext
net user <username>
```

Replace `<username>` with the name of the user you want to check.

### 3. Systeminfo

The `systeminfo` command displays detailed information about the system, including the current user's privileges.

```plaintext
systeminfo
```

Look for the "User Name" and "User Domain" fields to find the current user's information.

### 4. PowerShell

You can also use PowerShell to check the privileges of a user. Open a PowerShell session and run the following command:

```plaintext
(Get-WmiObject -Class Win32_UserAccount -Filter "Name='<username>'").Caption
```

Replace `<username>` with the name of the user you want to check.

By using these methods, you can determine the privileges of a user and identify potential vulnerabilities that can be exploited for privilege escalation.
```
whoami /priv
```
Τα **tokens που εμφανίζονται ως Απενεργοποιημένα** μπορούν να ενεργοποιηθούν και μπορείτε πραγματικά να καταχραστείτε _Ενεργοποιημένα_ και _Απενεργοποιημένα_ tokens.

### Ενεργοποίηση όλων των tokens

Εάν έχετε απενεργοποιημένα tokens, μπορείτε να χρησιμοποιήσετε το σενάριο [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ή το **script** που ενσωματώνεται σε αυτήν την [**ανάρτηση**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Ο πλήρης πίνακας με τα προνόμια των δικαιωμάτων βρίσκεται στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η παρακάτω περίληψη θα αναφέρει μόνο τους άμεσους τρόπους εκμετάλλευσης των προνομίων για την απόκτηση μιας διαχειριστικής συνεδρίας ή την ανάγνωση ευαίσθητων αρχείων.

| Προνόμιο                   | Επίδραση     | Εργαλείο                | Διαδρομή εκτέλεσης                                                                                                                                                                                                                                                                                                                               | Παρατηρήσεις                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Εργαλείο 3ου μέρους          | _"Θα επιτρέπει σε έναν χρήστη να προσομοιώσει διακριτικά και να αναβαθμίσει τα δικαιώματα σε nt σύστημα χρησιμοποιώντας εργαλεία όπως το potato.exe, το rottenpotato.exe και το juicypotato.exe"_                                                                                                                                                                                                      | Ευχαριστώ [Aurélien Chalot](https://twitter.com/Defte\_) για την ενημέρωση. Θα προσπαθήσω να το διατυπώσω με μια πιο συνταγογραφική μορφή σύντομα.                                                                                                                                                                                        |
| **`SeBackup`**             | **Απειλή**  | _**Εντολές που είναι ενσωματωμένες**_ | Ανάγνωση ευαίσθητων αρχείων με τη χρήση της εντολής `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Μπορεί να είναι πιο ενδιαφέρον αν μπορείτε να διαβάσετε το %WINDIR%\MEMORY.DMP<br><br>- Το `SeBackupPrivilege` (και το robocopy) δεν είναι χρήσιμο όταν πρόκειται για το άνοιγμα αρχείων.<br><br>- Το Robocopy απαιτεί τόσο το SeBackup όσο και το SeRestore για να λειτουργήσει με την παράμετρο /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Εργαλείο 3ου μέρους          | Δημιουργία αυθαίρετου διακριτικού περιλαμβάνοντας τοπικά δικαιώματα διαχειριστή με τη χρήση της `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Διπλασιάστε το διακριτικό του `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Το script μπορεί να βρεθεί στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Εργαλείο 3ου μέρους          | <p>1. Φορτώστε ένα ελαττωματικό οδηγό πυρήνα, όπως το <code>szkg64.sys</code><br>2. Εκμεταλλευτείτε την ευπάθεια του οδηγού<br><br>Εναλλακτικά, το προνόμιο μπορεί να χρησιμοποιηθεί για την απεγκατάσταση οδηγών που σχετίζονται με την ασφάλεια με την εντολή `ftlMC`. π.χ.: `fltMC sysmondrv`</p>                                                                           | <p>1. Η ευπάθεια <code>szkg64</code> αναφέρεται ως <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Ο κώδικας εκμετάλλευσης του <code>szkg64</code> δημιουργήθηκε από τον <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Εκκινήστε το PowerShell/ISE με το προνόμιο SeRestore παρόν.<br>2. Ενεργοποιήστε το προνόμιο με το <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομάστε το utilman.exe σε utilman.old<br>4. Μετονομάστε το cmd.exe σε utilman.exe<br>5. Κλειδώστε την κονσόλα και πατήστε Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσίας που αποθηκεύονται στο "Program Files" χρησιμοποιώντας το ίδιο προνόμιο</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Εντολές που είναι ενσωματωμένες**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομάστε το cmd.exe σε utilman.exe<br>4. Κλειδώστε την κονσόλα και πατήστε Win+U</p>                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσίας που αποθηκεύονται στο "Program Files" χρησιμοποιώντας το ίδιο προνόμιο
