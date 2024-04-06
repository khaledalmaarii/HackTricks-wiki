# Abusing Tokens

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε τη [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στη [**💬**](https://emojipedia.org/speech-balloon/) [ομάδα Discord](https://discord.gg/hRep4RUj7f) ή στη [ομάδα telegram](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Διακριτικά

Αν **δεν γνωρίζετε τι είναι τα Διακριτικά Πρόσβασης των Windows** διαβάστε αυτή τη σελίδα πριν συνεχίσετε:

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

**Ίσως να μπορείτε να αναβαθμίσετε τα δικαιώματά σας καταχρώμενοι τα διακριτικά που ήδη έχετε**

### SeImpersonatePrivilege

Αυτό το δικαίωμα που κατέχεται από οποιαδήποτε διαδικασία επιτρέπει την υποκατάσταση (αλλά όχι τη δημιουργία) οποιουδήποτε διακριτικού, εφόσον μπορεί να ληφθεί μια λαβή γι' αυτό. Ένα προνομιούχο διακριτικό μπορεί να αποκτηθεί από ένα υπηρεσία των Windows (DCOM) προκαλώντας τη να πραγματοποιήσει ελέγχους ταυτότητας NTLM εναντίον ενός εκμεταλλεύσιμου σφάλματος, επιτρέποντας στη συνέχεια την εκτέλεση μιας διαδικασίας με δικαιώματα ΣΥΣΤΗΜΑΤΟΣ. Αυτή η ευπάθεια μπορεί να εκμεταλλευτεί χρησιμοποιώντας διάφορα εργαλεία, όπως το [juicy-potato](https://github.com/ohpe/juicy-potato), το [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (το οποίο απαιτεί την απενεργοποίηση του winrm), το [SweetPotato](https://github.com/CCob/SweetPotato) και το [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="juicypotato.md" %}
[juicypotato.md](juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Είναι πολύ παρόμοιο με το **SeImpersonatePrivilege**, θα χρησιμοποιήσει την **ίδια μέθοδο** για να αποκτήσει ένα προνομιούχο διακριτικό.\
Στη συνέχεια, αυτό το δικαίωμα επιτρέπει **την ανάθεση ενός πρωτεύοντος διακριτικού** σε μια νέα/ανασταλμένη διαδικασία. Με το προνομιούχο διακριτικό υποκατάστασης μπορείτε να παράγετε ένα πρωτεύον διακριτικό (DuplicateTokenEx).\
Με το διακριτικό, μπορείτε να δημιουργήσετε μια **νέα διαδικασία** με το 'CreateProcessAsUser' ή να δημιουργήσετε μια διαδικασία ανασταλμένη και **να ορίσετε το διακριτικό** (γενικά, δεν μπορείτε να τροποποιήσετε το πρωτεύον διακριτικό μιας εκτελούμενης διαδικασίας).

### SeTcbPrivilege

Αν έχετε ενεργοποιήσει αυτό το διακριτικό μπορείτε να χρησιμοποιήσετε το **KERB\_S4U\_LOGON** για να λάβετε ένα **διακριτικό υποκατάστασης** για οποιονδήποτε άλλο χρήστη χωρίς να γνωρίζετε τα διαπιστευτήριά του, **προσθέσετε μια αυθαίρετη ομάδα** (διαχειριστές) στο διακριτικό, ορίσετε το **επίπεδο ακεραιότητας** του διακριτικού σε "**μεσαίο**" και αναθέσετε αυτό το διακριτικό στο **τρέχον νήμα** (SetThreadToken).

### SeBackupPrivilege

Το σύστημα προκαλεί την **χορήγηση όλων των δικαιωμάτων ανάγνωσης** ελέγχου σε οποιοδήποτε αρχείο (περιορισμένο σε λειτουργίες ανάγνωσης) με αυτό το διακριτικό. Χρησιμοποιείται για την **ανάγνωση των κατακερματισμένων κωδικών πρόσβασης των τοπικών λογαριασμών Διαχειριστή** από το μητρώο, με αποτέλεσμα να μπορούν να χρησιμοποιηθούν εργαλεία όπως το "**psexec**" ή το "**wmicexec**" με τον κατακερματισμένο κωδικό (τεχνική Pass-the-Hash). Ωστόσο, αυτή η τεχνική αποτυγχάνει υπό δύο προϋποθέσεις: όταν ο λογαριασμός τοπικού Διαχειριστή είναι απενεργοποιημένος ή όταν υπάρχει μια πολιτική που αφαιρεί τα διαχειριστικά δικαιώματα από τους τοπικούς Διαχειριστές που συνδέονται απομακρυσμένα.\
Μπορείτε να **καταχρηστείτε αυτό το διακριτικό** με:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* ακολουθώντας τον **IppSec** στο [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ή όπως εξηγείται στην ενότητα **ανάδειξη δικαιωμάτων με τους Τελεστές Αντιγράφων Ασφαλείας** του:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Το δικαίωμα για **εγγραφή πρόσβασης** σε οποιοδήποτε αρχείο συστήματος, ανεξαρτήτως της λίστας ελέγχου πρόσβασης (ACL) του αρχείου, παρέχεται από αυτό το δικαίωμα. Ανοίγει πολλές δυνατότητες για αναβάθμιση, συμπεριλαμβανομένης της δυνατότητας να **τροποποιήσετε υπηρεσίες**, να εκτελέσετε DLL Hijacking και να ορίσετε **debuggers** μέσω των Image File Execution Options μεταξύ διαφόρων άλλων τεχνικών.

### SeCreateTokenPrivilege

Το SeCreateTokenPrivilege είναι ένα ισχυρό δικαίωμα, ιδιαίτερα χρήσιμο όταν ένας χρήστης διαθέτει τη δυνατότητα υποκατάστασης διακριτικών, αλλά και σε περίπτωση έλλειψης του SeImpersonatePrivilege. Αυτή η ικανότητα εξαρτάται από τη δυνατότητα υποκατάστασης ενός διακριτικού που αντιπροσωπεύει τον ίδιο χρήστη και του οποίου το επίπεδο ακεραιότητας δεν υπερβαίνει αυτό τη

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

Περισσότεροι τρόποι για την κατάχρηση αυτού του προνόμιου στο [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Αυτό είναι παρόμοιο με το **SeRestorePrivilege**. Η κύρια λειτουργία του επιτρέπει σε ένα διεργασία να **αναλάβει την ιδιοκτησία ενός αντικειμένου**, παρακάμπτοντας την απαίτηση για συγκεκριμένη πρόσβαση μέσω της παροχής δικαιωμάτων πρόσβασης WRITE\_OWNER. Η διαδικασία περιλαμβάνει πρώτα την ασφαλή ανάληψη της ιδιοκτησίας του επιθυμητού κλειδιού καταχώρισης για σκοπούς εγγραφής, και στη συνέχεια την τροποποίηση του DACL για την ενεργοποίηση λειτουργιών εγγραφής.

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

Αυτό το προνόμιο επιτρέπει το **debugging άλλων διεργασιών**, συμπεριλαμβανομένης της ανάγνωσης και εγγραφής στη μνήμη. Διάφορες στρατηγικές για εισαγωγή μνήμης, ικανές να αποφεύγουν τις περισσότερες λύσεις αντιιστορίας και πρόληψης εισβολών στον κεντρικό υπολογιστή, μπορούν να χρησιμοποιηθούν με αυτό το προνόμιο.

#### Dump μνήμης

Μπορείτε να χρησιμοποιήσετε το [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) από το [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) για να **καταγράψετε τη μνήμη μιας διεργασίας**. Συγκεκριμένα, αυτό μπορεί να εφαρμοστεί στη διεργασία **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**, η οποία είναι υπεύθυνη για την αποθήκευση διαπιστευτηρίων χρήστη αφού ένας χρήστης έχει συνδεθεί με επιτυχία σε ένα σύστημα.

Στη συνέχεια μπορείτε να φορτώσετε αυτήν την καταγραφή στο mimikatz για να λάβετε κωδικούς πρόσβασης:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

#### RCE

Εάν θέλετε να λάβετε ένα κέλυφος `NT SYSTEM` μπορείτε να χρησιμοποιήσετε:

* [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
* [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
* [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

## Έλεγχος προνομίων

```
whoami /priv
```

Τα **tokens που εμφανίζονται ως Απενεργοποιημένα** μπορούν να ενεργοποιηθούν, μπορείτε να καταχραστείτε τα tokens _Ενεργοποιημένα_ και _Απενεργοποιημένα_.

### Ενεργοποίηση όλων των tokens

Αν έχετε απενεργοποιημένα tokens, μπορείτε να χρησιμοποιήσετε το script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) για να ενεργοποιήσετε όλα τα tokens:

```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ή **σενάριο** ενσωματώνεται σε αυτήν την [**ανάρτηση**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Πίνακας

Ο πλήρης οδηγός προνομίων δικαιωμάτων στο [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), η περίληψη παρακάτω θα αναφέρει μόνο τους άμεσους τρόπους εκμετάλλευσης του προνομίου για την απόκτηση μιας συνεδρίας διαχειριστή ή την ανάγνωση ευαίσθητων αρχείων.

| Προνόμιο                   | Επίδραση           | Εργαλείο                    | Διαδρομή εκτέλεσης                                                                                                                                                                                                                                                                                                                                                                | Σχόλια                                                                                                                                                                                                                                                                                                                |
| -------------------------- | ------------------ | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Διαχειριστής**_ | Εργαλείο τρίτου μέρους      | _"Θα επέτρεπε σε έναν χρήστη να προσομοιώσει διακριτικά τα δικαιώματα και να αναβαθμίσει σε σύστημα nt χρησιμοποιώντας εργαλεία όπως το potato.exe, rottenpotato.exe και juicypotato.exe"_                                                                                                                                                                                        | Ευχαριστώ [Aurélien Chalot](https://twitter.com/Defte\_) για την ενημέρωση. Θα προσπαθήσω να το επαναδιατυπώσω σε κάτι πιο σαν συνταγή σύντομα.                                                                                                                                                                       |
| **`SeBackup`**             | **Απειλή**         | _**Εντολές ενσωματωμένες**_ | Διαβάστε ευαίσθητα αρχεία με `robocopy /b`                                                                                                                                                                                                                                                                                                                                        | <p>- Μπορεί να είναι πιο ενδιαφέρον αν μπορείτε να διαβάσετε το %WINDIR%\MEMORY.DMP<br><br>- Το <code>SeBackupPrivilege</code> (και το robocopy) δεν είναι χρήσιμο όταν πρόκειται για ανοιχτά αρχεία.<br><br>- Το Robocopy απαιτεί τόσο το SeBackup όσο και το SeRestore για να λειτουργήσει με την παράμετρο /b.</p> |
| **`SeCreateToken`**        | _**Διαχειριστής**_ | Εργαλείο τρίτου μέρους      | Δημιουργία αυθαίρετου διακριτικού συμβόλου συμπεριλαμβανομένων των τοπικών δικαιωμάτων διαχειριστή με το `NtCreateToken`.                                                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                       |
| **`SeDebug`**              | _**Διαχειριστής**_ | **PowerShell**              | Διπλασιάστε το σύμβολο `lsass.exe`.                                                                                                                                                                                                                                                                                                                                               | Το σενάριο βρίσκεται στο [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                             |
| **`SeLoadDriver`**         | _**Διαχειριστής**_ | Εργαλείο τρίτου μέρους      | <p>1. Φόρτωση ελαττωματικού πυρήνα οδηγού όπως το <code>szkg64.sys</code><br>2. Εκμεταλλευτείτε την ευπάθεια του οδηγού<br><br>Εναλλακτικά, το προνόμιο μπορεί να χρησιμοποιηθεί για την εκφόρτωση οδηγών που σχετίζονται με την ασφάλεια με την εντολή ενσωματωμένης εντολής <code>ftlMC</code>. π.χ.: <code>fltMC sysmondrv</code></p>                                          | <p>1. Η ευπάθεια του <code>szkg64</code> καταχωρίζεται ως <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Ο κώδικας εκμετάλλευσης του <code>szkg64</code> δημιουργήθηκε από τον <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p>                         |
| **`SeRestore`**            | _**Διαχειριστής**_ | **PowerShell**              | <p>1. Εκκίνηση του PowerShell/ISE με το προνόμιο SeRestore παρόν.<br>2. Ενεργοποίηση του προνομίου με το <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Μετονομασία του utilman.exe σε utilman.old<br>4. Μετονομασία του cmd.exe σε utilman.exe<br>5. Κλείδωμα της κονσόλας και πάτημα Win+U</p> | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσιών που αποθηκεύονται στο "Αρχεία Προγράμματα" χρησιμοποιώντας το ίδιο προνόμιο</p>                                                                                  |
| **`SeTakeOwnership`**      | _**Διαχειριστής**_ | _**Εντολές ενσωματωμένες**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Μετονομασία του cmd.exe σε utilman.exe<br>4. Κλείδωμα της κονσόλας και πάτημα Win+U</p>                                                                                                                                                       | <p>Η επίθεση μπορεί να ανιχνευθεί από ορισμένο λογισμικό AV.</p><p>Η εναλλακτική μέθοδος βασίζεται στην αντικατάσταση των δυαδικών αρχείων υπηρεσιών που αποθηκεύονται στο "Αρχεία Προγράμματα" χρησιμοποιώντας το ίδιο προνόμιο.</p>                                                                                 |
| **`SeTcb`**                | _**Διαχειριστής**_ | Εργαλείο τρίτου μέρους      | <p>Διαχειριστείτε τα σύμβολα για να περιλαμβάνουν τα δικαιώματα τοπικού διαχειριστή. Μπορεί να απαιτηθεί το SeImpersonate.</p><p>Να επαληθευτεί.</p>                                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                       |

## Αναφορά

* Ρίξτε μια ματιά σε αυτόν τον πίνακα που ορίζει τα Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Ρίξτε μια ματιά σε [**αυτό το έγγραφο**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) σχετικά με την εκμετάλλευση προνομίων με tokens.

<details>

<summary><strong>Μάθετε το χακάρισμα του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκερ σας κόλπα υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
