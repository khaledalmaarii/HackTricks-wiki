# Εscalation προνομίων με Autoruns

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Συμβουλή για bug bounty**: **Εγγραφείτε** στο **Intigriti**, μια πρεμιέρα **πλατφόρμα bug bounty δημιουργημένη από χάκερς, για χάκερς**! Γίνετε μέλος στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και αρχίστε να κερδίζετε αμοιβές έως και **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

Το **Wmic** μπορεί να χρησιμοποιηθεί για να εκτελέσει προγράμματα κατά την **εκκίνηση**. Δείτε ποια δυαδικά αρχεία είναι προγραμματισμένα να τρέξουν κατά την εκκίνηση με:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Προγραμματισμένες Εργασίες

Οι **εργασίες** μπορούν να προγραμματιστούν να τρέχουν με **συγκεκριμένη συχνότητα**. Δείτε ποια δυαδικά αρχεία έχουν προγραμματιστεί να τρέχουν με:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Φάκελοι

Όλα τα δυαδικά αρχεία που βρίσκονται στους **φακέλους εκκίνησης θα εκτελεστούν κατά την εκκίνηση**. Οι κοινοί φάκελοι εκκίνησης είναι αυτοί που αναφέρονται συνεχόμενα, αλλά ο φάκελος εκκίνησης είναι επίσης καθορισμένος στο μητρώο. [Διαβάστε αυτό για να μάθετε πού.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Καταχώριση στο Μητρώο

{% hint style="info" %}
[Σημείωση από εδώ](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Η καταχώριση **Wow6432Node** στο μητρώο υποδεικνύει ότι χρησιμοποιείτε μια έκδοση Windows 64 bit. Το λειτουργικό σύστημα χρησιμοποιεί αυτό το κλειδί για να εμφανίσει μια ξεχωριστή προβολή του HKEY_LOCAL_MACHINE\SOFTWARE για εφαρμογές 32 bit που τρέχουν σε εκδόσεις Windows 64 bit.
{% endhint %}

### Εκτελέσεις

Γνωστές καταχωρίσεις AutoRun στο μητρώο:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Οι καταχωρίσεις στο μητρώο γνωστές ως **Run** και **RunOnce** σχεδιάστηκαν για να εκτελούν αυτόματα προγράμματα κάθε φορά που ένας χρήστης συνδέεται στο σύστημα. Η γραμμή εντολών που ανατίθεται ως τιμή δεδομένων ενός κλειδιού περιορίζεται σε 260 χαρακτήρες ή λιγότερο.

**Εκτελέσεις υπηρεσιών** (μπορούν να ελέγχουν την αυτόματη εκκίνηση υπηρεσιών κατά την εκκίνηση):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Στα Windows Vista και σε μεταγενέστερες εκδόσεις, τα κλειδιά μητρώου **Run** και **RunOnce** δεν δημιουργούνται αυτόματα. Οι καταχωρίσεις σε αυτά τα κλειδιά μπορούν είτε να εκκινήσουν προγράμματα απευθείας είτε να τα καθορίσουν ως εξαρτήσεις. Για παράδειγμα, για να φορτώσετε ένα αρχείο DLL κατά την σύνδεση, θα μπορούσατε να χρησιμοποιήσετε το κλειδί μητρώου **RunOnceEx** μαζί με ένα κλειδί "Depend". Αυτό επιδεικνύεται προσθέτοντας μια καταχώριση στο μητρώο για να εκτελέσει το "C:\temp\evil.dll" κατά την εκκίνηση του συστήματος:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Εκμετάλλευση 1**: Εάν μπορείτε να γράψετε μέσα σε οποιοδήποτε από τα αναφερόμενα κλειδιά μητρώου μέσα στο **HKLM**, μπορείτε να αναβαθμίσετε τα προνόμια όταν συνδεθεί ένας διαφορετικός χρήστης.
{% endhint %}

{% hint style="info" %}
**Εκμετάλλευση 2**: Εάν μπορείτε να αντικαταστήσετε οποιοδήποτε από τα δυαδικά που υποδεικνύονται σε οποιοδήποτε από τα κλειδιά μητρώου μέσα στο **HKLM**, μπορείτε να τροποποιήσετε αυτό το δυαδικό με ένα backdoor όταν συνδεθεί ένας διαφορετικός χρήστης και να αναβαθμίσετε τα προνόμια.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Διαδρομή Εκκίνησης

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Οι συντομεύσεις που τοποθετούνται στο φάκελο **Startup** θα εκκινήσουν αυτόματα υπηρεσίες ή εφαρμογές κατά την σύνδεση του χρήστη ή την επανεκκίνηση του συστήματος. Η τοποθεσία του φακέλου **Startup** ορίζεται στο μητρώο για τους τομείς **Τοπικής Μηχανής** και **Τρέχοντος Χρήστη**. Αυτό σημαίνει ότι οποιαδήποτε συντόμευση προστίθεται σε αυτές τις συγκεκριμένες τοποθεσίες **Startup** θα εξασφαλίσει ότι η συνδεδεμένη υπηρεσία ή πρόγραμμα θα ξεκινήσει μετά τη διαδικασία σύνδεσης ή επανεκκίνησης, κάνοντας τη μια απλή μέθοδο για τον προγραμματισμό εκτέλεσης προγραμμάτων αυτόματα.

{% hint style="info" %}
Αν μπορείτε να αντικαταστήσετε οποιονδήποτε \[Χρήστη] Φάκελο Κελύφους κάτω από **HKLM**, θα μπορείτε να τον κατευθύνετε προς ένα φάκελο που ελέγχεται από εσάς και να τοποθετήσετε ένα παρασκήνιο που θα εκτελείται κάθε φορά που ένας χρήστης συνδέεται στο σύστημα ανεβάζοντας τα δικαιώματα.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Κλειδιά Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Συνήθως, το κλειδί **Userinit** είναι ρυθμισμένο σε **userinit.exe**. Ωστόσο, εάν αυτό το κλειδί τροποποιηθεί, το συγκεκριμένο εκτελέσιμο θα εκκινηθεί επίσης από το **Winlogon** κατά τη σύνδεση του χρήστη. Αντίστοιχα, το κλειδί **Shell** προορίζεται να δείχνει στο **explorer.exe**, το οποίο είναι η προεπιλεγμένη επιφάνεια εργασίας για τα Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Εάν μπορείτε να αντικαταστήσετε την τιμή του μητρώου ή το δυαδικό αρχείο, θα μπορέσετε να αναβαθμίσετε τα προνόμια.
{% endhint %}

### Ρυθμίσεις Πολιτικής

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Ελέγξτε το κλειδί **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Αλλαγή της Εντολής Ασφαλούς Λειτουργίας Με Εντολή Εντολών

Στο Μητρώο των Windows κάτω από `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, υπάρχει μια τιμή με την ονομασία **`AlternateShell`** που έχει οριστεί από προεπιλογή σε `cmd.exe`. Αυτό σημαίνει ότι όταν επιλέγετε "Ασφαλής Λειτουργία με Εντολή Εντολών" κατά την εκκίνηση (πατώντας F8), χρησιμοποιείται το `cmd.exe`. Ωστόσο, είναι δυνατόν να ρυθμίσετε τον υπολογιστή σας ώστε να ξεκινά αυτόματα σε αυτήν τη λειτουργία χωρίς την ανάγκη να πατήσετε F8 και να την επιλέξετε χειροκίνητα.

Βήματα για τη δημιουργία μιας επιλογής εκκίνησης για αυτόματη εκκίνηση σε "Ασφαλής Λειτουργία με Εντολή Εντολών":

1. Αλλαγή των χαρακτηριστικών του αρχείου `boot.ini` για να αφαιρέσετε τα σημάδια "μόνο για ανάγνωση", "σύστημα" και "κρυφό": `attrib c:\boot.ini -r -s -h`
2. Άνοιγμα του `boot.ini` για επεξεργασία.
3. Εισαγωγή μιας γραμμής όπως: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Αποθήκευση των αλλαγών στο `boot.ini`.
5. Επαναεφαρμογή των αρχικών χαρακτηριστικών του αρχείου: `attrib c:\boot.ini +r +s +h`

* **Εκμετάλλευση 1:** Η αλλαγή του κλειδιού μητρώου **AlternateShell** επιτρέπει τη δημιουργία προσαρμοσμένης εγκατάστασης κέλυφους εντολών, πιθανώς για μη εξουσιοδοτημένη πρόσβαση.
* **Εκμετάλλευση 2 (Δικαιώματα Εγγραφής στην Εντολή PATH):** Έχοντας δικαιώματα εγγραφής σε οποιοδήποτε μέρος της μεταβλητής συστήματος **PATH**, ειδικά πριν το `C:\Windows\system32`, σας επιτρέπει να εκτελέσετε ένα προσαρμοσμένο `cmd.exe`, το οποίο θα μπορούσε να είναι μια πίσω πόρτα εάν το σύστημα ξεκινήσει σε Ασφαλή Λειτουργία.
* **Εκμετάλλευση 3 (Δικαιώματα Εγγραφής στην Εντολή PATH και στο boot.ini):** Η εγγραφή στο αρχείο `boot.ini` επιτρέπει την αυτόματη εκκίνηση σε Ασφαλή Λειτουργία, διευκολύνοντας τη μη εξουσιοδοτημένη πρόσβαση στην επόμενη επανεκκίνηση.

Για να ελέγξετε την τρέχουσα ρύθμιση του **AlternateShell**, χρησιμοποιήστε αυτές τις εντολές:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Εγκατεστημένος Συνιστώμενος Συστατικό

Το Active Setup είναι μια λειτουργία στα Windows που **εκκινεί πριν η περιβάλλον εργασίας είναι πλήρως φορτωμένο**. Δίνει προτεραιότητα στην εκτέλεση συγκεκριμένων εντολών, οι οποίες πρέπει να ολοκληρωθούν πριν συνεχιστεί η σύνδεση του χρήστη. Αυτή η διαδικασία συμβαίνει ακόμη και πριν ενεργοποιηθούν άλλες καταχωρήσεις εκκίνησης, όπως αυτές στις ενότητες καταχώρησης Run ή RunOnce του μητρώου.

Το Active Setup διαχειρίζεται μέσω των ακόλουθων κλειδιών του μητρώου:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Μέσα σε αυτά τα κλειδιά, υπάρχουν διάφορα υποκλειδιά, το καθένα αντιστοιχεί σε ένα συγκεκριμένο συστατικό. Οι τιμές των κλειδιών που είναι ιδιαίτερα ενδιαφέρουσες περιλαμβάνουν:

- **IsInstalled:**
  - Το `0` υποδηλώνει ότι η εντολή του στοιχείου δεν θα εκτελεστεί.
  - Το `1` σημαίνει ότι η εντολή θα εκτελεστεί μία φορά για κάθε χρήστη, που είναι η προεπιλεγμένη συμπεριφορά εάν η τιμή `IsInstalled` λείπει.
- **StubPath:** Ορίζει την εντολή που θα εκτελεστεί από το Active Setup. Μπορεί να είναι οποιαδήποτε έγκυρη γραμμή εντολών, όπως η εκκίνηση του `notepad`.

**Ασφαλείς Προτάσεις:**

- Η τροποποίηση ή η εγγραφή σε ένα κλειδί όπου το **`IsInstalled`** έχει οριστεί σε `"1"` με ένα συγκεκριμένο **`StubPath`** μπορεί να οδηγήσει σε μη εξουσιοδοτημένη εκτέλεση εντολών, πιθανώς για ανύψωση προνομίων.
- Η τροποποίηση του δυαδικού αρχείου που αναφέρεται σε οποιαδήποτε τιμή **`StubPath`** μπορεί επίσης να επιτύχει ανύψωση προνομίων, εφόσον υπάρχουν επαρκή δικαιώματα.

Για να ελέγξετε τις ρυθμίσεις **`StubPath`** σε συστατικά Active Setup, μπορούν να χρησιμοποιηθούν οι ακόλουθες εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Αντικείμενα Βοηθού Περιηγητή

### Επισκόπηση των Αντικειμένων Βοηθού Περιηγητή (BHOs)

Τα Αντικείμενα Βοηθού Περιηγητή (BHOs) είναι διακριτικά αρχεία DLL που προσθέτουν επιπλέον χαρακτηριστικά στο Internet Explorer της Microsoft. Φορτώνονται στο Internet Explorer και τον Εξερευνητή των Windows κάθε φορά που ξεκινάνε. Ωστόσο, η εκτέλεσή τους μπορεί να αποκλειστεί με την ρύθμιση του κλειδιού **NoExplorer** σε 1, εμποδίζοντάς τα να φορτώνονται με τις περιπτώσεις του Εξερευνητή των Windows.

Τα BHOs είναι συμβατά με τα Windows 10 μέσω του Internet Explorer 11, αλλά δεν υποστηρίζονται στο Microsoft Edge, τον προεπιλεγμένο περιηγητή σε νεότερες εκδόσεις των Windows.

Για να εξετάσετε τα BHOs που έχουν καταχωρηθεί σε ένα σύστημα, μπορείτε να ελέγξετε τα ακόλουθα κλειδιά του μητρώου:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Κάθε BHO εκπροσωπείται από το **CLSID** του στο μητρώο, λειτουργώντας ως μοναδικός αναγνωριστικός. Λεπτομερείς πληροφορίες για κάθε CLSID μπορούν να βρεθούν στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Για τον ερευνητικό έλεγχο των BHOs στο μητρώο, μπορούν να χρησιμοποιηθούν οι ακόλουθες εντολές:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Επεκτάσεις Internet Explorer

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Σημειώστε ότι το μητρώο θα περιέχει 1 νέο μητρώο για κάθε dll και θα εκπροσωπείται από το **CLSID**. Μπορείτε να βρείτε τις πληροφορίες του CLSID στο `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Οδηγοί Γραμματοσειράς

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Άνοιγμα Εντολής

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Επιλογές Εκτέλεσης Αρχείων Εικόνας
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Σημειώστε ότι όλες οι τοποθεσίες όπου μπορείτε να βρείτε αυτόματες εκτελέσεις έχουν **ήδη αναζητηθεί από το** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Ωστόσο, για μια **πιο ολοκληρωμένη λίστα αρχείων που εκτελούνται αυτόματα** μπορείτε να χρησιμοποιήσετε το [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) από τα SysInternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Περισσότερα

**Βρείτε περισσότερα Autoruns όπως registries στο** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Αναφορές

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Συμβουλή για bug bounty**: **Εγγραφείτε** στο **Intigriti**, μια προηγμένη **πλατφόρμα bug bounty δημιουργημένη από χάκερς, για χάκερς**! Γίνετε μέλος στο [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) σήμερα, και αρχίστε να κερδίζετε αμοιβές έως και **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
