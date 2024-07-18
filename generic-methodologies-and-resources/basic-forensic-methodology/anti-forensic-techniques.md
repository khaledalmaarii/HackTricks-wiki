# Anti-Forensic Techniques

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Timestamps

Ένας επιτιθέμενος μπορεί να ενδιαφέρεται να **αλλάξει τις χρονικές σφραγίδες των αρχείων** για να αποφύγει την ανίχνευση.\
Είναι δυνατόν να βρείτε τις χρονικές σφραγίδες μέσα στο MFT σε χαρακτηριστικά `$STANDARD_INFORMATION` \_\_ και \_\_ `$FILE_NAME`.

Και τα δύο χαρακτηριστικά έχουν 4 χρονικές σφραγίδες: **Τροποποίηση**, **πρόσβαση**, **δημιουργία** και **τροποποίηση μητρώου MFT** (MACE ή MACB).

**Ο εξερευνητής των Windows** και άλλα εργαλεία δείχνουν τις πληροφορίες από **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

Αυτό το εργαλείο **τροποποιεί** τις πληροφορίες χρονικής σφραγίδας μέσα στο **`$STANDARD_INFORMATION`** **αλλά** **όχι** τις πληροφορίες μέσα στο **`$FILE_NAME`**. Επομένως, είναι δυνατόν να **εντοπιστεί** **ύποπτη** **δραστηριότητα**.

### Usnjrnl

Το **USN Journal** (Ημερολόγιο Αριθμού Ακολουθίας Ενημέρωσης) είναι μια δυνατότητα του NTFS (σύστημα αρχείων Windows NT) που παρακολουθεί τις αλλαγές του όγκου. Το εργαλείο [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) επιτρέπει την εξέταση αυτών των αλλαγών.

![](<../../.gitbook/assets/image (801).png>)

Η προηγούμενη εικόνα είναι η **έξοδος** που εμφανίζεται από το **εργαλείο** όπου μπορεί να παρατηρηθεί ότι κάποιες **αλλαγές πραγματοποιήθηκαν** στο αρχείο.

### $LogFile

**Όλες οι αλλαγές μεταδεδομένων σε ένα σύστημα αρχείων καταγράφονται** σε μια διαδικασία γνωστή ως [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Τα καταγεγραμμένα μεταδεδομένα διατηρούνται σε ένα αρχείο με όνομα `**$LogFile**`, που βρίσκεται στον ριζικό κατάλογο ενός συστήματος αρχείων NTFS. Εργαλεία όπως το [LogFileParser](https://github.com/jschicht/LogFileParser) μπορούν να χρησιμοποιηθούν για την ανάλυση αυτού του αρχείου και την αναγνώριση αλλαγών.

![](<../../.gitbook/assets/image (137).png>)

Και πάλι, στην έξοδο του εργαλείου είναι δυνατόν να δούμε ότι **κάποιες αλλαγές πραγματοποιήθηκαν**.

Χρησιμοποιώντας το ίδιο εργαλείο είναι δυνατόν να εντοπιστεί **σε ποια χρονική στιγμή τροποποιήθηκαν οι χρονικές σφραγίδες**:

![](<../../.gitbook/assets/image (1089).png>)

* CTIME: Χρόνος δημιουργίας αρχείου
* ATIME: Χρόνος τροποποίησης αρχείου
* MTIME: Τροποποίηση μητρώου MFT του αρχείου
* RTIME: Χρόνος πρόσβασης αρχείου

### `$STANDARD_INFORMATION` και `$FILE_NAME` σύγκριση

Ένας άλλος τρόπος για να εντοπιστούν ύποπτα τροποποιημένα αρχεία θα ήταν να συγκρίνουμε τον χρόνο και στα δύο χαρακτηριστικά αναζητώντας **ασυμφωνίες**.

### Νανοδευτερόλεπτα

Οι χρονικές σφραγίδες του **NTFS** έχουν **ακρίβεια** **100 νανοδευτερολέπτων**. Έτσι, η εύρεση αρχείων με χρονικές σφραγίδες όπως 2010-10-10 10:10:**00.000:0000 είναι πολύ ύποπτη**.

### SetMace - Anti-forensic Tool

Αυτό το εργαλείο μπορεί να τροποποιήσει και τα δύο χαρακτηριστικά `$STARNDAR_INFORMATION` και `$FILE_NAME`. Ωστόσο, από τα Windows Vista, είναι απαραίτητο να υπάρχει ένα ζωντανό λειτουργικό σύστημα για να τροποποιήσει αυτές τις πληροφορίες.

## Data Hiding

Το NFTS χρησιμοποιεί ένα cluster και το ελάχιστο μέγεθος πληροφορίας. Αυτό σημαίνει ότι αν ένα αρχείο καταλαμβάνει και ένα cluster και μισό, το **υπόλοιπο μισό δεν θα χρησιμοποιηθεί ποτέ** μέχρι να διαγραφεί το αρχείο. Έτσι, είναι δυνατόν να **κρυφτεί δεδομένα σε αυτόν τον χώρο slack**.

Υπάρχουν εργαλεία όπως το slacker που επιτρέπουν την απόκρυψη δεδομένων σε αυτόν τον "κρυφό" χώρο. Ωστόσο, μια ανάλυση του `$logfile` και του `$usnjrnl` μπορεί να δείξει ότι προστέθηκαν κάποια δεδομένα:

![](<../../.gitbook/assets/image (1060).png>)

Έτσι, είναι δυνατόν να ανακτηθεί ο χώρος slack χρησιμοποιώντας εργαλεία όπως το FTK Imager. Σημειώστε ότι αυτός ο τύπος εργαλείου μπορεί να αποθηκεύσει το περιεχόμενο κρυπτογραφημένο ή ακόμα και κρυπτογραφημένο.

## UsbKill

Αυτό είναι ένα εργαλείο που θα **κλείσει τον υπολογιστή αν ανιχνευθεί οποιαδήποτε αλλαγή στις θύρες USB**.\
Ένας τρόπος για να το ανακαλύψετε θα ήταν να ελέγξετε τις τρέχουσες διαδικασίες και να **εξετάσετε κάθε εκτελέσιμο python script**.

## Live Linux Distributions

Αυτές οι διανομές **εκτελούνται μέσα στη μνήμη RAM**. Ο μόνος τρόπος για να τις ανιχνεύσετε είναι **σε περίπτωση που το σύστημα αρχείων NTFS είναι προσαρτημένο με δικαιώματα εγγραφής**. Αν είναι προσαρτημένο μόνο με δικαιώματα ανάγνωσης, δεν θα είναι δυνατόν να ανιχνευθεί η εισβολή.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

Είναι δυνατόν να απενεργοποιηθούν πολλές μέθοδοι καταγραφής των Windows για να καταστεί η εγκληματολογική έρευνα πολύ πιο δύσκολη.

### Disable Timestamps - UserAssist

Αυτό είναι ένα κλειδί μητρώου που διατηρεί ημερομηνίες και ώρες όταν κάθε εκτελέσιμο αρχείο εκτελείται από τον χρήστη.

Η απενεργοποίηση του UserAssist απαιτεί δύο βήματα:

1. Ρυθμίστε δύο κλειδιά μητρώου, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` και `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, και τα δύο στο μηδέν για να δηλώσετε ότι θέλουμε να απενεργοποιηθεί το UserAssist.
2. Καθαρίστε τους υποκαταλόγους του μητρώου σας που μοιάζουν με `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

Αυτό θα αποθηκεύσει πληροφορίες σχετικά με τις εφαρμογές που εκτελούνται με στόχο τη βελτίωση της απόδοσης του συστήματος Windows. Ωστόσο, αυτό μπορεί επίσης να είναι χρήσιμο για εγκληματολογικές πρακτικές.

* Εκτελέστε `regedit`
* Επιλέξτε τη διαδρομή αρχείου `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Κάντε δεξί κλικ και στα δύο `EnablePrefetcher` και `EnableSuperfetch`
* Επιλέξτε Τροποποίηση σε καθένα από αυτά για να αλλάξετε την τιμή από 1 (ή 3) σε 0
* Επανεκκινήστε

### Disable Timestamps - Last Access Time

Όποτε ένα φάκελος ανοίγεται από έναν όγκο NTFS σε έναν διακομιστή Windows NT, το σύστημα παίρνει τον χρόνο για να **ενημερώσει ένα πεδίο χρονικής σφραγίδας σε κάθε καταχωρημένο φάκελο**, που ονομάζεται χρόνος τελευταίας πρόσβασης. Σε έναν πολύ χρησιμοποιούμενο όγκο NTFS, αυτό μπορεί να επηρεάσει την απόδοση.

1. Ανοίξτε τον Επεξεργαστή Μητρώου (Regedit.exe).
2. Περιηγηθείτε στο `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Αναζητήστε το `NtfsDisableLastAccessUpdate`. Αν δεν υπάρχει, προσθέστε αυτό το DWORD και ρυθμίστε την τιμή του σε 1, που θα απενεργοποιήσει τη διαδικασία.
4. Κλείστε τον Επεξεργαστή Μητρώου και επανεκκινήστε τον διακομιστή.

### Delete USB History

Όλες οι **καταχωρήσεις συσκευών USB** αποθηκεύονται στο Μητρώο των Windows κάτω από το κλειδί μητρώου **USBSTOR** που περιέχει υποκλειδιά που δημιουργούνται όποτε συνδέετε μια συσκευή USB στον υπολογιστή ή το laptop σας. Μπορείτε να βρείτε αυτό το κλειδί εδώ H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Διαγράφοντας αυτό** θα διαγράψετε την ιστορία USB.\
Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) για να βεβαιωθείτε ότι τα έχετε διαγράψει (και για να τα διαγράψετε).

Ένα άλλο αρχείο που αποθηκεύει πληροφορίες σχετικά με τα USB είναι το αρχείο `setupapi.dev.log` μέσα στο `C:\Windows\INF`. Αυτό θα πρέπει επίσης να διαγραφεί.

### Disable Shadow Copies

**Λίστα** με τις shadow copies με `vssadmin list shadowstorage`\
**Διαγράψτε** τις εκτελώντας `vssadmin delete shadow`

Μπορείτε επίσης να τις διαγράψετε μέσω GUI ακολουθώντας τα βήματα που προτείνονται στο [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Για να απενεργοποιήσετε τις shadow copies [βήματα από εδώ](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ανοίξτε το πρόγραμμα Υπηρεσίες πληκτρολογώντας "services" στο πλαίσιο αναζήτησης κειμένου μετά την κλικ στο κουμπί εκκίνησης των Windows.
2. Από τη λίστα, βρείτε "Volume Shadow Copy", επιλέξτε το και στη συνέχεια αποκτήστε πρόσβαση στις Ιδιότητες κάνοντας δεξί κλικ.
3. Επιλέξτε Απενεργοποιημένο από το αναπτυσσόμενο μενού "Τύπος εκκίνησης" και στη συνέχεια επιβεβαιώστε την αλλαγή κάνοντας κλικ στο Εφαρμογή και OK.

Είναι επίσης δυνατόν να τροποποιήσετε τη ρύθμιση των αρχείων που θα αντιγραφούν στην shadow copy στο μητρώο `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

* Μπορείτε να χρησιμοποιήσετε ένα **εργαλείο Windows**: `cipher /w:C` Αυτό θα υποδείξει στον cipher να αφαιρέσει οποιαδήποτε δεδομένα από τον διαθέσιμο μη χρησιμοποιούμενο χώρο δίσκου μέσα στον δίσκο C.
* Μπορείτε επίσης να χρησιμοποιήσετε εργαλεία όπως το [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

* Windows + R --> eventvwr.msc --> Επεκτείνετε "Windows Logs" --> Κάντε δεξί κλικ σε κάθε κατηγορία και επιλέξτε "Clear Log"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Μέσα στην ενότητα υπηρεσιών απενεργοποιήστε την υπηρεσία "Windows Event Log"
* `WEvtUtil.exec clear-log` ή `WEvtUtil.exe cl`

### Disable $UsnJrnl

* `fsutil usn deletejournal /d c:`

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
