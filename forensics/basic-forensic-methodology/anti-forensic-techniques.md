<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>


# Χρονικές σημάνσεις

Ένας επιτιθέμενος μπορεί να ενδιαφέρεται να **αλλάξει τις χρονικές σημάνσεις των αρχείων** για να αποφύγει την ανίχνευσή του.\
Είναι δυνατόν να βρεθούν οι χρονικές σημάνσεις μέσα στο MFT στα χαρακτηριστικά `$STANDARD_INFORMATION` __και__ __`$FILE_NAME`.

Και τα δύο χαρακτηριστικά έχουν 4 χρονικές σημάνσεις: **Τροποποίηση**, **πρόσβαση**, **δημιουργία** και **τροποποίηση καταγραφής MFT** (MACE ή MACB).

Ο **Windows explorer** και άλλα εργαλεία εμφανίζουν τις πληροφορίες από το **`$STANDARD_INFORMATION`**.

## TimeStomp - Εργαλείο αντι-ανακριτικής

Αυτό το εργαλείο **τροποποιεί** τις πληροφορίες των χρονικών σημάνσεων μέσα στο **`$STANDARD_INFORMATION`** **αλλά όχι** τις πληροφορίες μέσα στο **`$FILE_NAME`**. Επομένως, είναι δυνατόν να **ανιχνευθεί** **ύποπτη** **δραστηριότητα**.

## Usnjrnl

Το **USN Journal** (Update Sequence Number Journal) είναι μια λειτουργία του NTFS (σύστημα αρχείων Windows NT) που καταγράφει τις αλλαγές του όγκου. Το εργαλείο [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) επιτρέπει την εξέταση αυτών των αλλαγών.

![](<../../.gitbook/assets/image (449).png>)

Η προηγούμενη εικόνα είναι το **αποτέλεσμα** που εμφανίζεται από το **εργαλείο** όπου μπορεί να παρατηρηθεί ότι έγιναν κάποιες **αλλαγές** στο αρχείο.

## $LogFile

**Όλες οι αλλαγές μεταδεδομένων σε ένα σύστημα αρχείων καταγράφονται** σε ένα διαδικασία που ονομάζεται [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Τα καταγεγραμμένα μεταδεδομένα κρατούνται σε ένα αρχείο με το όνομα `**$LogFile**`, που βρίσκεται στον ριζικό κατάλογο ενός συστήματος αρχείων NTFS. Εργαλεία όπως το [LogFileParser](https://github.com/jschicht/LogFileParser) μπορούν να χρησιμοποιηθούν για να αναλύσουν αυτό το αρχείο και να ανιχνεύσουν αλλαγές.

![](<../../.gitbook/assets/image (450).png>)

Και πάλι, στην έξοδο του εργαλείου είναι δυνατόν να δείτε ότι **έγιναν κάποιες αλλαγές**.

Χρησιμοποιώντας το ίδιο εργαλείο είναι δυνατόν να ανιχνευθεί σε **ποια χρονική στιγμή τροποποιήθηκαν οι χρονικές σημάνσεις**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Χρόνος δημιουργίας του αρχείου
* ATIME: Χρόνος τροποποίησης του αρχείου
* MTIME: Χρόνος τροποποίησης του μητρώου MFT του αρχείου
* RTIME: Χρόνος πρόσβασης στο αρχείο

## Σύγκριση `$STANDARD_INFORMATION` και `$FILE_NAME`

Ένας άλλος τ
## Διαγραφή Ιστορικού USB

Όλες οι **καταχωρήσεις συσκευών USB** αποθηκεύονται στο Μητρώο των Windows κάτω από το κλειδί μητρώου **USBSTOR**, το οποίο περιέχει υποκλειδιά που δημιουργούνται κάθε φορά που συνδέετε μια συσκευή USB στον υπολογιστή ή το laptop σας. Μπορείτε να βρείτε αυτό το κλειδί εδώ: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Διαγράφοντας αυτό**, θα διαγράψετε το ιστορικό USB.\
Μπορείτε επίσης να χρησιμοποιήσετε το εργαλείο [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) για να είστε βέβαιοι ότι τα έχετε διαγράψει (και για να τα διαγράψετε).

Ένα άλλο αρχείο που αποθηκεύει πληροφορίες σχετικά με τις USB είναι το αρχείο `setupapi.dev.log` μέσα στο `C:\Windows\INF`. Αυτό πρέπει επίσης να διαγραφεί.

## Απενεργοποίηση Αντιγράφων Σκιάς

**Λίστα** αντιγράφων σκιάς με την εντολή `vssadmin list shadowstorage`\
**Διαγραφή** τους με την εντολή `vssadmin delete shadow`

Μπορείτε επίσης να τα διαγράψετε μέσω του γραφικού περιβάλλοντος ακολουθώντας τα βήματα που προτείνονται στην [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Για να απενεργοποιήσετε τα αντίγραφα σκιάς [βήματα από εδώ](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ανοίξτε το πρόγραμμα Υπηρεσιών πληκτρολογώντας "services" στο πλαίσιο αναζήτησης κειμένου μετά από κλικ στο κουμπί Έναρξη των Windows.
2. Από τη λίστα, βρείτε την "Volume Shadow Copy", επιλέξτε την και στη συνέχεια αποκτήστε πρόσβαση στις Ιδιότητες κάνοντας δεξί κλικ.
3. Επιλέξτε την επιλογή "Disabled" από το αναπτυσσόμενο μενού "Τύπος εκκίνησης" και επιβεβαιώστε την αλλαγή κάνοντας κλικ στο Εφαρμογή και ΟΚ.

Είναι επίσης δυνατή η τροποποίηση της διαμόρφωσης των αρχείων που θα αντιγραφούν στο αντίγραφο σκιάς στο μητρώο `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Αντικατάσταση διαγραμμένων αρχείων

* Μπορείτε να χρησιμοποιήσετε ένα **εργαλείο των Windows**: `cipher /w:C` Αυτό θα οδηγήσει το cipher να αφαιρέσει οποιαδήποτε δεδομένα από το διαθέσιμο αχρησιμοποίητο χώρο στον δίσκο C.
* Μπορείτε επίσης να χρησιμοποιήσετε εργαλεία όπως το [**Eraser**](https://eraser.heidi.ie)

## Διαγραφή αρχείων καταγραφής συμβάντων των Windows

* Windows + R --> eventvwr.msc --> Ανάπτυξη "Καταγραφές των Windows" --> Δεξί κλικ σε κάθε κατηγορία και επιλογή "Εκκαθάριση καταγραφής"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Απενεργοποίηση καταγραφής συμβάντων των Windows

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Εντός της ενότητας υπηρεσιών, απενεργοποιήστε την υπηρεσία "Windows Event Log"
* `WEvtUtil.exec clear-log` ή `WEvtUtil.exe cl`

## Απενεργοποίηση $UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** 💬 στην ομάδα [**Discord**](https://discord.gg/hRep4RUj7f) ή στην ομάδα [**telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>
