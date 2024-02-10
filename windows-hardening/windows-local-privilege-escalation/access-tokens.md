# Διαπιστευτήρια Πρόσβασης

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Διαπιστευτήρια Πρόσβασης

Κάθε **χρήστης που έχει συνδεθεί** στο σύστημα **διαθέτει ένα διαπιστευτήριο πρόσβασης με πληροφορίες ασφαλείας** για αυτήν τη συνεδρία σύνδεσης. Το σύστημα δημιουργεί ένα διαπιστευτήριο πρόσβασης όταν ο χρήστης συνδέεται. **Κάθε διεργασία που εκτελείται** εκ μέρους του χρήστη **έχει ένα αντίγραφο του διαπιστευτηρίου πρόσβασης**. Το διαπιστευτήριο αναγνωρίζει τον χρήστη, τις ομάδες του χρήστη και τα προνόμια του χρήστη. Ένα διαπιστευτήριο περιέχει επίσης ένα αναγνωριστικό SID (Security Identifier) σύνδεσης που αναγνωρίζει την τρέχουσα συνεδρία σύνδεσης.

Μπορείτε να δείτε αυτές τις πληροφορίες εκτελώντας την εντολή `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
ή χρησιμοποιώντας το _Process Explorer_ από τα Sysinternals (επιλέξτε διεργασία και προσπελάστε την καρτέλα "Ασφάλεια"):

![](<../../.gitbook/assets/image (321).png>)

### Τοπικός διαχειριστής

Όταν ένας τοπικός διαχειριστής συνδέεται, **δημιουργούνται δύο διαπιστευτήρια πρόσβασης**: Ένα με δικαιώματα διαχειριστή και ένα άλλο με κανονικά δικαιώματα. **Από προεπιλογή**, όταν αυτός ο χρήστης εκτελεί μια διεργασία, χρησιμοποιείται αυτό με τα **κανονικά** (μη-διαχειριστή) **δικαιώματα**. Όταν αυτός ο χρήστης προσπαθεί να **εκτελέσει** οτιδήποτε **ως διαχειριστής** ("Εκτέλεση ως διαχειριστής" για παράδειγμα), θα χρησιμοποιηθεί το **UAC** για να ζητηθεί άδεια.\
Εάν θέλετε να [**μάθετε περισσότερα για το UAC, διαβάστε αυτήν τη σελίδα**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Παραπληροφόρηση χρήστη διαπιστευτηρίων

Εάν έχετε **έγκυρα διαπιστευτήρια οποιουδήποτε άλλου χρήστη**, μπορείτε να **δημιουργήσετε** μια **νέα συνεδρία σύνδεσης** με αυτά τα διαπιστευτήρια:
```
runas /user:domain\username cmd.exe
```
Το **access token** έχει επίσης μια **αναφορά** των συνεδριών σύνδεσης μέσα στο **LSASS**, αυτό είναι χρήσιμο αν η διαδικασία χρειάζεται να έχει πρόσβαση σε ορισμένα αντικείμενα του δικτύου.\
Μπορείτε να εκκινήσετε μια διαδικασία που **χρησιμοποιεί διαφορετικές πιστοποιήσεις για την πρόσβαση σε υπηρεσίες δικτύου** χρησιμοποιώντας:
```
runas /user:domain\username /netonly cmd.exe
```
Αυτό είναι χρήσιμο εάν έχετε διαπιστευτήρια για πρόσβαση σε αντικείμενα στο δίκτυο, αλλά αυτά τα διαπιστευτήρια δεν είναι έγκυρα μέσα στον τρέχοντα υπολογιστή, καθώς θα χρησιμοποιηθούν μόνο στο δίκτυο (στον τρέχοντα υπολογιστή θα χρησιμοποιηθούν οι τρέχουσες δικαιώματα του τρέχοντος χρήστη).

### Τύποι διακριτικών

Υπάρχουν δύο τύποι διακριτικών διαθέσιμα:

* **Κύριο διακριτικό**: Λειτουργεί ως αναπαράσταση των διαπιστευτηρίων ασφαλείας ενός διεργασίας. Η δημιουργία και η συσχέτιση των κύριων διακριτικών με τις διεργασίες είναι ενέργειες που απαιτούν αυξημένα δικαιώματα, τονίζοντας την αρχή του διαχωρισμού των δικαιωμάτων. Συνήθως, ένας υπηρεσίας πιστοποίησης είναι υπεύθυνος για τη δημιουργία του διακριτικού, ενώ μια υπηρεσία σύνδεσης χειρίζεται τη συσχέτισή του με το κέλυφος του λειτουργικού συστήματος του χρήστη. Αξίζει να σημειωθεί ότι οι διεργασίες κληρονομούν το κύριο διακριτικό της γονικής διεργασίας κατά τη δημιουργία τους.

* **Διακριτικό υποκατάστασης**: Επιτρέπει σε μια εφαρμογή εξυπηρετητή να προσωρινά υιοθετήσει την ταυτότητα του πελάτη για πρόσβαση σε ασφαλή αντικείμενα. Αυτός ο μηχανισμός είναι κατηγοριοποιημένος σε τέσσερα επίπεδα λειτουργίας:
- **Ανώνυμο**: Παρέχει πρόσβαση στον εξυπηρετητή όπως ένας μη αναγνωρισμένος χρήστης.
- **Αναγνώριση**: Επιτρέπει στον εξυπηρετητή να επαληθεύσει την ταυτότητα του πελάτη χωρίς να τη χρησιμοποιήσει για πρόσβαση σε αντικείμενα.
- **Υποκατάσταση**: Επιτρέπει στον εξυπηρετητή να λειτουργεί υπό την ταυτότητα του πελάτη.
- **Ανάθεση**: Παρόμοιο με την Υποκατάσταση, αλλά περιλαμβάνει τη δυνατότητα επέκτασης αυτής της υπόθεσης ταυτότητας σε απομακρυσμένα συστήματα με τα οποία αλληλεπιδρά ο εξυπηρετητής, εξασφαλίζοντας τη διατήρηση των διαπιστευτηρίων.

#### Παραπλανήστε διακριτικά

Χρησιμοποιώντας τον **module incognito** του metasploit, εάν έχετε αρκετά δικαιώματα, μπορείτε εύκολα να **καταγράψετε** και να **παραπλανήσετε** άλλα **διακριτικά**. Αυτό μπορεί να είναι χρήσιμο για να εκτελέσετε ενέργειες ως να ήσασταν ο άλλος χρήστης. Μπορείτε επίσης να **αναβαθμίσετε τα δικαιώματα** με αυτήν την τεχνική.

### Δικαιώματα διακριτικών

Μάθετε ποια **δικαιώματα διακριτικών μπορούν να καταχραστούν για την αναβάθμιση των δικαιωμάτων:**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

Ρίξτε μια ματιά σε [**όλα τα δυνατά δικαιώματα διακριτικών και μερικούς ορισμούς σε αυτήν την εξωτερική σελίδα**](https://github.com/gtworek/Priv2Admin).

## Αναφορές

Μάθετε περισσότερα για τα διακριτικά σε αυτά τα εκπαιδευτικά εγχειρίδια: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) και [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας στο hacking υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github
