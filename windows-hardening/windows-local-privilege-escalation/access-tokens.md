# Διακριτικά Πρόσβασης

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλου λογισμικού**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

---

## Διακριτικά Πρόσβασης

Κάθε **χρήστης που έχει συνδεθεί** στο σύστημα **διαθέτει ένα διακριτικό πρόσβασης με πληροφορίες ασφαλείας** για αυτήν τη συνεδρία σύνδεσης. Το σύστημα δημιουργεί ένα διακριτικό πρόσβασης όταν ο χρήστης συνδέεται. **Κάθε διεργασία που εκτελείται** εκ μέρους του χρήστη **έχει ένα αντίγραφο του διακριτικού πρόσβασης**. Το διακριτικό αναγνωρίζει τον χρήστη, τις ομάδες του χρήστη και τα προνόμια του χρήστη. Ένα διακριτικό περιλαμβάνει επίσης ένα SID σύνδεσης (Αναγνωριστικό Ασφάλειας) που αναγνωρίζει την τρέχουσα συνεδρία σύνδεσης.

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

![](<../../.gitbook/assets/image (769).png>)

### Τοπικός διαχειριστής

Όταν ένας τοπικός διαχειριστής συνδεθεί, **δημιουργούνται δύο διαθέσιμα διακριτικά**: Ένα με δικαιώματα διαχειριστή και ένα με κανονικά δικαιώματα. **Από προεπιλογή**, όταν αυτός ο χρήστης εκτελεί μια διαδικασία χρησιμοποιείται το διακριτικό με **κανονικά** (μη διαχειριστή) **δικαιώματα**. Όταν αυτός ο χρήστης προσπαθεί να **εκτελέσει** οτιδήποτε **ως διαχειριστής** ("Εκτέλεση ως Διαχειριστής" για παράδειγμα) το **UAC** θα χρησιμοποιηθεί για να ζητήσει άδεια.\
Αν θέλετε να [**μάθετε περισσότερα για το UAC διαβάστε αυτήν τη σελίδα**](../authentication-credentials-uac-and-efs/#uac)**.**

### Παρασύρση χρήστη διαπιστεύσεων

Αν έχετε **έγκυρες διαπιστεύσεις οποιουδήποτε άλλου χρήστη**, μπορείτε να **δημιουργήσετε** μια **νέα συνεδρία σύνδεσης** με αυτές τις διαπιστεύσεις:
```
runas /user:domain\username cmd.exe
```
Το **access token** έχει επίσης μια **αναφορά** των συνεδριών σύνδεσης μέσα στο **LSASS**, αυτό είναι χρήσιμο αν η διαδικασία χρειάζεται πρόσβαση σε κάποια αντικείμενα του δικτύου.\
Μπορείτε να εκκινήσετε μια διαδικασία που **χρησιμοποιεί διαφορετικές διαπιστεύσεις για την πρόσβαση σε υπηρεσίες δικτύου** χρησιμοποιώντας:
```
runas /user:domain\username /netonly cmd.exe
```
### Τύποι διακριτικών

Υπάρχουν δύο τύποι διακριτικών διαθέσιμα:

- **Κύριο Διακριτικό**: Λειτουργεί ως αναπαράσταση των διαπιστευτηρίων ασφαλείας ενός διεργασίας. Η δημιουργία και συσχέτιση των κύριων διακριτικών με διεργασίες είναι ενέργειες που απαιτούν αυξημένα προνόμια, υπογραμμίζοντας την αρχή του διαχωρισμού προνομίων. Συνήθως, ένα υπηρεσία πιστοποίησης είναι υπεύθυνο για τη δημιουργία διακριτικών, ενώ μια υπηρεσία σύνδεσης χειρίζεται τη συσχέτισή τους με το κέλυφος λειτουργικού συστήματος του χρήστη. Αξίζει να σημειωθεί ότι οι διεργασίες κληρονομούν το κύριο διακριτικό της γονικής τους διεργασίας κατά τη δημιουργία τους.
- **Διακριτικό Προσωποποίησης**: Δίνει σε μια εφαρμογή εξυπηρετητή τη δυνατότητα να υιοθετήσει προσωρινά την ταυτότητα του πελάτη για πρόσβαση σε ασφαλή αντικείμενα. Αυτός ο μηχανισμός είναι στρωμένος σε τέσσερα επίπεδα λειτουργίας:
  - **Ανώνυμο**: Χορηγεί πρόσβαση στον εξυπηρητή παρόμοια με αυτήν ενός μη αναγνωρισμένου χρήστη.
  - **Ταυτοποίηση**: Επιτρέπει στον εξυπηρητή να επαληθεύσει την ταυτότητα του πελάτη χωρίς να τη χρησιμοποιεί για πρόσβαση σε αντικείμενα.
  - **Προσωποποίηση**: Επιτρέπει στον εξυπηρητή να λειτουργεί υπό την ταυτότητα του πελάτη.
  - **Αναθέσεις**: Παρόμοιο με την Προσωποποίηση, αλλά περιλαμβάνει τη δυνατότητα επέκτασης αυτής της υπόθεσης ταυτότητας σε απομακρυσμένα συστήματα με τα οποία αλληλεπιδρά ο εξυπηρητής, εξασφαλίζοντας τη διατήρηση των διαπιστευτηρίων.

#### Προσωποποίηση Διακριτικών

Χρησιμοποιώντας το **module incognito** του metasploit, αν έχετε αρκετά προνόμια, μπορείτε εύκολα να **καταλογογραφήσετε** και **προσωποποιήσετε** άλλα **διακριτικά**. Αυτό μπορεί να είναι χρήσιμο για να εκτελέσετε **ενέργειες ως να ήσασταν ο άλλος χρήστης**. Μπορείτε επίσης να **αναβαθμίσετε προνόμια** με αυτήν την τεχνική.

### Προνόμια Διακριτικών

Μάθετε ποια **προνόμια διακριτικών μπορούν να καταχραστούν για την ανάδειξη προνομίων:**

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

Ρίξτε μια ματιά σε [**όλα τα πιθανά προνόμια διακριτικών και μερικούς ορισμούς σε αυτήν την εξωτερική σελίδα**](https://github.com/gtworek/Priv2Admin).

## Αναφορές

Μάθετε περισσότερα για τα διακριτικά σε αυτά τα εγχειρίδια: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) και [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
