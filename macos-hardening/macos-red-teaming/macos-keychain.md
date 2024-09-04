# macOS Keychain

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


## Main Keychains

* The **User Keychain** (`~/Library/Keychains/login.keycahin-db`), το οποίο χρησιμοποιείται για την αποθήκευση **διαπιστευτηρίων συγκεκριμένων χρηστών** όπως κωδικοί πρόσβασης εφαρμογών, κωδικοί πρόσβασης στο διαδίκτυο, πιστοποιητικά που δημιουργούνται από τον χρήστη, κωδικοί πρόσβασης δικτύου και δημόσια/ιδιωτικά κλειδιά που δημιουργούνται από τον χρήστη.
* The **System Keychain** (`/Library/Keychains/System.keychain`), το οποίο αποθηκεύει **διαπιστευτήρια σε επίπεδο συστήματος** όπως κωδικοί πρόσβασης WiFi, πιστοποιητικά ρίζας συστήματος, ιδιωτικά κλειδιά συστήματος και κωδικοί πρόσβασης εφαρμογών συστήματος.

### Password Keychain Access

Αυτά τα αρχεία, αν και δεν έχουν εγγενή προστασία και μπορούν να **κατεβούν**, είναι κρυπτογραφημένα και απαιτούν τον **καθαρό κωδικό πρόσβασης του χρήστη για να αποκρυπτογραφηθούν**. Ένα εργαλείο όπως το [**Chainbreaker**](https://github.com/n0fate/chainbreaker) θα μπορούσε να χρησιμοποιηθεί για την αποκρυπτογράφηση.

## Keychain Entries Protections

### ACLs

Κάθε καταχώρηση στο keychain διέπεται από **Λίστες Ελέγχου Πρόσβασης (ACLs)** που καθορίζουν ποιος μπορεί να εκτελεί διάφορες ενέργειες στην καταχώρηση του keychain, συμπεριλαμβανομένων:

* **ACLAuhtorizationExportClear**: Επιτρέπει στον κάτοχο να αποκτήσει το καθαρό κείμενο του μυστικού.
* **ACLAuhtorizationExportWrapped**: Επιτρέπει στον κάτοχο να αποκτήσει το καθαρό κείμενο κρυπτογραφημένο με έναν άλλο παρεχόμενο κωδικό πρόσβασης.
* **ACLAuhtorizationAny**: Επιτρέπει στον κάτοχο να εκτελεί οποιαδήποτε ενέργεια.

Οι ACLs συνοδεύονται επίσης από μια **λίστα αξιόπιστων εφαρμογών** που μπορούν να εκτελούν αυτές τις ενέργειες χωρίς προτροπή. Αυτό θα μπορούσε να είναι:

* **N`il`** (δεν απαιτείται εξουσιοδότηση, **όλοι είναι αξιόπιστοι**)
* Μια **κενή** λίστα (**κανείς** δεν είναι αξιόπιστος)
* **Λίστα** συγκεκριμένων **εφαρμογών**.

Επίσης, η καταχώρηση μπορεί να περιέχει το κλειδί **`ACLAuthorizationPartitionID`,** το οποίο χρησιμοποιείται για να προσδιορίσει το **teamid, apple,** και **cdhash.**

* Εάν το **teamid** καθορίζεται, τότε για να **προσεγγιστεί η καταχώρηση** αξίας **χωρίς** προτροπή, η χρησιμοποιούμενη εφαρμογή πρέπει να έχει το **ίδιο teamid**.
* Εάν το **apple** καθορίζεται, τότε η εφαρμογή πρέπει να είναι **υπογεγραμμένη** από την **Apple**.
* Εάν το **cdhash** υποδεικνύεται, τότε η **εφαρμογή** πρέπει να έχει το συγκεκριμένο **cdhash**.

### Creating a Keychain Entry

Όταν μια **νέα** **καταχώρηση** δημιουργείται χρησιμοποιώντας το **`Keychain Access.app`**, ισχύουν οι εξής κανόνες:

* Όλες οι εφαρμογές μπορούν να κρυπτογραφούν.
* **Καμία εφαρμογή** δεν μπορεί να εξάγει/αποκρυπτογραφεί (χωρίς προτροπή του χρήστη).
* Όλες οι εφαρμογές μπορούν να δουν τον έλεγχο ακεραιότητας.
* Καμία εφαρμογή δεν μπορεί να αλλάξει τις ACLs.
* Το **partitionID** ορίζεται σε **`apple`**.

Όταν μια **εφαρμογή δημιουργεί μια καταχώρηση στο keychain**, οι κανόνες είναι ελαφρώς διαφορετικοί:

* Όλες οι εφαρμογές μπορούν να κρυπτογραφούν.
* Μόνο η **δημιουργούσα εφαρμογή** (ή οποιαδήποτε άλλη εφαρμογή που έχει προστεθεί ρητά) μπορεί να εξάγει/αποκρυπτογραφεί (χωρίς προτροπή του χρήστη).
* Όλες οι εφαρμογές μπορούν να δουν τον έλεγχο ακεραιότητας.
* Καμία εφαρμογή δεν μπορεί να αλλάξει τις ACLs.
* Το **partitionID** ορίζεται σε **`teamid:[teamID here]`**.

## Accessing the Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

{% hint style="success" %}
Η **καταμέτρηση και εξαγωγή** μυστικών από το **keychain** που **δεν θα δημιουργήσει προτροπή** μπορεί να γίνει με το εργαλείο [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Λίστα και λήψη **πληροφοριών** για κάθε καταχώρηση του keychain:

* Η API **`SecItemCopyMatching`** δίνει πληροφορίες για κάθε καταχώρηση και υπάρχουν μερικά χαρακτηριστικά που μπορείτε να ορίσετε κατά τη χρήση της:
* **`kSecReturnData`**: Αν είναι αληθές, θα προσπαθήσει να αποκρυπτογραφήσει τα δεδομένα (ορίστε σε ψευδές για να αποφύγετε πιθανές αναδυόμενες ειδοποιήσεις)
* **`kSecReturnRef`**: Λάβετε επίσης αναφορά στο στοιχείο του keychain (ορίστε σε αληθές σε περίπτωση που αργότερα δείτε ότι μπορείτε να αποκρυπτογραφήσετε χωρίς αναδυόμενη ειδοποίηση)
* **`kSecReturnAttributes`**: Λάβετε μεταδεδομένα σχετικά με τις καταχωρήσεις
* **`kSecMatchLimit`**: Πόσα αποτελέσματα να επιστραφούν
* **`kSecClass`**: Τι είδους καταχώρηση keychain

Λάβετε **ACLs** κάθε καταχώρησης:

* Με την API **`SecAccessCopyACLList`** μπορείτε να λάβετε το **ACL για το στοιχείο του keychain**, και θα επιστρέψει μια λίστα ACLs (όπως `ACLAuhtorizationExportClear` και οι άλλες που αναφέρθηκαν προηγουμένως) όπου κάθε λίστα έχει:
* Περιγραφή
* **Λίστα Εμπιστευμένων Εφαρμογών**. Αυτό θα μπορούσε να είναι:
* Μια εφαρμογή: /Applications/Slack.app
* Ένα δυαδικό: /usr/libexec/airportd
* Μια ομάδα: group://AirPort

Εξαγωγή των δεδομένων:

* Η API **`SecKeychainItemCopyContent`** αποκτά το απλό κείμενο
* Η API **`SecItemExport`** εξάγει τα κλειδιά και τα πιστοποιητικά αλλά μπορεί να χρειαστεί να ορίσετε κωδικούς πρόσβασης για να εξάγετε το περιεχόμενο κρυπτογραφημένο

Και αυτές είναι οι **απαιτήσεις** για να μπορείτε να **εξάγετε ένα μυστικό χωρίς προτροπή**:

* Αν **1+ εμπιστευμένες** εφαρμογές αναφέρονται:
* Χρειάζεστε τις κατάλληλες **εξουσιοδοτήσεις** (**`Nil`**, ή να είστε **μέρος** της επιτρεπόμενης λίστας εφαρμογών στην εξουσιοδότηση για πρόσβαση στις μυστικές πληροφορίες)
* Χρειάζεστε υπογραφή κώδικα που να ταιριάζει με **PartitionID**
* Χρειάζεστε υπογραφή κώδικα που να ταιριάζει με αυτήν μιας **εμπιστευμένης εφαρμογής** (ή να είστε μέλος της σωστής ομάδας πρόσβασης Keychain)
* Αν **όλες οι εφαρμογές είναι εμπιστευτές**:
* Χρειάζεστε τις κατάλληλες **εξουσιοδοτήσεις**
* Χρειάζεστε υπογραφή κώδικα που να ταιριάζει με **PartitionID**
* Αν **δεν υπάρχει PartitionID**, τότε αυτό δεν είναι απαραίτητο

{% hint style="danger" %}
Επομένως, αν υπάρχει **1 εφαρμογή αναφερόμενη**, πρέπει να **εισάγετε κώδικα σε αυτήν την εφαρμογή**.

Αν **apple** αναφέρεται στο **partitionID**, μπορείτε να έχετε πρόσβαση σε αυτό με **`osascript`** οπότε οτιδήποτε εμπιστεύεται όλες τις εφαρμογές με apple στο partitionID. **`Python`** θα μπορούσε επίσης να χρησιμοποιηθεί γι' αυτό.
{% endhint %}

### Δύο επιπλέον χαρακτηριστικά

* **Αόρατο**: Είναι μια λογική σημαία για να **κρύψει** την καταχώρηση από την εφαρμογή **UI** Keychain
* **Γενικό**: Είναι για την αποθήκευση **μεταδεδομένων** (οπότε ΔΕΝ είναι ΚΡΥΠΤΟΓΡΑΦΗΜΕΝΟ)
* Η Microsoft αποθήκευε σε απλό κείμενο όλους τους ανανεωτικούς κωδικούς πρόσβασης για πρόσβαση σε ευαίσθητους τερματικούς σταθμούς.

## Αναφορές

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)


{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
