# Επικίνδυνες Εξουσιοδοτήσεις και Άδειες TCC στο macOS

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

{% hint style="warning" %}
Σημειώστε ότι οι εξουσιοδοτήσεις που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμες σε τρίτους, μόνο η Apple μπορεί να τις χορηγήσει.
{% endhint %}

## Υψηλό

### `com.apple.rootless.install.heritable`

Η εξουσιοδότηση **`com.apple.rootless.install.heritable`** επιτρέπει την **παράκαμψη του SIP**. Ελέγξτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Η εξουσιοδότηση **`com.apple.rootless.install`** επιτρέπει την **παράκαμψη του SIP**. Ελέγξτε [εδώ για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (προηγουμένως ονομαζόταν `task_for_pid-allow`)**

Αυτή η εξουσιοδότηση επιτρέπει την απόκτηση της **task port για οποιαδήποτε** διεργασία, εκτός από τον πυρήνα. Ελέγξτε [**εδώ για περισσότερες πληροφορίες**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Αυτή η εξουσιοδότηση επιτρέπει σε άλλες διεργασίες με την εξουσιοδότηση **`com.apple.security.cs.debugger`** να αποκτήσουν την task port της διεργασίας που εκτελείται από το δυαδικό αρχείο με αυτήν την εξουσιοδότηση και να **εισάγουν κώδικα σε αυτήν**. Ελέγξτε [**εδώ για περισσότερες πληροφορίες**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Οι εφαρμογές με την εξουσιοδότηση Debugging Tool μπορούν να καλέσουν την `task_for_pid()` για να ανακτήσουν μια έγκυρη task port για μη υπογεγραμμένες και τρίτες εφαρμογές με την εξουσιοδότηση `Get Task Allow` που έχει οριστεί σε `true`. Ωστόσο, ακόμα και με την εξουσιοδότηση του εργαλείου αποσφαλμάτωσης, ένας αποσφαλματωτής **δεν μπορεί να αποκτήσει τις task ports** των διεργασιών που **δεν έχουν την εξουσιοδότηση `Get Task Allow`**, και που προστατεύονται επομένως από το System Integrity Protection. Ελέγξτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Αυτή η εξουσιοδότηση επιτρέπει την **φόρτωση πλαισίων, προσθέτων ή βιβλιοθηκών χωρίς να έχουν υπογραφεί από την Apple ή να έχουν υπογραφεί με το ίδιο Team ID** όπως το κύριο εκτελέσιμο, οπότε ένας επιτιθέμενος μπορεί να καταχραστεί μια αυθαίρετη φόρτωση βιβλιοθήκης για να εισάγει κώδικα. Ελέγξτε [**εδώ για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Αυτή η εξουσιοδότηση είναι πολύ παρόμοια με την **`com.apple.security.cs.disable-library-validation`**, αλλά αντί να απενεργοποιεί απευθείας τον έλεγχο της βιβλιοθήκης, επιτρέπει στη διεργασία να καλέσει ένα σύστημα κλήσης `csops` για να τον απενεργοπ
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Παρέχει δικαιώματα **Πλήρης Πρόσβασης στον Δίσκο**, ένα από τα υψηλότερα δικαιώματα TCC που μπορεί να έχει κάποιος.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει γεγονότα σε άλλες εφαρμογές που συνήθως χρησιμοποιούνται για την **αυτοματοποίηση εργασιών**. Ελέγχοντας άλλες εφαρμογές, μπορεί να καταχραστεί τα δικαιώματα που έχουν χορηγηθεί σε αυτές τις εφαρμογές.

Όπως για παράδειγμα να τις καθησυχάσει να ζητήσουν από τον χρήστη τον κωδικό του:

{% code overflow="wrap" %}
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ή να τους κάνει να εκτελούν **οποιεσδήποτε ενέργειες**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων δικαιωμάτων, την **εγγραφή στη βάση δεδομένων TCC των χρηστών**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει την **αλλαγή** του χαρακτηριστικού **`NFSHomeDirectory`** ενός χρήστη που αλλάζει τη διαδρομή του φακέλου του αρχικού φακέλου και επομένως επιτρέπει την **παράκαμψη του TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων μέσα στο πακέτο των εφαρμογών (μέσα στο app.app), το οποίο απαγορεύεται από προεπιλογή.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Είναι δυνατό να ελεγχθεί ποιος έχει πρόσβαση σε αυτήν την εξουσιοδότηση στις _Ρυθμίσεις συστήματος_ > _Απόρρητο & Ασφάλεια_ > _Διαχείριση εφαρμογών_.

### `kTCCServiceAccessibility`

Η διαδικασία θα μπορεί να **καταχραστεί τις δυνατότητες προσβασιμότητας του macOS**, πράγμα που σημαίνει ότι για παράδειγμα θα μπορεί να πατήσει πλήκτρα. Έτσι, θα μπορούσε να ζητήσει πρόσβαση για να ελέγξει μια εφαρμογή όπως ο Finder και να εγκρίνει το παράθυρο διαλόγου με αυτήν την άδεια.

## Μεσαίο

### `com.apple.security.cs.allow-jit`

Αυτή η εξουσιοδότηση επιτρέπει τη **δημιουργία μνήμης που είναι εγγράψιμη και εκτελέσιμη** περνώντας τη σημαία `MAP_JIT` στη συνάρτηση συστήματος `mmap()`. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτή η εξουσιοδότηση επιτρέπει τη **παράκαμψη ή την τροποποίηση του C κώδικα**, τη χρήση της παλαιάς και αποσυρμένης συνάρτησης **`NSCreateObjectFileImageFromMemory`** (η οποία είναι θεμελιωδώς ανασφαλής), ή τη χρήση του πλαισίου **DVDPlayback**. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Η συμπερίληψη αυτής της εξουσιοδότησης εκθέτει την εφαρμογή σας σε κοινές ευπάθειες σε γλώσσες κώδικα με μνήμη που δεν είναι ασφαλείς. Σκεφτείτε προσεκτικά εάν η εφαρμογή σας χρειάζεται αυτήν την εξαίρεση.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Αυτή η εξουσιοδότηση επιτρέπει τη **τροποποίηση τμημάτων των ίδιων εκτελέσιμων αρχείων** στον δίσκο για να εξέλθει με βία. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Η εξουσιοδότηση Απενεργοποίησης Προστασίας Εκτελέσιμης Μνήμης είναι μια ακραία εξουσιοδότηση που αφαιρεί μια θεμελιώδη προστασία ασφαλείας από την εφαρμογή σας, καθιστώντας δυνατή την επανεγγραφή του εκτελέσιμου κώδικα της εφαρμογής σας από έναν επιτιθέμενο χωρίς ανίχνευση. Προτιμήστε πιο περιορισμένες εξουσιοδοτήσεις, αν είναι δυνατόν.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτή η εξουσιοδότηση επιτρέπει την προσάρτηση ενός αρχείου συστήματος nullfs (απαγορευμένο από προεπιλογή). Εργαλείο: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτήν την ανάρτηση στο blog, αυτή η άδεια TCC συνήθως βρίσκεται στη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Επιτρέψτε στη διαδικασία να ζητήσει όλες τις άδειες TCC.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
