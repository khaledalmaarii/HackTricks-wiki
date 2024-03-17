# Επικίνδυνα Entitlements & Άδειες TCC στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του GitHub.

</details>

{% hint style="warning" %}
Σημειώστε ότι τα entitlements που ξεκινούν με **`com.apple`** δεν είναι διαθέσιμα σε τρίτους, μόνο η Apple μπορεί να τα χορηγήσει.
{% endhint %}

## Υψηλό

### `com.apple.rootless.install.heritable`

Το entitlement **`com.apple.rootless.install.heritable`** επιτρέπει την **παράκαμψη του SIP**. Ελέγξτε [αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

Το entitlement **`com.apple.rootless.install`** επιτρέπει την **παράκαμψη του SIP**. Ελέγξτε [αυτό για περισσότερες πληροφορίες](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (προηγουμένως ονομαζόμενο `task_for_pid-allow`)**

Αυτό το entitlement επιτρέπει την ανάκτηση της **task port για οποιηδήποτε** διεργασία, εκτός από τον πυρήνα. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.get-task-allow`

Αυτό το entitlement επιτρέπει σε άλλες διεργασίες με το entitlement **`com.apple.security.cs.debugger`** να ανακτήσουν την task port της διεργασίας που εκτελείται από το δυαδικό με αυτό το entitlement και να **ενσωματώσουν κώδικα σε αυτήν**. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](../mac-os-architecture/macos-ipc-inter-process-communication/).

### `com.apple.security.cs.debugger`

Οι εφαρμογές με το Entitlement Εργαλείου Αποσφαλμάτωσης μπορούν να καλέσουν το `task_for_pid()` για να ανακτήσουν μια έγκυρη task port για μη υπογεγραμμένες και τρίτες εφαρμογές με το entitlement `Get Task Allow` που έχει οριστεί σε `true`. Ωστόσο, ακόμη και με το entitlement εργαλείου αποσφαλμάτωσης, ένας αποσφαλματωτής **δεν μπορεί να ανακτήσει τις task ports** διεργασιών που **δεν έχουν το entitlement `Get Task Allow`**, και που είναι επομένως προστατευμένες από την Προστασία Ακεραιότητας Συστήματος. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_debugger).

### `com.apple.security.cs.disable-library-validation`

Αυτό το entitlement επιτρέπει τη **φόρτωση πλαισίων, προσθέτων ή βιβλιοθηκών χωρίς να είναι υπογεγραμμένα από την Apple ή υπογεγραμμένα με τον ίδιο αναγνωριστικό ομάδας (Team ID)** με το κύριο εκτελέσιμο, έτσι ένας επιτιθέμενος θα μπορούσε να καταχραστεί μια αυθαίρετη φόρτωση βιβλιοθήκης για να ενσωματώσει κώδικα. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Αυτό το entitlement είναι πολύ παρόμοιο με το **`com.apple.security.cs.disable-library-validation`** αλλά **αντί να απενεργοποιεί απευθείας** την επικύρωση βιβλιοθήκης, επιτρέπει στη διεργασία να **καλέσει ένα σύστημα κλήσης `csops` για να την απενεργοποιήσει**.\
Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Αυτό το entitlement επιτρέπει τη **χρήση μεταβλητών περιβάλλοντος DYLD** που θα μπορούσαν να χρησιμοποιηθούν για την ενσωμάτωση βιβλιοθηκών και κώδικα. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ή `com.apple.rootless.storage`.`TCC`

[**Σύμφωνα με αυτό το blog**](https://objective-see.org/blog/blog\_0x4C.html) **και** [**αυτό το blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), αυτά τα entitlements επιτρέπουν τη **τροποποίηση** της **βάσης δεδομένων TCC**.

### **`system.install.apple-software`** και **`system.install.apple-software.standar-user`**

Αυτά τα entitlements επιτρέπουν τη **εγκατάσταση λογισμικού χωρίς να ζητηθούν άδειες** από τον χρήστη, πράγμα που μπορεί να είναι χρήσιμο για μια **ανόδο προνομίων**.

### `com.apple.private.security.kext-management`

Entitlement που απαιτείται για να ζητήσει τον **πυρήνα να φορτώσει μια επέκταση πυρήνα**.

### **`com.apple.private.icloud-account-access`**

Το entitlement **`com.apple.private.icloud-account-access`** είναι δυνατό να επικοινωνήσει με την υπηρεσία XPC **`com.apple.iCloudHelper`** η οποία θα **παρέχει τα iCloud tokens**.

**Το iMovie** και **το Garageband** είχαν αυτό το entitlement.

Για περισσότερες **πληροφορίες** σχετικά με την εκμετάλλευση για την **ανάκτηση των icloud tokens** από αυτό το entitlement, ελέγξτε την ομιλία: [**#OBTS v5.0: "Τι συμβαίνει στο Mac σας, Μένει στο iCloud της Apple;!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Δεν ξέρω τι επιτρέπει αυτό

### `com.apple.private.apfs.revert-to-snapshot`

TODO: Στην [**αυτή την αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι μπορεί να χρησιμοποιηθεί για** ενημέρωση των περιεχομένων που προστατεύονται από το SSV μετά από επανεκκίνηση. Αν γνωρίζετε πώς να το κάνετε, στείλτε ένα PR παρακαλώ!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: Στην [**αυτή την αναφορά**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **αναφέρεται ότι μπορεί να χρησιμοποιηθεί για** ενημέρωση των περιεχομένων που προστατεύονται από το SSV μετά από επανεκκίνηση. Αν γνωρίζετε πώς να το κάνετε, στείλτε ένα PR παρακαλώ!

### `keychain-access-groups`

Αυτό το entitlement καταλογίζει τα **ομάδες keychain** στις οποίες έχει πρόσβαση η εφαρμογή:
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

Παρέχει δικαιώματα **Πλήρης Πρόσβαση Δίσκου**, ένα από τα υψηλότερα δικαιώματα TCC που μπορεί να έχει κάποιος.

### **`kTCCServiceAppleEvents`**

Επιτρέπει στην εφαρμογή να στέλνει συμβάντα σε άλλες εφαρμογές που χρησιμοποιούνται συχνά για **αυτοματοποίηση εργασιών**. Ελέγχοντας άλλες εφαρμογές, μπορεί να καταχραστεί τα δικαιώματα που έχουν χορηγηθεί σε αυτές τις εφαρμογές.

Όπως να τις κάνει να ζητήσουν από τον χρήστη τον κωδικό πρόσβασής του:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
{% endcode %}

Ή να τους κάνει να εκτελέσουν **αυθαίρετες ενέργειες**.

### **`kTCCServiceEndpointSecurityClient`**

Επιτρέπει, μεταξύ άλλων δικαιωμάτων, τη **εγγραφή στη βάση δεδομένων TCC των χρηστών**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Επιτρέπει τη **τροποποίηση** του χαρακτηριστικού **`NFSHomeDirectory`** ενός χρήστη που αλλάζει τη διαδρομή του φακέλου του αρχικού φακέλου και επομένως επιτρέπει τη **παράκαμψη του TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Επιτρέπει την τροποποίηση αρχείων μέσα στα δέματα εφαρμογών (μέσα στο app.app), το οποίο είναι **απαγορευμένο από προεπιλογή**.

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Είναι δυνατόν να ελέγξετε ποιος έχει πρόσβαση αυτή στις _Ρυθμίσεις Συστήματος_ > _Απορρήτου & Ασφάλειας_ > _Διαχείριση Εφαρμογών_.

### `kTCCServiceAccessibility`

Η διαδικασία θα μπορεί να **καταχραστεί τα χαρακτηριστικά προσβασιμότητας του macOS**, Το οποίο σημαίνει ότι για παράδειγμα θα μπορεί να πατήσει πλήκτρα. Έτσι θα μπορούσε να ζητήσει πρόσβαση για να ελέγχει μια εφαρμογή όπως ο Finder και να εγκρίνει το παράθυρο διαλόγου με αυτή την άδεια.

## Μέσο

### `com.apple.security.cs.allow-jit`

Αυτή η άδεια επιτρέπει τη **δημιουργία μνήμης που είναι εγγράψιμη και εκτελέσιμη** περνώντας τη σημαία `MAP_JIT` στη συνάρτηση συστήματος `mmap()`. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Αυτή η άδεια επιτρέπει τη **παράκαμψη ή την επιδιόρθωση κώδικα C**, χρησιμοποιώντας την παλαιά και απαρχαιωμένη συνάρτηση **`NSCreateObjectFileImageFromMemory`** (η οποία είναι θεμελιωδώς ανασφαλής), ή χρησιμοποιώντας το πλαίσιο **DVDPlayback**. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_allow-unsigned-executable-memory).

{% hint style="danger" %}
Η συμπερίληψη αυτής της άδειας εκθέτει την εφαρμογή σας σε κοινές ευπάθειες σε γλώσσες κώδικα με ανεπαρκή μνήμη. Εξετάστε προσεκτικά εάν η εφαρμογή σας χρειάζεται αυτήν την εξαίρεση.
{% endhint %}

### `com.apple.security.cs.disable-executable-page-protection`

Αυτή η άδεια επιτρέπει τη **τροποποίηση τμημάτων των ίδιων εκτελέσιμων αρχείων** στο δίσκο για εξαναγκαστική έξοδο. Ελέγξτε [**αυτό για περισσότερες πληροφορίες**](https://developer.apple.com/documentation/bundleresources/entitlements/com\_apple\_security\_cs\_disable-executable-page-protection).

{% hint style="danger" %}
Η Άδεια Απενεργοποίησης Προστασίας Εκτελέσιμης Μνήμης είναι μια ακραία άδεια που αφαιρεί μια θεμελιώδη προστασία ασφαλείας από την εφαρμογή σας, καθιστώντας δυνατή την επανεγγραφή του εκτελέσιμου κώδικα της εφαρμογής σας χωρίς ανίχνευση. Προτιμήστε πιο περιορισμένες άδειες αν είναι δυνατόν.
{% endhint %}

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Αυτή η άδεια επιτρέπει την προσάρτηση ενός αρχείου συστήματος nullfs (απαγορευμένο από προεπιλογή). Εργαλείο: [**mount\_nullfs**](https://github.com/JamaicanMoose/mount\_nullfs/tree/master).

### `kTCCServiceAll`

Σύμφωνα με αυτήν την ανάρτηση στο blog, αυτή η άδεια TCC συνήθως βρίσκεται στη μορφή:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Να επιτρέπεται στη διαδικασία να **ζητήσει όλες τις άδειες TCC**.

### **`kTCCServicePostEvent`**

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε τη **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**Την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
