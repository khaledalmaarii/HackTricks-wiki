# Αμμοδοχείο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Το Ammosdoxeío MacOS (αρχικά ονομαζόταν Seatbelt) **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο ammosdoxeío στις **επιτρεπόμενες ενέργειες που καθορίζονται στο προφίλ του ammosdoxeίου** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο σε αναμενόμενους πόρους**.

Οποιαδήποτε εφαρμογή με το **δικαίωμα** **`com.apple.security.app-sandbox`** θα εκτελείται μέσα στο ammosdoxeío. Τα **δυαδικά αρχεία της Apple** συνήθως εκτελούνται μέσα σε ένα ammosdoxeío και για να δημοσιευτούν στο **App Store**, **αυτό το δικαίωμα είναι υποχρεωτικό**. Έτσι, οι περισσότερες εφαρμογές θα εκτελούνται μέσα στο ammosdoxeío.

Για να ελέγξετε τι μπορεί ή δεν μπορεί να κάνει ένας διεργασία, το **ammosdoxeío έχει hooks** σε όλες τις **κλήσεις συστήματος** στον πυρήνα. **Ανάλογα** με τα **δικαιώματα** της εφαρμογής, το ammosdoxeío θα **επιτρέπει** ορισμένες ενέργειες.

Ορισμένα σημαντικά στοιχεία του ammosdoxeίου είναι:

* Η **επέκταση πυρήνα** `/System/Library/Extensions/Sandbox.kext`
* Το **ιδιωτικό πλαίσιο** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Ένα **daemon** που εκτελείται στον χώρο χρήστη `/usr/libexec/sandboxd`
* Οι **κάδοι** `~/Library/Containers`

Μέσα στον φάκελο των κάδων μπορείτε να βρείτε **έναν φάκελο για κάθε εφαρμογή που εκτελείται μέσα στο ammosdoxeío** με το όνομα του αναγνωριστικού δέσμης:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Μέσα σε κάθε φάκελο με το αναγνωριστικό της εφαρμογής (bundle id), μπορείτε να βρείτε το αρχείο **plist** και τον φάκελο **Data** της εφαρμογής:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
Να σημειωθεί ότι ακόμα κι αν τα συμβολικά συνδέσμοι υπάρχουν για να "δραπετεύσουν" από το Sandbox και να έχουν πρόσβαση σε άλλους φακέλους, η εφαρμογή πρέπει ακόμα να **έχει δικαιώματα** για να τους προσεγγίσει. Αυτά τα δικαιώματα βρίσκονται μέσα στο **`.plist`**.
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Όλα τα δημιουργημένα/τροποποιημένα από μια εφαρμογή που εκτελείται σε άμμο θα λάβουν το **χαρακτηριστικό καραντίνας**. Αυτό θα εμποδίσει τον χώρο άμμου να ενεργοποιήσει τον Gatekeeper αν η εφαρμογή άμμου προσπαθήσει να εκτελέσει κάτι με την εντολή **`open`**.
{% endhint %}

### Προφίλ άμμου

Τα προφίλ άμμου είναι αρχεία ρυθμίσεων που υποδεικνύουν τι επιτρέπεται/απαγορεύεται σε αυτήν την άμμο. Χρησιμοποιεί την γλώσσα προφίλ άμμου (SBPL), η οποία χρησιμοποιεί την [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) γλώσσα προγραμματισμού.

Εδώ μπορείτε να βρείτε ένα παράδειγμα:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
Ελέγξτε αυτήν την [**έρευνα**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **για να ελέγξετε περισσότερες ενέργειες που μπορεί να επιτρέπονται ή να απαγορεύονται**.
{% endhint %}

Σημαντικές **υπηρεσίες συστήματος** τρέχουν επίσης μέσα στο δικό τους προσαρμοσμένο **sandbox** όπως η υπηρεσία `mdnsresponder`. Μπορείτε να δείτε αυτά τα προσαρμοσμένα **προφίλ sandbox** μέσα στα:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Άλλα προφίλ sandbox μπορούν να ελεγχθούν στο [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Οι εφαρμογές **App Store** χρησιμοποιούν το **προφίλ** **`/System/Library/Sandbox/Profiles/application.sb`**. Μπορείτε να ελέγξετε σε αυτό το προφίλ πώς οι εξουσιοδοτήσεις όπως **`com.apple.security.network.server`** επιτρέπουν σε ένα διεργασία να χρησιμοποιεί το δίκτυο.

Το SIP είναι ένα προφίλ Sandbox που ονομάζεται platform\_profile στο /System/Library/Sandbox/rootless.conf

### Παραδείγματα προφίλ Sandbox

Για να ξεκινήσετε μια εφαρμογή με ένα **συγκεκριμένο προφίλ sandbox** μπορείτε να χρησιμοποιήσετε:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```plaintext
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-metadata)
(allow file-read-data (literal "/path/to/file"))
(allow file-write-data (literal "/path/to/file"))
```

Το αρχείο `touch.sb` περιέχει τον κώδικα για το sandbox του macOS που επιτρέπει στην εφαρμογή να διαβάζει και να γράφει μεταδεδομένα αρχείων, καθώς και να διαβάζει και να γράφει δεδομένα σε ένα συγκεκριμένο αρχείο στη διαδρομή "/path/to/file".
```
{% endcode %}
{% endtab %}

{% tab title="sandbox-exec" %}
{% code title="sandbox-exec.sb" %}
```plaintext
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-metadata)
(allow file-read-data (literal "/path/to/file"))
(allow file-write-data (literal "/path/to/file"))
```

Το αρχείο `sandbox-exec.sb` περιέχει τον κώδικα για το sandbox του macOS που επιτρέπει στην εφαρμογή να διαβάζει και να γράφει μεταδεδομένα αρχείων, καθώς και να διαβάζει και να γράφει δεδομένα σε ένα συγκεκριμένο αρχείο στη διαδρομή "/path/to/file".
```
{% endcode %}
{% endtab %}
{% endtabs %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
{% code title="touch2.sb" %}

Ο ακόλουθος κώδικας είναι ένα παράδειγμα ενός αρχείου sandbox για το macOS. Το αρχείο αυτό ονομάζεται touch2.sb και χρησιμοποιείται για να περιορίσει τις δυνατότητες ενός προγράμματος που εκτελείται στο sandbox του macOS.

```plaintext
(version 1)
(deny default)

(allow file-write*
    (literal "/private/var/tmp/")
    (regex #"^/private/var/tmp/[^/]+\.txt$"))

(allow file-read*
    (literal "/private/var/tmp/")
    (regex #"^/private/var/tmp/[^/]+\.txt$"))

(allow file-read-metadata
    (literal "/private/var/tmp/")
    (regex #"^/private/var/tmp/[^/]+\.txt$"))

(allow file-write-data
    (literal "/private/var/tmp/")
    (regex #"^/private/var/tmp/[^/]+\.txt$"))

(allow file-write-metadata
    (literal "/private/var/tmp/")
    (regex #"^/private/var/tmp/[^/]+\.txt$"))

(allow mach-lookup
    (global-name "com.apple.security.keychain"))

(allow sysctl-read)

(allow signal)

(allow process-exec
    (literal "/bin/echo")
    (literal "/usr/bin/echo"))

(allow process-info-pidinfo)

(allow ipc-posix-shm)
```

Αυτός ο κώδικας ορίζει τις επιτρεπόμενες ενέργειες για το πρόγραμμα που εκτελείται στο sandbox. Επιτρέπει την εγγραφή και ανάγνωση αρχείων στον φάκελο "/private/var/tmp/" με την κατάληξη ".txt". Επιτρέπει επίσης την πρόσβαση στα μεταδεδομένα των αρχείων και την εκτέλεση των προγραμμάτων "/bin/echo" και "/usr/bin/echo". Επιπλέον, επιτρέπει την πρόσβαση στο keychain του macOS και την ανάγνωση των πληροφοριών των διεργασιών. Τέλος, επιτρέπει τη χρήση των IPC POSIX shared memory.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
{% code title="touch3.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Σημειώστε ότι το **λογισμικό που έχει αναπτύξει η Apple** και τρέχει σε **Windows** **δεν έχει επιπλέον μέτρα ασφαλείας**, όπως η εφαρμογή sandboxing.
{% endhint %}

Παραδείγματα παράκαμψης:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (μπορούν να γράψουν αρχεία έξω από το sandbox με όνομα που ξεκινά με `~$`).

### Προφίλ Sandbox του MacOS

Το macOS αποθηκεύει τα προφίλ του συστήματος sandbox σε δύο τοποθεσίες: **/usr/share/sandbox/** και **/System/Library/Sandbox/Profiles**.

Και αν μια εφαρμογή τρίτου μέρους έχει το δικαίωμα _**com.apple.security.app-sandbox**_, το σύστημα εφαρμόζει το προφίλ **/System/Library/Sandbox/Profiles/application.sb** σε αυτήν τη διεργασία.

### **Προφίλ Sandbox του iOS**

Το προεπιλεγμένο προφίλ ονομάζεται **container** και δεν έχουμε την αναπαράσταση SBPL σε κείμενο. Στη μνήμη, αυτό το sandbox αναπαρίσταται ως δυαδικό δέντρο Allow/Deny για κάθε άδεια από το sandbox.

### Αποσφαλμάτωση και Παράκαμψη Sandbox

Στο macOS, αντίθετα από το iOS όπου οι διεργασίες είναι sandboxed από την αρχή από τον πυρήνα, **οι διεργασίες πρέπει να επιλέξουν ενεργά να εισέλθουν στο sandbox**. Αυτό σημαίνει ότι στο macOS, μια διεργασία δεν περιορίζεται από το sandbox μέχρι να αποφασίσει ενεργά να εισέλθει σε αυτό.

Οι διεργασίες αυτόματα εισέρχονται στο Sandbox από τον χρήστη όταν ξεκινούν αν έχουν το δικαίωμα: `com.apple.security.app-sandbox`. Για μια λεπτομερή εξήγηση αυτής της διαδικασίας, ελέγξτε:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Έλεγχος Προνομίων PID**

[**Σύμφωνα με αυτό**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), το **`sandbox_check`** (είναι ένα `__mac_syscall`), μπορεί να ελέγξει **αν μια λειτουργία επιτρέπεται ή όχι** από το sandbox σε ένα συγκεκριμένο PID.

Το [**εργαλείο sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) μπορεί να ελέγξει αν ένα PID μπορεί να εκτελέσει μια συγκεκριμένη ενέργεια:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Προσαρμοσμένα SBPL σε εφαρμογές App Store

Είναι δυνατό για τις εταιρείες να κάνουν τις εφαρμογές τους να τρέχουν **με προσαρμοσμένα προφίλ Sandbox** (αντί για το προεπιλεγμένο). Πρέπει να χρησιμοποιήσουν το entitlement **`com.apple.security.temporary-exception.sbpl`** το οποίο πρέπει να εξουσιοδοτηθεί από την Apple.

Είναι δυνατό να ελεγχθεί ο ορισμός αυτού του entitlement στο **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Αυτό θα **αξιολογήσει το συμβολοσειρά μετά από αυτήν την εξουσιοδότηση** ως ένα προφίλ Sandbox.

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΛΑΝΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
