# macOS Sandbox

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

## Basic Information

Το MacOS Sandbox (αρχικά ονομαζόταν Seatbelt) **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο sandbox στις **επιτρεπόμενες ενέργειες που καθορίζονται στο προφίλ Sandbox** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο σε αναμενόμενους πόρους**.

Οποιαδήποτε εφαρμογή με την **παροχή** **`com.apple.security.app-sandbox`** θα εκτελείται μέσα στο sandbox. **Οι δυαδικοί κωδικοί της Apple** εκτελούνται συνήθως μέσα σε ένα Sandbox και προκειμένου να δημοσιευτούν στο **App Store**, **αυτή η παροχή είναι υποχρεωτική**. Έτσι, οι περισσότερες εφαρμογές θα εκτελούνται μέσα στο sandbox.

Για να ελέγξει τι μπορεί ή δεν μπορεί να κάνει μια διαδικασία, το **Sandbox έχει hooks** σε όλες τις **syscalls** σε όλο τον πυρήνα. **Ανάλογα** με τις **παροχές** της εφαρμογής, το Sandbox θα **επιτρέπει** ορισμένες ενέργειες.

Ορισμένα σημαντικά στοιχεία του Sandbox είναι:

* Η **επέκταση πυρήνα** `/System/Library/Extensions/Sandbox.kext`
* Το **ιδιωτικό πλαίσιο** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* Ένας **daemon** που εκτελείται στο userland `/usr/libexec/sandboxd`
* Οι **κοντέινερ** `~/Library/Containers`

Μέσα στο φάκελο κοντέινερ μπορείτε να βρείτε **έναν φάκελο για κάθε εφαρμογή που εκτελείται sandboxed** με το όνομα του bundle id:
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
Μέσα σε κάθε φάκελο bundle id μπορείτε να βρείτε το **plist** και τον **φάκελο Δεδομένων** της Εφαρμογής:
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
Σημειώστε ότι ακόμη και αν οι symlinks είναι εκεί για να "διαφύγουν" από το Sandbox και να αποκτήσουν πρόσβαση σε άλλους φακέλους, η εφαρμογή πρέπει να **έχει άδειες** για να τους προσπελάσει. Αυτές οι άδειες βρίσκονται μέσα στο **`.plist`**.
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
Ό,τι δημιουργείται/τροποποιείται από μια εφαρμογή που είναι σε Sandbox θα αποκτήσει το **χαρακτηριστικό καραντίνας**. Αυτό θα αποτρέψει έναν χώρο sandbox ενεργοποιώντας τον Gatekeeper αν η εφαρμογή sandbox προσπαθήσει να εκτελέσει κάτι με **`open`**.
{% endhint %}

### Sandbox Profiles

Τα Sandbox profiles είναι αρχεία ρύθμισης που υποδεικνύουν τι θα είναι **επιτρεπτό/απαγορευμένο** σε αυτό το **Sandbox**. Χρησιμοποιεί τη **Γλώσσα Προφίλ Sandbox (SBPL)**, η οποία χρησιμοποιεί τη γλώσσα προγραμματισμού [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)).

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
Δείτε αυτήν την [**έρευνα**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **για να δείτε περισσότερες ενέργειες που θα μπορούσαν να επιτραπούν ή να απορριφθούν.**
{% endhint %}

Σημαντικές **υπηρεσίες συστήματος** εκτελούνται επίσης μέσα σε δικό τους προσαρμοσμένο **sandbox**, όπως η υπηρεσία `mdnsresponder`. Μπορείτε να δείτε αυτά τα προσαρμοσμένα **προφίλ sandbox** μέσα σε:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* Άλλα προφίλ sandbox μπορούν να ελεγχθούν στο [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Οι εφαρμογές του **App Store** χρησιμοποιούν το **προφίλ** **`/System/Library/Sandbox/Profiles/application.sb`**. Μπορείτε να ελέγξετε σε αυτό το προφίλ πώς οι εξουσιοδοτήσεις όπως **`com.apple.security.network.server`** επιτρέπουν σε μια διαδικασία να χρησιμοποιεί το δίκτυο.

Το SIP είναι ένα προφίλ Sandbox που ονομάζεται platform\_profile στο /System/Library/Sandbox/rootless.conf

### Παραδείγματα Προφίλ Sandbox

Για να ξεκινήσετε μια εφαρμογή με ένα **συγκεκριμένο προφίλ sandbox**, μπορείτε να χρησιμοποιήσετε:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="touch" %}
{% code title="touch.sb" %}
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
{% endcode %}

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
Σημειώστε ότι το **λογισμικό** που έχει συγγραφεί από την **Apple** που τρέχει σε **Windows** **δεν έχει επιπλέον μέτρα ασφαλείας**, όπως η απομόνωση εφαρμογών.
{% endhint %}

Παραδείγματα παρακάμψεων:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (μπορούν να γράφουν αρχεία εκτός της απομόνωσης των οποίων το όνομα ξεκινά με `~$`).

### Προφίλ Απομόνωσης MacOS

Το macOS αποθηκεύει τα προφίλ απομόνωσης συστήματος σε δύο τοποθεσίες: **/usr/share/sandbox/** και **/System/Library/Sandbox/Profiles**.

Και αν μια εφαρμογή τρίτου μέρους φέρει την _**com.apple.security.app-sandbox**_ εξουσία, το σύστημα εφαρμόζει το προφίλ **/System/Library/Sandbox/Profiles/application.sb** σε αυτή τη διαδικασία.

### **Προφίλ Απομόνωσης iOS**

Το προεπιλεγμένο προφίλ ονομάζεται **container** και δεν έχουμε την κειμενική αναπαράσταση SBPL. Στη μνήμη, αυτή η απομόνωση αναπαρίσταται ως δυαδικό δέντρο Επιτρέπει/Απαγορεύει για κάθε άδεια από την απομόνωση.

### Debug & Παράκαμψη Απομόνωσης

Στο macOS, σε αντίθεση με το iOS όπου οι διαδικασίες είναι απομονωμένες από την αρχή από τον πυρήνα, **οι διαδικασίες πρέπει να επιλέξουν να μπουν στην απομόνωση μόνες τους**. Αυτό σημαίνει ότι στο macOS, μια διαδικασία δεν περιορίζεται από την απομόνωση μέχρι να αποφασίσει ενεργά να εισέλθει σε αυτήν.

Οι διαδικασίες απομονώνονται αυτόματα από το userland όταν ξεκινούν αν έχουν την εξουσία: `com.apple.security.app-sandbox`. Για μια λεπτομερή εξήγηση αυτής της διαδικασίας, ελέγξτε:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Έλεγχος Προνομίων PID**

[**Σύμφωνα με αυτό**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), το **`sandbox_check`** (είναι ένα `__mac_syscall`), μπορεί να ελέγξει **αν μια ενέργεια επιτρέπεται ή όχι** από την απομόνωση σε ένα συγκεκριμένο PID.

Το [**εργαλείο sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) μπορεί να ελέγξει αν ένα PID μπορεί να εκτελέσει μια συγκεκριμένη ενέργεια:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### Custom SBPL in App Store apps

Μπορεί να είναι δυνατόν για τις εταιρείες να κάνουν τις εφαρμογές τους να τρέχουν **με προσαρμοσμένα προφίλ Sandbox** (αντί με το προεπιλεγμένο). Πρέπει να χρησιμοποιήσουν την εξουσιοδότηση **`com.apple.security.temporary-exception.sbpl`** που πρέπει να εγκριθεί από την Apple.

Είναι δυνατόν να ελεγχθεί ο ορισμός αυτής της εξουσιοδότησης στο **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Αυτό θα **εκτελέσει τη συμβολοσειρά μετά από αυτή την εξουσιοδότηση** ως προφίλ Sandbox.

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
