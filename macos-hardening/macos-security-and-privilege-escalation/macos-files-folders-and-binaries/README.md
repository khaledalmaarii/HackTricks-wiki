# Αρχεία, Φάκελοι, Εκτελέσιμα & Μνήμη του macOS

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Δομή ιεραρχίας αρχείων

* **/Applications**: Οι εγκατεστημένες εφαρμογές πρέπει να βρίσκονται εδώ. Όλοι οι χρήστες θα μπορούν να τις προσπελάσουν.
* **/bin**: Εκτελέσιμα αρχεία γραμμής εντολών
* **/cores**: Εάν υπάρχει, χρησιμοποιείται για την αποθήκευση αποτυπωμάτων πυρήνα
* **/dev**: Όλα θεωρούνται ως αρχεία, οπότε μπορείτε να δείτε συσκευές υλικού που αποθηκεύονται εδώ.
* **/etc**: Αρχεία ρυθμίσεων
* **/Library**: Μπορείτε να βρείτε πολλούς υποφακέλους και αρχεία που σχετίζονται με προτιμήσεις, προσωρινά αρχεία και αρχεία καταγραφής εδώ. Υπάρχει ένας φάκελος Library στη ρίζα και σε κάθε φάκελο χρήστη.
* **/private**: Μη τεκμηριωμένος, αλλά πολλοί από τους αναφερόμενους φακέλους είναι συμβολικοί σύνδεσμοι στον ιδιωτικό φάκελο.
* **/sbin**: Απαραίτητα δυαδικά αρχεία συστήματος (σχετίζονται με τη διαχείριση)
* **/System**: Αρχείο για την εκτέλεση του OS X. Εδώ θα βρείτε κυρίως μόνο αρχεία της Apple (όχι από τρίτους).
* **/tmp**: Τα αρχεία διαγράφονται μετά από 3 ημέρες (είναι μια μαλακή σύνδεση στο /private/tmp)
* **/Users**: Ο φάκελος αρχικού καταλόγου για τους χρήστες.
* **/usr**: Ρυθμίσεις και δυαδικά αρχεία συστήματος
* **/var**: Αρχεία καταγραφής
* **/Volumes**: Οι προσαρτημένοι δίσκοι θα εμφανιστούν εδώ.
* **/.vol**: Εκτελώντας την εντολή `stat a.txt` θα λάβετε κάτι σαν `16777223 7545753 -rw-r--r-- 1 username wheel ...` όπου το πρώτο νούμερο είναι το αναγνωριστικό του όγκου όπου βρίσκεται το αρχείο και το δεύτερο είναι το αναγνωριστικό inode. Μπορείτε να έχετε πρόσβαση στο περιεχόμενο αυτού του αρχείου μέσω του /.vol/ με αυτές τις πληροφορίες εκτελώντας την εντολή `cat /.vol/16777223/7545753`

### Φάκελοι Εφαρμογών

* Οι **εφαρμογές του συστήματος** βρίσκονται στο `/System/Applications`
* Οι **εγκατεστημένες** εφαρμογές συνήθως εγκαθίστανται στο `/Applications` ή στο `~/Applications`
* Τα **δεδομένα των εφαρμογών** μπορούν να βρεθούν στο `/Library/Application Support` για τις εφαρμογές που εκτελούνται ως root και στο `~/Library/Application Support` για τις εφαρμογές που εκτελούνται ως χρήστης.
* Οι **δαίμονες** των εφαρμογών **τρίτων** που **χρειάζονται να εκτελούνται ως root** συνήθως βρίσκονται στο `/Library/PrivilegedHelperTools/`
* Οι **εφαρμογές με αμμούχο περιβάλλον** αντιστοιχούν στον φάκελο `~/Library/Containers`. Κάθε εφαρμογή έχει έναν φάκελο με το όνομα του αναγνω
```bash
# dyld_shared_cache_util
dyld_shared_cache_util -extract ~/shared_cache/ /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# dyldextractor
dyldex -l [dyld_shared_cache_path] # List libraries
dyldex_all [dyld_shared_cache_path] # Extract all
# More options inside the readme
```
{% endcode %}

Σε παλαιότερες εκδόσεις μπορείτε να βρείτε την **κοινόχρηστη μνήμη** στο **`/System/Library/dyld/`**.

Στο iOS μπορείτε να τα βρείτε στο **`/System/Library/Caches/com.apple.dyld/`**.

{% hint style="success" %}
Σημειώστε ότι ακόμη κι αν το εργαλείο `dyld_shared_cache_util` δεν λειτουργεί, μπορείτε να περάσετε το **κοινό dyld δυαδικό αρχείο στο Hopper** και το Hopper θα είναι σε θέση να αναγνωρίσει όλες τις βιβλιοθήκες και να σας επιτρέψει να **επιλέξετε ποια θέλετε** να ερευνήσετε:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (680).png" alt="" width="563"><figcaption></figcaption></figure>

## Ειδικές άδειες αρχείων

### Άδειες φακέλου

Σε έναν **φάκελο**, το **read** επιτρέπει να τον **καταλογογραφήσετε**, το **write** επιτρέπει να **διαγράψετε** και να **γράψετε** αρχεία σε αυτόν, και το **execute** επιτρέπει να **διασχίσετε** τον κατάλογο. Έτσι, για παράδειγμα, ένας χρήστης με **άδεια ανάγνωσης για ένα αρχείο** μέσα σε έναν κατάλογο όπου δεν έχει **άδεια εκτέλεσης** **δεν θα μπορεί να διαβάσει** το αρχείο.

### Τροποποιητές σημαιών

Υπάρχουν ορισμένες σημαίες που μπορούν να οριστούν στα αρχεία και θα κάνουν το αρχείο να συμπεριφέρεται διαφορετικά. Μπορείτε να **ελέγξετε τις σημαίες** των αρχείων μέσα σε έναν κατάλογο με την εντολή `ls -lO /path/directory`

* **`uchg`**: Επικαλούμενη ως **σημαία uchange** θα **εμποδίσει οποιαδήποτε ενέργεια** αλλαγής ή διαγραφής του **αρχείου**. Για να το ορίσετε, χρησιμοποιήστε: `chflags uchg file.txt`
* Ο ριζικός χρήστης μπορεί να **αφαιρέσει τη σημαία** και να τροποποιήσει το αρχείο
* **`restricted`**: Αυτή η σημαία καθιστά το αρχείο **προστατευμένο από το SIP** (δεν μπορείτε να προσθέσετε αυτήν τη σημαία σε ένα αρχείο).
* **`Sticky bit`**: Αν ένας κατάλογος έχει το sticky bit, **μόνο** ο ιδιοκτήτης του καταλόγου ή ο ριζικός χρήστης μπορεί να μετονομάσει ή να διαγράψει αρχεία. Συνήθως αυτό ορίζεται στον κατάλογο /tmp για να αποτρέψει τους απλούς χρήστες από τη διαγραφή ή τη μετακίνηση αρχείων άλλων χρηστών.

### **ACLs αρχείων**

Τα **ACLs αρχείων** περιέχουν **ACE** (Access Control Entries) όπου μπορούν να ανατεθούν πιο **λεπτομερείς άδειες** σε διάφορους χρήστες.

Είναι δυνατόν να χορηγηθούν αυτές οι άδειες σε έναν **κατάλογο**: `list`, `search`, `add_file`, `add_subdirectory`, `delete_child`, `delete_child`.\
Και σε ένα **αρχείο**: `read`, `write`, `append`, `execute`.

Όταν το αρχείο περιέχει ACLs, θα **βρείτε ένα "+" κατά την εμφάνιση των άδειών όπως εδώ**:
```bash
ls -ld Movies
drwx------+   7 username  staff     224 15 Apr 19:42 Movies
```
Μπορείτε να **διαβάσετε τα ACLs** του αρχείου με:
```bash
ls -lde Movies
drwx------+ 7 username  staff  224 15 Apr 19:42 Movies
0: group:everyone deny delete
```
Μπορείτε να βρείτε **όλα τα αρχεία με ACLs** με (αυτό είναι πολύ αργό):
```bash
ls -RAle / 2>/dev/null | grep -E -B1 "\d: "
```
### Πηγαία Αποθήκευση | macOS ADS

Αυτός είναι ένας τρόπος για να αποκτήσετε **Εναλλακτικά Ροές Δεδομένων σε μηχανήματα MacOS**. Μπορείτε να αποθηκεύσετε περιεχόμενο μέσα σε ένα επεκταμένο χαρακτηριστικό που ονομάζεται **com.apple.ResourceFork** μέσα σε ένα αρχείο αποθηκεύοντάς το στο **file/..namedfork/rsrc**.
```bash
echo "Hello" > a.txt
echo "Hello Mac ADS" > a.txt/..namedfork/rsrc

xattr -l a.txt #Read extended attributes
com.apple.ResourceFork: Hello Mac ADS

ls -l a.txt #The file length is still q
-rw-r--r--@ 1 username  wheel  6 17 Jul 01:15 a.txt
```
Μπορείτε **να βρείτε όλα τα αρχεία που περιέχουν αυτό το επεκταμένο χαρακτηριστικό** με την εντολή:

{% code overflow="wrap" %}
```bash
find / -type f -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.ResourceFork"
```
{% endcode %}

## **Παγκόσμια δυαδικά &** Μορφή Mach-o

Οι δυαδικοί κώδικες του Mac OS συνήθως μεταγλωττίζονται ως **παγκόσμιοι δυαδικοί κώδικες**. Ένας **παγκόσμιος δυαδικός κώδικας** μπορεί να **υποστηρίζει πολλές αρχιτεκτονικές στον ίδιο αρχείο**.

{% content-ref url="universal-binaries-and-mach-o-format.md" %}
[universal-binaries-and-mach-o-format.md](universal-binaries-and-mach-o-format.md)
{% endcontent-ref %}

## Απορροφητήριο μνήμης macOS

{% content-ref url="macos-memory-dumping.md" %}
[macos-memory-dumping.md](macos-memory-dumping.md)
{% endcontent-ref %}

## Αρχεία κατηγορίας κινδύνου Mac OS

Ο κατάλογος `/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/System` είναι ο τόπος όπου αποθηκεύονται πληροφορίες σχετικά με το **κίνδυνο που συνδέεται με διάφορες επεκτάσεις αρχείων**. Αυτός ο κατάλογος κατηγοριοποιεί τα αρχεία σε διάφορα επίπεδα κινδύνου, επηρεάζοντας τον τρόπο με τον οποίο το Safari χειρίζεται αυτά τα αρχεία κατά τη λήψη. Οι κατηγορίες είναι οι εξής:

- **LSRiskCategorySafe**: Τα αρχεία σε αυτήν την κατηγορία θεωρούνται **εντελώς ασφαλή**. Το Safari θα ανοίγει αυτόματα αυτά τα αρχεία μετά τη λήψη τους.
- **LSRiskCategoryNeutral**: Αυτά τα αρχεία δεν συνοδεύονται από προειδοποιήσεις και δεν ανοίγονται **αυτόματα** από το Safari.
- **LSRiskCategoryUnsafeExecutable**: Τα αρχεία σε αυτήν την κατηγορία **ενεργοποιούν μια προειδοποίηση** που υποδεικνύει ότι το αρχείο είναι μια εφαρμογή. Αυτό λειτουργεί ως μέτρο ασφαλείας για να ειδοποιήσει τον χρήστη.
- **LSRiskCategoryMayContainUnsafeExecutable**: Αυτή η κατηγορία αφορά αρχεία, όπως αρχεία αρχειοθέτησης, που μπορεί να περιέχουν μια εκτελέσιμη εφαρμογή. Το Safari θα **ενεργοποιήσει μια προειδοποίηση** εκτός αν μπορεί να επαληθεύσει ότι όλο το περιεχόμενο είναι ασφαλές ή ουδέτερο.

## Αρχεία καταγραφής

* **`$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**: Περιέχει πληροφορίες σχετικά με τα ληφθέντα αρχεία, όπως η URL από την οποία λήφθηκαν.
* **`/var/log/system.log`**: Κύρια καταγραφή των συστημάτων OSX. Το αρχείο com.apple.syslogd.plist είναι υπεύθυνο για την εκτέλεση της καταγραφής συστήματος (μπορείτε να ελέγξετε εάν είναι απενεργοποιημένο αναζητώντας το "com.apple.syslogd" στο `launchctl list`.
* **`/private/var/log/asl/*.asl`**: Αυτά είναι τα αρχεία καταγραφής του Apple System που μπορεί να περιέχουν ενδιαφέρουσες πληροφορίες.
* **`$HOME/Library/Preferences/com.apple.recentitems.plist`**: Αποθηκεύει πρόσφατα ανακτηθέντα αρχεία και εφαρμογές μέσω του "Finder".
* **`$HOME/Library/Preferences/com.apple.loginitems.plsit`**: Αποθηκεύει στοιχεία που θα εκκινηθούν κατά την εκκίνηση του συστήματος
* **`$HOME/Library/Logs/DiskUtility.log`**: Αρχείο καταγραφής για την εφαρμογή DiskUtility (πληροφορίες σχετικά με τους δίσκους, συμπεριλαμβανομένων των USB)
* **`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`**: Δεδομένα σχετικά με τα ασύρματα σημεία πρόσβασης.
* **`/private/var/db/launchd.db/com.apple.launchd/overrides.plist`**: Λίστα απενεργοποιημένων δαίμονων.

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
