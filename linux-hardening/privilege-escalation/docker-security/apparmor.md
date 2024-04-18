# AppArmor

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι μια μηχανή αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει **δωρεάν** λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλου λογισμικού**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων με αντάλλαγμα λύτρων που προκύπτουν από κακόβουλο λογισμικό που κλέβει πληροφορίες.

Μπορείτε να ελέγξετε τον ιστότοπό τους και να δοκιμάσετε τη μηχανή τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

---

## Βασικές Πληροφορίες

Το AppArmor είναι μια **ενίσχυση πυρήνα σχεδιασμένη για να περιορίζει τους πόρους που είναι διαθέσιμοι σε προγράμματα μέσω προφίλ ανά πρόγραμμα**, εφαρμόζοντας αποτελεσματικά τον Επιβεβλημένο Έλεγχο Πρόσβασης (MAC) δεσμεύοντας τα χαρακτηριστικά ελέγχου πρόσβασης απευθείας στα προγράμματα αντί για τους χρήστες. Αυτό το σύστημα λειτουργεί με τον **φόρτωση προφίλ στον πυρήνα**, συνήθως κατά την εκκίνηση, και αυτά τα προφίλ καθορίζουν ποιους πόρους μπορεί να έχει πρόσβαση ένα πρόγραμμα, όπως συνδέσεις δικτύου, πρόσβαση σε ροές socket και άδειες αρχείων.

Υπάρχουν δύο λειτουργικές καταστάσεις για τα προφίλ AppArmor:

- **Λειτουργία Επιβολής**: Αυτή η λειτουργία επιβάλλει ενεργά τις πολιτικές που έχουν οριστεί στο προφίλ, αποκλείοντας ενέργειες που παραβιάζουν αυτές τις πολιτικές και καταγράφοντας οποιεσδήποτε προσπάθειες παραβίασής τους μέσω συστημάτων όπως το syslog ή το auditd.
- **Λειτουργία Διαμαρτυρίας**: Αντίθετα με τη λειτουργία επιβολής, η λειτουργία διαμαρτυρίας δεν αποκλείει ενέργειες που παραβιάζουν τις πολιτικές του προφίλ. Αντ' αυτού, καταγράφει αυτές τις προσπάθειες ως παραβιάσεις πολιτικής χωρίς να επιβάλλει περιορισμούς.

### Στοιχεία του AppArmor

- **Πυρήνας Ενότητας**: Υπεύθυνος για την επιβολή των πολιτικών.
- **Πολιτικές**: Καθορίζουν τους κανόνες και τους περιορισμούς για τη συμπεριφορά του προγράμματος και την πρόσβαση σε πόρους.
- **Αναλυτής**: Φορτώνει τις πολιτικές στον πυρήνα για επιβολή ή αναφορά.
- **Προγράμματα Χρηστών**: Αυτά είναι προγράμματα λειτουργίας χρήστη που παρέχουν μια διεπαφή για την αλληλεπίδραση και τη διαχείριση του AppArmor.

### Διαδρομές Προφίλ

Τα προφίλ Apparmor συνήθως αποθηκεύονται στο _**/etc/apparmor.d/**_\
Με την εντολή `sudo aa-status` θα μπορείτε να καταλογίσετε τα δυαδικά που περιορίζονται από κάποιο προφίλ. Αν μπορείτε να αλλάξετε το χαρακτήρα "/" με ένα τελεία από τη διαδρομή κάθε καταχωρημένου δυαδικού, θα λάβετε το όνομα του προφίλ apparmor μέσα στο αναφερόμενο φάκελο.

Για παράδειγμα, ένα **προφίλ apparmor** για _/usr/bin/man_ θα βρίσκεται στο _/etc/apparmor.d/usr.bin.man_

### Εντολές
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Δημιουργία προφίλ

* Για να υποδείξετε τον επηρεαζόμενο εκτελέσιμο, επιτρέπονται **απόλυτα μονοπάτια και μπαλαντέρ** (για file globbing) για την καθορισμό αρχείων.
* Για να υποδείξετε την πρόσβαση που το δυαδικό θα έχει σε **αρχεία** μπορούν να χρησιμοποιηθούν οι ακόλουθοι **έλεγχοι πρόσβασης**:
  * **r** (ανάγνωση)
  * **w** (εγγραφή)
  * **m** (χαρτογράφηση μνήμης ως εκτελέσιμο)
  * **k** (κλείδωμα αρχείου)
  * **l** (δημιουργία σκληρών συνδέσμων)
  * **ix** (για να εκτελέσετε ένα άλλο πρόγραμμα με το νέο πρόγραμμα να κληρονομεί την πολιτική)
  * **Px** (εκτέλεση υπό άλλο προφίλ, μετά τον καθαρισμό του περιβάλλοντος)
  * **Cx** (εκτέλεση υπό προφίλ παιδιού, μετά τον καθαρισμό του περιβάλλοντος)
  * **Ux** (εκτέλεση χωρίς περιορισμούς, μετά τον καθαρισμό του περιβάλλοντος)
* **Μεταβλητές** μπορούν να οριστούν στα προφίλ και μπορούν να ρυθμιστούν από έξω από το προφίλ. Για παράδειγμα: @{PROC} και @{HOME} (προσθέστε #include \<tunables/global> στο αρχείο προφίλ)
* **Οι κανόνες απαγόρευσης υποστηρίζονται για να αντικαταστήσουν τους κανόνες επιτροπής**.

### aa-genprof

Για να ξεκινήσετε εύκολα τη δημιουργία ενός προφίλ, το apparmor μπορεί να σας βοηθήσει. Είναι δυνατόν να κάνετε **το apparmor να ελέγξει τις ενέργειες που εκτελεί ένα δυαδικό και στη συνέχεια να σας επιτρέψει να αποφασίσετε ποιες ενέργειες θέλετε να επιτρέψετε ή να απαγορεύσετε**.\
Απλά χρειάζεται να εκτελέσετε:
```bash
sudo aa-genprof /path/to/binary
```
Στη συνέχεια, σε ένα διαφορετικό τερματικό, εκτελέστε όλες τις ενέργειες που συνήθως θα εκτελούσε το δυαδικό αρχείο:
```bash
/path/to/binary -a dosomething
```
Στη συνέχεια, στην πρώτη κονσόλα πατήστε "**s**" και στις καταγεγραμμένες ενέργειες υποδείξτε εάν θέλετε να αγνοήσετε, επιτρέψετε, ή οτιδήποτε άλλο. Όταν τελειώσετε, πατήστε "**f**" και το νέο προφίλ θα δημιουργηθεί στο _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Χρησιμοποιώντας τα πλήκτρα βέλους μπορείτε να επιλέξετε τι θέλετε να επιτρέψετε/απαγορεύσετε/οτιδήποτε άλλο
{% endhint %}

### aa-easyprof

Μπορείτε επίσης να δημιουργήσετε ένα πρότυπο ενός προφίλ apparmor ενός δυαδικού με:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Σημειώστε ότι από προεπιλογή σε ένα δημιουργημένο προφίλ τίποτα δεν επιτρέπεται, οπότε όλα απορρίπτονται. Θα πρέπει να προσθέσετε γραμμές όπως `/etc/passwd r,` για να επιτρέψετε στο δυαδικό να διαβάσει το `/etc/passwd` για παράδειγμα.
{% endhint %}

Στη συνέχεια μπορείτε να **επιβάλετε** το νέο προφίλ με
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Τροποποίηση ενός προφίλ από τα logs

Το παρακάτω εργαλείο θα διαβάσει τα logs και θα ρωτήσει τον χρήστη εάν επιθυμεί να επιτρέψει κάποιες από τις ανιχνευμένες απαγορευμένες ενέργειες:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Χρησιμοποιώντας τα πλήκτρα βέλους μπορείτε να επιλέξετε τι θέλετε να επιτρέώσετε/απαγορεύσετε/οτιδήποτε
{% endhint %}

### Διαχείριση ενός Προφίλ
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Αρχεία καταγραφής

Παράδειγμα **ΑΥΤΙΣΜΟΥ** και **ΑΠΟΡΡΙΨΗΣ** καταγραφών από το _/var/log/audit/audit.log_ του εκτελέσιμου **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Μπορείτε επίσης να λάβετε αυτές τις πληροφορίες χρησιμοποιώντας:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor στο Docker

Σημειώστε πως το προφίλ **docker-profile** του docker φορτώνεται από προεπιλογή:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Από προεπιλογή το προφίλ **Apparmor docker-default** δημιουργείται από [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Περίληψη προφίλ docker-default**:

* **Πρόσβαση** σε όλο το **δίκτυο**
* Δεν έχει οριστεί **κάποια ικανότητα** (Ωστόσο, μερικές ικανότητες θα προέλθουν από τη συμπερίληψη βασικών κανόνων βάσης, δηλαδή #include \<abstractions/base>)
* **Απαγορεύεται η εγγραφή** σε οποιοδήποτε αρχείο **/proc**
* Άλλοι **υποκατάλογοι/αρχεία** του /**proc** και /**sys** έχουν **απαγορευμένη** πρόσβαση για ανάγνωση/εγγραφή/κλείδωμα/σύνδεση/εκτέλεση
* **Δεν επιτρέπεται η τοποθέτηση (mount)**
* Η **Ptrace** μπορεί να εκτελεστεί μόνο σε ένα διεργασία που περιορίζεται από το **ίδιο προφίλ apparmor**

Μόλις **εκτελέσετε ένα container docker**, θα πρέπει να δείτε την ακόλουθη έξοδο:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Σημειώστε ότι **το apparmor θα αποκλείσει ακόμα και τα προνόμια δικαιωμάτων** που έχουν χορηγηθεί στον ελατήριο από προεπιλογή. Για παράδειγμα, θα μπορεί να **αποκλείσει την άδεια εγγραφής μέσα στον φάκελο /proc ακόμα κι αν έχει χορηγηθεί η δυνατότητα SYS\_ADMIN** επειδή από προεπιλογή το προφίλ apparmor του docker αρνείται αυτήν την πρόσβαση:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Πρέπει να **απενεργοποιήσετε το apparmor** για να παρακάμψετε τους περιορισμούς του:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Σημειώστε ότι από προεπιλογή το **AppArmor** θα απαγορεύσει στο container να κάνει mount φακέλους από μέσα ακόμα και με τη δυνατότητα SYS\_ADMIN.

Σημειώστε ότι μπορείτε να **προσθέσετε/αφαιρέσετε** **δυνατότητες** στο docker container (αυτό θα παραμείνει περιορισμένο από μεθόδους προστασίας όπως το **AppArmor** και το **Seccomp**):

* `--cap-add=SYS_ADMIN` προσθέτει τη δυνατότητα `SYS_ADMIN`
* `--cap-add=ALL` προσθέτει όλες τις δυνατότητες
* `--cap-drop=ALL --cap-add=SYS_PTRACE` αφαιρεί όλες τις δυνατότητες και δίνει μόνο την `SYS_PTRACE`

{% hint style="info" %}
Συνήθως, όταν **ανακαλύπτετε** ότι έχετε μια **προνομιούχα δυνατότητα** διαθέσιμη **μέσα** σε ένα **docker container** αλλά κάποιο τμήμα του **exploit δεν λειτουργεί**, αυτό οφείλεται στο ότι το docker **apparmor το εμποδίζει**.
{% endhint %}

### Παράδειγμα

(Παράδειγμα από [**εδώ**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Για να εικονογραφήσω τη λειτουργικότητα του AppArmor, δημιούργησα ένα νέο προφίλ Docker "mydocker" με την παρακάτω γραμμή προστεθειμένη:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Για να ενεργοποιήσουμε το προφίλ, πρέπει να κάνουμε τα ακόλουθα:
```
sudo apparmor_parser -r -W mydocker
```
Για να εμφανίσουμε τα προφίλ, μπορούμε να χρησιμοποιήσουμε την παρακάτω εντολή. Η παρακάτω εντολή εμφανίζει το νέο προφίλ AppArmor μου.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Όπως φαίνεται παρακάτω, λαμβάνουμε σφάλμα όταν προσπαθούμε να αλλάξουμε το "/etc/" επειδή το προφίλ του AppArmor αποτρέπει την εγγραφή πρόσβασης στο "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Παράκαμψη AppArmor Docker1

Μπορείτε να βρείτε ποιο προφίλ **apparmor εκτελείται από ένα container** χρησιμοποιώντας:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Στη συνέχεια, μπορείτε να εκτελέσετε την παρακάτω γραμμή για **να βρείτε το ακριβές προφίλ που χρησιμοποιείται**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### Παράκαμψη AppArmor Docker2

**Το AppArmor βασίζεται στα μονοπάτια**, αυτό σημαίνει ότι ακόμα και αν **προστατεύει** αρχεία μέσα σε έναν κατάλογο όπως το **`/proc`**, αν μπορείτε **να ρυθμίσετε πώς θα εκτελείται το container**, μπορείτε **να προσαρτήσετε** τον κατάλογο proc του κεντρικού συστήματος μέσα στο **`/host/proc`** και δεν θα προστατεύεται πλέον από το AppArmor.

### Παράκαμψη Shebang του AppArmor

Σε [**αυτό το σφάλμα**](https://bugs.launchpad.net/apparmor/+bug/1911431) μπορείτε να δείτε ένα παράδειγμα πώς **ακόμα κι αν αποτρέπετε την εκτέλεση του perl με συγκεκριμένους πόρους**, αν απλώς δημιουργήσετε ένα shell script **προσδιορίζοντας** στην πρώτη γραμμή **`#!/usr/bin/perl`** και **εκτελέσετε το αρχείο απευθείας**, θα μπορείτε να εκτελέσετε ό,τι θέλετε. Π.χ.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) είναι ένας μηχανισμός αναζήτησης που τροφοδοτείται από το **dark web** και προσφέρει δωρεάν λειτουργίες για να ελέγξετε αν μια εταιρεία ή οι πελάτες της έχουν **διαρρεύσει** από **κλέφτες κακόβουλων λογισμικών**.

Ο κύριος στόχος του WhiteIntel είναι η καταπολέμηση των αναλήψεων λογαριασμών και των επιθέσεων ransomware που προκύπτουν από κακόβουλα λογισμικά που κλέβουν πληροφορίες.

Μπορείτε να ελέγξετε την ιστοσελίδα τους και να δοκιμάσετε τον μηχανισμό τους δωρεάν στο:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
