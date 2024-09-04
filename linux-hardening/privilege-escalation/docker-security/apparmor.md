# AppArmor

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

Το AppArmor είναι μια **βελτίωση του πυρήνα που έχει σχεδιαστεί για να περιορίζει τους πόρους που είναι διαθέσιμοι σε προγράμματα μέσω προφίλ ανά πρόγραμμα**, εφαρμόζοντας αποτελεσματικά τον Υποχρεωτικό Έλεγχο Πρόσβασης (MAC) συνδέοντας τα χαρακτηριστικά ελέγχου πρόσβασης απευθείας σε προγράμματα αντί για χρήστες. Αυτό το σύστημα λειτουργεί με **φόρτωση προφίλ στον πυρήνα**, συνήθως κατά την εκκίνηση, και αυτά τα προφίλ καθορίζουν ποιους πόρους μπορεί να έχει πρόσβαση ένα πρόγραμμα, όπως συνδέσεις δικτύου, πρόσβαση σε ακατέργαστους υποδοχείς και άδειες αρχείων.

Υπάρχουν δύο λειτουργικά modes για τα προφίλ του AppArmor:

* **Λειτουργία Επιβολής**: Αυτή η λειτουργία επιβάλλει ενεργά τις πολιτικές που ορίζονται μέσα στο προφίλ, αποκλείοντας ενέργειες που παραβιάζουν αυτές τις πολιτικές και καταγράφοντας οποιαδήποτε προσπάθεια παραβίασης τους μέσω συστημάτων όπως το syslog ή το auditd.
* **Λειτουργία Καταγγελίας**: Σε αντίθεση με τη λειτουργία επιβολής, η λειτουργία καταγγελίας δεν αποκλείει ενέργειες που παραβιάζουν τις πολιτικές του προφίλ. Αντίθετα, καταγράφει αυτές τις προσπάθειες ως παραβιάσεις πολιτικής χωρίς να επιβάλλει περιορισμούς.

### Components of AppArmor

* **Module Πυρήνα**: Υπεύθυνο για την επιβολή πολιτικών.
* **Πολιτικές**: Καθορίζουν τους κανόνες και τους περιορισμούς για τη συμπεριφορά του προγράμματος και την πρόσβαση στους πόρους.
* **Αναλυτής**: Φορτώνει πολιτικές στον πυρήνα για επιβολή ή αναφορά.
* **Εργαλεία**: Αυτά είναι προγράμματα σε λειτουργία χρήστη που παρέχουν μια διεπαφή για αλληλεπίδραση και διαχείριση του AppArmor.

### Profiles path

Τα προφίλ του AppArmor αποθηκεύονται συνήθως στο _**/etc/apparmor.d/**_\
Με το `sudo aa-status` θα μπορείτε να καταγράψετε τα δυαδικά αρχεία που περιορίζονται από κάποιο προφίλ. Αν αλλάξετε το χαρακτήρα "/" με μια τελεία στο μονοπάτι κάθε καταγεγραμμένου δυαδικού αρχείου, θα αποκτήσετε το όνομα του προφίλ του AppArmor μέσα στον αναφερόμενο φάκελο.

Για παράδειγμα, ένα **προφίλ apparmor** για το _/usr/bin/man_ θα βρίσκεται στο _/etc/apparmor.d/usr.bin.man_

### Commands
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

* Για να υποδείξετε το επηρεαζόμενο εκτελέσιμο, επιτρέπονται **απόλυτες διαδρομές και wildcard** για τον καθορισμό αρχείων.
* Για να υποδείξετε την πρόσβαση που θα έχει το δυαδικό αρχείο σε **αρχεία**, μπορούν να χρησιμοποιηθούν οι εξής **έλεγχοι πρόσβασης**:
* **r** (ανάγνωση)
* **w** (εγγραφή)
* **m** (χάρτης μνήμης ως εκτελέσιμο)
* **k** (κλείδωμα αρχείων)
* **l** (δημιουργία σκληρών συνδέσμων)
* **ix** (για να εκτελέσετε ένα άλλο πρόγραμμα με την πολιτική του νέου προγράμματος να κληρονομείται)
* **Px** (εκτέλεση υπό άλλο προφίλ, μετά τον καθαρισμό του περιβάλλοντος)
* **Cx** (εκτέλεση υπό ένα παιδικό προφίλ, μετά τον καθαρισμό του περιβάλλοντος)
* **Ux** (εκτέλεση χωρίς περιορισμούς, μετά τον καθαρισμό του περιβάλλοντος)
* **Μεταβλητές** μπορούν να οριστούν στα προφίλ και μπορούν να χειριστούν από έξω από το προφίλ. Για παράδειγμα: @{PROC} και @{HOME} (προσθέστε #include \<tunables/global> στο αρχείο προφίλ)
* **Οι κανόνες άρνησης υποστηρίζονται για να παρακάμπτουν τους κανόνες επιτρεπόμενης πρόσβασης**.

### aa-genprof

Για να ξεκινήσετε εύκολα τη δημιουργία ενός προφίλ, το apparmor μπορεί να σας βοηθήσει. Είναι δυνατόν να κάνετε **το apparmor να επιθεωρήσει τις ενέργειες που εκτελεί ένα δυαδικό αρχείο και στη συνέχεια να σας αφήσει να αποφασίσετε ποιες ενέργειες θέλετε να επιτρέψετε ή να αρνηθείτε**.\
Απλά χρειάζεται να εκτελέσετε:
```bash
sudo aa-genprof /path/to/binary
```
Στη συνέχεια, σε μια διαφορετική κονσόλα εκτελέστε όλες τις ενέργειες που θα εκτελεί συνήθως το δυαδικό αρχείο:
```bash
/path/to/binary -a dosomething
```
Στη συνέχεια, στην πρώτη κονσόλα πατήστε "**s**" και στη συνέχεια στις καταγεγραμμένες ενέργειες υποδείξτε αν θέλετε να αγνοήσετε, να επιτρέψετε ή οτιδήποτε άλλο. Όταν τελειώσετε πατήστε "**f**" και το νέο προφίλ θα δημιουργηθεί στο _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Χρησιμοποιώντας τα πλήκτρα βέλους μπορείτε να επιλέξετε τι θέλετε να επιτρέψετε/αρνηθείτε/οτιδήποτε άλλο
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
Σημειώστε ότι από προεπιλογή σε ένα δημιουργημένο προφίλ τίποτα δεν επιτρέπεται, οπότε όλα απορρίπτονται. Θα χρειαστεί να προσθέσετε γραμμές όπως `/etc/passwd r,` για να επιτρέψετε την ανάγνωση του δυαδικού αρχείου `/etc/passwd`, για παράδειγμα.
{% endhint %}

Μπορείτε στη συνέχεια να **επιβάλετε** το νέο προφίλ με
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modifying a profile from logs

Το παρακάτω εργαλείο θα διαβάσει τα αρχεία καταγραφής και θα ρωτήσει τον χρήστη αν θέλει να επιτρέψει ορισμένες από τις ανιχνευθείσες απαγορευμένες ενέργειες:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Χρησιμοποιώντας τα πλήκτρα βέλους μπορείτε να επιλέξετε τι θέλετε να επιτρέψετε/αρνηθείτε/οτιδήποτε
{% endhint %}

### Διαχείριση ενός Προφίλ
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Παράδειγμα **AUDIT** και **DENIED** logs από το _/var/log/audit/audit.log_ του εκτελέσιμου **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Μπορείτε επίσης να αποκτήσετε αυτές τις πληροφορίες χρησιμοποιώντας:
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
## Apparmor in Docker

Σημειώστε πώς το προφίλ **docker-profile** του docker φορτώνεται από προεπιλογή:
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
Κατά προεπιλογή, το **προφίλ docker-default του Apparmor** δημιουργείται από [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Περίληψη προφίλ docker-default**:

* **Πρόσβαση** σε όλο το **δικτύωμα**
* **Καμία ικανότητα** δεν έχει οριστεί (Ωστόσο, κάποιες ικανότητες θα προέρχονται από την συμπερίληψη βασικών κανόνων, δηλαδή #include \<abstractions/base>)
* **Εγγραφή** σε οποιοδήποτε **/proc** αρχείο **δεν επιτρέπεται**
* Άλλες **υποκαταλόγους**/**αρχεία** του /**proc** και /**sys** έχουν **αρνηθεί** πρόσβαση σε ανάγνωση/εγγραφή/κλείδωμα/σύνδεση/εκτέλεση
* **Σύνδεση** **δεν επιτρέπεται**
* **Ptrace** μπορεί να εκτελείται μόνο σε μια διαδικασία που περιορίζεται από το **ίδιο προφίλ apparmor**

Μόλις **τρέξετε ένα κοντέινερ docker**, θα πρέπει να δείτε την παρακάτω έξοδο:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Σημειώστε ότι **το apparmor θα μπλοκάρει ακόμη και τα δικαιώματα ικανοτήτων** που παραχωρούνται στο κοντέινερ από προεπιλογή. Για παράδειγμα, θα είναι σε θέση να **μπλοκάρει την άδεια εγγραφής μέσα στο /proc ακόμη και αν η ικανότητα SYS\_ADMIN παραχωρείται** επειδή από προεπιλογή το προφίλ apparmor του docker αρνείται αυτή την πρόσβαση:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Πρέπει να **απενεργοποιήσετε το apparmor** για να παρακάμψετε τους περιορισμούς του:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Σημειώστε ότι από προεπιλογή, το **AppArmor** θα **απαγορεύει επίσης στο κοντέινερ να προσαρτήσει** φακέλους από το εσωτερικό ακόμη και με ικανότητα SYS\_ADMIN.

Σημειώστε ότι μπορείτε να **προσθέσετε/αφαιρέσετε** **ικανότητες** στο κοντέινερ docker (αυτό θα είναι ακόμα περιορισμένο από μεθόδους προστασίας όπως το **AppArmor** και το **Seccomp**):

* `--cap-add=SYS_ADMIN` δίνει ικανότητα `SYS_ADMIN`
* `--cap-add=ALL` δίνει όλες τις ικανότητες
* `--cap-drop=ALL --cap-add=SYS_PTRACE` αφαιρεί όλες τις ικανότητες και δίνει μόνο `SYS_PTRACE`

{% hint style="info" %}
Συνήθως, όταν **ανακαλύπτετε** ότι έχετε μια **προνομιακή ικανότητα** διαθέσιμη **μέσα** σε ένα **docker** κοντέινερ **αλλά** κάποιο μέρος της **εκμετάλλευσης δεν λειτουργεί**, αυτό θα είναι επειδή το docker **apparmor θα το αποτρέπει**.
{% endhint %}

### Παράδειγμα

(Παράδειγμα από [**εδώ**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Για να απεικονίσω τη λειτουργικότητα του AppArmor, δημιούργησα ένα νέο προφίλ Docker “mydocker” με την παρακάτω γραμμή προστιθέμενη:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Για να ενεργοποιήσουμε το προφίλ, πρέπει να κάνουμε τα εξής:
```
sudo apparmor_parser -r -W mydocker
```
Για να καταγράψουμε τα προφίλ, μπορούμε να εκτελέσουμε την παρακάτω εντολή. Η παρακάτω εντολή καταγράφει το νέο μου προφίλ AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Όπως φαίνεται παρακάτω, λαμβάνουμε σφάλμα όταν προσπαθούμε να αλλάξουμε το “/etc/” καθώς το προφίλ AppArmor εμποδίζει την πρόσβαση εγγραφής στο “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Μπορείτε να βρείτε ποιο **προφίλ apparmor εκτελεί ένα κοντέινερ** χρησιμοποιώντας:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Τότε, μπορείτε να εκτελέσετε την παρακάτω γραμμή για να **βρείτε το ακριβές προφίλ που χρησιμοποιείται**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In την περίεργη περίπτωση που μπορείτε να **τροποποιήσετε το προφίλ apparmor docker και να το επαναφορτώσετε.** Μπορείτε να αφαιρέσετε τους περιορισμούς και να τους "παρακάμψετε".

### AppArmor Docker Bypass2

**Το AppArmor είναι βασισμένο σε διαδρομές**, αυτό σημαίνει ότι ακόμη και αν μπορεί να **προστατεύει** αρχεία μέσα σε έναν φάκελο όπως το **`/proc`**, αν μπορείτε να **ρυθμίσετε πώς θα εκτελείται το κοντέινερ**, μπορείτε να **τοποθετήσετε** τον φάκελο proc του host μέσα σε **`/host/proc`** και δεν θα **προστατεύεται πλέον από το AppArmor**.

### AppArmor Shebang Bypass

Στο [**αυτό το σφάλμα**](https://bugs.launchpad.net/apparmor/+bug/1911431) μπορείτε να δείτε ένα παράδειγμα του πώς **ακόμη και αν αποτρέπετε την εκτέλεση του perl με ορισμένους πόρους**, αν απλώς δημιουργήσετε ένα shell script **καθορίζοντας** στην πρώτη γραμμή **`#!/usr/bin/perl`** και **εκτελέσετε το αρχείο απευθείας**, θα μπορείτε να εκτελέσετε ό,τι θέλετε. Π.χ.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
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
