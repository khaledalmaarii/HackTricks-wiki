# macOS GCD - Grand Central Dispatch

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστηρίξτε το HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε** 💬 [**στην ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Κοινοποιήστε κόλπα χάκερ υποβάλλοντας PRs** στα [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του GitHub.

</details>
{% endhint %}

## Βασικές Πληροφορίες

**Το Grand Central Dispatch (GCD),** γνωστό και ως **libdispatch** (`libdispatch.dyld`), είναι διαθέσιμο τόσο σε macOS όσο και σε iOS. Είναι μια τεχνολογία που αναπτύχθηκε από την Apple για τη βελτιστοποίηση της υποστήριξης εφαρμογών για την ταυτόχρονη (πολυνηματική) εκτέλεση σε πολυπύρηνο υλικό.

Το **GCD** παρέχει και διαχειρίζεται **ουρές FIFO** στις οποίες η εφαρμογή σας μπορεί να **υποβάλει εργασίες** σε μορφή **block objects**. Τα blocks που υποβάλλονται στις ουρές αποστολής εκτελούνται σε ένα pool νημάτων πλήρως διαχειριζόμενο από το σύστημα. Το GCD δημιουργεί αυτόματα νήματα για την εκτέλεση των εργασιών στις ουρές αποστολής και προγραμματίζει αυτές τις εργασίες να τρέχουν στους διαθέσιμους πυρήνες.

{% hint style="success" %}
Συνοπτικά, για να εκτελέσετε κώδικα **παράλληλα**, οι διεργασίες μπορούν να στείλουν **blocks κώδικα στο GCD**, το οποίο θα φροντίσει για την εκτέλεσή τους. Συνεπώς, οι διεργασίες δεν δημιουργούν νέα νήματα. Το **GCD εκτελεί τον δοσμένο κώδικα με το δικό του pool νημάτων** (το οποίο μπορεί να αυξηθεί ή να μειωθεί ανάλογα με τις ανάγκες).
{% endhint %}

Αυτό είναι πολύ χρήσιμο για τη διαχείριση της παράλληλης εκτέλεσης με επιτυχία, μειώνοντας σημαντικά τον αριθμό των νημάτων που δημιουργούν οι διεργασίες και βελτιστοποιώντας την παράλληλη εκτέλεση. Αυτό είναι ιδανικό για εργασίες που απαιτούν **μεγάλη παράλληλη εκτέλεση** (brute-forcing;) ή για εργασίες που δεν πρέπει να αποκλείουν το κύριο νήμα: Για παράδειγμα, το κύριο νήμα στο iOS χειρίζεται τις αλληλεπιδράσεις με το UI, οπότε οποιαδήποτε άλλη λειτουργικότητα που θα μπορούσε να κάνει την εφαρμογή να κολλήσει (αναζήτηση, πρόσβαση σε ιστοσελίδα, ανάγνωση αρχείου...) διαχειρίζεται με αυτόν τον τρόπο.

### Blocks

Ένα block είναι ένα **αυτόνομο τμήμα κώδικα** (όπως μια συνάρτηση με ορίσματα που επιστρέφει μια τιμή) και μπορεί επίσης να καθορίσει δεσμευμένες μεταβλητές.\
Ωστόσο, στο επίπεδο του μεταγλωττιστή τα blocks δεν υπάρχουν, είναι `os_object`s. Κάθε ένα από αυτά τα αντικείμενα αποτελείται από δύο δομές:

* **block literal**:&#x20;
* Ξεκινά με το πεδίο **`isa`**, που δείχνει στην κλάση του block:
* `NSConcreteGlobalBlock` (blocks από `__DATA.__const`)
* `NSConcreteMallocBlock` (blocks στη στοίβα)
* `NSConcreateStackBlock` (blocks στη στοίβα)
* Έχει **`flags`** (που υποδεικνύουν τα πεδία που υπάρχουν στην περιγραφή του block) και μερικά δεσμευμένα bytes
* Ο δείκτης συνάρτησης για κλήση
* Ένας δείκτης στην περιγραφή του block
* Δεσμευμένες μεταβλητές block (αν υπάρχουν)
* **block descriptor**: Το μέγεθός του εξαρτάται από τα δεδομένα που υπάρχουν (όπως υποδεικνύεται στα προηγούμενα flags)
* Έχει μερικά δεσμευμένα bytes
* Το μέγεθός του
* Συνήθως θα έχει ένα δείκτη σε μια υπογραφή στυλ Objective-C για να γνωρίζει πόσο χώρο χρειάζεται για τις παραμέτρους (σημαία `BLOCK_HAS_SIGNATURE`)
* Αν υπάρχουν αναφερόμενες μεταβλητές, αυτό το block θα έχει επίσης δείκτες σε ένα βοηθό αντιγραφής (αντιγραφή της τιμής στην αρχή) και βοηθό διάθεσης (απελευθέρωσή της).

### Ουρές

Μια ουρά αποστολής είναι ένα αντικείμενο με όνομα που παρέχει ταξινόμηση FIFO των blocks για εκτέλεση.

Τα blocks τοποθετούνται σε ουρές για να εκτελεστούν, και αυτές υποστηρίζουν 2 λειτουργίες: `DISPATCH_QUEUE_SERIAL` και `DISPATCH_QUEUE_CONCURRENT`. Φυσικά η **σειριακή** δεν θα έχει προβλήματα συνθήκης αγώνα καθώς ένα block δεν θα εκτελεστεί μέχρι να ολοκληρωθεί το προηγούμενο. Αλλά **ο άλλος τύπος ουράς μπορεί να το έχει**.

Προεπιλεγμένες ουρές:

* `.main-thread`: Από `dispatch_get_main_queue()`
* `.libdispatch-manager`: Διαχειριστής ουράς του GCD
* `.root.libdispatch-manager`: Διαχειριστής ουράς του GCD
* `.root.maintenance-qos`: Εργασίες χαμηλότερης προτεραιότητας
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Διαθέσιμη ως `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Διαθέσιμη ως `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Διαθέσιμη ως `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Διαθέσιμη ως `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Υψηλότερη προτεραιότητα
* `.root.background-qos.overcommit`

Σημειώστε ότι θα είναι το σύστημα που θα αποφασίσει **ποια νήματα θα χειριστούν ποιες ουρές κάθε φορά** (πολλά νήματα μπορεί να εργαστούν στην ίδια ουρά ή το ίδιο νήμα μπορεί να εργαστεί σε διαφορετικές ουρές σε κάποιο σημείο)

#### Χαρακτηριστικά

Όταν δημιουργείτε μια ουρά με το **`dispatch_queue_create`** το τρίτο όρισμα είναι ένα `dispatch_queue_attr_t`, το οποίο συνήθως είναι είτε `DISPATCH_QUEUE_SERIAL` (που στην πραγματικότητα είναι NULL) είτε `DISPATCH_QUEUE_CONCURRENT` που είναι ένας δείκτης σε μια δομή `dispatch_queue_attr_t` που επιτρέπει τον έλεγχο ορισμένων παραμέτρων της ουράς.

### Αντικείμενα αποστολής

Υπάρχουν αρκετά αντικείμενα που χρησιμοποιεί το libdispatch και οι ουρές και τα blocks είναι μόνο 2 από αυτά. Είναι δυνατόν να δημιουργήσετε αυτά τα αντικείμενα με το `dispatch_object_create`:

* `block`
* `data`: Μπλοκ δεδομένων
* `group`: Ομάδα blocks
* `io`: Ασύγχρονα αιτήματα I/O
* `mach
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
Και αυτό είναι ένα παράδειγμα χρήσης **παραλληλισμού** με το **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** είναι μια βιβλιοθήκη που παρέχει **δεσμεύσεις Swift** στο πλαίσιο Grand Central Dispatch (GCD) το οποίο αρχικά έχει γραφτεί σε C.\
Η βιβλιοθήκη **`libswiftDispatch`** τυλίγει τα APIs του C GCD σε μια διεπαφή που είναι πιο φιλική προς τη γλώσσα Swift, κάνοντας το πιο εύκολο και πιο ευανάγνωστο για τους προγραμματιστές Swift να εργαστούν με το GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Παράδειγμα κώδικα**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

Το παρακάτω σενάριο του Frida μπορεί να χρησιμοποιηθεί για **ενσωμάτωση σε αρκετές λειτουργίες `dispatch`** και εξαγωγή του ονόματος της ουράς, του αναστροφής και του block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Προς το παρόν το Ghidra δεν κατανοεί ούτε τη δομή ObjectiveC **`dispatch_block_t`**, ούτε αυτή της **`swift_dispatch_block`**.

Έτσι, αν θέλετε να τις κατανοήσει, μπορείτε απλά να τις **δηλώσετε**:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Στη συνέχεια, βρείτε ένα σημείο στον κώδικα όπου χρησιμοποιούνται:

{% hint style="success" %}
Σημειώστε όλες τις αναφορές που γίνονται στο "block" για να καταλάβετε πώς μπορείτε να καταλάβετε ότι η δομή χρησιμοποιείται.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Κάντε δεξί κλικ στη μεταβλητή -> Αλλαγή τύπου μεταβλητής και επιλέξτε σε αυτήν την περίπτωση **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Το Ghidra θα επαναγράψει αυτόματα τα πάντα:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Αναφορές

* [**\*OS Internals, Volume I: User Mode. Από τον Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
