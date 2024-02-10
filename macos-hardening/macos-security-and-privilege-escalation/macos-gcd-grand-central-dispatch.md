# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Βασικές Πληροφορίες

Το **Grand Central Dispatch (GCD)**, γνωστό και ως **libdispatch**, είναι διαθέσιμο τόσο στο macOS όσο και στο iOS. Είναι μια τεχνολογία που αναπτύχθηκε από την Apple για τη βελτιστοποίηση της υποστήριξης των εφαρμογών για την ταυτόχρονη (πολυνηματική) εκτέλεση σε πολυπύρηνο υλικό.

Το **GCD** παρέχει και διαχειρίζεται **ουρές FIFO**, στις οποίες η εφαρμογή σας μπορεί να **υποβάλει εργασίες** σε μορφή **block objects**. Τα blocks που υποβάλλονται στις ουρές αποστολής εκτελούνται σε ένα πισίνα νημάτων που διαχειρίζεται πλήρως το σύστημα. Το GCD αυτόματα δημιουργεί νήματα για την εκτέλεση των εργασιών στις ουρές αποστολής και προγραμματίζει αυτές τις εργασίες να εκτελούνται στους διαθέσιμους πυρήνες.

{% hint style="success" %}
Συνολικά, για να εκτελεστεί κώδικας **παράλληλα**, οι διεργασίες μπορούν να στείλουν **blocks κώδικα στο GCD**, το οποίο θα φροντίσει για την εκτέλεσή τους. Επομένως, οι διεργασίες δεν δημιουργούν νέα νήματα. Το **GCD εκτελεί τον δοθέντα κώδικα με τη δική του πισίνα νημάτων**.
{% endhint %}

Αυτό είναι πολύ χρήσιμο για τη διαχείριση της παράλληλης εκτέλεσης με επιτυχία, μειώνοντας σημαντικά τον αριθμό των νημάτων που δημιουργούν οι διεργασίες και βελτιστοποιώντας την παράλληλη εκτέλεση. Αυτό είναι ιδανικό για εργασίες που απαιτούν **μεγάλη παράλληλη εκτέλεση** (brute-forcing;) ή για εργασίες που δεν πρέπει να αποκλείουν το κύριο νήμα: Για παράδειγμα, το κύριο νήμα στο iOS χειρίζεται τις αλληλεπιδράσεις με το UI, οπότε οποιαδήποτε άλλη λειτουργικότητα που θα μπορούσε να κάνει την εφαρμογή να κολλήσει (αναζήτηση, πρόσβαση σε ιστοσελίδα, ανάγνωση αρχείου...) διαχειρίζεται με αυτόν τον τρόπο.

## Objective-C

Στο Objective-C υπάρχουν διάφορες συναρτήσεις για να στείλετε ένα block για εκτέλεση παράλληλα:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Υποβάλλει ένα block για ασύγχρονη εκτέλεση σε μια ουρά αποστολής και επιστρέφει αμέσως.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Υποβάλλει ένα block για εκτέλεση και επιστρέφει μετά την ολοκλήρωση του block.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Εκτελεί ένα block μόνο μία φορά για τη διάρκεια ενός προγράμματος.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Υποβάλλει ένα αντικείμενο εργασίας για εκτέλεση και επιστρέφει μόνο μετά την ολοκλήρωση της εκτέλεσής του. Αντίθετα από το [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), αυτή η συνάρτηση σέβεται όλα τα χαρακτηριστικά της ουράς κατά την εκτέλεση του block.

Αυτές οι συναρτήσεις αναμένουν τις παρακάτω παραμέτρους: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Αυτή είναι η **δομή ενός Block**:
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
Και αυτό είναι ένα παράδειγμα για να χρησιμοποιήσετε το **παραλληλισμό** με το **`dispatch_async`**:
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

Η βιβλιοθήκη **`libswiftDispatch`** παρέχει **δεσμεύσεις Swift** στο πλαίσιο Grand Central Dispatch (GCD) που αρχικά έχει γραφεί σε C.\
Η βιβλιοθήκη **`libswiftDispatch`** εγκαλύπτει τις C GCD APIs με ένα πιο φιλικό προς την Swift διεπαφή, καθιστώντας το πιο εύκολο και πιο ευανάγνωστο για τους προγραμματιστές Swift να εργαστούν με το GCD.

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

Το παρακάτω Frida script μπορεί να χρησιμοποιηθεί για να **συνδεθεί σε διάφορες συναρτήσεις `dispatch`** και να εξάγει το όνομα της ουράς, το backtrace και το block: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Αυτή τη στιγμή το Ghidra δεν κατανοεί ούτε τη δομή **`dispatch_block_t`** της ObjectiveC, ούτε τη δομή **`swift_dispatch_block`**.

Έτσι, αν θέλετε να τις κατανοήσει, μπορείτε απλά να τις **δηλώσετε**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Στη συνέχεια, βρείτε ένα σημείο στον κώδικα όπου χρησιμοποιούνται:

{% hint style="success" %}
Σημειώστε όλες τις αναφορές που γίνονται στο "block" για να κατανοήσετε πώς μπορείτε να καταλάβετε ότι η δομή χρησιμοποιείται.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Κάντε δεξί κλικ στη μεταβλητή -> Αλλαγή τύπου μεταβλητής και επιλέξτε σε αυτήν την περίπτωση **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Το Ghidra θα επαναγράψει αυτόματα τα πάντα:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Αν θέλετε να δείτε την εταιρεία σας να διαφημίζεται στο HackTricks ή να κατεβάσετε το HackTricks σε μορφή PDF, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
