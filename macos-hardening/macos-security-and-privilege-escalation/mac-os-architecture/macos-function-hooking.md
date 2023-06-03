# Hooking de Fonction macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Interception de Fonction

Créez un **dylib** avec une section **`__interpose`** (ou une section marquée avec **`S_INTERPOSING`**) contenant des tuples de **pointeurs de fonction** qui font référence aux fonctions **originales** et de **remplacement**.

Ensuite, **injectez** la dylib avec **`DYLD_INSERT_LIBRARIES`** (l'interception doit avoir lieu avant le chargement de l'application principale). Évidemment, cette restriction a les **restrictions** appliquées à l'utilisation de DYLD\_INSERT\_LIBRARIES.&#x20;

### Interception de printf

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

    int ret = printf("[+] Hello from interpose\n");
    return ret;
}

__attribute__((used)) static struct { const void *replacement; const void *replacee; } _interpose_printf
__attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&my_printf, (const void *)(unsigned long)&printf };
```
{% endcode %}
{% endtab %}

{% tab title="hello.c" %}

```c
#include <stdio.h>

int main() {
    printf("Hello, world!\n");
    return 0;
}
```

{% endtab %}
{% endtabs %}

Le code ci-dessus est un exemple simple de programme C qui imprime "Hello, world!" sur la console.
```c
//gcc hello.c -o hello
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```
{% endtab %}
{% endtabs %} 

devient

{% endtab %}
{% endtabs %}
```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./hello
[+] Hello from interpose
```
## Méthode Swizzling

En ObjectiveC, voici comment une méthode est appelée : `[myClassInstance nameOfTheMethodFirstParam:param1 secondParam:param2]`

Il est nécessaire de connaître l'**objet**, la **méthode** et les **paramètres**. Et lorsqu'une méthode est appelée, un **message est envoyé** en utilisant la fonction **`objc_msgSend`** : `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(someObject, @selector(method1p1:p2:), value1, value2);`

L'objet est **`someObject`**, la méthode est **`@selector(method1p1:p2:)`** et les arguments sont **value1**, **value2**.

En suivant les structures d'objet, il est possible d'atteindre un **tableau de méthodes** où les **noms** et les **pointeurs** vers le code de la méthode sont **stockés**.

{% hint style="danger" %}
Notez que parce que les méthodes et les classes sont accessibles en fonction de leurs noms, ces informations sont stockées dans le binaire, il est donc possible de les récupérer avec `otool -ov </path/bin>` ou [`class-dump </path/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Accès aux méthodes brutes

Il est possible d'accéder aux informations des méthodes telles que le nom, le nombre de paramètres ou l'adresse comme dans l'exemple suivant :
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
### Méthode Swizzling avec method\_exchangeImplementations

La fonction method\_exchangeImplementations permet de changer l'adresse d'une fonction pour une autre. Ainsi, lorsque la fonction est appelée, c'est l'autre qui est exécutée.
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
    // Now when the method substringFromIndex is called, what is really coode is swizzledSubstringFromIndex
    // And when swizzledSubstringFromIndex is called, substringFromIndex is really colled
    
    // Example usage
    NSString *myString = @"Hello, World!";
    NSString *subString = [myString substringFromIndex:7];
    NSLog(@"Substring: %@", subString);
    
    return 0;
}
```
### Méthode Swizzling avec method\_setImplementation

Le format précédent est étrange car vous modifiez l'implémentation de 2 méthodes l'une par l'autre. En utilisant la fonction **`method_setImplementation`**, vous pouvez **changer** l'**implémentation** d'une **méthode pour une autre**.

N'oubliez pas de **stocker l'adresse de l'implémentation de l'originale** si vous allez l'appeler depuis la nouvelle implémentation avant de l'écraser, car il sera beaucoup plus compliqué de localiser cette adresse plus tard.
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
## Méthodologie d'attaque de Hooking

Sur cette page, différentes façons de hooker des fonctions ont été discutées. Cependant, elles impliquaient **l'exécution de code à l'intérieur du processus pour attaquer**.

Pour ce faire, la technique la plus simple à utiliser est d'injecter un [Dyld via des variables d'environnement ou de détournement](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md). Cependant, je suppose que cela pourrait également être fait via [l'injection de processus Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

Cependant, les deux options sont **limitées** aux binaires/processus **non protégés**. Consultez chaque technique pour en savoir plus sur les limitations.

Cependant, une attaque de hooking de fonction est très spécifique, un attaquant fera cela pour **voler des informations sensibles à l'intérieur d'un processus** (sinon, vous feriez simplement une attaque d'injection de processus). Et ces informations sensibles pourraient être situées dans des applications téléchargées par l'utilisateur telles que MacPass.

Le vecteur d'attaque de l'attaquant consisterait à trouver une vulnérabilité ou à supprimer la signature de l'application, à injecter la variable d'environnement **`DYLD_INSERT_LIBRARIES`** via le fichier Info.plist de l'application en ajoutant quelque chose comme:
```xml
<key>LSEnvironment</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key> 
    <string>/Applications/MacPass.app/Contents/malicious.dylib</string>
</dict>
```
Ajoutez dans cette bibliothèque le code de hooking pour exfiltrer les informations : mots de passe, messages...

## Références

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
