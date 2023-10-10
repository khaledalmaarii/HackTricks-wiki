# macOS GCD - Grand Central Dispatch

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

**Grand Central Dispatch (GCD)**, também conhecido como **libdispatch**, está disponível tanto no macOS quanto no iOS. É uma tecnologia desenvolvida pela Apple para otimizar o suporte de aplicativos para execução concorrente (multithreaded) em hardware multicore.

**GCD** fornece e gerencia **filas FIFO** para as quais seu aplicativo pode **enviar tarefas** na forma de **objetos de bloco**. Blocos enviados para filas de despacho são **executados em um pool de threads** totalmente gerenciado pelo sistema. O GCD cria automaticamente threads para executar as tarefas nas filas de despacho e agenda essas tarefas para serem executadas nos núcleos disponíveis.

{% hint style="success" %}
Em resumo, para executar código em **paralelo**, os processos podem enviar **blocos de código para o GCD**, que cuidará de sua execução. Portanto, os processos não criam novas threads; **o GCD executa o código fornecido com seu próprio pool de threads**.
{% endhint %}

Isso é muito útil para gerenciar a execução paralela com sucesso, reduzindo significativamente o número de threads que os processos criam e otimizando a execução paralela. Isso é ideal para tarefas que requerem **grande paralelismo** (força bruta?) ou para tarefas que não devem bloquear a thread principal: por exemplo, a thread principal no iOS lida com interações de interface do usuário, então qualquer outra funcionalidade que possa fazer com que o aplicativo trave (pesquisar, acessar a web, ler um arquivo...) é gerenciada dessa maneira.

## Objective-C

No Objective-C, existem diferentes funções para enviar um bloco para ser executado em paralelo:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Envia um bloco para execução assíncrona em uma fila de despacho e retorna imediatamente.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Envia um objeto de bloco para execução e retorna após a conclusão desse bloco.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Executa um objeto de bloco apenas uma vez durante a vida útil de um aplicativo.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Envia um item de trabalho para execução e retorna somente após a conclusão. Ao contrário de [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), essa função respeita todos os atributos da fila ao executar o bloco.

Essas funções esperam os seguintes parâmetros: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Esta é a **estrutura de um Bloco**:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
E este é um exemplo de como usar **paralelismo** com **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

A biblioteca **`libswiftDispatch`** fornece **ligações Swift** para o framework Grand Central Dispatch (GCD), que é originalmente escrito em C.\
A biblioteca **`libswiftDispatch`** envolve as APIs C do GCD em uma interface mais amigável para Swift, tornando mais fácil e intuitivo para os desenvolvedores Swift trabalharem com GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Exemplo de código**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

O seguinte script Frida pode ser usado para **interceptar várias funções `dispatch`** e extrair o nome da fila, o rastreamento de pilha e o bloco: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Atualmente, o Ghidra não entende nem a estrutura **`dispatch_block_t`** do ObjectiveC, nem a estrutura **`swift_dispatch_block`**.

Portanto, se você quiser que ele entenda, você pode apenas **declará-las**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Em seguida, encontre um local no código onde elas são **usadas**:

{% hint style="success" %}
Observe todas as referências feitas a "block" para entender como você pode descobrir que a estrutura está sendo usada.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Clique com o botão direito na variável -> Retype Variable e selecione neste caso **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

O Ghidra irá reescrever automaticamente tudo:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
