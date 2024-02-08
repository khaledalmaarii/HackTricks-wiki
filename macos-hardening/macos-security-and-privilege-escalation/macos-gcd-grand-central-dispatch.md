# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informações Básicas

**Grand Central Dispatch (GCD),** também conhecido como **libdispatch**, está disponível tanto no macOS quanto no iOS. É uma tecnologia desenvolvida pela Apple para otimizar o suporte de aplicativos para execução concorrente (multithreaded) em hardware multicore.

**GCD** fornece e gerencia **filas FIFO** para as quais seu aplicativo pode **enviar tarefas** na forma de **objetos de bloco**. Blocos enviados para filas de despacho são **executados em um pool de threads** totalmente gerenciado pelo sistema. GCD cria automaticamente threads para executar as tarefas nas filas de despacho e agenda essas tarefas para serem executadas nos núcleos disponíveis.

{% hint style="success" %}
Em resumo, para executar código em **paralelo**, os processos podem enviar **blocos de código para o GCD**, que cuidará de sua execução. Portanto, os processos não criam novas threads; **o GCD executa o código fornecido com seu próprio pool de threads**.
{% endhint %}

Isso é muito útil para gerenciar a execução paralela com sucesso, reduzindo significativamente o número de threads que os processos criam e otimizando a execução paralela. Isso é ideal para tarefas que requerem **grande paralelismo** (força bruta?) ou para tarefas que não devem bloquear a thread principal: Por exemplo, a thread principal no iOS lida com interações de UI, então qualquer outra funcionalidade que possa fazer o aplicativo travar (pesquisa, acesso a uma web, leitura de um arquivo...) é gerenciada dessa maneira.

## Objective-C

Em Objetive-C, existem diferentes funções para enviar um bloco a ser executado em paralelo:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Submete um bloco para execução assíncrona em uma fila de despacho e retorna imediatamente.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Submete um objeto de bloco para execução e retorna após a conclusão desse bloco.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Executa um objeto de bloco apenas uma vez durante a vida útil de um aplicativo.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Submete um item de trabalho para execução e retorna somente após a conclusão. Ao contrário de [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), esta função respeita todos os atributos da fila ao executar o bloco.

Essas funções esperam esses parâmetros: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

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

A **`libswiftDispatch`** é uma biblioteca que fornece **ligações Swift** para o framework Grand Central Dispatch (GCD) originalmente escrito em C.\
A biblioteca **`libswiftDispatch`** encapsula as APIs C do GCD em uma interface mais amigável ao Swift, tornando mais fácil e intuitivo para os desenvolvedores Swift trabalharem com o GCD.

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

Atualmente, o Ghidra não entende nem a estrutura **`dispatch_block_t`** do ObjectiveC, nem a **`swift_dispatch_block`**.

Portanto, se você deseja que ele as entenda, você pode simplesmente **declará-las**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Em seguida, encontre um local no código onde elas são **usadas**:

{% hint style="success" %}
Observe todas as referências feitas a "block" para entender como você pode descobrir que a estrutura está sendo usada.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Clique com o botão direito na variável -> Alterar Tipo de Variável e selecione neste caso **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

O Ghidra irá reescrever automaticamente tudo:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>
