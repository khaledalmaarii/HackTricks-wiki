# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

**Grand Central Dispatch (GCD)**, noto anche come **libdispatch**, è disponibile sia su macOS che su iOS. È una tecnologia sviluppata da Apple per ottimizzare il supporto delle applicazioni per l'esecuzione concorrente (multithreaded) su hardware multicore.

**GCD** fornisce e gestisce **code FIFO** a cui la tua applicazione può **inviare attività** sotto forma di **oggetti block**. I blocchi inviati alle code di invio vengono **eseguiti su un pool di thread** completamente gestito dal sistema. GCD crea automaticamente thread per eseguire le attività nelle code di invio e pianifica l'esecuzione di tali attività sui core disponibili.

{% hint style="success" %}
In sintesi, per eseguire codice in **parallelo**, i processi possono inviare **blocchi di codice a GCD**, che si occuperà della loro esecuzione. Pertanto, i processi non creano nuovi thread; **GCD esegue il codice fornito con il proprio pool di thread**.
{% endhint %}

Ciò è molto utile per gestire con successo l'esecuzione parallela, riducendo notevolmente il numero di thread creati dai processi e ottimizzando l'esecuzione parallela. Questo è ideale per attività che richiedono **un grande parallelismo** (brute-forcing?) o per attività che non dovrebbero bloccare il thread principale: ad esempio, il thread principale su iOS gestisce le interazioni dell'interfaccia utente, quindi qualsiasi altra funzionalità che potrebbe far bloccare l'applicazione (ricerca, accesso a un sito web, lettura di un file...) viene gestita in questo modo.

## Objective-C

In Objective-C ci sono diverse funzioni per inviare un blocco da eseguire in parallelo:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Invia un blocco per l'esecuzione asincrona su una coda di invio e restituisce immediatamente.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Invia un oggetto blocco per l'esecuzione e restituisce dopo che il blocco ha finito di eseguire.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Esegue un oggetto blocco solo una volta per tutta la durata di un'applicazione.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Invia un elemento di lavoro per l'esecuzione e restituisce solo dopo che ha finito di eseguire. A differenza di [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), questa funzione rispetta tutti gli attributi della coda quando esegue il blocco.

Queste funzioni si aspettano questi parametri: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Questa è la **struttura di un Blocco**:
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
E questo è un esempio di utilizzo del **parallelismo** con **`dispatch_async`**:
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

**`libswiftDispatch`** è una libreria che fornisce **binding Swift** al framework Grand Central Dispatch (GCD) che è originariamente scritto in C.\
La libreria **`libswiftDispatch`** incapsula le API C GCD in un'interfaccia più amichevole per Swift, rendendo più facile e intuitivo per gli sviluppatori Swift lavorare con GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Esempio di codice**:
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

Il seguente script di Frida può essere utilizzato per **intercettare diverse funzioni `dispatch`** ed estrarre il nome della coda, la traccia di esecuzione e il blocco: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Attualmente Ghidra non comprende né la struttura **`dispatch_block_t`** di ObjectiveC, né quella di **`swift_dispatch_block`**.

Quindi, se vuoi farlo capire, puoi semplicemente **dichiararle**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Successivamente, trova un punto nel codice in cui vengono **utilizzate**:

{% hint style="success" %}
Nota tutti i riferimenti al "block" per capire come puoi individuare l'utilizzo della struttura.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Fai clic con il pulsante destro del mouse sulla variabile -> Retype Variable e seleziona in questo caso **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra riscriverà automaticamente tutto:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF**, consulta i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository GitHub di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
