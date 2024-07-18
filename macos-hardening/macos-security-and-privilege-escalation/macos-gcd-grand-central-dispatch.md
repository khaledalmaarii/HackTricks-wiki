# macOS GCD - Grand Central Dispatch

{% hint style="success" %}
Impara e pratica l'Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>
{% endhint %}

## Informazioni di Base

**Grand Central Dispatch (GCD),** noto anche come **libdispatch** (`libdispatch.dyld`), è disponibile sia su macOS che su iOS. Si tratta di una tecnologia sviluppata da Apple per ottimizzare il supporto dell'applicazione per l'esecuzione concorrente (multithreaded) sull'hardware multicore.

**GCD** fornisce e gestisce **code FIFO** a cui la tua applicazione può **inviare attività** sotto forma di **oggetti block**. I blocchi inviati alle code di invio vengono **eseguiti su un pool di thread** completamente gestito dal sistema. GCD crea automaticamente thread per eseguire le attività nelle code di invio e pianifica l'esecuzione di tali attività sui core disponibili.

{% hint style="success" %}
In sintesi, per eseguire codice in **parallelo**, i processi possono inviare **blocchi di codice a GCD**, che si occuperà della loro esecuzione. Pertanto, i processi non creano nuovi thread; **GCD esegue il codice fornito con il proprio pool di thread** (che potrebbe aumentare o diminuire secondo necessità).
{% endhint %}

Questo è molto utile per gestire con successo l'esecuzione parallela, riducendo notevolmente il numero di thread creati dai processi e ottimizzando l'esecuzione parallela. Questo è ideale per attività che richiedono **grande parallelismo** (forza bruta?) o per attività che non dovrebbero bloccare il thread principale: ad esempio, il thread principale su iOS gestisce le interazioni dell'interfaccia utente, quindi qualsiasi altra funzionalità che potrebbe far bloccare l'applicazione (ricerca, accesso a un sito web, lettura di un file...) è gestita in questo modo.

### Blocchi

Un blocco è una **sezione di codice autocontenuta** (come una funzione con argomenti che restituisce un valore) e può anche specificare variabili vincolate.\
Tuttavia, a livello di compilatore i blocchi non esistono, sono `os_object`. Ciascuno di questi oggetti è formato da due strutture:

* **letterale del blocco**:&#x20;
* Inizia con il campo **`isa`**, che punta alla classe del blocco:
* `NSConcreteGlobalBlock` (blocchi da `__DATA.__const`)
* `NSConcreteMallocBlock` (blocchi nello heap)
* `NSConcreateStackBlock` (blocchi nello stack)
* Ha **`flags`** (che indicano i campi presenti nel descrittore del blocco) e alcuni byte riservati
* Il puntatore alla funzione da chiamare
* Un puntatore al descrittore del blocco
* Variabili importate dal blocco (se presenti)
* **descrittore del blocco**: La sua dimensione dipende dai dati presenti (come indicato nei flag precedenti)
* Ha alcuni byte riservati
* La sua dimensione
* Di solito avrà un puntatore a una firma in stile Objective-C per sapere di quanto spazio è necessario per i parametri (flag `BLOCK_HAS_SIGNATURE`)
* Se le variabili sono referenziate, questo blocco avrà anche puntatori a un aiutante di copia (che copia il valore all'inizio) e a un aiutante di smaltimento (liberandolo).

### Code di Invio

Una coda di invio è un oggetto nominato che fornisce l'ordinamento FIFO dei blocchi per le esecuzioni.

I blocchi vengono impostati nelle code per essere eseguiti e supportano 2 modalità: `DISPATCH_QUEUE_SERIAL` e `DISPATCH_QUEUE_CONCURRENT`. Naturalmente il **seriale** non avrà problemi di condizione di gara poiché un blocco non verrà eseguito fino a quando il precedente non sarà terminato. Ma **l'altro tipo di coda potrebbe averlo**.

Code predefinite:

* `.main-thread`: Da `dispatch_get_main_queue()`
* `.libdispatch-manager`: Gestore delle code di GCD
* `.root.libdispatch-manager`: Gestore delle code di GCD
* `.root.maintenance-qos`: Attività a priorità più bassa
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Disponibile come `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Priorità più alta
* `.root.background-qos.overcommit`

Si noti che sarà il sistema a decidere **quali thread gestiscono quali code in ogni momento** (più thread potrebbero lavorare nella stessa coda o lo stesso thread potrebbe lavorare in code diverse in un certo momento)

#### Attributi

Quando si crea una coda con **`dispatch_queue_create`** il terzo argomento è un `dispatch_queue_attr_t`, che di solito è o `DISPATCH_QUEUE_SERIAL` (che in realtà è NULL) o `DISPATCH_QUEUE_CONCURRENT` che è un puntatore a una struttura `dispatch_queue_attr_t` che consente di controllare alcuni parametri della coda.

### Oggetti di Invio

Ci sono diversi oggetti che libdispatch utilizza e le code e i blocchi sono solo 2 di essi. È possibile creare questi oggetti con `dispatch_object_create`:

* `block`
* `data`: Blocchi di dati
* `group`: Gruppo di blocchi
* `io`: Richieste di I/O asincrone
* `mach`: Porte Mach
* `mach_msg`: Messaggi Mach
* `pthread_root_queue`: Una coda con un pool di thread pthread e senza code di lavoro
* `queue`
* `semaphore`
* `source`: Sorgente di eventi

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
E questo è un esempio per utilizzare **il parallelismo** con **`dispatch_async`**:
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

**`libswiftDispatch`** è una libreria che fornisce **binding Swift** al framework Grand Central Dispatch (GCD) originariamente scritto in C.\
La libreria **`libswiftDispatch`** incapsula le API C GCD in un'interfaccia più amichevole per Swift, rendendo più semplice e intuitivo per gli sviluppatori Swift lavorare con GCD.

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

Il seguente script Frida può essere utilizzato per **agganciarsi a diverse funzioni `dispatch`** ed estrarre il nome della coda, la traccia retrospettiva e il blocco: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Quindi, se vuoi che le comprenda, puoi semplicemente **dichiararle**:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Successivamente, trova un punto nel codice in cui vengono **utilizzate**:

{% hint style="success" %}
Nota tutti i riferimenti al "block" per capire come potresti individuare che la struttura viene utilizzata.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Fai clic destro sulla variabile -> Ridichiara la variabile e seleziona in questo caso **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra riscriverà automaticamente tutto:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

* [**\*OS Internals, Volume I: User Mode. Di Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
{% endhint %}
