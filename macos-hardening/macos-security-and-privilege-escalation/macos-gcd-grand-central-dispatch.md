# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

**Grand Central Dispatch (GCD),** ook bekend as **libdispatch**, is beskikbaar op beide macOS en iOS. Dit is 'n tegnologie wat deur Apple ontwikkel is om programondersteuning te optimaliseer vir gelyktydige (multidraad) uitvoering op multikern-hardeware.

**GCD** voorsien en bestuur **FIFO-rye** waarheen jou program take in die vorm van **blokvoorwerpe** kan **indien**. Blokke wat na verspreidingsrye gestuur word, word **uitgevoer op 'n pool van drade** wat volledig deur die stelsel bestuur word. GCD skep outomaties drade vir die uitvoering van die take in die verspreidingsrye en skeduleer daardie take om op die beskikbare kerne uit te voer.

{% hint style="success" %}
Kortom, om kode **parallel** uit te voer, kan prosesse **blokke kode na GCD stuur**, wat vir hul uitvoering sal sorg. Daarom skep prosesse nie nuwe drade nie; **GCD voer die gegewe kode met sy eie pool van drade uit**.
{% endhint %}

Dit is baie nuttig om parallelle uitvoering suksesvol te bestuur, waardeur die aantal drade wat prosesse skep aansienlik verminder word en die parallelle uitvoering geoptimaliseer word. Dit is ideaal vir take wat **groot parallelisme** vereis (brute-forcing?) of vir take wat nie die hoofdraad moet blokkeer nie: Byvoorbeeld, die hoofdraad op iOS hanteer UI-interaksies, sodat enige ander funksionaliteit wat die program kan laat vashang (soek, toegang tot 'n web, lees van 'n lêer...) op hierdie manier hanteer word.

## Objective-C

In Objective-C is daar verskillende funksies om 'n blok te stuur om parallel uitgevoer te word:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Stuur 'n blok vir asynchrone uitvoering na 'n verspreidingsry en keer onmiddellik terug.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Stuur 'n blokvoorwerp vir uitvoering en keer terug nadat daardie blok klaar is met uitvoer.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Voer 'n blokvoorwerp slegs een keer uit vir die leeftyd van 'n aansoek.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Stuur 'n werkitem vir uitvoering en keer slegs terug nadat dit klaar is met uitvoer. Anders as [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), respekteer hierdie funksie alle eienskappe van die ry wanneer dit die blok uitvoer.

Hierdie funksies verwag hierdie parameters: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Dit is die **struktuur van 'n Blok**:
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
En hierdie is 'n voorbeeld om **parallelisme** te gebruik met **`dispatch_async`**:
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

**`libswiftDispatch`** is 'n biblioteek wat **Swift-bindings** aan die Grand Central Dispatch (GCD) raamwerk bied wat oorspronklik in C geskryf is.\
Die **`libswiftDispatch`** biblioteek wikkel die C GCD API's in 'n meer Swift-vriendelike koppelvlak, wat dit makliker en intuïtiever maak vir Swift-ontwikkelaars om met GCD te werk.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Kodevoorbeeld**:
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

Die volgende Frida-skrip kan gebruik word om in verskeie `dispatch`-funksies in te hake en die tou-naam, die agtervolging en die blok te onttrek: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Tansaner Ghidra verstaan tans nie die ObjectiveC **`dispatch_block_t`** struktuur nie, sowel as die **`swift_dispatch_block`** een.

As jy wil hê dit moet hulle verstaan, kan jy hulle net **deklareer**:

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

Vind dan 'n plek in die kode waar hulle **gebruik** word:

{% hint style="success" %}
Merk alle verwysings na "block" om te verstaan hoe jy kan uitvind dat die struktuur gebruik word.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

Regsklik op die veranderlike -> Herklassifiseer Veranderlike en kies in hierdie geval **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra sal outomaties alles herskryf:

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>
