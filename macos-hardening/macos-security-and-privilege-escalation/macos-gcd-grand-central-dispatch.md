# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Basiese Inligting

**Grand Central Dispatch (GCD)**, ook bekend as **libdispatch**, is beskikbaar in beide macOS en iOS. Dit is 'n tegnologie wat deur Apple ontwikkel is om programondersteuning te optimaliseer vir gelyktydige (multidraadse) uitvoering op multikern-hardeware.

**GCD** voorsien en bestuur **FIFO-rye** waarheen jou program take in die vorm van **blok-voorwerpe** kan indien. Blokke wat na verspreidingsrye ingedien word, word uitgevoer op 'n stel drade wat volledig deur die stelsel bestuur word. GCD skep outomaties drade om die take in die verspreidingsrye uit te voer en skeduleer daardie take om op die beskikbare kerne uitgevoer te word.

{% hint style="success" %}
Opsommend, om kode **gelyktydig** uit te voer, kan prosesse **blokke kode na GCD stuur**, wat sal sorg vir hul uitvoering. Daarom skep prosesse nie nuwe drade nie; **GCD voer die gegewe kode uit met sy eie stel drade**.
{% endhint %}

Dit is baie nuttig om gelyktydige uitvoering suksesvol te bestuur, waardeur die aantal drade wat prosesse skep aansienlik verminder word en die gelyktydige uitvoering geoptimaliseer word. Dit is ideaal vir take wat **groot gelyktydigheid** vereis (brute force?) of vir take wat nie die hoofdraad moet blokkeer nie: Byvoorbeeld, die hoofdraad op iOS hanteer UI-interaksies, so enige ander funksionaliteit wat die program kan laat hang (soek, toegang tot 'n web, lees van 'n lêer...) word op hierdie manier bestuur.

## Objective-C

In Objective-C is daar verskillende funksies om 'n blok te stuur vir gelyktydige uitvoering:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Dien 'n blok in vir asynchrone uitvoering op 'n verspreidingsry en keer onmiddellik terug.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Dien 'n blokvoorwerp in vir uitvoering en keer terug nadat daardie blok klaar uitgevoer is.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Voer 'n blokvoorwerp slegs een keer uit vir die leeftyd van 'n toepassing.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Dien 'n werkitem in vir uitvoering en keer slegs terug nadat dit klaar uitgevoer is. Anders as [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), respekteer hierdie funksie alle eienskappe van die ry wanneer dit die blok uitvoer.

Hierdie funksies verwag hierdie parameters: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Dit is die **structuur van 'n Blok**:
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
En hier is 'n voorbeeld om **parallelisme** te gebruik met **`dispatch_async`**:
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

**`libswiftDispatch`** is 'n biblioteek wat **Swift-bindings** aan die Grand Central Dispatch (GCD) raamwerk bied, wat oorspronklik in C geskryf is.\
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

Die volgende Frida-skrip kan gebruik word om in te haak by verskeie `dispatch`-funksies en die waglynnaam, die terugspoor en die blok uit te trek: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Tans is Ghidra nie bewus van die ObjectiveC **`dispatch_block_t`** struktuur of die **`swift_dispatch_block`** een nie.

As jy wil hê dit moet dit verstaan, kan jy dit net **verklaar**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Vind dan 'n plek in die kode waar hulle **gebruik** word:

{% hint style="success" %}
Merk alle verwysings na "block" op om te verstaan hoe jy kan uitvind dat die struktuur gebruik word.
{% endhint %}

Klik met die regterknop op die veranderlike -> Herklassifiseer Veranderlike en kies in hierdie geval **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra sal outomaties alles herskryf:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil hê jou **maatskappy geadverteer moet word in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
