# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

**Grand Central Dispatch (GCD),** ook bekend as **libdispatch** (`libdispatch.dyld`), is beskikbaar op beide macOS en iOS. Dit is 'n tegnologie wat deur Apple ontwikkel is om programondersteuning te optimaliseer vir gelyktydige (multidraad) uitvoering op meerkern-hardeware.

**GCD** voorsien en bestuur **FIFO-rye** waar jou aansoek kan **take indien** in die vorm van **blokvoorwerpe**. Blokke wat na verspreidingsrye gestuur word, word **uitgevoer op 'n poel van drade** wat volledig deur die stelsel bestuur word. GCD skep outomaties drade vir die uitvoering van die take in die verspreidingsrye en skeduleer daardie take om op die beskikbare kerne uit te voer.

{% hint style="success" %}
Opsomming, om kode **gelyktydig** uit te voer, kan prosesse **blokke kode na GCD stuur**, wat sal sorg vir hul uitvoering. Daarom skep prosesse nie nuwe drade nie; **GCD voer die gegewe kode uit met sy eie poel van drade** (wat moontlik vermeerder of verminder soos nodig).
{% endhint %}

Dit is baie nuttig om parallelle uitvoering suksesvol te bestuur, wat die aantal drade wat prosesse skep aansienlik verminder en die parallelle uitvoering optimaliseer. Dit is ideaal vir take wat **groot parallelisme** vereis (brute-krag?) of vir take wat nie die hoofdraad moet blokkeer nie: Byvoorbeeld, die hoofdraad op iOS hanteer UI-interaksies, dus enige ander funksionaliteit wat die program kan laat vashang (soek, 'n web besoek, 'n lêer lees...) word op hierdie manier hanteer.

### Blokke

'n Blok is 'n **selfstandige afdeling kode** (soos 'n funksie met argumente wat 'n waarde teruggee) en kan ook gebonde veranderlikes spesifiseer.\
Tog, op kompilervlak bestaan blokke nie, hulle is `os_object`s. Elkeen van hierdie voorwerpe word gevorm deur twee strukture:

* **blokliteraal**:&#x20;
* Dit begin met die **`isa`** veld, wat na die blok se klas wys:
* `NSConcreteGlobalBlock` (blokke van `__DATA.__const`)
* `NSConcreteMallocBlock` (blokke in die hoop)
* `NSConcreateStackBlock` (blokke in stapel)
* Dit het **`vlaggies`** (wat aandui watter velde teenwoordig is in die blokbeskrywing) en 'n paar gereserveerde byte
* Die funksie-aanwysers om te roep
* 'n aanwyser na die blokbeskrywing
* Ingevoerde blokveranderlikes (indien enige)
* **blokbeskrywing**: Dit se grootte hang af van die data wat teenwoordig is (soos aangedui in die vorige vlaggies)
* Dit het 'n paar gereserveerde byte
* Die grootte daarvan
* Dit sal gewoonlik 'n aanwyser na 'n Objective-C-stylhandtekening hê om te weet hoeveel spasie vir die parameters benodig word (vlag `BLOCK_HAS_SIGNATURE`)
* As veranderlikes verwys word, sal hierdie blok ook aanwysers hê na 'n kopiehulp (wat die waarde aan die begin kopieer) en 'n verwyderhulp (om dit vry te stel).

### Ry

'n Verspreidingsry is 'n benoemde voorwerp wat FIFO-orden van blokke vir uitvoering voorsien.

Blokke word in rye geplaas om uitgevoer te word, en hierdie ondersteun 2 modusse: `DISPATCH_QUEUE_SERIAL` en `DISPATCH_QUEUE_CONCURRENT`. Natuurlik sal die **seriële** een **geen wedstrydkondisieprobleme hê** nie aangesien 'n blok nie uitgevoer sal word totdat die vorige een klaar is nie. Maar **die ander tipe ry kan dit hê**.

Verstekrye:

* `.main-thread`: Vanaf `dispatch_get_main_queue()`
* `.libdispatch-manager`: GCD se rybestuurder
* `.root.libdispatch-manager`: GCD se rybestuurder
* `.root.maintenance-qos`: Laagste prioriteitstake
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Beskikbaar as `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Hoogste prioriteit
* `.root.background-qos.overcommit`

Let daarop dat dit die stelsel sal wees wat besluit **watter drade watter rye op enige tyd hanteer** (veral drade kan in dieselfde ry werk of dieselfde draad kan op 'n stadium in verskillende rye werk)

#### Eienskappe

Wanneer 'n ry geskep word met **`dispatch_queue_create`** is die derde argument 'n `dispatch_queue_attr_t`, wat gewoonlik ofwel `DISPATCH_QUEUE_SERIAL` (wat eintlik NULL is) of `DISPATCH_QUEUE_CONCURRENT` is wat 'n aanwyser na 'n `dispatch_queue_attr_t` struktuur is wat toelaat om sekere parameters van die ry te beheer.

### Verspreidingsvoorwerpe

Daar is verskeie voorwerpe wat libdispatch gebruik en rye en blokke is net 2 van hulle. Dit is moontlik om hierdie voorwerpe te skep met `dispatch_object_create`:

* `blok`
* `data`: Datablokke
* `groep`: Groep van blokke
* `io`: Asyns I/O-versoeke
* `mach`: Mach-poorte
* `mach_msg`: Mach-boodskappe
* `pthread_root_queue`: 'n Ry met 'n pthread-draadpoel en nie werkrye nie
* `ry`
* `semaphore`
* `bron`: Gebeurtenisbron

## Objective-C

In Objective-C is daar verskillende funksies om 'n blok te stuur om parallel uitgevoer te word:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Stuur 'n blok vir asynchrone uitvoering na 'n verspreidingsry en keer dadelik terug.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Stuur 'n blokvoorwerp vir uitvoering en keer terug nadat daardie blok klaar is met uitvoer.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Voer 'n blokvoorwerp net een keer uit vir die leeftyd van 'n aansoek.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Stuur 'n werkeenheid vir uitvoering en keer slegs terug nadat dit klaar is met uitvoer. Anders as [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), respekteer hierdie funksie alle eienskappe van die ry wanneer dit die blok uitvoer.

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

Die volgende Frida-skrip kan gebruik word om in verskeie `dispatch`-funksies in te hake en die tou naam, die agterspoor en die blok te onttrek: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Tans Ghidra verstaan nie die ObjectiveC **`dispatch_block_t`** struktuur nie, ook nie die **`swift_dispatch_block`** een nie.

So as jy wil hê dit moet hulle verstaan, kan jy hulle net **declare**:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Vind dan 'n plek in die kode waar hulle **gebruik** word:

{% hint style="success" %}
Merk alle verwysings na "block" om te verstaan hoe jy kan uitvind dat die struktuur gebruik word.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Regsklik op die veranderlike -> Herklassifiseer Veranderlike en kies in hierdie geval **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra sal outomaties alles herskryf:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Verwysings

* [**\*OS Internals, Volume I: User Mode. Deur Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
