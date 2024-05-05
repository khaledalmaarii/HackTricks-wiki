# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Taarifa Msingi

**Grand Central Dispatch (GCD),** inayojulikana pia kama **libdispatch** (`libdispatch.dyld`), inapatikana kwenye macOS na iOS. Ni teknolojia iliyoendelezwa na Apple kuboresha msaada wa programu kwa utekelezaji wa sawia (multithreaded) kwenye vifaa vya multicore.

**GCD** hutoa na kusimamia **mistari ya FIFO** ambayo maombi yako yanaweza **kuwasilisha kazi** katika mfumo wa **vitu vya block**. Blocks zilizowasilishwa kwenye mistari ya utekelezaji wa dispatch zina **tekelezwa kwenye dimbwi la nyuzi** linalosimamiwa kabisa na mfumo. GCD inaunda nyuzi kiotomatiki kwa kutekeleza kazi kwenye mistari ya utekelezaji wa dispatch na kupanga kazi hizo zitekelezwe kwenye viini vilivyopo.

{% hint style="success" %}
Kwa muhtasari, ili kutekeleza nambari kwa **sawa**, michakato inaweza kutuma **vitengo vya nambari kwa GCD**, ambayo itahusika na utekelezaji wao. Kwa hivyo, michakato haziumbi nyuzi mpya; **GCD inatekeleza nambari iliyotolewa na dimbwi lake la nyuzi** (ambalo linaweza kuongezeka au kupungua kama inavyohitajika).
{% endhint %}

Hii ni muhimu sana kusimamia utekelezaji wa sawia kwa ufanisi, ikipunguza sana idadi ya nyuzi ambazo michakato huzalisha na kuboresha utekelezaji wa sawia. Hii ni bora kwa kazi zinazohitaji **sawa kubwa** (kuvunja nguvu?) au kwa kazi ambazo hazipaswi kuzuia nyuzi kuu: Kwa mfano, nyuzi kuu kwenye iOS inashughulikia mwingiliano wa UI, kwa hivyo utendaji mwingine wowote ambao unaweza kufanya programu isikae bila kufanya kazi (kutafuta, kupata wavuti, kusoma faili...) unasimamiwa kwa njia hii.

### Blocks

Block ni **sehemu iliyojitegemea ya nambari** (kama kazi na hoja zinazorudisha thamani) na inaweza pia kubainisha pembe zilizofungwa.\
Walakini, kwenye kiwango cha kielekezi, blocks hazipo, ni `os_object`s. Kila moja ya vitu hivi inaundwa na miundo miwili:

* **block literal**:&#x20;
* Inaanza na uga wa **`isa`**, ukionyesha darasa la block:
* `NSConcreteGlobalBlock` (blocks kutoka `__DATA.__const`)
* `NSConcreteMallocBlock` (blocks kwenye rundo)
* `NSConcreateStackBlock` (blocks kwenye rundo)
* Ina **`flags`** (ikionyesha uga uliopo katika maelezo ya block) na baadhi ya baiti zilizohifadhiwa
* Kiashiria cha kazi ya kupiga simu
* Kiashiria kwa maelezo ya block
* Pembe zilizoingizwa za block (ikiwapo zipo)
* **muelezo wa block**: Ukubwa wake unategemea data iliyopo (kama ilivyoelezwa katika bendera za awali)
* Ina baadhi ya baiti zilizohifadhiwa
* Ukubwa wake
* Kawaida itakuwa na kiashiria kwa saini ya mtindo wa Objective-C ili kujua ni kiasi gani cha nafasi inahitajika kwa vigezo (bendera `BLOCK_HAS_SIGNATURE`)
* Ikiwa pembe zinarejelewa, block hii pia itakuwa na viashiria kwa msaidizi wa nakala (kunakili thamani mwanzoni) na msaidizi wa kutolea mbali (kuifuta).

### Mistari ya Utekelezaji

Mstari wa utekelezaji wa dispatch ni kitu kilichopewa jina linalotoa upangaji wa FIFO wa blocks kwa utekelezaji.

Blocks hupangwa kwenye mistari ili kutekelezwa, na hizi zinasaidia njia 2: `DISPATCH_QUEUE_SERIAL` na `DISPATCH_QUEUE_CONCURRENT`. Kwa hakika **ile ya mfululizo** **haitakuwa na shida ya hali ya mbio** kwani block haitatekelezwa hadi ile iliyotangulia imemaliza. Lakini **aina nyingine ya mstari wa utekelezaji inaweza kuwa nayo**.

Mistari ya msingi:

* `.main-thread`: Kutoka `dispatch_get_main_queue()`
* `.libdispatch-manager`: Meneja wa mistari wa GCD
* `.root.libdispatch-manager`: Meneja wa mistari wa GCD
* `.root.maintenance-qos`: Kazi zenye kipaumbele cha chini
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Inapatikana kama `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Kipaumbele cha juu
* `.root.background-qos.overcommit`

Tambua kuwa itakuwa mfumo ndio utakaoamua **nyuzi zipi zitashughulikia mistari gani wakati wowote** (nyuzi nyingi zinaweza kufanya kazi kwenye mstari mmoja au nyuzi ile ile inaweza kufanya kazi kwenye mistari tofauti wakati fulani)

#### Sifa

Wakati wa kuunda mstari na **`dispatch_queue_create`** hoja ya tatu ni `dispatch_queue_attr_t`, ambayo kawaida ni au `DISPATCH_QUEUE_SERIAL` (ambayo kimsingi ni NULL) au `DISPATCH_QUEUE_CONCURRENT` ambayo ni kiashiria kwa muundo wa `dispatch_queue_attr_t` ambao huruhusu kudhibiti baadhi ya vigezo vya mstari.

### Vitu vya Utekelezaji

Kuna vitu kadhaa ambavyo libdispatch hutumia na mistari na blocks ni vitu 2 tu kati yao. Ni rahisi kuunda vitu hivi na `dispatch_object_create`:

* `block`
* `data`: Blocks za data
* `group`: Kikundi cha blocks
* `io`: Maombi ya I/O ya Async
* `mach`: Bandari za Mach
* `mach_msg`: Ujumbe wa Mach
* `pthread_root_queue`: Mstari na dimbwi la nyuzi za pthread na sio mistari ya kazi
* `queue`
* `semaphore`
* `source`: Chanzo cha tukio

## Objective-C

Katika Objetive-C kuna kazi tofauti za kutuma block ili itekelezwe kwa sawia:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Inawasilisha block kwa utekelezaji wa sawia kwenye mstari wa utekelezaji wa dispatch na kurudi mara moja.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Inawasilisha kipengee cha block kwa utekelezaji na kurudi baada ya block hiyo kumaliza kutekelezwa.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Inatekeleza kipengee cha block mara moja tu kwa maisha ya programu.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Inawasilisha kipengee cha kazi kwa utekelezaji na kurudi baada ya kumaliza kutekelezwa. Tofauti na [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), kazi hii inaheshimu sifa zote za mstari wakati inatekeleza block.

Kazi hizi zinatarajia vigezo hivi: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Hii ni **muundo wa Block**:
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
Na hii ni mfano wa kutumia **ujumuishaji** na **`dispatch_async`**:
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

**`libswiftDispatch`** ni maktaba inayotoa **kufungamanisha Swift** kwa mfumo wa Grand Central Dispatch (GCD) ambao awali uliandikwa kwa C.\
Maktaba ya **`libswiftDispatch`** inafunika APIs za C GCD kwa kiolesura cha kirafiki zaidi cha Swift, ikifanya iwe rahisi na ya kihisia zaidi kwa watengenezaji wa Swift kufanya kazi na GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Mfano wa nambari**:
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

Skripti ya Frida ifuatayo inaweza kutumika kufanya **hook katika kazi kadhaa za `dispatch`** na kutoa jina la foleni, nyuma ya mstari na kizuizi: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Kwa sasa Ghidra haielewi wala muundo wa **`dispatch_block_t`** wa ObjectiveC, wala ule wa **`swift_dispatch_block`**.

Hivyo, ikiwa unataka ielewe, unaweza tu **kuzitangaza**:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Kisha, tafuta sehemu katika nambari ambapo zinatumiwa:

{% hint style="success" %}
Tambua marejeo yote yaliyofanywa kwa "block" ili kuelewa jinsi unavyoweza kugundua kuwa muundo unatumika.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Bonyeza kulia kwenye kipengee -> Badilisha Aina ya Kipengee na chagua katika kesi hii **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra itaandika tena kila kitu kiotomatiki:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Marejeo

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
