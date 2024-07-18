# macOS GCD - Grand Central Dispatch

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Taarifa Msingi

**Grand Central Dispatch (GCD),** inayojulikana pia kama **libdispatch** (`libdispatch.dyld`), inapatikana kwenye macOS na iOS. Ni teknolojia iliyoendelezwa na Apple kuboresha msaada wa programu kwa utekelezaji wa wakati mmoja (multithreaded) kwenye vifaa vya multicore.

**GCD** hutoa na kusimamia **mistari ya FIFO** ambayo programu yako inaweza **kuwasilisha kazi** katika mfumo wa **vitu vya block**. Blocks zilizowasilishwa kwenye mistari ya utekelezaji wa haraka hutekelezwa kwenye dimbwi la nyuzi zinazosimamiwa kabisa na mfumo. GCD inaunda nyuzi kiotomatiki kwa kutekeleza kazi kwenye mistari ya utekelezaji wa haraka na kupanga kazi hizo zitekelezwe kwenye miunganisho inayopatikana.

{% hint style="success" %}
Kwa muhtasari, ili kutekeleza nambari kwa **njia za pamoja**, michakato inaweza kutuma **vitengo vya nambari kwa GCD**, ambayo itahusika na utekelezaji wao. Kwa hivyo, michakato haziumbi nyuzi mpya; **GCD hutekeleza nambari iliyotolewa na dimbwi lake la nyuzi** (ambalo linaweza kuongezeka au kupungua kama inavyohitajika).
{% endhint %}

Hii ni muhimu sana kusimamia utekelezaji wa pamoja kwa ufanisi, ikipunguza sana idadi ya nyuzi ambazo michakato huzalisha na kuboresha utekelezaji wa pamoja. Hii ni bora kwa kazi zinazohitaji **pamoja kubwa** (kuvunja nguvu?) au kwa kazi ambazo hazipaswi kuzuia nyuzi kuu: Kwa mfano, nyuzi kuu kwenye iOS inashughulikia mwingiliano wa UI, kwa hivyo utendaji mwingine wowote ambao unaweza kufanya programu isimame (utafutaji, kupata wavuti, kusoma faili...) unashughulikiwa kwa njia hii.

### Blocks

Block ni **sehemu iliyojitegemea ya nambari** (kama kazi na hoja zinazorudisha thamani) na inaweza pia kubainisha pembe zilizofungwa.\
Walakini, kwenye kiwango cha kisasa cha kompyuta, blocks hazipo, ni `os_object`s. Kila moja ya vitu hivi inaundwa na miundo miwili:

* **block literal**:&#x20;
* Inaanza na uga wa **`isa`**, ukionyesha darasa la block:
* `NSConcreteGlobalBlock` (blocks kutoka `__DATA.__const`)
* `NSConcreteMallocBlock` (blocks kwenye rundo)
* `NSConcreateStackBlock` (blocks kwenye rundo)
* Ina **`flags`** (inayoonyesha mashamba yaliyopo kwenye maelezo ya block) na baadhi ya baiti zilizohifadhiwa
* Kiashiria cha kazi ya kupiga simu
* Kiunganishi kwa maelezo ya block
* Pembe zilizoingizwa za block (ikiwapo zipo)
* **mchoro wa block**: Ukubwa wake unategemea data iliyopo (kama ilivyoelezwa kwenye alama za awali)
* Ina baadhi ya baiti zilizohifadhiwa
* Ukubwa wake
* Kawaida itakuwa na kiashiria kwa saini ya mtindo wa Objective-C ili kujua ni nafasi ngapi inahitajika kwa vigezo (alama `BLOCK_HAS_SIGNATURE`)
* Ikiwa pembe zinarejelewa, block hii pia itakuwa na viunganishi kwa msaidizi wa nakala (kunakili thamani mwanzoni) na msaidizi wa kutolea mbali (kuifuta).

### Mistari

Mstari wa utekelezaji ni kitu kilichopewa jina kinachotoa upangaji wa FIFO wa vitengo kwa utekelezaji.

Blocks hupangwa kwenye mistari ili kutekelezwa, na hizi zinasaidia njia 2: `DISPATCH_QUEUE_SERIAL` na `DISPATCH_QUEUE_CONCURRENT`. Bila shaka **ile ya mfululizo** **haitakuwa na shida ya hali ya mbio** kwani block haitatekelezwa hadi ile iliyotangulia imemaliza. Lakini **aina nyingine ya mstari inaweza kuwa nayo**.

Mistari ya msingi:

* `.main-thread`: Kutoka `dispatch_get_main_queue()`
* `.libdispatch-manager`: Meneja wa mistari ya GCD
* `.root.libdispatch-manager`: Meneja wa mistari ya GCD
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

Tambua kuwa itakuwa mfumo ndiye anayeamua **nyuzi zipi zinashughulikia mistari gani wakati wowote** (nyuzi nyingi zinaweza kufanya kazi kwenye mstari mmoja au nyuzi ile ile inaweza kufanya kazi kwenye mistari tofauti wakati fulani)

#### Sifa

Wakati wa kuunda mstari na **`dispatch_queue_create`** hoja ya tatu ni `dispatch_queue_attr_t`, ambayo kawaida ni au `DISPATCH_QUEUE_SERIAL` (ambayo kimsingi ni NULL) au `DISPATCH_QUEUE_CONCURRENT` ambayo ni kiashiria kwa `dispatch_queue_attr_t` muundo ambao huruhusu kudhibiti baadhi ya vigezo vya mstari.

### Vitu vya Kutuma

Kuna vitu kadhaa ambavyo libdispatch hutumia na mistari na blocks ni vitu 2 tu kati yao. Inawezekana kuunda vitu hivi na `dispatch_object_create`:

* `block`
* `data`: Vitengo vya data
* `group`: Kikundi cha vitengo
* `io`: Maombi ya I/O ya Async
* `mach`: Bandari za Mach
* `mach_msg`: Ujumbe wa Mach
* `pthread_root_queue`: Mstari na dimbwi la nyuzi za pthread na sio mistari ya kazi
* `queue`
* `semaphore`
* `source`: Chanzo cha tukio

## Objective-C

Katika Objetive-C kuna kazi tofauti za kutuma block ili itekelezwe kwa pamoja:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Inawasilisha block kwa utekelezaji wa pamoja kwenye mstari wa utekelezaji na kurudi mara moja.
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

**`libswiftDispatch`** ni maktaba inayotoa **mikufu ya Swift** kwa mfumo wa Grand Central Dispatch (GCD) ambao awali uliandikwa kwa C.\
Maktaba ya **`libswiftDispatch`** inafunika APIs za C GCD kwa interface ya kirafiki zaidi ya Swift, ikifanya iwe rahisi na ya kihisia zaidi kwa watengenezaji wa Swift kufanya kazi na GCD.

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

Skripti ya Frida ifuatayo inaweza kutumika kufanya **hook katika `dispatch` kadhaa** na kutoa jina la foleni, nyuma ya mstari na kizuizi: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Kwa sasa Ghidra haisomei wala muundo wa **`dispatch_block_t`** wa ObjectiveC, wala ule wa **`swift_dispatch_block`**.

Hivyo, ikiwa unataka iweze kusoma muundo huo, unaweza tu **kudeclare**:

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
