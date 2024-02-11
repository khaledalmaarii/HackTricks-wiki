# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

**Grand Central Dispatch (GCD)**, inayojulikana pia kama **libdispatch**, inapatikana kwenye macOS na iOS. Ni teknolojia iliyoendelezwa na Apple ili kuongeza ufanisi wa programu katika kutekeleza kwa wakati mmoja (multithreaded) kwenye vifaa vya multicore.

**GCD** hutoa na kusimamia **queues za FIFO** ambazo programu yako inaweza **kuwasilisha kazi** kwa njia ya **block objects**. Blocks zilizowasilishwa kwenye dispatch queues zinatekelezwa kwenye kundi la threads linalosimamiwa kabisa na mfumo. GCD kiotomatiki hujenga threads kwa kutekeleza kazi kwenye dispatch queues na kupangia kazi hizo kutekelezwa kwenye cores zilizopo.

{% hint style="success" %}
Kwa ufupi, ili kutekeleza namna ya **kodsi kwa wakati mmoja**, michakato inaweza kutuma **blocks ya kodi kwa GCD**, ambayo itahusika na utekelezaji wake. Kwa hiyo, michakato haizalishi threads mpya; **GCD inatekeleza kodi iliyotolewa na kundi lake la threads**.
{% endhint %}

Hii ni muhimu sana katika kusimamia utekelezaji wa wakati mmoja kwa mafanikio, ikipunguza sana idadi ya threads ambazo michakato inazalisha na kuongeza ufanisi wa utekelezaji wa wakati mmoja. Hii ni nzuri kwa kazi zinazohitaji **ufanisi mkubwa** (kama vile kuvunja nguvu?) au kazi ambazo hazipaswi kuzuia thread kuu: Kwa mfano, thread kuu kwenye iOS inashughulikia mwingiliano wa UI, kwa hivyo kazi nyingine yoyote ambayo inaweza kufanya programu isikwame (kutafuta, kupata upatikanaji wa wavuti, kusoma faili...) inasimamiwa kwa njia hii.

## Objective-C

Kwenye Objective-C kuna tofauti kazi za kutuma block ili zitekelezwe kwa wakati mmoja:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Inawasilisha block kwa utekelezaji usio wa kusubiri kwenye dispatch queue na inarudi mara moja.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Inawasilisha block kwa utekelezaji na inarudi baada ya block hiyo kumaliza kutekelezwa.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Inatekeleza block mara moja tu kwa muda wa maisha ya programu.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Inawasilisha kipengee cha kazi kwa utekelezaji na inarudi tu baada ya kumaliza kutekelezwa. Tofauti na [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), kazi hii inaheshimu sifa zote za queue wakati inatekeleza block.

Kazi hizi zinatarajia vipengele hivi: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Hii ndio **muundo wa Block**:
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
Na hii ni mfano wa kutumia **parallelism** na **`dispatch_async`**:

```objective-c
dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

dispatch_async(queue, ^{
    // Code to be executed concurrently
});

dispatch_async(queue, ^{
    // Code to be executed concurrently
});

dispatch_async(queue, ^{
    // Code to be executed concurrently
});
```

Katika mfano huu, tunatumia **parallelism** kwa kutumia **`dispatch_async`**:

```objective-c
dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

dispatch_async(queue, ^{
    // Code to be executed concurrently
});

dispatch_async(queue, ^{
    // Code to be executed concurrently
});

dispatch_async(queue, ^{
    // Code to be executed concurrently
});
```
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

**`libswiftDispatch`** ni maktaba inayotoa **kufungwa kwa Swift** kwa mfumo wa Grand Central Dispatch (GCD) ambao awali uliandikwa kwa C.\
Maktaba ya **`libswiftDispatch`** inafunga APIs za C GCD katika kiolesura cha Swift zaidi, ikifanya iwe rahisi na ya kueleweka zaidi kwa watengenezaji wa Swift kufanya kazi na GCD.

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

Skripti ya Frida ifuatayo inaweza kutumika kufanya **hook katika kazi kadhaa za `dispatch`** na kuchukua jina la foleni, mfuatano wa nyuma, na kizuizi: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Kwa sasa Ghidra haelewi muundo wa **`dispatch_block_t`** wa ObjectiveC, wala ule wa **`swift_dispatch_block`**.

Ili iweze kuelewa, unaweza tu **kuzitangaza**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Kisha, tafuta sehemu katika nambari ambapo zinatumika:

{% hint style="success" %}
Chukua kumbukumbu zote zinazohusiana na "block" ili kuelewa jinsi unavyoweza kugundua kuwa muundo huo unatumika.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Bonyeza kulia kwenye kipengee -> Badilisha Aina ya Kipengee na chagua katika kesi hii **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra itaandika tena kila kitu kiotomatiki:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
