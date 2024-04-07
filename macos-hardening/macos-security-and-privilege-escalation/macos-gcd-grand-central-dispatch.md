# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

**Grand Central Dispatch (GCD),** inayojulikana pia kama **libdispatch**, inapatikana kwenye macOS na iOS. Ni teknolojia iliyoundwa na Apple kuboresha msaada wa programu kwa utekelezaji wa wakati mmoja (multithreaded) kwenye vifaa vya manyoya.

**GCD** hutoa na kusimamia **mistari ya FIFO** ambayo maombi yako yanaweza **kuwasilisha kazi** katika mfumo wa **vitu vya block**. Blocks zilizowasilishwa kwenye mistari ya kutuma hutekelezwa kwenye dimbwi la nyuzi zinazosimamiwa kabisa na mfumo. GCD inaunda nyuzi kiotomatiki kwa kutekeleza kazi kwenye mistari ya kutuma na kupanga kazi hizo zitekelezwe kwenye miingilio inayopatikana.

{% hint style="success" %}
Kwa muhtasari, ili kutekeleza nambari kwa **wakati mmoja**, michakato inaweza kutuma **vitengo vya nambari kwa GCD**, ambayo itahusika na utekelezaji wao. Kwa hivyo, michakato haziumbi nyuzi mpya; **GCD hutekeleza nambari iliyotolewa na dimbwi lake la nyuzi**.
{% endhint %}

Hii ni muhimu sana kusimamia utekelezaji wa wakati mmoja kwa ufanisi, ikipunguza sana idadi ya nyuzi ambazo michakato huzalisha na kuboresha utekelezaji wa wakati mmoja. Hii ni wazo kwa kazi zinazohitaji **upatanishi mkubwa** (kuvunja nguvu?) au kwa kazi ambazo hazipaswi kuzuia nyuzi kuu: Kwa mfano, nyuzi kuu kwenye iOS inashughulikia mwingiliano wa UI, kwa hivyo utendaji mwingine wowote ambao unaweza kufanya programu isimame (kutafuta, kupata wavuti, kusoma faili...) unasimamiwa kwa njia hii.

## Objective-C

Katika Objetive-C kuna kazi tofauti za kutuma block ili itekelezwe kwa wakati mmoja:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Inawasilisha block kwa utekelezaji wa wakati mwingine kwenye foleni ya kutuma na kurudi mara moja.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Inawasilisha kipengee cha block kwa utekelezaji na kurudi baada ya kipengee hicho kumaliza kutekelezwa.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Inatekeleza kipengee cha block mara moja tu kwa maisha ya programu.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Inawasilisha kipengee cha kazi kwa utekelezaji na kurudi baada ya kumaliza kutekelezwa. Tofauti na [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), kazi hii inaheshimu sifa zote za foleni wakati inatekeleza kipengee.

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
Na hii ni mfano wa kutumia **ushirikiano** na **`dispatch_async`**:
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
Maktaba ya **`libswiftDispatch`** inafunga APIs za C GCD katika kiolesura cha kirafiki zaidi cha Swift, ikifanya iwe rahisi na ya kihisia zaidi kwa watengenezaji wa Swift kufanya kazi na GCD.

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

Skripti ya Frida ifuatayo inaweza kutumika kufanya **hook katika `dispatch`** kadhaa na kutoa jina la foleni, nyuma ya mstari na kizuizi: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Hivyo, ikiwa unataka iweze kusoma, unaweza tu **kuzitangaza**:

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

Kisha, tafuta sehemu katika nambari ambapo zinatumiwa:

{% hint style="success" %}
Chukua kumbukumbu ya marejeo yote yanayohusiana na "block" ili kuelewa jinsi unavyoweza kugundua kuwa muundo unatumika.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

Bonyeza kulia kwenye kipengee -> Badilisha Aina ya Kipengee na chagua katika kesi hii **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra itaandika tena kiotomatiki kila kitu:

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>
