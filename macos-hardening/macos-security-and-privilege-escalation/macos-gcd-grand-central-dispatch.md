# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>AWS hackleme becerilerini sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINA**](https://github.com/sponsors/carlospolop) göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'ı takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek paylaşın**.

</details>

## Temel Bilgiler

**Grand Central Dispatch (GCD)**, macOS ve iOS'ta bulunan bir teknolojidir. Apple tarafından geliştirilen bu teknoloji, çok çekirdekli donanımda eşzamanlı (çoklu iş parçacıklı) yürütme için uygulama desteğini optimize etmektedir.

**GCD**, uygulamanızın **blok nesneleri** şeklinde **görevleri** **FIFO kuyruklarına** gönderebileceği ve yönetebileceği bir yapı sağlar. Gönderilen bloklar, sistem tarafından tamamen yönetilen bir thread havuzunda yürütülür. GCD, görevleri yürütmek için thread'ler oluşturur ve bu görevleri kullanılabilir çekirdeklerde çalıştırmak için zamanlama yapar.

{% hint style="success" %}
Özetlemek gerekirse, **paralel olarak** kodu **yürütmek** için işlemler, kod bloklarını GCD'ye gönderebilir ve GCD bu kodun yürütmesiyle ilgilenir. Bu nedenle, işlemler yeni thread'ler oluşturmaz; **GCD, kendi thread havuzuyla verilen kodu yürütür**.
{% endhint %}

Bu, paralel yürütme yönetimini başarıyla yönetmek için çok yardımcı olur, işlemlerin oluşturduğu thread sayısını büyük ölçüde azaltır ve paralel yürütme işlemini optimize eder. Bu, **büyük paralelizm** gerektiren görevler (brute-force?) veya ana thread'i bloke etmemesi gereken görevler için çok uygundur: Örneğin, iOS'taki ana thread, UI etkileşimlerini yönetir, bu nedenle uygulamanın takılmasına neden olabilecek herhangi bir diğer işlev (arama yapma, web'e erişme, dosya okuma...) bu şekilde yönetilir.

## Objective-C

Objective-C'de, bir bloğun paralel olarak yürütülmesi için farklı işlevler bulunmaktadır:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Bir bloğu asenkron olarak bir dispatch kuyruğunda yürütmek için gönderir ve hemen döner.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Bir blok nesnesini yürütmek için gönderir ve bu blok yürütüldükten sonra döner.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Bir blok nesnesini bir uygulamanın ömrü boyunca yalnızca bir kez yürütür.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Bir iş öğesini yürütmek için gönderir ve yalnızca işlem tamamlandıktan sonra döner. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)'in aksine, bu işlev, bloğu yürütürken kuyruğun tüm özelliklerine saygı duyar.

Bu işlevler, şu parametreleri bekler: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Bu, bir Blok'un **struct**'udur:
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
Ve **`dispatch_async`** ile **paralelizm** kullanmanın bir örneği aşağıda verilmiştir:
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

**`libswiftDispatch`**, C ile yazılmış olan Grand Central Dispatch (GCD) çerçevesine Swift bağlantıları sağlayan bir kütüphanedir.\
**`libswiftDispatch`** kütüphanesi, C GCD API'lerini daha Swift dostu bir arayüzde sarmalar ve Swift geliştiricilerinin GCD ile çalışmasını daha kolay ve sezgisel hale getirir.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Kod örneği**:
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

Aşağıdaki Frida betiği, birkaç `dispatch` işlevine **hook yapmak** ve sıra adını, geri izlemeyi ve bloğu çıkarmak için kullanılabilir: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Ghidra şu anda ObjectiveC **`dispatch_block_t`** yapısını veya **`swift_dispatch_block`** yapısını anlamıyor.

Bu nedenle, onları anlaması için sadece **bildirmeniz** gerekebilir:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Ardından, kodun içinde kullanıldığı bir yeri **bulun**:

{% hint style="success" %}
Yapının kullanıldığını nasıl anlayabileceğinizi anlamak için "block" ile yapılan tüm referansları dikkate alın.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Değişkenin üzerine sağ tıklayın -> Değişkeni Yeniden Türle ve bu durumda **`swift_dispatch_block`**'u seçin:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra otomatik olarak her şeyi yeniden yazacaktır:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **tanıtmak veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**'da takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna **PR göndererek** paylaşın.

</details>
