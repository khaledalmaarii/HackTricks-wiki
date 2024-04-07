# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>AWS hacklemeyi sıfırdan ileri seviyeye öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**The PEASS Family'yi**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **💬 [Discord grubumuza](https://discord.gg/hRep4RUj7f) katılın veya [telegram grubuna](https://t.me/peass) katılın veya bizi Twitter'da** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)** takip edin.**
* **Hacking püf noktalarınızı paylaşarak** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek katkıda bulunun.

</details>

## Temel Bilgiler

**Grand Central Dispatch (GCD)**, aynı zamanda **libdispatch** olarak da bilinir, macOS ve iOS'te mevcuttur. Apple tarafından geliştirilen bir teknolojidir ve çok çekirdekli donanımlarda eşzamanlı (çoklu iş parçacıklı) yürütme için uygulama desteğini optimize etmek amacıyla geliştirilmiştir.

**GCD**, uygulamanızın **görevleri** **blok nesneleri** şeklinde **göndermesi** için ve **FIFO kuyruklarını** sağlamak ve yönetmek için kullanılır. Gönderilen bloklar, sistem tarafından tamamen yönetilen bir **iş parçacığı havuzunda** yürütülür. GCD, görevleri yürütmek için iş parçacıkları oluşturur ve bu görevleri mevcut çekirdeklere çalışacak şekilde planlar.

{% hint style="success" %}
Özetle, **paralel olarak kodu yürütmek** için işlemler, kod bloklarını **GCD'ye gönderebilir** ve GCD bu kodları yürütir. Bu nedenle, işlemler yeni iş parçacıkları oluşturmaz; **GCD, kendi iş parçacığı havuzuyla verilen kodu yürütir**.
{% endhint %}

Bu, paralel yürütümü başarılı bir şekilde yönetmek için çok yardımcı olur, işlemlerin oluşturduğu iş parçacığı sayısını büyük ölçüde azaltır ve paralel yürütümü optimize eder. Bu, **büyük paralelizm** gerektiren görevler (kaba kuvvet?) veya ana iş parçacığını bloke etmemesi gereken görevler için çok uygundur: Örneğin, iOS'taki ana iş parçacığı UI etkileşimlerini yönetir, bu nedenle uygulamanın donmasına neden olabilecek herhangi bir işlev (arama, web'e erişim, dosya okuma...) bu şekilde yönetilir.

## Objective-C

Objetive-C'de kodun paralel olarak yürütülmesi için farklı işlevler bulunmaktadır:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Bir kod bloğunu eşzamansız olarak bir dağıtım kuyruğunda yürütmek için gönderir ve hemen döner.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Bir kod bloğunu yürütmek için gönderir ve o blok yürütüldükten sonra döner.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Bir uygulamanın ömrü boyunca yalnızca bir kez bir kod bloğunu yürütür.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Bir iş öğesini yürütmek için gönderir ve yalnızca o işlem yürütüldükten sonra döner. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync)'den farklı olarak, bu işlev, kuyruğun tüm özelliklerine saygı duyar ve bloğu yürütürken bu özellikleri dikkate alır.

Bu işlevler şu parametreleri bekler: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Bu, bir Blok'un **yapısıdır**:
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
Ve **`dispatch_async`** kullanarak **paralelizm** kullanımına dair bir örnek:
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

**`libswiftDispatch`** is a library that provides **Swift bindings** to the Grand Central Dispatch (GCD) framework which is originally written in C.\
The **`libswiftDispatch`** library wraps the C GCD APIs in a more Swift-friendly interface, making it easier and more intuitive for Swift developers to work with GCD.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Code example**:
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

Aşağıdaki Frida betiği, birkaç `dispatch` fonksiyonuna **hook yapmak** ve sıra adını, geri izlemeyi ve bloğu çıkarmak için kullanılabilir: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Şu anda Ghidra, ne ObjectiveC **`dispatch_block_t`** yapısını, ne de **`swift_dispatch_block`** yapısını anlamıyor.

Bu nedenle, onları anlamasını istiyorsanız, sadece **bildirmeniz gerekebilir**:

<figure><img src="../../.gitbook/assets/image (1157).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1159).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

Ardından, kodun içinde **kullanıldığı yeri bulun**:

{% hint style="success" %}
Yapıyı nasıl kullanıldığını anlamak için "block" ile yapılan tüm referanslara dikkat edin.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1161).png" alt="" width="563"><figcaption></figcaption></figure>

Değişkenin üzerine sağ tıklayın -> Değişkeni Yeniden Türle ve bu durumda **`swift_dispatch_block`**'u seçin:

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra otomatik olarak her şeyi yeniden yazacaktır:

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>
