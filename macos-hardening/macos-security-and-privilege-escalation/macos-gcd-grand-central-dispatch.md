# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahramana öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> ile!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek istiyorsanız** veya **HackTricks'i PDF olarak indirmek istiyorsanız** [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünleri**](https://peass.creator-spring.com)'ni edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* **Katılın** 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) veya bizi **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)'da **takip edin**.
* **Hacking püf noktalarınızı göndererek HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına PR göndererek paylaşın.

</details>

## Temel Bilgiler

**Grand Central Dispatch (GCD),** aynı zamanda **libdispatch** (`libdispatch.dyld`) olarak da bilinir ve macOS ve iOS'te mevcuttur. Apple tarafından çok çekirdekli donanımlarda eş zamanlı (çoklu iş parçacıklı) yürütme için uygulama desteğini optimize etmek amacıyla geliştirilen bir teknolojidir.

**GCD**, uygulamanızın **blok nesneleri** şeklinde **görevleri gönderebileceği FIFO kuyruklarını sağlar ve yönetir**. Dağıtım kuyruklarına gönderilen bloklar, sistem tarafından tamamen yönetilen bir iş parçacığı havuzunda yürütülür. GCD, dağıtım kuyruklarındaki görevleri yürütmek için otomatik olarak iş parçacıkları oluşturur ve bu görevleri mevcut çekirdeklere çalışacak şekilde planlar.

{% hint style="success" %}
Özetle, **paralel olarak kodu yürütmek** için işlemler, **GCD'ye kod blokları gönderebilir**, bu da onların yürütümüyle ilgilenir. Bu nedenle, işlemler yeni iş parçacıkları oluşturmaz; **GCD, verilen kodu kendi iş parçacığı havuzuyla yürütür** (gerektiğinde artırabilir veya azaltabilir).
{% endhint %}

Bu, paralel yürütümü başarılı bir şekilde yönetmek için çok yardımcı olur, işlemlerin oluşturduğu iş parçacığı sayısını büyük ölçüde azaltır ve paralel yürütümü optimize eder. Bu, **büyük paralelizm** gerektiren görevler için (kaba kuvvet?) veya ana iş parçacığını engellememesi gereken görevler için idealdir: Örneğin, iOS'taki ana iş parçacığı UI etkileşimlerini yönetir, bu nedenle uygulamanın donmasına neden olabilecek herhangi başka bir işlev (arama, web'e erişim, dosya okuma...) bu şekilde yönetilir.

### Bloklar

Bir blok, **kendi başına bir kod bölümü** (argüman döndüren bir işlev gibi) ve bağlı değişkenleri de belirtebilir.\
Ancak, derleyici seviyesinde bloklar mevcut değildir, bunlar `os_object`'lerdir. Bu nesnelerin her biri iki yapıdan oluşur:

* **blok literali**:&#x20;
* Bloğun sınıfına işaret eden **`isa`** alanıyla başlar:
* `NSConcreteGlobalBlock` (`__DATA.__const` blokları)
* `NSConcreteMallocBlock` (heap'teki bloklar)
* `NSConcreateStackBlock` (yığında bloklar)
* Blok tanımlayıcısında bulunan alanları gösteren **`flags`** ve bazı ayrılmış baytlar
* Çağrılacak işlev işaretçisi
* Bir blok tanımlayıcısına işaretçi
* İçe aktarılan blok değişkenleri (varsa)
* **blok tanımlayıcısı**: Bu, mevcut veriye bağlı olarak boyutu değişir (önceki bayraklarda belirtildiği gibi)
* Bazı ayrılmış baytlar içerir
* Boyutu
* Genellikle, parametreler için ne kadar alanın gerektiğini bilmek için bir Objective-C tarzı imza işaretçisine işaret eder (bayrak `BLOCK_HAS_SIGNATURE`)
* Değişkenler referans alınıyorsa, bu blok ayrıca bir kopya yardımcısına (değeri başlangıçta kopyalayan) ve atma yardımcısına (serbest bırakan) işaretçilere sahip olacaktır.

### Kuyruklar

Dağıtım kuyruğu, blokların yürütülmesi için FIFO sıralaması sağlayan adlandırılmış bir nesnedir.

Blokların yürütülmesi için kuyruklara yerleştirilir ve bunlar 2 modu destekler: `DISPATCH_QUEUE_SERIAL` ve `DISPATCH_QUEUE_CONCURRENT`. Elbette **seri** olan **yarış koşulu sorunu olmayacak** çünkü bir blok, önceki blok bitene kadar yürütülmeyecektir. Ancak **diğer kuyruk türü bunu yapabilir**.

Varsayılan kuyruklar:

* `.main-thread`: `dispatch_get_main_queue()`'den
* `.libdispatch-manager`: GCD'nin kuyruk yöneticisi
* `.root.libdispatch-manager`: GCD'nin kuyruk yöneticisi
* `.root.maintenance-qos`: En düşük öncelikli görevler
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: `DISPATCH_QUEUE_PRIORITY_BACKGROUND` olarak mevcut
* `.root.background-qos.overcommit`
* `.root.utility-qos`: `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE` olarak mevcut
* `.root.utility-qos.overcommit`
* `.root.default-qos`: `DISPATCH_QUEUE_PRIORITY_DEFAULT` olarak mevcut
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: `DISPATCH_QUEUE_PRIORITY_HIGH` olarak mevcut
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: En yüksek öncelikli
* `.root.background-qos.overcommit`

Her zaman **hangi iş parçacıklarının hangi kuyrukları her zaman ele alacağını** (çoklu iş parçacıkları aynı kuyrukta çalışabilir veya aynı iş parçacığı farklı kuyruklarda çalışabilir) sistem belirleyecektir.

#### Özellikler

**`dispatch_queue_create`** ile bir kuyruk oluşturulurken üçüncü argüman bir `dispatch_queue_attr_t` olup genellikle ya `DISPATCH_QUEUE_SERIAL` (aslında NULL) ya da `DISPATCH_QUEUE_CONCURRENT` olabilir, bu da kuyruğun bazı parametrelerini kontrol etmeye izin veren bir `dispatch_queue_attr_t` yapısına işaret eder.

### Dağıtım nesneleri

Libdispatch'in kullandığı ve kuyruklar ve blokların sadece 2 tanesidir. Bu nesneleri `dispatch_object_create` ile oluşturmak mümkündür:

* `block`
* `data`: Veri blokları
* `group`: Blok grubu
* `io`: Asenkron G/Ç istekleri
* `mach`: Mach portları
* `mach_msg`: Mach mesajları
* `pthread_root_queue`: İş parçacığı havuzu ve iş kuyrukları olmayan bir kuyruk
* `queue`
* `semaphore`
* `source`: Olay kaynağı

## Objective-C

Objetive-C'de bir bloğun paralel olarak yürütülmesi için farklı işlevler bulunmaktadır:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Bir bloğu bir dağıtım kuyruğunda asenkron olarak yürütmek için gönderir ve hemen döner.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Bir blok nesnesini yürütüm için gönderir ve o blok yürütüldükten sonra döner.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Bir uygulamanın ömrü boyunca bir blok nesnesini yalnızca bir kez yürütür.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Bir iş öğesini yürütmek için gönderir ve yalnızca o iş öğesi yürütüldükten sonra döner. [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync) gibi bu işlev, bloğu yürütürken kuyruğun tüm özelliklerine saygı duyar.

Bu işlevler şu parametreleri bekler: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

İşte bir Blok'un **yapısı**:
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
Ve **`dispatch_async`** kullanarak **paralelizm** kullanımına bir örnek:
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

Aşağıdaki Frida betiği, birkaç `dispatch` fonksiyonuna **kanca takmak** ve sıra adını, geri izlemeyi ve bloğu çıkarmak için kullanılabilir: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Şu anda Ghidra, ne ObjectiveC **`dispatch_block_t`** yapısını ne de **`swift_dispatch_block`** yapısını anlamıyor.

Bu yapıları anlamasını istiyorsanız, sadece **onları tanımlayabilirsiniz**:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Ardından, kodun içinde **kullanıldığı yeri bulun**:

{% hint style="success" %}
"block" ile yapılan tüm referansları not alarak, yapının nasıl kullanıldığını anlayabilirsiniz.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Değişkenin üzerine sağ tıklayın -> Değişkeni Yeniden Türle ve bu durumda **`swift_dispatch_block`**'u seçin:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra otomatik olarak her şeyi yeniden yazacaktır:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## Referanslar

* [**\*OS Internals, Cilt I: Kullanıcı Modu. Jonathan Levin tarafından**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
