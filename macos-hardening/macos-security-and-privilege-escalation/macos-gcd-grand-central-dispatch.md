# macOS GCD - Grand Central Dispatch

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Поділіться своїми хакінг-трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

## Базова інформація

**Grand Central Dispatch (GCD),** також відомий як **libdispatch**, доступний як в macOS, так і в iOS. Це технологія, розроблена Apple для оптимізації підтримки програм для одночасного (багатопотокового) виконання на багатоядерному обладнанні.

**GCD** надає та керує **чергами FIFO**, до яких ваша програма може **надсилати завдання** у вигляді **блок-об'єктів**. Блоки, надіслані в черги розподілу, **виконуються в пулі потоків**, повністю керованих системою. GCD автоматично створює потоки для виконання завдань у чергах розподілу та планує виконання цих завдань на доступних ядрах.

{% hint style="success" %}
У підсумку, для виконання коду **паралельно**, процеси можуть надсилати **блоки коду в GCD**, який буде відповідати за їх виконання. Таким чином, процеси не створюють нові потоки; **GCD виконує заданий код за допомогою свого власного пулу потоків**.
{% endhint %}

Це дуже корисно для успішного управління паралельним виконанням, значно зменшуючи кількість потоків, які створюють процеси, та оптимізуючи паралельне виконання. Це ідеально підходить для завдань, які вимагають **великої паралельності** (брутфорс?) або для завдань, які не повинні блокувати основний потік: наприклад, основний потік на iOS відповідає за взаємодію з користувачем, тому будь-яка інша функціональність, яка може призвести до зависання додатка (пошук, доступ до веб-сайту, читання файлу...), керується цим способом.

## Objective-C

У Objetive-C є різні функції для відправлення блоку на виконання паралельно:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Надсилає блок для асинхронного виконання в чергу розподілу та повертається негайно.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Надсилає блок на виконання та повертається після завершення виконання цього блоку.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Виконує блок лише один раз за час існування програми.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Надсилає робочий елемент на виконання та повертається лише після завершення його виконання. На відміну від [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), ця функція поважає всі атрибути черги під час виконання блоку.

Ці функції очікують ці параметри: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_queue\_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch\_block\_t) **`block`**

Ось **структура блоку**:
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
І ось приклад використання **паралелизму** з **`dispatch_async`**:
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

**`libswiftDispatch`** - це бібліотека, яка надає **зв'язки Swift** до фреймворку Grand Central Dispatch (GCD), який спочатку був написаний на C.\
Бібліотека **`libswiftDispatch`** обгортає API GCD на C в більш дружній для Swift інтерфейс, що робить роботу з GCD легшою та інтуїтивно зрозумілою для розробників Swift.

* **`DispatchQueue.global().sync{ ... }`**
* **`DispatchQueue.global().async{ ... }`**
* **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
* **`async await`**
* **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Приклад коду**:
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

Наступний скрипт Frida може бути використаний для **підключення до кількох функцій `dispatch`** та витягування назви черги, стеку викликів та блоку: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Наразі Ghidra не розуміє ні структуру ObjectiveC **`dispatch_block_t`**, ні **`swift_dispatch_block`**.

Тому, якщо ви хочете, щоб він їх розумів, ви можете просто **оголосити їх**:

<figure><img src="../../.gitbook/assets/image (688).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (690).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (691).png" alt="" width="563"><figcaption></figcaption></figure>

Потім знайдіть місце в коді, де вони **використовуються**:

{% hint style="success" %}
Зверніть увагу на всі посилання на "block", щоб зрозуміти, як ви можете зрозуміти, що структура використовується.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (692).png" alt="" width="563"><figcaption></figcaption></figure>

Клацніть правою кнопкою миші на змінну -> Перейменувати змінну та виберіть у цьому випадку **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (693).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra автоматично перепише все:

<figure><img src="../../.gitbook/assets/image (694).png" alt="" width="563"><figcaption></figcaption></figure>
