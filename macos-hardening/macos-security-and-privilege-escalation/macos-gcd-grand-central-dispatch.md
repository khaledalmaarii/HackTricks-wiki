# macOS GCD - Grand Central Dispatch

{% hint style="success" %}
Вивчайте та практикуйте взлом AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте взлом GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
{% endhint %}

## Основна інформація

**Grand Central Dispatch (GCD),** також відомий як **libdispatch** (`libdispatch.dyld`), доступний як в macOS, так і в iOS. Це технологія, розроблена Apple для оптимізації підтримки програм для одночасного (багатопотокового) виконання на багатоядерному обладнанні.

**GCD** надає та керує **чергами FIFO**, до яких ваша програма може **надсилати завдання** у вигляді **блок-об'єктів**. Блоки, надіслані в черги розподілу, **виконуються в пулі потоків**, повністю керованих системою. GCD автоматично створює потоки для виконання завдань у чергах розподілу та планує виконання цих завдань на доступних ядрах.

{% hint style="success" %}
У підсумку, для виконання коду **паралельно**, процеси можуть надсилати **блоки коду в GCD**, який буде відповідати за їх виконання. Таким чином, процеси не створюють нові потоки; **GCD виконує заданий код зі своїм власним пулом потоків** (який може збільшуватися або зменшуватися за необхідності).
{% endhint %}

Це дуже корисно для успішного управління паралельним виконанням, значно зменшуючи кількість потоків, які створюють процеси, та оптимізуючи паралельне виконання. Це ідеально підходить для завдань, які вимагають **великої паралельності** (брутфорс?) або для завдань, які не повинні блокувати основний потік: наприклад, основний потік на iOS обробляє взаємодію з користувачем, тому будь-яку іншу функціональність, яка може призвести до зависання додатка (пошук, доступ до веб-сайту, читання файлу...), керується цим способом.

### Блоки

Блок - це **самостійний фрагмент коду** (схожий на функцію з аргументами, що повертає значення) і може також вказувати зв'язані змінні.\
Однак на рівні компілятора блоки не існують, вони є `os_object`s. Кожен з цих об'єктів складається з двох структур:

* **літерал блоку**:&#x20;
* Він починається з поля **`isa`**, яке вказує на клас блоку:
* `NSConcreteGlobalBlock` (блоки з `__DATA.__const`)
* `NSConcreteMallocBlock` (блоки в купі)
* `NSConcreateStackBlock` (блоки в стеку)
* Він має **`flags`** (вказує на поля, присутні в описнику блоку) та деякі зарезервовані байти
* Вказівник на функцію для виклику
* Вказівник на описник блоку
* Імпортовані змінні блоку (якщо є)
* **описник блоку**: Його розмір залежить від даних, які присутні (як вказано в попередніх прапорцях)
* Він має деякі зарезервовані байти
* Розмір цього
* Зазвичай він має вказівник на підпис у стилі Objective-C, щоб знати, скільки місця потрібно для параметрів (прапорець `BLOCK_HAS_SIGNATURE`)
* Якщо змінні посилаються, цей блок також матиме вказівники на допоміжник копіювання (копіювання значення на початку) та допоміжник видалення (звільнення його).

### Черги

Черга розподілу - це іменований об'єкт, який забезпечує чергування блоків для виконання.

Блоки встановлюються в черги для виконання, і вони підтримують 2 режими: `DISPATCH_QUEUE_SERIAL` та `DISPATCH_QUEUE_CONCURRENT`. Звичайно **серійний** не матиме проблем з умовами гонки, оскільки блок не буде виконаний, поки попередній не завершиться. Але **інший тип черги може мати це**.

Стандартні черги:

* `.main-thread`: З `dispatch_get_main_queue()`
* `.libdispatch-manager`: Менеджер черги GCD
* `.root.libdispatch-manager`: Менеджер черги GCD
* `.root.maintenance-qos`: Завдання найнижчого пріоритету
* `.root.maintenance-qos.overcommit`
* `.root.background-qos`: Доступно як `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
* `.root.background-qos.overcommit`
* `.root.utility-qos`: Доступно як `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
* `.root.utility-qos.overcommit`
* `.root.default-qos`: Доступно як `DISPATCH_QUEUE_PRIORITY_DEFAULT`
* `.root.background-qos.overcommit`
* `.root.user-initiated-qos`: Доступно як `DISPATCH_QUEUE_PRIORITY_HIGH`
* `.root.background-qos.overcommit`
* `.root.user-interactive-qos`: Найвищий пріоритет
* `.root.background-qos.overcommit`

Зверніть увагу, що система вирішує, **які потоки обробляють які черги в кожний момент часу** (декілька потоків можуть працювати в одній черзі або той самий потік може працювати в різних чергах на деякому етапі)

#### Атрибути

При створенні черги з **`dispatch_queue_create`** третій аргумент - це `dispatch_queue_attr_t`, який зазвичай є або `DISPATCH_QUEUE_SERIAL` (який фактично є NULL), або `DISPATCH_QUEUE_CONCURRENT`, який є вказівником на структуру `dispatch_queue_attr_t`, яка дозволяє контролювати деякі параметри черги.

### Об'єкти розподілу

Є кілька об'єктів, які використовує libdispatch, і черги та блоки - лише 2 з них. Ці об'єкти можна створити за допомогою `dispatch_object_create`:

* `block`
* `data`: Блоки даних
* `group`: Група блоків
* `io`: Асинхронні запити введення/виведення
* `mach`: Порти Mach
* `mach_msg`: Повідомлення Mach
* `pthread_root_queue`: Черга з пулом потоків pthread та без робочих черг
* `queue`
* `semaphore`
* `source`: Джерело подій

## Objective-C

У Objetive-C є різні функції для відправлення блоку на виконання паралельно:

* [**dispatch\_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch\_async): Надсилає блок для асинхронного виконання в черзі розподілу та повертається негайно.
* [**dispatch\_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync): Надсилає об'єкт блоку для виконання та повертається після завершення виконання цього блоку.
* [**dispatch\_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch\_once): Виконує блок об'єкта лише один раз за час існування додатка.
* [**dispatch\_async\_and\_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch\_async\_and\_wait): Надсилає робочий елемент для виконання та повертається лише після завершення виконання. На відміну від [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch\_sync), ця функція поважає всі атрибути черги під час виконання блоку.

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
## Фріда

Наступний скрипт Фріди може бути використаний для **підключення до кількох функцій `dispatch`** та витягування назви черги, стеку викликів та блоку: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
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

Наразі Ghidra не розуміє ані структури ObjectiveC **`dispatch_block_t`**, ані **`swift_dispatch_block`**.

Тому, якщо ви хочете, щоб він їх розумів, ви можете просто **оголосити їх**:

<figure><img src="../../.gitbook/assets/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Потім знайдіть місце в коді, де вони **використовуються**:

{% hint style="success" %}
Зверніть увагу на всі посилання на "block", щоб зрозуміти, як ви можете зрозуміти, що структура використовується.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Клацніть правою кнопкою миші на змінну -> Перетипізувати змінну та виберіть у цьому випадку **`swift_dispatch_block`**:

<figure><img src="../../.gitbook/assets/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra автоматично перепише все:

<figure><img src="../../.gitbook/assets/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

* [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
