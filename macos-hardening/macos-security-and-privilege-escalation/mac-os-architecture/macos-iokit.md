# macOS IOKit

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Робите в **кібербезпеці компанії**? Хочете, щоб ваша **компанія була рекламована на HackTricks**? Або ви хочете мати доступ до **останньої версії PEASS або завантажити HackTricks у форматі PDF**? Перегляньте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Дізнайтеся про [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу ексклюзивну колекцію [**NFT**](https://opensea.io/collection/the-peass-family)
* Отримайте [**офіційний мерч PEASS та HackTricks**](https://peass.creator-spring.com)
* **Приєднуйтесь до** [**💬**](https://emojipedia.org/speech-balloon/) **групи Discord** або до [**групи Telegram**](https://t.me/peass) або **слідкуйте** за мною на **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**репозиторію hacktricks**](https://github.com/carlospolop/hacktricks) **та** [**репозиторію hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Базова інформація

IO Kit - це відкрита, об'єктно-орієнтована **рамка драйверів пристроїв** в ядрі XNU, яка обробляє **динамічно завантажені драйвери пристроїв**. Вона дозволяє додавати модульний код до ядра на льоту, підтримуючи різноманітне обладнання.

Драйвери IOKit в основному **експортують функції з ядра**. Типи параметрів цих функцій **передбачені** і перевірені. Крім того, подібно до XPC, IOKit - це лише ще один шар над **повідомленнями Mach**.

**Код ядра IOKit XNU** відкритий Apple за посиланням [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Крім того, компоненти IOKit простору користувача також є відкритими [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Проте **жоден з драйверів IOKit** не є відкритим. У будь-якому випадку, час від часу випуск драйвера може містити символи, які полегшують його налагодження. Перевірте, як [**отримати розширення драйвера з прошивки тут**](./#ipsw)**.**

Це написано на **C++**. Ви можете отримати розгорнуті символи C++ за допомогою:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
Функції, які викривають IOKit, можуть виконувати додаткові перевірки безпеки, коли клієнт намагається викликати функцію, але слід зауважити, що додатки зазвичай обмежені пісочницею, з якою IOKit функціями вони можуть взаємодіяти.
{% endhint %}

## Драйвери

У macOS вони розташовані в:

* **`/System/Library/Extensions`**
* Файли KEXT, вбудовані в операційну систему OS X.
* **`/Library/Extensions`**
* Файли KEXT, встановлені стороннім програмним забезпеченням

У iOS вони розташовані в:

* **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
До числа 9 перераховані драйвери **завантажуються за адресою 0**. Це означає, що вони не є справжніми драйверами, а **частиною ядра і не можуть бути вивантажені**.

Для пошуку конкретних розширень можна використовувати:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Щоб завантажити та вивантажити розширення ядра, виконайте:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** - це важлива частина фреймворку IOKit в macOS та iOS, яка служить базою даних для представлення конфігурації апаратного забезпечення та стану системи. Це **ієрархічна колекція об'єктів, яка представляє всю апаратну частину та драйвери**, завантажені в систему, та їх взаємозв'язки між собою.&#x20;

Ви можете отримати доступ до IORegistry за допомогою **`ioreg`** в командному рядку для його перевірки з консолі (особливо корисно для iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Ви можете завантажити **`IORegistryExplorer`** з **Додаткових інструментів Xcode** з [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) та переглянути **macOS IORegistry** через **графічний** інтерфейс.

<figure><img src="../../../.gitbook/assets/image (695).png" alt="" width="563"><figcaption></figcaption></figure>

У IORegistryExplorer "площини" використовуються для організації та відображення взаємозв'язків між різними об'єктами в IORegistry. Кожна площина представляє певний тип відносин або певний вид апаратної частини та конфігурації драйвера системи. Ось деякі зі звичайних площин, з якими ви можете зіткнутися в IORegistryExplorer:

1. **Площина IOService**: Це найзагальніша площина, яка відображає об'єкти служб, що представляють драйвери та nubs (канали зв'язку між драйверами). Вона показує відносини між постачальниками та клієнтами цих об'єктів.
2. **Площина IODeviceTree**: Ця площина представляє фізичні зв'язки між пристроями, як вони підключені до системи. Часто використовується для візуалізації ієрархії пристроїв, підключених через шини, такі як USB або PCI.
3. **Площина IOPower**: Відображає об'єкти та їх відносини з точки зору керування живленням. Вона може показати, які об'єкти впливають на стан живлення інших, що корисно для відлагодження проблем, пов'язаних з живленням.
4. **Площина IOUSB**: Спеціально спрямована на USB-пристрої та їх відносини, показуючи ієрархію USB хабів та підключених пристроїв.
5. **Площина IOAudio**: Ця площина призначена для представлення аудіопристроїв та їх відносин всередині системи.
6. ...

## Приклад коду взаємодії з драйвером

Наведений нижче код підключається до служби IOKit `"YourServiceNameHere"` та викликає функцію всередині селектора 0. Для цього:

* спочатку викликається **`IOServiceMatching`** та **`IOServiceGetMatchingServices`**, щоб отримати службу.
* Потім встановлюється з'єднання, викликаючи **`IOServiceOpen`**.
* І, нарешті, викликається функція з **`IOConnectCallScalarMethod`**, вказуючи селектор 0 (селектор - це номер, який призначено функції, яку ви хочете викликати).
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
Є **інші** функції, які можна використовувати для виклику функцій IOKit окрім **`IOConnectCallScalarMethod`** такі як **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Розбір точки входу драйвера

Ви можете отримати їх, наприклад, з [**образу прошивки (ipsw)**](./#ipsw). Потім завантажте його у ваш улюблений декомпілятор.

Ви можете почати декомпілювати функцію **`externalMethod`**, оскільки це функція драйвера, яка отримуватиме виклик та викликатиме правильну функцію:

<figure><img src="../../../.gitbook/assets/image (696).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (697).png" alt=""><figcaption></figcaption></figure>

Цей жахливий виклик означає:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Зверніть увагу, що в попередньому визначенні відсутній параметр **`self`**, правильне визначення виглядало б так:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Фактично, ви можете знайти справжнє визначення за посиланням [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
З цією інформацією ви можете переписати Ctrl+Right -> `Редагувати підпис функції` та встановити відомі типи:

<figure><img src="../../../.gitbook/assets/image (702).png" alt=""><figcaption></figcaption></figure>

Новий декомпільований код буде виглядати так:

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

Для наступного кроку нам потрібно мати визначену структуру **`IOExternalMethodDispatch2022`**. Це відкритий код на [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), ви можете визначити його:

<figure><img src="../../../.gitbook/assets/image (698).png" alt=""><figcaption></figcaption></figure>

Тепер, слідуючи за `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, ви можете побачити багато даних:

<figure><img src="../../../.gitbook/assets/image (704).png" alt="" width="563"><figcaption></figcaption></figure>

Змініть тип даних на **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (705).png" alt="" width="375"><figcaption></figcaption></figure>

після зміни:

<figure><img src="../../../.gitbook/assets/image (707).png" alt="" width="563"><figcaption></figcaption></figure>

І оскільки тепер ми маємо там **масив з 7 елементів** (перевірте кінцевий декомпільований код), натисніть, щоб створити масив з 7 елементів:

<figure><img src="../../../.gitbook/assets/image (708).png" alt="" width="563"><figcaption></figcaption></figure>

Після створення масиву ви можете побачити всі експортовані функції:

<figure><img src="../../../.gitbook/assets/image (709).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Якщо ви пам'ятаєте, для **виклику** **експортованої** функції з простору користувача нам не потрібно викликати назву функції, але **номер селектора**. Тут ви можете побачити, що селектор **0** - це функція **`initializeDecoder`**, селектор **1** - **`startDecoder`**, селектор **2** - **`initializeEncoder`**...
{% endhint %}
