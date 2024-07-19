# macOS IOKit

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basic Information

IO Kit - це відкритий, об'єктно-орієнтований **фреймворк драйверів пристроїв** в ядрі XNU, який обробляє **динамічно завантажувані драйвери пристроїв**. Він дозволяє модульному коду додаватися до ядра на льоту, підтримуючи різне апаратне забезпечення.

Драйвери IOKit в основному **експортують функції з ядра**. Ці параметри функцій **типи** є **попередньо визначеними** та перевіреними. Більше того, подібно до XPC, IOKit - це просто ще один шар на **верхівці Mach повідомлень**.

**Код IOKit XNU ядра** відкритий Apple в [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Більше того, компоненти IOKit у просторі користувача також є відкритими [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Однак **жоден з драйверів IOKit** не є відкритим. У будь-якому випадку, час від часу випуск драйвера може супроводжуватися символами, які полегшують його налагодження. Перевірте, як [**отримати розширення драйвера з прошивки тут**](./#ipsw)**.**

Він написаний на **C++**. Ви можете отримати демангліровані символи C++ за допомогою:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% hint style="danger" %}
IOKit **відкриті функції** можуть виконувати **додаткові перевірки безпеки**, коли клієнт намагається викликати функцію, але слід зазначити, що програми зазвичай **обмежені** **пісочницею**, з якою функції IOKit можуть взаємодіяти.
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
До номера 9 вказані драйвери **завантажуються за адресою 0**. Це означає, що це не справжні драйвери, а **частина ядра, і їх не можна вивантажити**.

Щоб знайти конкретні розширення, ви можете використовувати:
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

**IORegistry** є важливою частиною фреймворку IOKit в macOS та iOS, яка слугує базою даних для представлення апаратної конфігурації та стану системи. Це **ієрархічна колекція об'єктів, які представляють все апаратне забезпечення та драйвери**, завантажені в системі, та їх взаємозв'язки.

Ви можете отримати IORegistry, використовуючи cli **`ioreg`**, щоб перевірити його з консолі (особливо корисно для iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Ви можете завантажити **`IORegistryExplorer`** з **Xcode Additional Tools** з [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) і перевірити **macOS IORegistry** через **графічний** інтерфейс.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

У IORegistryExplorer "площини" використовуються для організації та відображення відносин між різними об'єктами в IORegistry. Кожна площина представляє собою певний тип відносин або конкретний вигляд апаратного забезпечення та конфігурації драйверів системи. Ось деякі з поширених площин, з якими ви можете зіткнутися в IORegistryExplorer:

1. **IOService Plane**: Це найзагальніша площина, що відображає об'єкти сервісів, які представляють драйвери та нуби (канали зв'язку між драйверами). Вона показує відносини постачальника та клієнта між цими об'єктами.
2. **IODeviceTree Plane**: Ця площина представляє фізичні з'єднання між пристроями, коли вони підключені до системи. Вона часто використовується для візуалізації ієрархії пристроїв, підключених через шини, такі як USB або PCI.
3. **IOPower Plane**: Відображає об'єкти та їх відносини в термінах управління енергією. Вона може показувати, які об'єкти впливають на стан живлення інших, що корисно для налагодження проблем, пов'язаних з енергією.
4. **IOUSB Plane**: Спеціально зосереджена на USB-пристроях та їх відносинах, показуючи ієрархію USB-хабів та підключених пристроїв.
5. **IOAudio Plane**: Ця площина призначена для представлення аудіопристроїв та їх відносин у системі.
6. ...

## Приклад коду драйвера

Наступний код підключається до сервісу IOKit `"YourServiceNameHere"` і викликає функцію всередині селектора 0. Для цього:

* спочатку викликає **`IOServiceMatching`** та **`IOServiceGetMatchingServices`**, щоб отримати сервіс.
* Потім встановлює з'єднання, викликавши **`IOServiceOpen`**.
* І нарешті викликає функцію з **`IOConnectCallScalarMethod`**, вказуючи селектор 0 (селектор - це номер, який функція, яку ви хочете викликати, має призначений).
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
Є **інші** функції, які можна використовувати для виклику функцій IOKit, окрім **`IOConnectCallScalarMethod`**, такі як **`IOConnectCallMethod`**, **`IOConnectCallStructMethod**...

## Реверс інтерфейсу драйвера

Ви можете отримати їх, наприклад, з [**образу прошивки (ipsw)**](./#ipsw). Потім завантажте його у ваш улюблений декомпілятор.

Ви можете почати декомпілювати функцію **`externalMethod`**, оскільки це функція драйвера, яка буде отримувати виклик і викликати правильну функцію:

<figure><img src="../../../.gitbook/assets/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1169).png" alt=""><figcaption></figcaption></figure>

Цей жахливий виклик, розмальований, означає: 

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Зверніть увагу, що в попередньому визначенні пропущено параметр **`self`**, хороше визначення буде таким:

{% code overflow="wrap" %}
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
{% endcode %}

Насправді, ви можете знайти справжнє визначення за адресою [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
З цією інформацією ви можете переписати Ctrl+Right -> `Edit function signature` і встановити відомі типи:

<figure><img src="../../../.gitbook/assets/image (1174).png" alt=""><figcaption></figcaption></figure>

Новий декомпільований код виглядатиме так:

<figure><img src="../../../.gitbook/assets/image (1175).png" alt=""><figcaption></figcaption></figure>

Для наступного кроку нам потрібно визначити структуру **`IOExternalMethodDispatch2022`**. Вона є відкритим кодом у [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), ви можете визначити її:

<figure><img src="../../../.gitbook/assets/image (1170).png" alt=""><figcaption></figcaption></figure>

Тепер, слідуючи за `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, ви можете побачити багато даних:

<figure><img src="../../../.gitbook/assets/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Змініть тип даних на **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../.gitbook/assets/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

після зміни:

<figure><img src="../../../.gitbook/assets/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

І як ми тепер знаємо, що в нас є **масив з 7 елементів** (перевірте фінальний декомпільований код), натисніть, щоб створити масив з 7 елементів:

<figure><img src="../../../.gitbook/assets/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Після створення масиву ви можете побачити всі експортовані функції:

<figure><img src="../../../.gitbook/assets/image (1181).png" alt=""><figcaption></figcaption></figure>

{% hint style="success" %}
Якщо ви пам'ятаєте, щоб **викликати** експортовану функцію з простору користувача, нам не потрібно викликати ім'я функції, а лише **номер селектора**. Тут ви можете побачити, що селектор **0** - це функція **`initializeDecoder`**, селектор **1** - **`startDecoder`**, селектор **2** - **`initializeEncoder`**...
{% endhint %}

{% hint style="success" %}
Вчіться та практикуйте AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вчіться та практикуйте GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримати HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
