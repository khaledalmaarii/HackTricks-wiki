# macOS XPC

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

XPC, що означає XNU (ядро, яке використовується в macOS) міжпроцесорна комунікація, є фреймворком для **комунікації між процесами** на macOS та iOS. XPC надає механізм для виконання **безпечних, асинхронних викликів методів між різними процесами** в системі. Це частина безпекової парадигми Apple, що дозволяє **створювати програми з розділеними привілеями**, де кожен **компонент** працює з **тільки тими правами, які йому потрібні** для виконання своєї роботи, тим самим обмежуючи потенційні збитки від скомпрометованого процесу.

XPC використовує форму міжпроцесорної комунікації (IPC), яка є набором методів для різних програм, що працюють на одній системі, для обміну даними.

Основні переваги XPC включають:

1. **Безпека**: Розділяючи роботу на різні процеси, кожному процесу можуть бути надані тільки ті права, які йому потрібні. Це означає, що навіть якщо процес буде скомпрометований, його можливості завдати шкоди будуть обмежені.
2. **Стабільність**: XPC допомагає ізолювати збої до компонента, в якому вони відбуваються. Якщо процес зазнає збою, його можна перезапустити без впливу на решту системи.
3. **Продуктивність**: XPC дозволяє легко виконувати кілька завдань одночасно в різних процесах.

Єдиний **недолік** полягає в тому, що **розділення програми на кілька процесів**, які спілкуються через XPC, є **менш ефективним**. Але в сучасних системах це майже не помітно, а переваги переважають.

## Application Specific XPC services

XPC компоненти програми знаходяться **всередині самої програми.** Наприклад, у Safari ви можете знайти їх у **`/Applications/Safari.app/Contents/XPCServices`**. Вони мають розширення **`.xpc`** (як **`com.apple.Safari.SandboxBroker.xpc`**) і **також є пакетами** з основним бінарним файлом всередині: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` та `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Як ви, можливо, думаєте, **XPC компонент матиме різні права та привілеї** в порівнянні з іншими XPC компонентами або основним бінарним файлом програми. ОКРІМ випадку, якщо XPC служба налаштована з [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) встановленим на “True” у її **Info.plist** файлі. У цьому випадку XPC служба буде працювати в **тій же безпековій сесії, що й програма**, яка її викликала.

XPC служби **запускаються** за допомогою **launchd** за потреби і **закриваються** після завершення всіх завдань, щоб звільнити системні ресурси. **Специфічні для програми XPC компоненти можуть використовуватися тільки самою програмою**, тим самим зменшуючи ризик, пов'язаний з потенційними вразливостями.

## System Wide XPC services

Системні XPC служби доступні всім користувачам. Ці служби, або launchd, або Mach-типу, повинні бути **визначені в plist** файлах, розташованих у вказаних каталогах, таких як **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, або **`/Library/LaunchAgents`**.

Ці plist файли матимуть ключ під назвою **`MachServices`** з назвою служби та ключ під назвою **`Program`** з шляхом до бінарного файлу:
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Ті, що в **`LaunchDameons`**, виконуються від імені root. Тому, якщо неправа процес може спілкуватися з одним з них, це може дозволити ескалацію привілеїв.

## XPC Об'єкти

* **`xpc_object_t`**

Кожне XPC повідомлення є об'єктом словника, який спрощує серіалізацію та десеріалізацію. Більше того, `libxpc.dylib` оголошує більшість типів даних, тому можливо перевірити, що отримані дані мають очікуваний тип. У C API кожен об'єкт є `xpc_object_t` (і його тип можна перевірити за допомогою `xpc_get_type(object)`).\
Більше того, функцію `xpc_copy_description(object)` можна використовувати для отримання рядкового представлення об'єкта, що може бути корисним для налагодження.\
Ці об'єкти також мають деякі методи для виклику, такі як `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` створюються за допомогою виклику функції `xpc_<objetType>_create`, яка внутрішньо викликає `_xpc_base_create(Class, Size)`, де вказується тип класу об'єкта (один з `XPC_TYPE_*`) і його розмір (додаткові 40B будуть додані до розміру для метаданих). Це означає, що дані об'єкта почнуться з офсету 40B.\
Отже, `xpc_<objectType>_t` є своєрідним підкласом `xpc_object_t`, який буде підкласом `os_object_t*`.

{% hint style="warning" %}
Зверніть увагу, що саме розробник повинен використовувати `xpc_dictionary_[get/set]_<objectType>`, щоб отримати або встановити тип і реальне значення ключа.
{% endhint %}

* **`xpc_pipe`**

**`xpc_pipe`** — це FIFO труба, яку процеси можуть використовувати для спілкування (спілкування використовує повідомлення Mach).\
Можливо створити XPC сервер, викликавши `xpc_pipe_create()` або `xpc_pipe_create_from_port()`, щоб створити його, використовуючи конкретний Mach порт. Потім, щоб отримувати повідомлення, можна викликати `xpc_pipe_receive` і `xpc_pipe_try_receive`.

Зверніть увагу, що об'єкт **`xpc_pipe`** є **`xpc_object_t`** з інформацією в його структурі про два Mach порти, що використовуються, і ім'я (якщо є). Ім'я, наприклад, демон `secinitd` у його plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` налаштовує трубу, названу `com.apple.secinitd`.

Приклад **`xpc_pipe`** — це **bootstrap pipe**, створена **`launchd`**, що робить можливим спільне використання Mach портів.

* **`NSXPC*`**

Це об'єкти високого рівня Objective-C, які дозволяють абстракцію XPC з'єднань.\
Більше того, їх легше налагоджувати за допомогою DTrace, ніж попередні.

* **`GCD Queues`**

XPC використовує GCD для передачі повідомлень, більше того, він генерує певні черги диспетчеризації, такі як `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Сервіси

Це **пакети з розширенням `.xpc`**, розташовані всередині папки **`XPCServices`** інших проектів, і в `Info.plist` у них є `CFBundlePackageType`, встановлений на **`XPC!`**.\
Цей файл має інші ключі конфігурації, такі як `ServiceType`, який може бути Application, User, System або `_SandboxProfile`, який може визначати пісочницю, або `_AllowedClients`, який може вказувати права або ID, необхідні для контакту з сервісом. Ці та інші параметри конфігурації будуть корисні для налаштування сервісу під час запуску.

### Запуск Сервісу

Додаток намагається **підключитися** до XPC сервісу, використовуючи `xpc_connection_create_mach_service`, потім launchd знаходить демон і запускає **`xpcproxy`**. **`xpcproxy`** забезпечує виконання налаштованих обмежень і створює сервіс з наданими FDs і Mach портами.

Для покращення швидкості пошуку XPC сервісу використовується кеш.

Можливо відстежувати дії `xpcproxy`, використовуючи:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
The XPC library використовує `kdebug` для логування дій, викликаючи `xpc_ktrace_pid0` та `xpc_ktrace_pid1`. Коди, які він використовує, не задокументовані, тому їх потрібно додати до `/usr/share/misc/trace.codes`. Вони мають префікс `0x29`, і, наприклад, один з них `0x29000004`: `XPC_serializer_pack`.\
Утиліта `xpcproxy` використовує префікс `0x22`, наприклад: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Повідомлення подій

Застосунки можуть **підписуватися** на різні події **повідомлення**, що дозволяє їм **ініціюватися за запитом**, коли такі події відбуваються. **Налаштування** для цих сервісів виконується в **файлах plist launchd**, розташованих у **тих же каталогах, що й попередні**, і містять додатковий **ключ `LaunchEvent`**.

### XPC Перевірка процесу підключення

Коли процес намагається викликати метод через XPC-з'єднання, **XPC-сервіс повинен перевірити, чи дозволено цьому процесу підключатися**. Ось поширені способи перевірки цього та поширені помилки:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC Авторизація

Apple також дозволяє додаткам **налаштовувати деякі права та способи їх отримання**, тому якщо викликаючий процес має їх, йому буде **дозволено викликати метод** з XPC-сервісу:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC Сніфер

Щоб перехоплювати XPC повідомлення, ви можете використовувати [**xpcspy**](https://github.com/hot3eed/xpcspy), який використовує **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Іншим можливим інструментом для використання є [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Приклад коду C для XPC зв'язку

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xpc_client.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.service.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
## XPC Communication Objective-C Code Example

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% endtab %}

{% tab title="oc_xpc_client.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{% endtab %}

{% tab title="xyz.hacktricks.svcoc.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## Клієнт всередині коду Dylb
```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
NSString*  _serviceName = @"xyz.hacktricks.svcoc";

NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

[_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

[_agentConnection resume];

[[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
(void)error;
NSLog(@"Connection Failure");
}] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}    ];
NSLog(@"Done!");

return;
}
```
## Remote XPC

Ця функціональність, надана `RemoteXPC.framework` (з `libxpc`), дозволяє спілкуватися через XPC між різними хостами.\
Служби, які підтримують віддалений XPC, матимуть у своєму plist ключ UsesRemoteXPC, як це відбувається у випадку з `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Однак, хоча служба буде зареєстрована з `launchd`, саме `UserEventAgent` з плагінами `com.apple.remoted.plugin` та `com.apple.remoteservicediscovery.events.plugin` надає цю функціональність.

Більше того, `RemoteServiceDiscovery.framework` дозволяє отримувати інформацію з `com.apple.remoted.plugin`, відкриваючи функції, такі як `get_device`, `get_unique_device`, `connect`...

Як тільки використовується connect і збирається сокет `fd` служби, можна використовувати клас `remote_xpc_connection_*`.

Можна отримати інформацію про віддалені служби, використовуючи інструмент cli `/usr/libexec/remotectl` з параметрами, такими як:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Зв'язок між BridgeOS та хостом відбувається через спеціальний інтерфейс IPv6. `MultiverseSupport.framework` дозволяє встановлювати сокети, `fd` яких буде використовуватися для зв'язку.\
Можна знайти ці комунікації, використовуючи `netstat`, `nettop` або відкриту альтернативу, `netbottom`.

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
