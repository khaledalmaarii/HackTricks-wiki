# macOS XPC

## macOS XPC

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **та** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв GitHub**.

</details>

### Основна інформація

XPC, що означає міжпроцесну комунікацію XNU (ядра, яке використовується в macOS), є фреймворком для **комунікації між процесами** на macOS та iOS. XPC надає механізм для здійснення **безпечних, асинхронних викликів методів між різними процесами** у системі. Це частина парадигми безпеки Apple, яка дозволяє **створювати додатки з розділенням привілеїв**, де кожен **компонент** працює з **лише необхідними дозволами** для виконання своєї роботи, тим самим обмежуючи можливість завдання шкоди від компрометованого процесу.

XPC використовує форму міжпроцесної комунікації (IPC), яка є набором методів для взаємодії різних програм, що працюють на одній системі.

Основні переваги XPC включають:

1. **Безпека**: Розділяючи роботу на різні процеси, кожному процесу можна надати лише необхідні дозволи. Це означає, що навіть якщо процес скомпрометований, він має обмежену можливість завдати шкоду.
2. **Стабільність**: XPC допомагає ізолювати збої в компоненті, де вони виникають. Якщо процес впаде, його можна перезапустити без впливу на решту системи.
3. **Продуктивність**: XPC дозволяє легко виконувати одночасність, оскільки різні завдання можуть виконуватися одночасно в різних процесах.

Єдиний **недолік** полягає в тому, що **розділення додатка на кілька процесів**, які взаємодіють через XPC, є **менш ефективним**. Проте в сучасних системах це майже не помітно, а переваги кращі.

### Служби XPC, специфічні для додатків

Компоненти XPC додатка **знаходяться всередині самого додатка**. Наприклад, у Safari ви можете знайти їх у **`/Applications/Safari.app/Contents/XPCServices`**. Вони мають розширення **`.xpc`** (наприклад, **`com.apple.Safari.SandboxBroker.xpc`**) і також є **пакетами** разом з основним бінарним файлом всередині: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` та `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Як ви, можливо, подумали, **компонент XPC матиме різні дозволи та привілеї** порівняно з іншими компонентами XPC або основним бінарним файлом додатка. ЗА ВИКЛЮЧЕННЯМ, якщо служба XPC налаштована з [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession), встановленим на «True» у своєму файлі **Info.plist**. У цьому випадку служба XPC буде працювати в **тій самій сеансі безпеки, що й додаток**, який її викликав.

Служби XPC **запускаються** за допомогою **launchd** при необхідності та **зупиняються**, як тільки всі завдання **виконані**, для звільнення системних ресурсів. **Специфічні для додатків компоненти XPC можуть використовуватися лише додатком**, тим самим зменшуючи ризик, пов'язаний з можливими вразливостями.

### Служби XPC для всієї системи

Служби XPC для всієї системи доступні всім користувачам. Ці служби, які можуть бути запущені або типу Mach, повинні бути **визначені в файлах plist**, розташованих у вказаних каталогах, таких як **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** або **`/Library/LaunchAgents`**.

У цих файлах plist буде ключ з назвою **`MachServices`** з назвою служби та ключ з назвою **`Program`** з шляхом до бінарного файлу:

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

Ті, що знаходяться в **`LaunchDameons`**, запускаються користувачем root. Тому, якщо непривілейований процес може спілкуватися з одним з них, він може мати можливість підвищити привілеї.

### Повідомлення подій XPC

Додатки можуть **підписуватися** на різні події **повідомлень**, що дозволяє їм **ініціювати за потреби** ці події. Налаштування для цих служб виконується в файлах **launchd plist**, розташованих в **тих самих каталогах, що й попередні**, і містять додатковий ключ **`LaunchEvent`**.

#### Перевірка процесу підключення XPC

Коли процес намагається викликати метод через з'єднання XPC, **XPC-служба повинна перевірити, чи дозволено цьому процесу підключатися**. Ось загальні способи перевірки цього та загальні помилки:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Авторизація XPC

Apple також дозволяє додаткам **налаштовувати деякі права та способи їх отримання**, тому якщо викликаючий процес має їх, йому буде **дозволено викликати метод** з XPC-служби:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### XPC Сніфер

Для перехоплення повідомлень XPC можна використовувати [**xpcspy**](https://github.com/hot3eed/xpcspy), який використовує **Frida**.

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

### Приклад коду на мові C для XPC-комунікації

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
#### xpc\_client.c

```c
#include <stdio.h>
#include <xpc/xpc.h>

int main() {
    xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.xpcd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        printf("Received event: %s\n", xpc_copy_description(event));
    });
    xpc_connection_resume(connection);
    sleep(10);
    return 0;
}
```

This code creates an XPC connection to the `com.apple.xpcd` service and sets an event handler to print any received events. The connection is then resumed and the program sleeps for 10 seconds before exiting.

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

### Приклад коду XPC-комунікації на Objective-C

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

\### macOS XPC

XPC (XPC Services) is a macOS inter-process communication technology that allows processes to communicate with each other. It is commonly used for system services and background daemons.

**XPC Basics**

* **Service**: A macOS service that can be called by other processes.
* **Connection**: The communication channel between the client and the service.
* **Message**: Data sent between the client and the service.

**XPC Vulnerabilities**

* **Insecure Connections**: Lack of encryption or authentication can lead to unauthorized access.
* **Message Tampering**: Modifying XPC messages can lead to unexpected behavior or privilege escalation.
* **Memory Corruption**: Buffer overflows or other memory-related vulnerabilities can be exploited for code execution.

**Exploiting XPC**

1. **Identify XPC Services**: Use tools like `launchctl` or `XPC Explorer` to find XPC services on the system.
2. **Analyze Service**: Understand the service's functionality and message structure.
3. **Fuzzing**: Send malformed or unexpected data to the service to trigger vulnerabilities.
4. **Reverse Engineering**: Analyze the service binary to find security weaknesses.
5. **Exploit Development**: Develop exploits based on identified vulnerabilities.

**Mitigation**

* **Secure Connections**: Use encryption and authentication to protect XPC communications.
* **Input Validation**: Validate and sanitize input data to prevent message tampering.
* **Memory Safety**: Implement secure coding practices to prevent memory corruption vulnerabilities.

XPC is a powerful feature in macOS, but it can introduce security risks if not implemented and used correctly. Understanding XPC basics and common vulnerabilities is essential for securing macOS systems.

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

\`\`\`bash # Compile the server & client gcc -framework Foundation oc\_xpc\_server.m -o oc\_xpc\_server gcc -framework Foundation oc\_xpc\_client.m -o oc\_xpc\_client

## Save server on it's location

cp oc\_xpc\_server /tmp

## Load daemon

sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

## Call client

./oc\_xpc\_client

## Clean

sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc\_xpc\_server

````
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
````

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у форматі PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **і** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>
