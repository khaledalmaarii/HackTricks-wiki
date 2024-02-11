# macOS XPC

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

XPC, ambayo inasimama kwa XNU (kernel inayotumiwa na macOS) Mawasiliano kati ya Michakato, ni mfumo wa **mawasiliano kati ya michakato** kwenye macOS na iOS. XPC hutoa njia ya kufanya **wito salama na usio na mpangilio kati ya michakato tofauti** kwenye mfumo. Ni sehemu ya mfumo wa usalama wa Apple, kuruhusu **uundaji wa programu zilizotengwa kwa ruhusa** ambapo kila **sehemu** inaendesha na **ruhusa tu inayohitajika** kufanya kazi yake, hivyo kupunguza uharibifu unaoweza kusababishwa na mchakato uliodukuliwa.

XPC hutumia aina ya Mawasiliano kati ya Michakato (IPC), ambayo ni seti ya njia za programu tofauti zinazoendesha kwenye mfumo huo kutuma na kupokea data.

Faida kuu za XPC ni pamoja na:

1. **Usalama**: Kwa kutenganisha kazi katika michakato tofauti, kila mchakato unaweza kupewa ruhusa tu inayohitajika. Hii inamaanisha kwamba hata kama mchakato umedukuliwa, una uwezo mdogo wa kusababisha madhara.
2. **Uimara**: XPC husaidia kubainisha ajali kwenye sehemu ambapo zinatokea. Ikiwa mchakato unapata ajali, unaweza kuanzishwa upya bila kuathiri sehemu nyingine ya mfumo.
3. **Utendaji**: XPC inaruhusu urahisi wa ushirikiano, kwani kazi tofauti zinaweza kufanyika wakati mmoja katika michakato tofauti.

Kizuizi pekee ni kwamba **kutenganisha programu katika michakato tofauti** na kuwasiliana kupitia XPC ni **si ufanisi sana**. Lakini katika mifumo ya leo hii haiwezi kugundulika sana na faida ni bora zaidi.

## Huduma za XPC za Maombi Maalum

Sehemu za XPC za programu zipo **ndani ya programu yenyewe**. Kwa mfano, kwenye Safari unaweza kuzipata kwenye **`/Applications/Safari.app/Contents/XPCServices`**. Zina ugani wa **`.xpc`** (kama **`com.apple.Safari.SandboxBroker.xpc`**) na pia ni **vifurushi** pamoja na binary kuu ndani yake: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` na `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Kama unavyofikiria, **sehemu ya XPC itakuwa na ruhusa na mamlaka tofauti** kuliko sehemu zingine za XPC au binary kuu ya programu. ISIPOKUWA ikiwa huduma ya XPC imeundwa na [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) imewekwa kuwa "Kweli" kwenye faili yake ya **Info.plist**. Katika kesi hii, huduma ya XPC itaendeshwa katika **kikao cha usalama sawa na programu** iliyoiita.

Huduma za XPC huanza na **launchd** wakati zinahitajika na **zimezimwa** mara tu kazi zote zinapokamilika ili kuachilia rasilimali za mfumo. **Sehemu za XPC za maombi maalum zinaweza kutumiwa tu na programu**, hivyo kupunguza hatari inayohusiana na udhaifu wowote uwezekanao.

## Huduma za XPC za Mfumo Mzima

Huduma za XPC za mfumo mzima zinapatikana kwa watumiaji wote. Huduma hizi, iwe ni launchd au aina ya Mach, zinahitaji **kuainishwa katika faili za plist** zilizoko kwenye saraka maalum kama vile **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, au **`/Library/LaunchAgents`**.

Faili hizi za plist zitakuwa na ufunguo unaoitwa **`MachServices`** na jina la huduma, na ufunguo unaoitwa **`Program`** na njia ya binary:
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
Wale katika **`LaunchDameons`** hufanywa na root. Kwa hivyo, ikiwa mchakato usio na mamlaka unaweza kuwasiliana na moja ya hizi, inaweza kuwa na uwezo wa kuongeza mamlaka.

## Ujumbe wa Tukio la XPC

Maombi yanaweza **jisajili** kwa ujumbe tofauti wa **tukio**, kuwawezesha kuwa **kuanzishwa kwa ombi** wakati matukio kama hayo yanatokea. **Usanidi** wa huduma hizi unafanywa katika faili za **plist za launchd**, zilizoko katika **miongozo ile ile kama za awali** na zikiwa na ufunguo wa ziada wa **`LaunchEvent`**.

### Ukaguzi wa Mchakato wa Kuunganisha XPC

Wakati mchakato unajaribu kuita njia kupitia uhusiano wa XPC, **huduma ya XPC inapaswa kuhakiki ikiwa mchakato huo una ruhusa ya kuunganisha**. Hapa kuna njia za kawaida za kufanya ukaguzi huo na mitego ya kawaida:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## Idhini ya XPC

Apple pia inaruhusu programu **kuwezesha baadhi ya haki na jinsi ya kuzipata** ili ikiwa mchakato unaopiga simu una haki hizo, itakuwa **imekuruhusiwa kuita njia** kutoka kwa huduma ya XPC:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## Mchunguzi wa XPC

Ili kuchunguza ujumbe wa XPC, unaweza kutumia [**xpcspy**](https://github.com/hot3eed/xpcspy) ambayo hutumia **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## Mfano wa Kanuni ya Mawasiliano ya XPC

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
## Mfano wa Kanuni ya XPC Communication Objective-C

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
## Mteja ndani ya kificho cha Dylb

In this technique, we will explore how to create a client inside a Dylb code. Dylb is a macOS framework that allows inter-process communication (IPC) using the XPC protocol.

Katika mbinu hii, tutachunguza jinsi ya kuunda mteja ndani ya kificho cha Dylb. Dylb ni mfumo wa macOS ambao huruhusu mawasiliano kati ya michakato (IPC) kwa kutumia itifaki ya XPC.

### Prerequisites

Before we begin, make sure you have the following:

- A macOS system
- Xcode installed
- Basic knowledge of macOS IPC and XPC

### Steps

Follow these steps to create a client inside a Dylb code:

1. Open Xcode and create a new project.
2. Choose "Command Line Tool" as the project template.
3. Provide a name for your project and select the desired language (e.g., Swift).
4. Click "Next" and choose a location to save your project.
5. In the project navigator, locate the main.swift file and open it.
6. Import the necessary frameworks for Dylb and XPC:

```swift
import Dylb
import XPC
```

7. Inside the main function, create an XPC connection:

```swift
let connection = xpc_connection_create_mach_service("com.example.server", nil, 0)
```

Replace "com.example.server" with the Mach service name of the server you want to connect to.

8. Set the event handler for the connection:

```swift
xpc_connection_set_event_handler(connection) { event in
    // Handle events here
}
```

9. Resume the connection:

```swift
xpc_connection_resume(connection)
```

10. Send a message to the server:

```swift
let message = xpc_dictionary_create(nil, nil, 0)
xpc_dictionary_set_string(message, "key", "value")
xpc_connection_send_message(connection, message)
```

Replace "key" and "value" with the appropriate data you want to send.

11. Handle the response from the server inside the event handler:

```swift
if xpc_get_type(event) == XPC_TYPE_DICTIONARY {
    let response = event.takeUnretainedValue()
    // Handle the response here
}
```

12. Build and run your project to test the client inside the Dylb code.

### Conclusion

By creating a client inside a Dylb code, you can establish communication with a server using XPC. This technique can be useful for various macOS applications that require inter-process communication.

### Hitimisho

Kwa kuunda mteja ndani ya kificho cha Dylb, unaweza kuweka mawasiliano na seva kwa kutumia XPC. Mbinu hii inaweza kuwa na manufaa kwa programu mbalimbali za macOS ambazo zinahitaji mawasiliano kati ya michakato.
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
<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
