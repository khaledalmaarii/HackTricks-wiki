# macOS XPC

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repositoriums.

</details>

## Basiese Inligting

XPC, wat staan vir XNU (die kernel wat deur macOS gebruik word) interproseskommunikasie, is 'n raamwerk vir **kommunikasie tussen prosesse** op macOS en iOS. XPC bied 'n meganisme vir die maak van **veilige, asynchrone metode-oproepe tussen verskillende prosesse** op die stelsel. Dit is 'n deel van Apple se veiligheidsparadigma wat die **skepping van voorreg-geskeide toepassings** moontlik maak waar elke **komponent** met **slegs die toestemmings wat dit nodig het** om sy werk te doen, loop, en sodoende die potensiële skade van 'n gekompromitteerde proses beperk.

XPC maak gebruik van 'n vorm van interproseskommunikasie (IPC), wat 'n stel metodes is vir verskillende programme wat op dieselfde stelsel loop om data heen en weer te stuur.

Die primêre voordele van XPC sluit in:

1. **Veiligheid**: Deur werk in verskillende prosesse te skei, kan elke proses slegs die toestemmings kry wat dit nodig het. Dit beteken dat selfs as 'n proses gekompromitteer word, dit beperkte vermoë het om skade aan te rig.
2. **Stabiliteit**: XPC help om ongelukke te isoleer tot die komponent waar dit plaasvind. As 'n proses afbreek, kan dit herbegin word sonder om die res van die stelsel te affekteer.
3. **Prestasie**: XPC maak maklike gelyktydigheid moontlik, aangesien verskillende take gelyktydig in verskillende prosesse uitgevoer kan word.

Die enigste **nadeel** is dat **die skeiding van 'n toepassing in verskeie prosesse** wat kommunikeer via XPC **minder doeltreffend** is. Maar in hedendaagse stelsels is dit amper onmerkbaar en die voordele is beter.

## Toepassing-spesifieke XPC-diens

Die XPC-komponente van 'n toepassing is **binne die toepassing self**. Byvoorbeeld, in Safari kan jy hulle vind in **`/Applications/Safari.app/Contents/XPCServices`**. Hulle het die uitbreiding **`.xpc`** (soos **`com.apple.Safari.SandboxBroker.xpc`**) en is **ook bundels** met die hoofbinêre binne-in dit: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` en 'n `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Soos jy dalk dink, sal 'n **XPC-komponent verskillende toestemmings en voorregte** hê as die ander XPC-komponente of die hooftoepassingsbinêre. BEHALWE as 'n XPC-diens gekonfigureer is met [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) wat op "True" gestel is in sy **Info.plist**-lêer. In hierdie geval sal die XPC-diens in dieselfde veiligheidssessie loop as die toepassing wat dit geroep het.

XPC-diens word **begin** deur **launchd** wanneer dit nodig is en **afgeskakel** sodra alle take **voltooi** is om stelselhulpbronne vry te maak. **Toepassing-spesifieke XPC-komponente kan slegs deur die toepassing gebruik word**, wat die risiko wat verband hou met potensiële kwesbaarhede verminder.

## Stelselwye XPC-diens

Stelselwye XPC-diens is toeganklik vir alle gebruikers. Hierdie dienste, hetsy launchd of Mach-tipe, moet **in plist-lêers** gedefinieer word wat in gespesifiseerde gidsies soos **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, of **`/Library/LaunchAgents`** geleë is.

Hierdie plist-lêers sal 'n sleutel hê met die naam **`MachServices`** met die naam van die diens, en 'n sleutel met die naam **`Program`** met die pad na die binêre lêer:
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
Diegene in **`LaunchDameons`** word deur root uitgevoer. As 'n onbevoorregte proses met een van hierdie kan kommunikeer, kan dit in staat wees om voorregte te verhoog.

## XPC Gebeurtenisboodskappe

Toepassings kan inteken op verskillende gebeurtenisboodskappe, wat hulle in staat stel om op aanvraag geïnisieer te word wanneer sulke gebeure plaasvind. Die opstelling vir hierdie dienste word gedoen in **`launchd plist-lêers`**, wat in dieselfde gids as die voriges geleë is en 'n ekstra **`LaunchEvent`** sleutel bevat.

### XPC Verbindende Prosessetoets

Wanneer 'n proses probeer om 'n metode te roep via 'n XPC-verbindig, moet die XPC-diens nagaan of daardie proses toegelaat word om te verbind. Hier is die algemene maniere om dit te toets en die algemene valstrikke:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC Magtiging

Apple laat ook programme toe om sommige regte te konfigureer en hoe om dit te verkry, sodat as die aanroepende proses dit het, dit toegelaat sal word om 'n metode van die XPC-diens te roep:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC Sniffer

Om die XPC-boodskappe te snuffel, kan jy [**xpcspy**](https://github.com/hot3eed/xpcspy) gebruik wat **Frida** gebruik.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## XPC Kommunikasie C Kode Voorbeeld

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
## XPC Kommunikasie Objective-C Kode Voorbeeld

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
## Kliënt binne 'n Dylb-kode

In hierdie scenario sal ons 'n kliënt binne 'n Dylb-kode implementeer. Die Dylb-kode is 'n dinamiese biblioteek wat gebruik word om funksies te deel tussen verskillende toepassings. Ons sal die kliënt binne die Dylb-kode gebruik om te kommunikeer met 'n bedienersagteware wat deur die Dylb-kode verskaf word.

Hier is die stappe om 'n kliënt binne 'n Dylb-kode te implementeer:

1. Skep 'n nuwe Dylb-kodeprojek en voeg die nodige afhanklikhede by.
2. Skep 'n kliëntklas binne die Dylb-kodeprojek. Hierdie klas sal gebruik word om die bedienersagteware te kommunikeer.
3. Implementeer die nodige funksies binne die kliëntklas om die kommunikasie met die bedienersagteware te fasiliteer. Dit kan insluit die stuur van versoeke, ontvangs van antwoorde, en verwerking van data.
4. Skep 'n hoofprogram binne die Dylb-kodeprojek om die kliëntklas te instansieer en die kommunikasie met die bedienersagteware te demonstreer.
5. Bou die Dylb-kodeprojek en voeg dit by die toepassings wat die funksionaliteit van die bedienersagteware wil gebruik.

Met die kliënt binne die Dylb-kode kan toepassings nou die funksies van die bedienersagteware gebruik sonder om dit self te implementeer. Dit maak dit makliker om funksionaliteit te deel en hergebruik tussen verskillende toepassings.
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

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
