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

XPC, wat staan vir XNU (die kern wat deur macOS gebruik word) inter-Process Communication, is 'n raamwerk vir **kommunikasie tussen prosesse** op macOS en iOS. XPC bied 'n mekanisme vir die maak van **veilige, asynchrone metode-oproepe tussen verskillende prosesse** op die stelsel. Dit is 'n deel van Apple se sekuriteitsparadigma, wat die **skepping van privilige-geskeide toepassings** moontlik maak waar elke **komponent** loop met **slegs die regte wat dit nodig het** om sy werk te doen, en so die potensiële skade van 'n gecompromitteerde proses beperk.

XPC gebruik 'n vorm van Inter-Process Communication (IPC), wat 'n stel metodes is vir verskillende programme wat op dieselfde stelsel loop om data heen en weer te stuur.

Die primêre voordele van XPC sluit in:

1. **Sekuriteit**: Deur werk in verskillende prosesse te skei, kan elke proses slegs die regte toegeken word wat dit nodig het. Dit beteken dat selfs al word 'n proses gecompromitteer, dit beperkte vermoë het om skade aan te rig.
2. **Stabiliteit**: XPC help om crashes te isoleer na die komponent waar hulle voorkom. As 'n proses crash, kan dit herbegin word sonder om die res van die stelsel te beïnvloed.
3. **Prestasie**: XPC maak dit maklik om gelijktijdigheid te hê, aangesien verskillende take gelyktydig in verskillende prosesse uitgevoer kan word.

Die enigste **nadeel** is dat **die skeiding van 'n toepassing in verskeie prosesse** wat via XPC kommunikeer **minder doeltreffend** is. Maar in vandag se stelsels is dit amper nie opmerklik nie en die voordele is beter.

## Application Specific XPC services

Die XPC-komponente van 'n toepassing is **binne die toepassing self.** Byvoorbeeld, in Safari kan jy hulle vind in **`/Applications/Safari.app/Contents/XPCServices`**. Hulle het 'n uitbreiding **`.xpc`** (soos **`com.apple.Safari.SandboxBroker.xpc`**) en is **ook bundels** saam met die hoof-binary binne-in: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` en 'n `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Soos jy dalk dink, sal 'n **XPC-komponent verskillende regte en voorregte hê** as die ander XPC-komponente of die hoof-toepassing binary. BEHALWE as 'n XPC-diens geconfigureer is met [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) wat op “True” in sy **Info.plist**-lêer gestel is. In hierdie geval sal die XPC-diens in die **dieselfde sekuriteitsessie as die toepassing** wat dit aangeroep het, loop.

XPC-dienste word **gestart** deur **launchd** wanneer nodig en **afgeskakel** sodra alle take **voltooi** is om stelselhulpbronne vry te maak. **Toepassing-spesifieke XPC-komponente kan slegs deur die toepassing gebruik word**, wat die risiko wat met potensiële kwesbaarhede geassosieer word, verminder.

## System Wide XPC services

Stelsel-wye XPC-dienste is beskikbaar vir alle gebruikers. Hierdie dienste, hetsy launchd of Mach-tipe, moet **gedefinieer word in plist** lêers wat in gespesifiseerde gidse soos **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, of **`/Library/LaunchAgents`** geleë is.

Hierdie plists lêers sal 'n sleutel hê wat **`MachServices`** genoem word met die naam van die diens, en 'n sleutel wat **`Program`** genoem word met die pad na die binary:
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
Diegene in **`LaunchDameons`** word deur root uitgevoer. So as 'n nie-bevoegde proses met een van hierdie kan praat, kan dit in staat wees om bevoegdhede te verhoog.

## XPC Objekte

* **`xpc_object_t`**

Elke XPC boodskap is 'n woordeboek objek wat die serialisering en deserialisering vereenvoudig. Boonop verklaar `libxpc.dylib` die meeste van die datatipes, so dit is moontlik om te maak dat die ontvangde data van die verwagte tipe is. In die C API is elke objek 'n `xpc_object_t` (en sy tipe kan nagegaan word met `xpc_get_type(object)`).\
Boonop kan die funksie `xpc_copy_description(object)` gebruik word om 'n string voorstelling van die objek te verkry wat nuttig kan wees vir foutopsporing.\
Hierdie objekte het ook 'n paar metodes om te bel soos `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Die `xpc_object_t` word geskep deur die `xpc_<objetType>_create` funksie aan te roep, wat intern `_xpc_base_create(Class, Size)` aanroep waar die tipe van die klas van die objek (een van `XPC_TYPE_*`) en die grootte daarvan aangedui word (sommige ekstra 40B sal by die grootte vir metadata gevoeg word). Dit beteken dat die data van die objek by die offset 40B sal begin.\
Daarom is die `xpc_<objectType>_t` 'n soort subklas van die `xpc_object_t` wat 'n subklas van `os_object_t*` sou wees.

{% hint style="warning" %}
Let daarop dat dit die ontwikkelaar moet wees wat `xpc_dictionary_[get/set]_<objectType>` gebruik om die tipe en werklike waarde van 'n sleutel te kry of in te stel.
{% endhint %}

* **`xpc_pipe`**

'n **`xpc_pipe`** is 'n FIFO-pyp wat prosesse kan gebruik om te kommunikeer (die kommunikasie gebruik Mach-boodskappe).\
Dit is moontlik om 'n XPC-bediener te skep deur `xpc_pipe_create()` of `xpc_pipe_create_from_port()` aan te roep om dit met 'n spesifieke Mach-poort te skep. Dan, om boodskappe te ontvang, is dit moontlik om `xpc_pipe_receive` en `xpc_pipe_try_receive` aan te roep.

Let daarop dat die **`xpc_pipe`** objek 'n **`xpc_object_t`** is met inligting in sy struktuur oor die twee Mach-poorte wat gebruik word en die naam (indien enige). Die naam, byvoorbeeld, die daemon `secinitd` in sy plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` konfigureer die pyp genaamd `com.apple.secinitd`.

'n Voorbeeld van 'n **`xpc_pipe`** is die **bootstrap pyp** wat deur **`launchd`** geskep word wat die deel van Mach-poorte moontlik maak.

* **`NSXPC*`**

Dit is Objective-C hoëvlak objekte wat die abstraksie van XPC verbindings toelaat.\
Boonop is dit makliker om hierdie objekte met DTrace te foutopspoor as die vorige.

* **`GCD Queues`**

XPC gebruik GCD om boodskappe oor te dra, boonop genereer dit sekere afleweringsqueues soos `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Dienste

Dit is **bundels met `.xpc`** uitbreiding wat binne die **`XPCServices`** gids van ander projekte geleë is en in die `Info.plist` het hulle die `CFBundlePackageType` op **`XPC!`** gestel.\
Hierdie lêer het ander konfigurasiesleutels soos `ServiceType` wat kan wees Toepassing, Gebruiker, Stelsel of `_SandboxProfile` wat 'n sandbox kan definieer of `_AllowedClients` wat moontlik regte of ID kan aandui wat benodig word om die diens te kontak. Hierdie en ander konfigurasie opsies sal nuttig wees om die diens te konfigureer wanneer dit gelaai word.

### Begin 'n Diens

Die app probeer om te **verbinde** met 'n XPC diens deur `xpc_connection_create_mach_service` te gebruik, dan lokaliseer launchd die daemon en begin **`xpcproxy`**. **`xpcproxy`** afdwing geconfigureerde beperkings en. spawn die diens met die verskafde FDs en Mach-poorte.

Om die spoed van die soektog na die XPC diens te verbeter, word 'n kas gebruik.

Dit is moontlik om die aksies van `xpcproxy` te volg met:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Die XPC-biblioteek gebruik `kdebug` om aksies te log wat `xpc_ktrace_pid0` en `xpc_ktrace_pid1` aanroep. Die kodes wat dit gebruik is nie gedokumenteer nie, so dit is nodig om dit by `/usr/share/misc/trace.codes` te voeg. Hulle het die voorvoegsel `0x29` en byvoorbeeld een is `0x29000004`: `XPC_serializer_pack`.\
Die nut `xpcproxy` gebruik die voorvoegsel `0x22`, byvoorbeeld: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Gebeurtenisboodskappe

Toepassings kan **subskribeer** op verskillende gebeurtenis **boodskappe**, wat hulle in staat stel om **op aanvraag geaktiveer** te word wanneer sulke gebeurtenisse plaasvind. Die **opstelling** vir hierdie dienste word in **launchd plist-lêers** gedoen, geleë in die **dieselfde gidse as die vorige** en bevat 'n ekstra **`LaunchEvent`** sleutel.

### XPC Verbinding Proses Kontrole

Wanneer 'n proses probeer om 'n metode via 'n XPC-verbinding aan te roep, moet die **XPC-diens kontroleer of daardie proses toegelaat word om te verbind**. Hier is die algemene maniere om dit te kontroleer en die algemene valstrikke:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC Magtiging

Apple laat ook toepassings toe om **sekere regte te konfigureer en hoe om dit te verkry**, so as die oproepende proses dit het, sal dit **toegelaat word om 'n metode** van die XPC-diens aan te roep:

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
'n Ander moontlike hulpmiddel om te gebruik is [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

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
## Kliënt binne 'n Dylb kode
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

Hierdie funksionaliteit wat deur `RemoteXPC.framework` (van `libxpc`) verskaf word, stel in staat om via XPC deur verskillende gasheer te kommunikeer.\
Die dienste wat afstand XPC ondersteun, sal in hul plist die sleutel UsesRemoteXPC hê, soos die geval is met `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Tog, alhoewel die diens geregistreer sal wees met `launchd`, is dit `UserEventAgent` met die plugins `com.apple.remoted.plugin` en `com.apple.remoteservicediscovery.events.plugin` wat die funksionaliteit verskaf.

Boonop stel die `RemoteServiceDiscovery.framework` in staat om inligting van die `com.apple.remoted.plugin` te verkry wat funksies soos `get_device`, `get_unique_device`, `connect`... blootstel.

Sodra connect gebruik word en die socket `fd` van die diens versamel is, is dit moontlik om die `remote_xpc_connection_*` klas te gebruik.

Dit is moontlik om inligting oor afstanddienste te verkry met die cli-gereedskap `/usr/libexec/remotectl` deur parameters soos:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Die kommunikasie tussen BridgeOS en die gasheer vind plaas deur 'n toegewyde IPv6-koppelvlak. Die `MultiverseSupport.framework` maak dit moontlik om sokkies te vestig waarvan die `fd` gebruik sal word vir kommunikasie.\
Dit is moontlik om hierdie kommunikasies te vind met `netstat`, `nettop` of die oopbron opsie, `netbottom`.

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) of die [**telegram group**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
