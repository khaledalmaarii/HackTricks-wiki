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

XPC, što znači XNU (jezgro koje koristi macOS) međuprocesna komunikacija, je okvir za **komunikaciju između procesa** na macOS-u i iOS-u. XPC pruža mehanizam za **sigurne, asinhrone pozive metoda između različitih procesa** na sistemu. To je deo Apple-ove sigurnosne paradigme, koja omogućava **kreiranje aplikacija sa odvojenim privilegijama** gde svaki **komponent** radi sa **samo onim dozvolama koje su mu potrebne** da obavi svoj posao, čime se ograničava potencijalna šteta od kompromitovanog procesa.

XPC koristi oblik međuprocesne komunikacije (IPC), što je skup metoda za različite programe koji rade na istom sistemu da šalju podatke napred-nazad.

Primarne prednosti XPC-a uključuju:

1. **Sigurnost**: Razdvajanjem posla u različite procese, svaki proces može dobiti samo one dozvole koje su mu potrebne. To znači da čak i ako je proces kompromitovan, ima ograničenu sposobnost da nanese štetu.
2. **Stabilnost**: XPC pomaže da se srušavanja izoluju na komponentu gde se dešavaju. Ako proces padne, može se ponovo pokrenuti bez uticaja na ostatak sistema.
3. **Performanse**: XPC omogućava laku konkurentnost, jer se različiti zadaci mogu izvoditi istovremeno u različitim procesima.

Jedini **nedostatak** je što je **razdvajanje aplikacije u nekoliko procesa** koji komuniciraju putem XPC **manje efikasno**. Ali u današnjim sistemima to gotovo nije primetno i prednosti su bolje.

## Application Specific XPC services

XPC komponente aplikacije su **unutar same aplikacije.** Na primer, u Safariju ih možete pronaći u **`/Applications/Safari.app/Contents/XPCServices`**. Imaju ekstenziju **`.xpc`** (kao **`com.apple.Safari.SandboxBroker.xpc`**) i **takođe su paketi** sa glavnim binarnim fajlom unutar njega: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` i `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Kao što možda mislite, **XPC komponenta će imati različite privilegije i ovlašćenja** od drugih XPC komponenti ili glavnog binarnog fajla aplikacije. OSIM ako je XPC usluga konfigurisana sa [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) postavljenim na “True” u svom **Info.plist** fajlu. U ovom slučaju, XPC usluga će raditi u **istoim sigurnosnoj sesiji kao aplikacija** koja je pozvala.

XPC usluge se **pokreću** od strane **launchd** kada je to potrebno i **zatvaraju** se kada su svi zadaci **završeni** kako bi se oslobodili sistemski resursi. **Komponente XPC specifične za aplikaciju mogu koristiti samo aplikacija**, čime se smanjuje rizik povezan sa potencijalnim ranjivostima.

## System Wide XPC services

Sistemske XPC usluge su dostupne svim korisnicima. Ove usluge, bilo launchd ili Mach-tip, moraju biti **definisane u plist** fajlovima smeštenim u određenim direktorijumima kao što su **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, ili **`/Library/LaunchAgents`**.

Ovi plist fajlovi će imati ključ pod nazivom **`MachServices`** sa imenom usluge, i ključ pod nazivom **`Program`** sa putanjom do binarnog fajla:
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
The ones in **`LaunchDameons`** se pokreću kao root. Dakle, ako neprivilegovan proces može da komunicira sa jednim od ovih, mogao bi da eskalira privilegije.

## XPC Objekti

* **`xpc_object_t`**

Svaka XPC poruka je objekat rečnika koji pojednostavljuje serijalizaciju i deserializaciju. Štaviše, `libxpc.dylib` definiše većinu tipova podataka, tako da je moguće osigurati da su primljeni podaci očekivanog tipa. U C API-ju svaki objekat je `xpc_object_t` (i njegov tip se može proveriti koristeći `xpc_get_type(object)`).\
Pored toga, funkcija `xpc_copy_description(object)` može se koristiti za dobijanje string reprezentacije objekta koja može biti korisna za svrhe debagovanja.\
Ovi objekti takođe imaju neke metode koje se mogu pozvati kao što su `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

`xpc_object_t` se kreiraju pozivanjem `xpc_<objetType>_create` funkcije, koja interno poziva `_xpc_base_create(Class, Size)` gde se navodi tip klase objekta (jedan od `XPC_TYPE_*`) i veličina objekta (neka dodatna 40B će biti dodata veličini za metapodatke). Što znači da će podaci objekta početi na offsetu 40B.\
Dakle, `xpc_<objectType>_t` je neka vrsta podklase `xpc_object_t` koja bi bila podklasa `os_object_t*`.

{% hint style="warning" %}
Napomena da bi developer trebao koristiti `xpc_dictionary_[get/set]_<objectType>` da dobije ili postavi tip i stvarnu vrednost ključa.
{% endhint %}

* **`xpc_pipe`**

**`xpc_pipe`** je FIFO cev koju procesi mogu koristiti za komunikaciju (komunikacija koristi Mach poruke).\
Moguće je kreirati XPC server pozivom `xpc_pipe_create()` ili `xpc_pipe_create_from_port()` da bi se kreirao koristeći specifičnu Mach port. Zatim, da bi primili poruke, moguće je pozvati `xpc_pipe_receive` i `xpc_pipe_try_receive`.

Napomena da je objekat **`xpc_pipe`** **`xpc_object_t`** sa informacijama u svojoj strukturi o dva korišćena Mach porta i imenu (ako postoji). Ime, na primer, demon `secinitd` u svom plist-u `/System/Library/LaunchDaemons/com.apple.secinitd.plist` konfiguriše cev nazvanu `com.apple.secinitd`.

Primer **`xpc_pipe`** je **bootstrap pipe** koju kreira **`launchd`** čime se omogućava deljenje Mach portova.

* **`NSXPC*`**

Ovo su objekti visokog nivoa u Objective-C koji omogućavaju apstrakciju XPC veza.\
Štaviše, lakše je debagovati ove objekte sa DTrace nego prethodne.

* **`GCD Queues`**

XPC koristi GCD za slanje poruka, štaviše generiše određene redove za raspoređivanje kao što su `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Servisi

Ovo su **paketi sa `.xpc`** ekstenzijom smešteni unutar **`XPCServices`** foldera drugih projekata i u `Info.plist` imaju `CFBundlePackageType` postavljen na **`XPC!`**.\
Ovaj fajl ima druge konfiguracione ključeve kao što su `ServiceType` koji može biti Application, User, System ili `_SandboxProfile` koji može definisati sandbox ili `_AllowedClients` koji može ukazivati na prava ili ID potrebne za kontaktiranje servisa. Ove i druge konfiguracione opcije će biti korisne za konfiguraciju servisa prilikom pokretanja.

### Pokretanje Servisa

Aplikacija pokušava da **poveže** sa XPC servisom koristeći `xpc_connection_create_mach_service`, zatim launchd locira demon i pokreće **`xpcproxy`**. **`xpcproxy`** sprovodi konfigurisana ograničenja i pokreće servis sa obezbeđenim FDs i Mach portovima.

Da bi se poboljšala brzina pretrage XPC servisa, koristi se keš.

Moguće je pratiti akcije `xpcproxy` koristeći:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
XPC biblioteka koristi `kdebug` za logovanje akcija pozivajući `xpc_ktrace_pid0` i `xpc_ktrace_pid1`. Kodovi koje koristi nisu dokumentovani, pa je potrebno dodati ih u `/usr/share/misc/trace.codes`. Imaju prefiks `0x29`, a na primer jedan je `0x29000004`: `XPC_serializer_pack`.\
Utiliti `xpcproxy` koristi prefiks `0x22`, na primer: `0x2200001c: xpcproxy:will_do_preexec`.

## XPC Event Messages

Aplikacije mogu **pretplatiti** na različite događaje **poruke**, omogućavajući im da budu **inicirane na zahtev** kada se takvi događaji dogode. **Podešavanje** za ove usluge se vrši u **launchd plist datotekama**, smeštenim u **iste direktorijume kao prethodne** i sadrže dodatni **`LaunchEvent`** ključ.

### XPC Connecting Process Check

Kada proces pokuša da pozove metodu putem XPC veze, **XPC usluga treba da proveri da li je taj proces dozvoljen da se poveže**. Evo uobičajenih načina da se to proveri i uobičajenih zamki:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC Authorization

Apple takođe omogućava aplikacijama da **konfigurišu neka prava i kako ih dobiti**, tako da ako pozivajući proces ima ta prava, biće **dozvoljeno da pozove metodu** iz XPC usluge:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC Sniffer

Da biste presreli XPC poruke, možete koristiti [**xpcspy**](https://github.com/hot3eed/xpcspy) koji koristi **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Još jedan mogući alat za korišćenje je [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## XPC komunikacija C kod primer

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
## XPC komunikacija Primer Objective-C koda

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
## Клијент унутар Dylb кода
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

Ova funkcionalnost koju pruža `RemoteXPC.framework` (iz `libxpc`) omogućava komunikaciju putem XPC između različitih hostova.\
Servisi koji podržavaju daljinski XPC će imati u svom plist ključ UsesRemoteXPC kao što je slučaj sa `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Međutim, iako će servis biti registrovan sa `launchd`, to je `UserEventAgent` sa pluginovima `com.apple.remoted.plugin` i `com.apple.remoteservicediscovery.events.plugin` koji pruža funkcionalnost.

Štaviše, `RemoteServiceDiscovery.framework` omogućava dobijanje informacija iz `com.apple.remoted.plugin` izlažući funkcije kao što su `get_device`, `get_unique_device`, `connect`...

Kada se koristi connect i socket `fd` servisa se prikupi, moguće je koristiti klasu `remote_xpc_connection_*`.

Moguće je dobiti informacije o daljinskim servisima koristeći cli alat `/usr/libexec/remotectl` koristeći parametre kao:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Komunikacija između BridgeOS-a i hosta se odvija putem posvećenog IPv6 interfejsa. `MultiverseSupport.framework` omogućava uspostavljanje soketa čiji će `fd` biti korišćen za komunikaciju.\
Moguće je pronaći te komunikacije koristeći `netstat`, `nettop` ili otvorenu opciju, `netbottom`.

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
