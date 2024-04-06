# macOS XPC

## macOS XPC

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### Podstawowe informacje

XPC, co oznacza XNU (jądro używane przez macOS) Inter-Process Communication, to framework do **komunikacji między procesami** na macOS i iOS. XPC zapewnia mechanizm do **bezpiecznych, asynchronicznych wywołań metod między różnymi procesami** w systemie. Jest to część paradygmatu bezpieczeństwa Apple, umożliwiająca **tworzenie aplikacji z podziałem uprawnień**, gdzie każdy **komponent** działa z **tylko tymi uprawnieniami, które są mu potrzebne**, ograniczając tym samym potencjalne szkody spowodowane przez skompromitowany proces.

XPC wykorzystuje formę komunikacji międzyprocesowej (IPC), która jest zestawem metod umożliwiających przesyłanie danych między różnymi programami działającymi na tym samym systemie.

Główne korzyści z XPC to:

1. **Bezpieczeństwo**: Poprzez rozdzielenie pracy na różne procesy, każdemu procesowi można przyznać tylko te uprawnienia, które są mu potrzebne. Oznacza to, że nawet jeśli proces zostanie skompromitowany, ma ograniczoną zdolność do wyrządzenia szkody.
2. **Stabilność**: XPC pomaga izolować awarie do komponentu, w którym występują. Jeśli proces ulegnie awarii, można go ponownie uruchomić, nie wpływając na resztę systemu.
3. **Wydajność**: XPC umożliwia łatwą współbieżność, ponieważ różne zadania mogą być wykonywane jednocześnie w różnych procesach.

Jedynym **wadą** jest to, że **rozdzielenie aplikacji na kilka procesów** komunikujących się za pomocą XPC jest **mniej wydajne**. Jednak w dzisiejszych systemach jest to prawie niezauważalne, a korzyści są większe.

### Usługi XPC specyficzne dla aplikacji

Komponenty XPC aplikacji znajdują się **wewnątrz samej aplikacji**. Na przykład w Safari można je znaleźć w **`/Applications/Safari.app/Contents/XPCServices`**. Mają rozszerzenie **`.xpc`** (np. **`com.apple.Safari.SandboxBroker.xpc`**) i są **również paczkami** z głównym plikiem binarnym wewnątrz: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` oraz `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Jak można się domyślać, **komponent XPC będzie miał inne uprawnienia i przywileje** niż inne komponenty XPC lub główny plik binarny aplikacji. Z WYJĄTKIEM, jeśli usługa XPC jest skonfigurowana z ustawieniem [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) ustawionym na "True" w pliku **Info.plist**. W tym przypadku usługa XPC będzie działać w **tym samym sesji zabezpieczeń co aplikacja**, która ją wywołała.

Usługi XPC są **uruchamiane** przez **launchd** w razie potrzeby i **zamykane**, gdy wszystkie zadania są **zakończone**, aby zwolnić zasoby systemowe. **Komponenty XPC specyficzne dla aplikacji mogą być wykorzystywane tylko przez aplikację**, co zmniejsza ryzyko związane z potencjalnymi podatnościami.

### Usługi XPC na poziomie systemu

Usługi XPC na poziomie systemu są dostępne dla wszystkich użytkowników. Te usługi, zarówno typu launchd, jak i Mach, muszą być **zdefiniowane w plikach plist** znajdujących się w określonych katalogach, takich jak **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** lub **`/Library/LaunchAgents`**.

Te pliki plist będą miały klucz o nazwie **`MachServices`** z nazwą usługi oraz klucz o nazwie **`Program`** z ścieżką do pliku binarnego:

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

Te znajdujące się w **`LaunchDameons`** są uruchamiane przez roota. Jeśli proces bez uprawnień może komunikować się z jednym z nich, może próbować podwyższyć uprawnienia.

### Komunikaty zdarzeń XPC

Aplikacje mogą **subskrybować** różne **komunikaty zdarzeń**, umożliwiając ich **inicjację na żądanie**, gdy takie zdarzenia wystąpią. **Konfiguracja** tych usług odbywa się w plikach **plist launchd**, znajdujących się w **tych samych katalogach** i zawierających dodatkowy klucz **`LaunchEvent`**.

#### Sprawdzanie procesu łączącego się przez XPC

Gdy proces próbuje wywołać metodę za pośrednictwem połączenia XPC, **usługa XPC powinna sprawdzić, czy ten proces ma uprawnienia do połączenia**. Oto powszechne sposoby sprawdzania tego oraz powszechne pułapki:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### Autoryzacja XPC

Apple pozwala również aplikacjom **konfigurować pewne prawa i sposób ich uzyskania**, dzięki czemu jeśli wywołujący proces je posiada, będzie **mógł wywołać metodę** z usługi XPC:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### Sniffer XPC

Aby podsłuchiwać komunikaty XPC, można użyć [**xpcspy**](https://github.com/hot3eed/xpcspy), który korzysta z **Frida**.

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

### Przykład kodu C do komunikacji XPC

{% tabs %}
{% tab title="undefined" %}
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
#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.securityd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        
        if (type == XPC_TYPE_DICTIONARY) {
            const char *description = xpc_dictionary_get_string(event, "description");
            printf("Received event: %s\n", description);
        }
    });
    
    xpc_connection_resume(connection);
    
    dispatch_main();
    
    return 0;
}
```

This is a simple example of an XPC client in C. It creates a connection to the `com.apple.securityd` Mach service, which is a privileged service responsible for security-related tasks on macOS.

The `xpc_connection_set_event_handler` function sets a block of code to be executed whenever an event is received from the server. In this case, it checks if the event is a dictionary and prints the value of the "description" key.

The `xpc_connection_resume` function starts the connection and the `dispatch_main` function enters the main event loop, allowing the client to receive events.

To compile and run this code, you will need to link against the XPC framework using the `-lxpc` flag. For example:

```bash
gcc -o xpc_client xpc_client.c -lxpc
./xpc_client
```

This code can be used as a starting point for building more complex XPC clients that interact with privileged services on macOS.
{% endtab %}

{% tab title="undefined" %}
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
xyz.hacktricks.service.plist to plik konfiguracyjny dla usługi XPC, która jest używana do komunikacji międzyprocesowej na systemie macOS. Plik ten zawiera informacje dotyczące konfiguracji usługi, takie jak identyfikator usługi, ścieżka do pliku wykonywalnego, argumenty wiersza poleceń, uprawnienia i wiele innych. Aby skonfigurować usługę XPC, należy edytować ten plik i dostosować go do swoich potrzeb. Upewnij się, że plik ten znajduje się w odpowiednim katalogu, aby usługa mogła zostać poprawnie uruchomiona.

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

### Przykład kodu XPC Communication w Objective-C

{% tabs %}
{% tab title="undefined" %}
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

xyz.hacktricks.svcoc.plist jest plikiem konfiguracyjnym dla usługi XPC w systemie macOS. Usługa XPC (Cross Process Communication) umożliwia komunikację między procesami w systemie operacyjnym. Ten plik plist zawiera informacje dotyczące konfiguracji usługi XPC, takie jak identyfikator usługi, ścieżka do pliku wykonywalnego, argumenty wiersza poleceń i inne ustawienia. Można go modyfikować, aby zmienić zachowanie usługi XPC lub wykorzystać go do eskalacji uprawnień w systemie macOS.

Aby wykorzystać ten plik plist do eskalacji uprawnień, można spróbować wprowadzić zmiany w konfiguracji usługi XPC, takie jak zmiana ścieżki do pliku wykonywalnego na plik z wyższymi uprawnieniami lub dodanie argumentów wiersza poleceń umożliwiających wykonanie nieautoryzowanych działań. Należy jednak pamiętać, że takie działania są nielegalne i naruszają prywatność i bezpieczeństwo systemu operacyjnego.

W celu zabezpieczenia systemu macOS przed nadużyciem usługi XPC, zaleca się przestrzeganie najlepszych praktyk dotyczących bezpieczeństwa, takich jak:

* Regularne aktualizowanie systemu operacyjnego i oprogramowania.
* Ograniczenie dostępu do usług XPC tylko dla niezbędnych procesów.
* Monitorowanie i analiza logów systemowych w celu wykrywania podejrzanych aktywności.
* Używanie silnych haseł i uwierzytelniania dwuskładnikowego.
* Unikanie instalowania podejrzanych aplikacji i plików z nieznanych źródeł.

Przestrzeganie tych zasad pomoże w zabezpieczeniu systemu macOS przed potencjalnymi atakami wykorzystującymi usługę XPC.

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
## Klient wewnątrz kodu Dylb

The Client inside a Dylb code is a technique used in macOS privilege escalation to abuse the XPC service. XPC (Cross-Process Communication) is a mechanism that allows processes to communicate with each other in macOS.

To exploit this technique, the attacker first needs to identify a vulnerable XPC service. This can be done by analyzing the target application or system. Once a vulnerable XPC service is identified, the attacker can create a client inside a Dylb code to interact with the XPC service.

The Dylb code is a dynamic library that is injected into the target process. It allows the attacker to hook into the XPC service and intercept its function calls. By doing so, the attacker can manipulate the data being sent or received by the XPC service.

The client inside the Dylb code can be used to escalate privileges by abusing the XPC service's functionality. For example, the attacker can modify the parameters of a function call to bypass security checks or execute arbitrary code with elevated privileges.

To implement this technique, the attacker needs to have knowledge of macOS internals, XPC service vulnerabilities, and dynamic library injection techniques. It requires advanced skills in macOS exploitation and privilege escalation.

It is important to note that this technique is highly intrusive and can potentially crash the target process or system if not implemented correctly. Therefore, it should only be used in controlled environments for legitimate security testing purposes.
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

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
