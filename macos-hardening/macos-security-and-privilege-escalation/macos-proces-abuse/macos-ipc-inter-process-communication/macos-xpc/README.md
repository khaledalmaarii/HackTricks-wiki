# macOS XPC

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Informazioni di base

XPC, che sta per XNU (il kernel utilizzato da macOS) Inter-Process Communication, è un framework per la **comunicazione tra processi** su macOS e iOS. XPC fornisce un meccanismo per effettuare **chiamate di metodo sicure e asincrone tra processi diversi** nel sistema. Fa parte del paradigma di sicurezza di Apple, consentendo la **creazione di applicazioni con privilegi separati** in cui ogni **componente** viene eseguito con **solo i permessi necessari** per svolgere il proprio lavoro, limitando così i danni potenziali da un processo compromesso.

XPC utilizza una forma di Inter-Process Communication (IPC), che è un insieme di metodi per inviare dati avanti e indietro tra programmi diversi in esecuzione sullo stesso sistema.

I principali vantaggi di XPC includono:

1. **Sicurezza**: Separando il lavoro in diversi processi, ogni processo può essere autorizzato solo ai permessi necessari. Ciò significa che anche se un processo viene compromesso, ha una capacità limitata di causare danni.
2. **Stabilità**: XPC aiuta a isolare i crash al componente in cui si verificano. Se un processo si blocca, può essere riavviato senza influire sul resto del sistema.
3. **Prestazioni**: XPC consente una facile concorrenza, poiché diverse attività possono essere eseguite contemporaneamente in diversi processi.

L'unico **svantaggio** è che **separare un'applicazione in diversi processi** che comunicano tramite XPC è **meno efficiente**. Ma nei sistemi odierni questo è quasi impercettibile e i vantaggi sono maggiori.

## Servizi XPC specifici dell'applicazione

I componenti XPC di un'applicazione sono **all'interno dell'applicazione stessa**. Ad esempio, in Safari puoi trovarli in **`/Applications/Safari.app/Contents/XPCServices`**. Hanno l'estensione **`.xpc`** (come **`com.apple.Safari.SandboxBroker.xpc`**) e sono **anche bundle** con il binario principale al suo interno: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` e un `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Come potresti pensare, un **componente XPC avrà diversi diritti e privilegi** rispetto agli altri componenti XPC o al binario principale dell'applicazione. ECCETTO se un servizio XPC è configurato con [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) impostato su "True" nel suo file **Info.plist**. In questo caso, il servizio XPC verrà eseguito nella **stessa sessione di sicurezza dell'applicazione** che lo ha chiamato.

I servizi XPC vengono **avviati** da **launchd** quando necessario e **chiusi** una volta completate tutte le attività per liberare le risorse di sistema. **I componenti XPC specifici dell'applicazione possono essere utilizzati solo dall'applicazione**, riducendo così il rischio associato a potenziali vulnerabilità.

## Servizi XPC a livello di sistema

I servizi XPC a livello di sistema sono accessibili a tutti gli utenti. Questi servizi, sia di tipo launchd che di tipo Mach, devono essere **definiti in file plist** situati in directory specificate come **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, o **`/Library/LaunchAgents`**.

Questi file plist avranno una chiave chiamata **`MachServices`** con il nome del servizio e una chiave chiamata **`Program`** con il percorso del binario:
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
Quelli in **`LaunchDameons`** sono eseguiti da root. Quindi, se un processo non privilegiato può comunicare con uno di questi, potrebbe essere in grado di ottenere privilegi elevati.

## Messaggi di evento XPC

Le applicazioni possono **sottoscriversi** a diversi **messaggi di evento**, consentendo loro di essere **iniziate su richiesta** quando tali eventi si verificano. La **configurazione** di questi servizi viene effettuata nei file **plist di launchd**, situati nelle **stesse directory dei precedenti** e contenenti una chiave **`LaunchEvent`** aggiuntiva.

### Controllo del processo di connessione XPC

Quando un processo tenta di chiamare un metodo tramite una connessione XPC, il **servizio XPC dovrebbe verificare se tale processo è autorizzato a connettersi**. Ecco i modi comuni per effettuare tale verifica e le trappole comuni:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## Autorizzazione XPC

Apple consente anche alle app di **configurare alcuni diritti e come ottenerli**, quindi se il processo chiamante li possiede, sarà **autorizzato a chiamare un metodo** dal servizio XPC:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## Sniffer XPC

Per intercettare i messaggi XPC, è possibile utilizzare [**xpcspy**](https://github.com/hot3eed/xpcspy) che utilizza **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## Esempio di codice C per la comunicazione XPC

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
```c
#include <stdio.h>
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
    
    sleep(10);
    
    xpc_release(connection);
    
    return 0;
}
```
{% endtab %}

{% tab title="xpc_server.c" %}
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
```objective-c
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

void handle_request(xpc_object_t request) {
    // Handle the request here
    // ...
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        xpc_connection_t connection = xpc_connection_create_mach_service("com.example.myxpc", NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
        
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
            xpc_type_t type = xpc_get_type(event);
            
            if (type == XPC_TYPE_DICTIONARY) {
                const char *message = xpc_dictionary_get_string(event, "message");
                if (message) {
                    printf("Received message: %s\n", message);
                }
                
                handle_request(event);
            }
        });
        
        xpc_connection_resume(connection);
        
        dispatch_main();
    }
    
    return 0;
}
```
{% endtab %}
{% endtabs %}

## Esempio di codice Objective-C per la comunicazione XPC

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
## Client all'interno di un codice Dylb

The client code is responsible for establishing a connection with the server and sending requests to it. In the case of a Dylb code, the client is embedded within the code itself.

Il codice del client è responsabile di stabilire una connessione con il server e inviare richieste ad esso. Nel caso di un codice Dylb, il client è incorporato direttamente nel codice stesso.

To create a client inside a Dylb code, you can use the following steps:

Per creare un client all'interno di un codice Dylb, è possibile seguire i seguenti passaggi:

1. Import the necessary libraries or modules required for establishing a network connection.

   Importare le librerie o i moduli necessari per stabilire una connessione di rete.

2. Define the server's IP address and port number to establish a connection.

   Definire l'indirizzo IP del server e il numero di porta per stabilire una connessione.

3. Create a socket object to establish a connection with the server.

   Creare un oggetto socket per stabilire una connessione con il server.

4. Use the socket object to send requests to the server.

   Utilizzare l'oggetto socket per inviare richieste al server.

5. Receive and process the server's response.

   Ricevere e elaborare la risposta del server.

Here is an example of a client code inside a Dylb code:

Ecco un esempio di codice client all'interno di un codice Dylb:

```python
import socket

# Define server IP address and port number
server_ip = "192.168.0.1"
server_port = 8080

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Establish a connection with the server
client_socket.connect((server_ip, server_port))

# Send a request to the server
request = "Hello, server!"
client_socket.send(request.encode())

# Receive and process the server's response
response = client_socket.recv(1024).decode()
print("Server response:", response)

# Close the connection
client_socket.close()
```

Make sure to replace the `server_ip` and `server_port` variables with the actual IP address and port number of the server you want to connect to.

Assicurarsi di sostituire le variabili `server_ip` e `server_port` con l'effettivo indirizzo IP e numero di porta del server a cui si desidera connettersi.
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

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
