# macOS XPC

## macOS XPC

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

### Grundlegende Informationen

XPC steht für XNU (den Kernel, der von macOS verwendet wird) Inter-Process Communication und ist ein Framework für die **Kommunikation zwischen Prozessen** auf macOS und iOS. XPC bietet einen Mechanismus für sichere, asynchrone Methodenaufrufe zwischen verschiedenen Prozessen auf dem System. Es ist Teil des Sicherheitsparadigmas von Apple und ermöglicht die Erstellung von privilegiert getrennten Anwendungen, bei denen jede **Komponente** nur mit den Berechtigungen ausgeführt wird, die sie für ihre Aufgabe benötigt, um potenzielle Schäden durch einen kompromittierten Prozess zu begrenzen.

XPC verwendet eine Form der Inter-Process Communication (IPC), die eine Reihe von Methoden für verschiedene Programme auf demselben System zum Senden von Daten hin und her umfasst.

Die Hauptvorteile von XPC sind:

1. **Sicherheit**: Durch die Aufteilung der Arbeit in verschiedene Prozesse kann jedem Prozess nur die benötigten Berechtigungen gewährt werden. Dies bedeutet, dass selbst wenn ein Prozess kompromittiert ist, er nur begrenzte Möglichkeiten hat, Schaden anzurichten.
2. **Stabilität**: XPC hilft dabei, Abstürze auf die Komponente zu isolieren, in der sie auftreten. Wenn ein Prozess abstürzt, kann er neu gestartet werden, ohne den Rest des Systems zu beeinträchtigen.
3. **Leistung**: XPC ermöglicht eine einfache Nebenläufigkeit, da verschiedene Aufgaben gleichzeitig in verschiedenen Prozessen ausgeführt werden können.

Der einzige **Nachteil** besteht darin, dass die **Aufteilung einer Anwendung in mehrere Prozesse**, die über XPC kommunizieren, **weniger effizient** ist. In heutigen Systemen ist dies jedoch kaum spürbar und die Vorteile überwiegen.

### Anwendungsspezifische XPC-Dienste

Die XPC-Komponenten einer Anwendung befinden sich **innerhalb der Anwendung selbst**. Zum Beispiel finden Sie sie in Safari unter **`/Applications/Safari.app/Contents/XPCServices`**. Sie haben die Erweiterung **`.xpc`** (wie **`com.apple.Safari.SandboxBroker.xpc`**) und sind **auch Bundles** mit der Hauptbinary darin: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` und eine `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Wie Sie vielleicht denken, hat eine **XPC-Komponente unterschiedliche Berechtigungen und Privilegien** als die anderen XPC-Komponenten oder die Haupt-App-Binary. AUßER wenn ein XPC-Dienst mit [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) auf "True" in seiner **Info.plist**-Datei konfiguriert ist. In diesem Fall wird der XPC-Dienst in derselben Sicherheitssitzung wie die aufrufende Anwendung ausgeführt.

XPC-Dienste werden bei Bedarf von **launchd** gestartet und werden heruntergefahren, sobald alle Aufgaben abgeschlossen sind, um Systemressourcen freizugeben. **Anwendungsspezifische XPC-Komponenten können nur von der Anwendung genutzt werden**, wodurch das Risiko potenzieller Sicherheitslücken reduziert wird.

### Systemweite XPC-Dienste

Systemweite XPC-Dienste sind für alle Benutzer zugänglich. Diese Dienste, entweder launchd oder Mach-Typ, müssen in Plist-Dateien definiert werden, die sich in bestimmten Verzeichnissen wie **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** oder **`/Library/LaunchAgents`** befinden.

Diese Plist-Dateien enthalten einen Schlüssel namens **`MachServices`** mit dem Namen des Dienstes und einen Schlüssel namens **`Program`** mit dem Pfad zur Binary:

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

Diejenigen in **`LaunchDameons`** werden von root ausgeführt. Wenn ein unprivilegierter Prozess mit einem von ihnen kommunizieren kann, könnte er in der Lage sein, Privilegien zu eskalieren.

### XPC-Ereignisnachrichten

Anwendungen können sich für verschiedene Ereignisnachrichten **abonnieren**, um sie bei Bedarf **auf Anfrage** zu initiieren. Die **Einrichtung** für diese Dienste erfolgt in **Launchd-Plist-Dateien**, die sich in den **gleichen Verzeichnissen wie die vorherigen** befinden und einen zusätzlichen **`LaunchEvent`**-Schlüssel enthalten.

#### XPC-Verbindungsprozessprüfung

Wenn ein Prozess versucht, eine Methode über eine XPC-Verbindung aufzurufen, sollte der **XPC-Dienst überprüfen, ob dieser Prozess eine Verbindung herstellen darf**. Hier sind die gängigen Möglichkeiten, dies zu überprüfen, und die häufigsten Fallstricke:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### XPC-Berechtigung

Apple ermöglicht es auch Apps, **einige Rechte zu konfigurieren und wie sie diese erhalten**, sodass der aufrufende Prozess berechtigt ist, eine Methode aus dem XPC-Dienst aufzurufen:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### XPC-Sniffer

Um die XPC-Nachrichten abzufangen, können Sie [**xpcspy**](https://github.com/hot3eed/xpcspy) verwenden, das **Frida** verwendet.

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

### XPC-Kommunikations-C-Code-Beispiel

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

### XPC-Kommunikation Beispielcode in Objective-C

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

{% tab title="undefined" %}
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
## Client innerhalb eines Dylb-Codes

Ein Dylb-Code ist ein Code, der in macOS verwendet wird, um XPC-Dienste (Interprozesskommunikation) zu implementieren. Ein XPC-Dienst ermöglicht die Kommunikation zwischen verschiedenen Prozessen auf einem macOS-System.

Um einen Client innerhalb eines Dylb-Codes zu implementieren, müssen Sie zunächst die XPC-Bibliothek importieren:

```objective-c
#import <xpc/xpc.h>
````

Dann können Sie eine XPC-Verbindung herstellen, indem Sie eine XPC-Verbindung erstellen und den Ziel-Dienstnamen angeben:

```objective-c
xpc_connection_t connection = xpc_connection_create_mach_service("com.example.MyXPCService", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
```

Stellen Sie sicher, dass Sie den richtigen Dienstnamen angeben, der dem XPC-Dienst entspricht, mit dem Sie kommunizieren möchten.

Nachdem Sie die Verbindung hergestellt haben, können Sie eine Nachricht an den XPC-Dienst senden:

```objective-c
xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "key", "value");

xpc_connection_send_message(connection, message);
```

Ersetzen Sie "key" und "value" durch die entsprechenden Schlüssel-Wert-Paare, die Sie senden möchten.

Schließlich müssen Sie die Verbindung aufräumen, wenn Sie fertig sind:

```objective-c
xpc_release(connection);
```

Dieser Code erstellt einen Client innerhalb eines Dylb-Codes, der eine Verbindung zu einem XPC-Dienst herstellt und eine Nachricht sendet. Sie können diesen Code anpassen, um Ihre spezifischen Anforderungen zu erfüllen.

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

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) **bei oder folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) **und** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories senden.**

</details>
