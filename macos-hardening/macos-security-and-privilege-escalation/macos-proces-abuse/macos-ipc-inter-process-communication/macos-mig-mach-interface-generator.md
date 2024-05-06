# macOS MIG - Mach Interface Generator

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Taarifa Msingi

MIG iliundwa ili **kurahisisha mchakato wa uundaji wa nambari ya Mach IPC**. Kimsingi **inazalisha nambari inayohitajika** kwa server na mteja kuingiliana na ufafanuzi uliopewa. Hata kama nambari iliyozalishwa ni mbaya, mwandishi wa programu atahitaji tu kuagiza na nambari yake itakuwa rahisi sana kuliko hapo awali.

Ufafanuzi unatajwa katika Lugha ya Ufafanuzi wa Interface (IDL) kwa kutumia kielelezo cha `.defs`.

Ufafanuzi huu una sehemu 5:

* **Tangazo la Subsystem**: Neno kuu la mfumo hutumiwa kuonyesha **jina** na **id**. Pia inawezekana kuashiria kama **`KernelServer`** ikiwa server inapaswa kukimbia katika kernel.
* **Unganisho na uagizaji**: MIG hutumia C-prepocessor, hivyo inaweza kutumia uagizaji. Zaidi ya hayo, inawezekana kutumia `uimport` na `simport` kwa nambari iliyoundwa na mtumiaji au server.
* **Tangazo la Aina**: Inawezekana kufafanua aina za data ingawa kawaida itaagiza `mach_types.defs` na `std_types.defs`. Kwa zile za desturi, sintaksia fulani inaweza kutumika:
* \[i`n/out]tran`: Kazi inayohitaji kutafsiriwa kutoka ujumbe unaokuja au kwenda
* `c[user/server]type`: Kufanana na aina nyingine ya C.
* `destructor`: Italeta kazi hii wakati aina inaachiliwa.
* **Operesheni**: Hizi ni ufafanuzi wa njia za RPC. Kuna aina 5 tofauti:
* `routine`: Inatarajia jibu
* `simpleroutine`: Haina kutarajia jibu
* `procedure`: Inatarajia jibu
* `simpleprocedure`: Haina kutarajia jibu
* `function`: Inatarajia jibu

### Mfano

Unda faili ya ufafanuzi, katika kesi hii na kazi rahisi sana:

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

Tafadhali kumbuka kwamba **hoja ya kwanza ni bandari ya kufunga** na MIG ita **kushughulikia bandari ya majibu kiotomatiki** (isipokuwa kuita `mig_get_reply_port()` katika msimbo wa mteja). Zaidi ya hayo, **Kitambulisho cha shughuli** itakuwa **ya mfululizo** ikitoka kwa Kitambulisho cha mfumo ulioonyeshwa (kwa hivyo ikiwa shughuli imepitwa na wakati inafutwa na `skip` hutumiwa bado kutumia Kitambulisho chake).

Sasa tumia MIG kuzalisha msimbo wa seva na mteja ambao utaweza kuingiliana kati yao kuita kazi ya Kutoa:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Zitafunguliwa faili kadhaa mpya katika saraka ya sasa.

{% hint style="success" %}
Unaweza kupata mfano wenye utata zaidi kwenye mfumo wako kwa: `mdfind mach_port.defs`\
Na unaweza kuikusanya kutoka kwenye saraka ile ile kama faili na: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

Katika faili za **`myipcServer.c`** na **`myipcServer.h`** unaweza kupata tangazo na ufafanuzi wa muundo wa **`SERVERPREFmyipc_subsystem`**, ambao kimsingi unafafanua kazi ya kuita kulingana na kitambulisho cha ujumbe uliopokelewa (tulitaja nambari ya kuanzia 500):

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% endtab %}

{% tab title="myipcServer.h" %} 

### macOS MIG (Mach Interface Generator)

MIG is a tool used to define inter-process communication on macOS systems. It generates client-server code for message-based communication between processes. By defining interfaces in a .defs file, MIG creates the necessary code for message handling, allowing processes to communicate with each other.

#### Example:

```c
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t myipc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);
```

In this example, `myipc_server` is the function that handles incoming messages from clients. It processes the messages and generates appropriate responses.

MIG simplifies the development of inter-process communication mechanisms on macOS, making it easier to implement secure and efficient communication between processes. 

{% endtab %}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

Kulingana na muundo uliopita, kazi **`myipc_server_routine`** itapata **kitambulisho cha ujumbe** na kurudisha kazi sahihi ya kuita:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
Katika mfano huu tumetaja tu kazi 1 katika ufafanuzi, lakini kama tungelitaja kazi zaidi, zingelikuwa ndani ya safu ya **`SERVERPREFmyipc_subsystem`** na ya kwanza ingelipewa ID **500**, ya pili ID **501**...

Ikiwa kazi ilikuwa inatarajiwa kutuma **jibu** kazi `mig_internal kern_return_t __MIG_check__Reply__<jina>` pia ingekuwepo.

Kwa kweli ni rahisi kutambua uhusiano huu katika muundo wa **`subsystem_to_name_map_myipc`** kutoka **`myipcServer.h`** (**`subsystem_to_name_map_***`** katika faili nyingine):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Hatimaye, kazi nyingine muhimu ya kufanya server ifanye kazi itakuwa **`myipc_server`**, ambayo ndiyo itakayoitisha **kazi inayohusiana** na kitambulisho kilichopokelewa:

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Ukubwa wa chini: routine() itaupdate ikiwa tofauti */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Angalia mistari iliyotangazwa hapo awali inayofikia kazi ya kuita kwa kutumia kitambulisho.

Msimu ufuatao ni nambari ya kuunda **server** na **mteja** ambapo mteja anaweza kuita kazi ya kutoa kutoka kwa server:

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% endtab %}

{% tab title="myipc_client.c" %} 

### Mteja wa IPC yangu

Hii ni programu ndogo ya mteja ambayo inatumia interface ya MIG kufanya mawasiliano na mchakato wa mwenyeji. 

```c
#include <stdio.h>
#include <servers/bootstrap.h>
#include "myipc.h"

int main() {
    ipc_port_t port;
    kern_return_t kr;

    kr = bootstrap_look_up(bootstrap_port, "com.example.myipc", &port);
    if (kr != KERN_SUCCESS) {
        printf("Hitilafu wakati wa kutafuta mchakato wa mwenyeji: %s\n", mach_error_string(kr));
        return 1;
    }

    myipc_ping(port);

    return 0;
}
```

{% endtab %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{% endtab %}
{% endtabs %}

### Rekodi ya NDR

Rekodi ya NDR inaagizwa na `libsystem_kernel.dylib`, na ni muundo wa data ambao huruhusu MIG **kubadilisha data ili iwe haina upendeleo kwa mfumo** inayotumiwa kwani MIG ilikusudiwa kutumiwa kati ya mifumo tofauti (na siyo tu kwenye mashine moja).

Hii ni ya kuvutia kwa sababu ikiwa `_NDR_record` inapatikana kwenye binary kama tegemezi (`jtool2 -S <binary> | grep NDR` au `nm`), inamaanisha kuwa binary ni mteja au Seva wa MIG.

Zaidi ya hayo **Seva za MIG** zina meza ya kutuma katika `__DATA.__const` (au katika `__CONST.__constdata` kwenye kernel ya macOS na `__DATA_CONST.__const` kwenye kernel nyingine za \*OS). Hii inaweza kudakuliwa na **`jtool2`**.

Na **Wateja wa MIG** watatumia `__NDR_record` kutuma kwa kutumia `__mach_msg` kwa seva.

## Uchambuzi wa Binary

### jtool

Kwa kuwa binaries nyingi sasa hutumia MIG kuweka wazi bandari za mach, ni ya kuvutia kujua jinsi ya **kutambua kuwa MIG ilitumika** na **kazi ambazo MIG inatekeleza** na kila kitambulisho cha ujumbe.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) inaweza kuchambua habari ya MIG kutoka kwa binary ya Mach-O ikionyesha kitambulisho cha ujumbe na kutambua kazi ya kutekelezwa:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Zaidi ya hayo, kazi za MIG ni tu vifungashio vya kazi halisi inayoitwa, maana yake ni kwamba kupata uchambuzi wake na kutafuta BL unaweza kupata kazi halisi inayoitwa:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Utoaji wa Pamoja

Ilitajwa hapo awali kwamba kazi itakayoshughulikia **wito wa kazi sahihi kulingana na kitambulisho cha ujumbe uliopokelewa** ilikuwa `myipc_server`. Walakini, kawaida hautakuwa na alama za binary (hakuna majina ya kazi), kwa hivyo ni muhimu kuchunguza jinsi inavyoonekana baada ya kudecompile kwani itakuwa sawa sana (msimbo wa kazi hii ni huru kutoka kwa kazi zilizofunuliwa):

{% tabs %}
{% tab title="myipc_server kudecompile 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Maelekezo ya awali ya kupata pointers sahihi za kazi
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Wito kwa sign_extend_64 inayoweza kusaidia kutambua kazi hii
// Hii inahifadhi rax kwa pointer kwa wito unahitaji kuitwa
// Angalia matumizi ya anwani 0x100004040 (array ya anwani za kazi)
// 0x1f4 = 500 (ID ya kuanzia)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Ikiwa - vinginevyo, ikiwa inarudi uwongo, wakati vinginevyo inaita kazi sahihi na inarudi kweli
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Anwani iliyohesabiwa inayoitisha kazi sahihi na vigezo 2
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server kudecompile 2" %}
Hii ni kazi sawa iliyodecompile kwenye toleo tofauti la Hopper bure:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Maelekezo ya awali ya kupata pointers sahihi za kazi
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (ID ya kuanzia)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// Ile ile if else kama katika toleo lililopita
// Angalia matumizi ya anwani 0x100004040 (array ya anwani za kazi)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Wito kwa anwani iliyohesabiwa ambapo kazi inapaswa kuwa
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

Kwa kweli ikiwa unakwenda kwenye kazi **`0x100004000`** utapata safu ya **muundo wa maelezo ya kazi**. Elementi ya kwanza ya muundo ni **anwani** ambapo **kazi** imefanywa, na **muundo unachukua bytes 0x28**, kwa hivyo kila 0x28 bytes (kuanzia byte 0) unaweza kupata bytes 8 na hiyo itakuwa **anwani ya kazi** itakayoitwa:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Data hii inaweza kuchimbuliwa [**kwa kutumia skripti hii ya Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
### Kurekebisha

Msimbo uliotengenezwa na MIG pia huita `kernel_debug` ili kuzalisha machapisho kuhusu shughuli za kuingia na kutoka. Inawezekana kuzikagua kwa kutumia **`trace`** au **`kdv`**: `kdv all | grep MIG`

## Marejeo

* [\*OS Internals, Kijitabu cha Kwanza, Mode ya Mtumiaji, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
