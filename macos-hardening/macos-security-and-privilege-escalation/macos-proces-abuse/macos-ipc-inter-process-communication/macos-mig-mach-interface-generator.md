# macOS MIG - Jenereta ya Kiolesura cha Mach

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

MIG iliumbwa ili **kurahisisha mchakato wa kuunda nambari ya Mach IPC**. Kimsingi, ina **jenereta ya nambari inayohitajika** ili seva na mteja waweze kuwasiliana na ufafanuzi uliopewa. Hata kama nambari iliyozalishwa ni mbaya, msanidi programu atahitaji tu kuimporti na nambari yake itakuwa rahisi zaidi kuliko hapo awali.

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

Sasa tumia mig ili kuzalisha nambari ya seva na mteja ambayo itaweza kuwasiliana ndani yao wenyewe ili kuita kazi ya Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Zitafunguliwa faili kadhaa mpya katika saraka ya sasa.

Katika faili za **`myipcServer.c`** na **`myipcServer.h`** unaweza kupata tamko na ufafanuzi wa muundo wa **`SERVERPREFmyipc_subsystem`**, ambao kimsingi unafafanua kazi ya kuita kulingana na kitambulisho cha ujumbe uliopokelewa (tumetaja nambari ya kuanzia 500):

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
{% tab title="myipcServer.h" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/mig.h>
#include "myipcServer.h"

kern_return_t myipc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
    // Handle the incoming message
    switch (InHeadP->msgh_id)
    {
        case MACH_MSG_ID_REQUEST:
            printf("Received request message\n");
            break;
        default:
            printf("Unknown message received\n");
            break;
    }
    
    // Prepare the outgoing message
    OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    OutHeadP->msgh_size = sizeof(mach_msg_header_t);
    OutHeadP->msgh_remote_port = InHeadP->msgh_remote_port;
    OutHeadP->msgh_local_port = MACH_PORT_NULL;
    OutHeadP->msgh_id = MACH_MSG_ID_REPLY;
    
    return KERN_SUCCESS;
}
```

{% endtab %}

{% tab title="myipcClient.c" %}
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

Kulingana na muundo uliopita, kazi ya **`myipc_server_routine`** itapokea **kitambulisho cha ujumbe** na kurudisha kazi sahihi ya kuita:
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
Katika mfano huu tumetaja tu kazi 1 katika ufafanuzi, lakini kama tungeweza kutaja kazi zaidi, zingekuwa ndani ya safu ya **`SERVERPREFmyipc_subsystem`** na ya kwanza ingepewa kitambulisho cha **500**, ya pili kitambulisho cha **501**...

Kwa kweli niwezekano kutambua uhusiano huu katika muundo wa **`subsystem_to_name_map_myipc`** kutoka **`myipcServer.h`**:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Hatimaye, kazi muhimu nyingine ya kufanya server itakuwa **`myipc_server`**, ambayo ndiyo itakayoitisha kazi inayohusiana na id iliyopokelewa:

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
/* Ukubwa mdogo: routine() itaupdate ikiwa tofauti */
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

Angalia mistari iliyotangazwa hapo awali kwa kufikia kazi ya kuita kwa kutumia ID.

Hapa chini ni nambari ya kuunda **server** na **client** rahisi ambapo client anaweza kuita kazi ya Subtract kutoka kwa server:

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
{% tab title="myipc_client.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipc.h"

int main(int argc, char *argv[]) {
    kern_return_t kr;
    mach_port_t bootstrap_port, service_port;
    char *message = "Hello, server!";
    char reply[256];

    // Get the bootstrap port
    kr = task_get_bootstrap_port(mach_task_self(), &bootstrap_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to get bootstrap port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Look up the service port
    kr = bootstrap_look_up(bootstrap_port, "com.example.myipc", &service_port);
    if (kr != KERN_SUCCESS) {
        printf("Failed to look up service port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Send a message to the server
    kr = myipc_send_message(service_port, message, reply, sizeof(reply));
    if (kr != KERN_SUCCESS) {
        printf("Failed to send message: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Print the server's reply
    printf("Server replied: %s\n", reply);

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

### Uchambuzi wa Binary

Kwa kuwa binaries nyingi sasa hutumia MIG kuwezesha mach ports, ni muhimu kujua jinsi ya **kutambua kuwa MIG ilitumika** na **kazi ambazo MIG inatekeleza** kwa kila kitambulisho cha ujumbe.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) inaweza kuchambua habari za MIG kutoka kwenye binary ya Mach-O ikionyesha kitambulisho cha ujumbe na kutambua kazi ya kutekeleza:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Ilitajwa hapo awali kwamba kazi ambayo itashughulikia **kuita kazi sahihi kulingana na kitambulisho cha ujumbe uliopokelewa** ilikuwa `myipc_server`. Walakini, kawaida hautakuwa na alama za binary (hakuna majina ya kazi), kwa hivyo ni muhimu **kuangalia jinsi inavyoonekana baada ya kudecompile** kwani itakuwa sawa daima (msimbo wa kazi hii ni huru kutoka kwa kazi zilizofichuliwa):

{% tabs %}
{% tab title="myipc_server kudecompile 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Maagizo ya awali ya kupata pointa sahihi za kazi
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Wito wa sign_extend_64 ambao unaweza kusaidia kutambua kazi hii
// Hii inahifadhi rax kama pointa kwa wito ambao unahitaji kuitwa
// Angalia matumizi ya anwani 0x100004040 (orodha ya anwani za kazi)
// 0x1f4 = 500 (kitambulisho cha kuanzia)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, ikiwa if inarudi uongo, wakati else inaita kazi sahihi na inarudi kweli
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Anwani iliyohesabiwa ambayo inaita kazi sahihi na ina vigezo 2
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
Hii ni kazi ile ile iliyokudecompile katika toleo tofauti la Hopper free:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Maagizo ya awali ya kupata pointa sahihi za kazi
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
// 0x1f4 = 500 (kitambulisho cha kuanzia)
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
// If - else ile ile kama katika toleo la awali
// Angalia matumizi ya anwani 0x100004040 (orodha ya anwani za kazi)
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

Kwa kweli, ikiwa unakwenda kwenye kazi **`0x100004000`** utapata safu ya muundo wa **`routine_descriptor`**. Kipengele cha kwanza cha muundo huo ni **anwani** ambapo **kazi** imefanywa, na **muundo unachukua byte 0x28**, kwa hivyo kila baada ya byte 0x28 (kuanzia byte 0) unaweza kupata byte 8 na hiyo itakuwa **anwani ya kazi** ambayo itaitwa:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Data hii inaweza kuchimbwa [**
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.
