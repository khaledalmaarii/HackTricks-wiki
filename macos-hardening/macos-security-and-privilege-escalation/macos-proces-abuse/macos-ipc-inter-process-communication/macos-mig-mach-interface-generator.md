# macOS MIG - Mach-Interface-Generator

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

MIG is geskep om die proses van Mach IPC-kode-skepping te **vereenvoudig**. Dit genereer basies die benodigde kode vir die bediener en kliënt om te kommunikeer met 'n gegewe definisie. Selfs al is die gegenereerde kode lelik, 'n ontwikkelaar hoef dit net in te voer en sy kode sal baie eenvoudiger wees as voorheen.

### Voorbeeld

Skep 'n definisie-lêer, in hierdie geval met 'n baie eenvoudige funksie:

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

Gebruik nou mig om die bediener- en kliëntkode te genereer wat binne mekaar kan kommunikeer om die Subtract-funksie aan te roep:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Verskeie nuwe lêers sal in die huidige gids geskep word.

In die lêers **`myipcServer.c`** en **`myipcServer.h`** kan jy die verklaring en definisie van die struktuur **`SERVERPREFmyipc_subsystem`** vind, wat basies die funksie definieer om te roep gebaseer op die ontvangste boodskap-ID (ons het 'n beginnommer van 500 aangedui):

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
#include <mach/mach_error.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t myipc_server(mach_port_t server_port) {
    kern_return_t kr;
    mach_port_t client_port = MACH_PORT_NULL;
    mach_msg_header_t *msg;
    mach_msg_return_t mr;

    while (1) {
        // Receive message from client
        msg = (mach_msg_header_t *) malloc(sizeof(mach_msg_header_t));
        mr = mach_msg(msg, MACH_RCV_MSG, 0, sizeof(mach_msg_header_t), server_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            printf("Error receiving message from client: %s\n", mach_error_string(mr));
            free(msg);
            continue;
        }

        // Check if message is of the expected type
        if (msg->msgh_id != MACH_MSG_ID_REQUEST) {
            printf("Invalid message type received\n");
            free(msg);
            continue;
        }

        // Extract client port from message
        client_port = msg->msgh_remote_port;

        // Process the request
        kr = process_request(client_port);

        // Send response to client
        msg->msgh_remote_port = client_port;
        msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        msg->msgh_size = sizeof(mach_msg_header_t);
        msg->msgh_id = MACH_MSG_ID_RESPONSE;
        mr = mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            printf("Error sending response to client: %s\n", mach_error_string(mr));
        }

        // Clean up
        free(msg);
    }

    return KERN_SUCCESS;
}

kern_return_t process_request(mach_port_t client_port) {
    // Process the request from the client
    // ...

    return KERN_SUCCESS;
}
```

{% endtab %}

{% tab title="myipcClient.h" %}
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

Gebaseer op die vorige struktuur sal die funksie **`myipc_server_routine`** die **boodskap ID** ontvang en die korrekte funksie teruggee om te roep:
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
In hierdie voorbeeld het ons slegs 1 funksie in die definisies gedefinieer, maar as ons meer funksies gedefinieer het, sou hulle binne die reeks van **`SERVERPREFmyipc_subsystem`** gewees het en die eerste een sou toegewys gewees het aan die ID **500**, die tweede een aan die ID **501**...

Eintlik is dit moontlik om hierdie verhouding te identifiseer in die struktuur **`subsystem_to_name_map_myipc`** vanaf **`myipcServer.h`**:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Uiteindelik, 'n belangrike funksie om die bediener te laat werk, sal **`myipc_server`** wees, wat die funksie wat verband hou met die ontvangste id werklik **oproep**:

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
/* Minimal size: routine() will update it if different */
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

Kontroleer die vorige uitgeligte lyne deur toegang tot die funksie wat opgeroep moet word deur ID.

Hieronder is die kode om 'n eenvoudige **bediener** en **kliënt** te skep waar die kliënt die funksies van die bediener kan oproep Subtract:

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
    kr = bootstrap_port(&bootstrap_port);
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
    kr = myipc_send_message(service_port, message, reply);
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

### Binêre Analise

Aangesien baie binêre lêers nou MIG gebruik om mach-poorte bloot te stel, is dit interessant om te weet hoe om **te identifiseer dat MIG gebruik is** en die **funksies wat MIG uitvoer** met elke boodskap-ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) kan MIG-inligting ontleed van 'n Mach-O binêre lêer wat die boodskap-ID aandui en die funksie identifiseer om uit te voer:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Dit is voorheen genoem dat die funksie wat sal sorg vir **die oproep van die korrekte funksie afhangende van die ontvangste boodskap-ID** `myipc_server` was. Tog sal jy gewoonlik nie die simbole van die binêre lêer hê nie (geen funksienames nie), so dit is interessant om **te kyk hoe dit lyk wanneer dit ontsaai word**, aangesien dit altyd baie soortgelyk sal wees (die kode van hierdie funksie is onafhanklik van die blootgestelde funksies):

{% tabs %}
{% tab title="myipc_server ontsaai 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Aanvanklike instruksies om die korrekte funksiepunte te vind
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Oproep na sign_extend_64 wat kan help om hierdie funksie te identifiseer
// Dit stoor in rax die wyser na die oproep wat gemaak moet word
// Kyk na die gebruik van die adres 0x100004040 (funksie-adresreeks)
// 0x1f4 = 500 (die begin-ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, die if gee vals terug, terwyl die else die korrekte funksie oproep en waar teruggee
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Bereken die adres wat die korrekte funksie met 2 argumente oproep
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

{% tab title="myipc_server ontsaai 2" %}
Hierdie is dieselfde funksie wat ontsaai is in 'n ander Hopper-vry weergawe:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Aanvanklike instruksies om die korrekte funksiepunte te vind
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
// 0x1f4 = 500 (die begin-ID)
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
// Dieselfde if else as in die vorige weergawe
// Kyk na die gebruik van die adres 0x100004040 (funksie-adresreeks)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Oproep na die berekende adres waar die funksie moet wees
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

Eintlik, as jy na die funksie **`0x100004000`** gaan, sal jy die reeks **`routine_descriptor`** strukture vind. Die eerste element van die struktuur is die **adres** waar die **funksie** geïmplementeer is, en die **struktuur neem 0x28 byte in beslag**, so elke 0x28 byte (beginnend by byte 0) kan jy 8 byte kry en dit sal die **adres van die funksie** wees wat geroep sal word:

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Hierdie data kan [**uitgehaal word met behulp van hierdie Hopper-skrip**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

<
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking truuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.
