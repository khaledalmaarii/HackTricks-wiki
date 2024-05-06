# macOS MIG - Mach-koppelvlakgenerator

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Basiese Inligting

MIG is geskep om die proses van Mach IPC-kode-skepping te **vereenvoudig**. Dit genereer basies die benodigde kode vir die bediener en kliënt om met 'n gegewe definisie te kommunikeer. Selfs as die gegenereerde kode lelik is, sal 'n ontwikkelaar dit net hoef in te voer en sy kode sal baie eenvoudiger wees as voorheen.

Die definisie word gespesifiseer in die Interface Definisie Taal (IDL) deur die gebruik van die `.defs`-uitbreiding.

Hierdie definisies het 5 afdelings:

* **Onderstelselverklaring**: Die sleutelwoord `subsystem` word gebruik om die **naam** en die **id** aan te dui. Dit is ook moontlik om dit as **`KernelServer`** te merk as die bediener in die kernel moet loop.
* **Insleepsels en invoere**: MIG gebruik die C-preprosessor, sodat dit invoere kan gebruik. Daarbenewens is dit moontlik om `uimport` en `simport` te gebruik vir gebruiker- of bediener gegenereerde kode.
* **Tipeverklarings**: Dit is moontlik om datatipes te definieer, alhoewel dit gewoonlik `mach_types.defs` en `std_types.defs` sal invoer. Vir aangepaste tipes kan 'n paar sintaksis gebruik word:
* \[i`n/out]tran`: Funksie wat van 'n inkomende of na 'n uitgaande boodskap vertaal moet word
* `c[user/server]type`: Koppeling na 'n ander C-tipe.
* `destructor`: Roep hierdie funksie aan wanneer die tipe vrygestel word.
* **Operasies**: Dit is die definisies van die RPC-metodes. Daar is 5 verskillende tipes:
* `routine`: Verwag 'n antwoord
* `simpleroutine`: Verwag nie 'n antwoord nie
* `procedure`: Verwag 'n antwoord
* `simpleprocedure`: Verwag nie 'n antwoord nie
* `function`: Verwag 'n antwoord

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

Merk op dat die eerste **argument die poort is om te bind** en MIG sal **outomaties die antwoordpoort hanteer** (tensy `mig_get_reply_port()` geroep word in die kliëntkode). Verder sal die **ID van die operasies** **opeenvolgend** wees beginnende by die aangeduide subsisteem-ID (so as 'n operasie verouderd is, word dit verwyder en `skip` word gebruik om steeds sy ID te gebruik).

Gebruik nou MIG om die bediener- en kliëntkode te genereer wat binne mekaar kan kommunikeer om die Aftrek-funksie te roep:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Verskeie nuwe lêers sal geskep word in die huidige gids.

{% hint style="success" %}
Jy kan 'n meer komplekse voorbeeld in jou stelsel vind met: `mdfind mach_port.defs`\
En jy kan dit van dieselfde gids af saamstel as die lêer met: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

In die lêers **`myipcServer.c`** en **`myipcServer.h`** kan jy die verklaring en definisie van die struktuur **`SERVERPREFmyipc_subsystem`** vind, wat basies die funksie definieer om te roep gebaseer op die ontvangsboodskap-ID (ons het 'n beginnommer van 500 aangedui):

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

Mach Interface Generator (MIG) is a tool used in macOS for defining inter-process communication (IPC) interfaces. It generates C code that handles the serialization and deserialization of messages sent between processes. MIG simplifies the development of IPC mechanisms in macOS by abstracting the low-level details of message passing.

#### Example:

```c
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t myipc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
    // Server-side implementation of the MIG-generated server function
    return myipc_server_routine(InHeadP, OutHeadP);
}
```

In the example above, `myipc_server` is the server-side implementation of the MIG-generated server function. This function is responsible for processing incoming messages and generating appropriate responses.

MIG plays a crucial role in macOS security as vulnerabilities in MIG-generated code can be exploited for privilege escalation and other security threats. It is important to follow secure coding practices when working with MIG to prevent potential security risks.  
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

Gebaseer op die vorige struktuur sal die funksie **`myipc_server_routine`** die **boodskap ID** kry en die korrekte funksie teruggee om te roep:
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
In hierdie voorbeeld het ons slegs 1 funksie in die definisies gedefinieer, maar as ons meer funksies sou definieer, sou hulle binne die array van **`SERVERPREFmyipc_subsystem`** gewees het en die eerste een sou aan die ID **500** toegewys gewees het, die tweede aan die ID **501**...

As die funksie verwag het om 'n **antwoord** te stuur, sou die funksie `mig_internal kern_return_t __MIG_check__Reply__<name>` ook bestaan.

Eintlik is dit moontlik om hierdie verhouding in die struktuur **`subsystem_to_name_map_myipc`** van **`myipcServer.h`** (**`subsystem_to_name_map_***`** in ander lêers) te identifiseer:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Uiteindelik, nog 'n belangrike funksie om die bediener te laat werk, sal **`myipc_server`** wees, wat die een is wat werklik die funksie **oproep** wat verband hou met die ontvangste id:

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

Kontroleer die voorheen uitgeligte lyne wat die funksie toegang gee om op ID te roep.

Die volgende is die kode om 'n eenvoudige **bediener** en **kliënt** te skep waar die kliënt die funksies van die bediener kan oproep deur aftrekking:

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
### Afrikaans Translation
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

### Die NDR_record

Die NDR_record word uitgevoer deur `libsystem_kernel.dylib`, en dit is 'n struktuur wat MIG toelaat om **data te transformeer sodat dit onverskillig is van die stelsel** waarvoor dit gebruik word aangesien MIG gedink was om tussen verskillende stelsels gebruik te word (en nie net op dieselfde masjien nie).

Dit is interessant omdat as `_NDR_record` gevind word in 'n binêre lêer as 'n afhanklikheid (`jtool2 -S <binary> | grep NDR` of `nm`), beteken dit dat die binêre lêer 'n MIG-kliënt of -bediener is.

Verder het **MIG-bedieners** die verspreidingstabel in `__DATA.__const` (of in `__CONST.__constdata` in macOS-kernel en `__DATA_CONST.__const` in ander \*OS-kernel). Dit kan gedump word met **`jtool2`**.

En **MIG-kliënte** sal die `__NDR_record` gebruik om met `__mach_msg` na die bedieners te stuur.

## Binêre Analise

### jtool

Aangesien baie binêre lêers nou MIG gebruik om mach-poorte bloot te lê, is dit interessant om te weet hoe om te **identifiseer dat MIG gebruik is** en die **funksies wat MIG uitvoer** met elke boodskap-ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) kan MIG-inligting van 'n Mach-O binêre lêer ontleding wat die boodskap-ID aandui en die funksie identifiseer om uit te voer:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Verder is MIG-funksies net omhulsels van die werklike funksie wat opgeroep word, wat beteken dat deur sy disassemblage te kry en te soek vir BL, jy moontlik die werklike funksie wat opgeroep word, kan vind:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Monteer

Dit is voorheen genoem dat die funksie wat sal sorg vir **die oproep van die korrekte funksie afhangende van die ontvangsboodskap-ID** `myipc_server` was. Gewoonlik sal jy egter nie die simbole van die binêre lêer hê (geen funksienames nie), dus is dit interessant om **te kyk hoe dit gedeaktiveer lyk** aangesien dit altyd baie soortgelyk sal wees (die kode van hierdie funksie is onafhanklik van die blootgestelde funksies):

{% tabs %}
{% tab title="myipc_server gedeaktiveer 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Aanvanklike instruksies om die regte funksiepunte te vind
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
// Kyk na die gebruik van die adres 0x100004040 (funksie-adresse-reeks)
// 0x1f4 = 500 (die begin-ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Indien - anders, indien die indien vals teruggee, terwyl die anders die korrekte funksie oproep en waar teruggee
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Gekalibreerde adres wat die korrekte funksie met 2 argumente oproep
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

{% tab title="myipc_server gedeaktiveer 2" %}
Hierdie is dieselfde funksie gedeaktiveer in 'n ander Hopper gratis weergawe:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Aanvanklike instruksies om die regte funksiepunte te vind
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
// Dieselfde indien anders as in die vorige weergawe
// Kyk na die gebruik van die adres 0x100004040 (funksie-adresse-reeks)
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

Eintlik, as jy na die funksie **`0x100004000`** gaan, sal jy die reeks van **`routine_descriptor`** strukture vind. Die eerste element van die struktuur is die **adres** waar die **funksie** geïmplementeer is, en die **struktuur neem 0x28 byte**, dus elke 0x28 byte (beginnende vanaf byte 0) kan jy 8 byte kry en dit sal die **adres van die funksie** wees wat geroep sal word:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Hierdie data kan onttrek word [**deur hierdie Hopper-skrip te gebruik**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
### Foutopsporing

Die kode wat deur MIG gegenereer word, roep ook `kernel_debug` aan om logboeke oor operasies by intrede en uittrede te genereer. Dit is moontlik om hulle te kontroleer met behulp van **`trace`** of **`kdv`**: `kdv all | grep MIG`

## Verwysings

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
