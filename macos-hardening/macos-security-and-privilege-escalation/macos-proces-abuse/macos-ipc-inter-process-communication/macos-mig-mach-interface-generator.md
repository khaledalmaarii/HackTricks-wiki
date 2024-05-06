# macOS MIG - Mach Interfejs Generator

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Osnovne Informacije

MIG je kreiran kako bi **simplifikovao proces kreiranja Mach IPC** koda. On u osnovi **generiše potreban kod** za server i klijenta da komuniciraju sa datom definicijom. Čak i ako je generisani kod ružan, programer će samo trebati da ga uveze i njegov kod će biti mnogo jednostavniji nego pre.

Definicija je specificirana u jeziku definicije interfejsa (IDL) koristeći ekstenziju `.defs`.

Ove definicije imaju 5 sekcija:

* **Deklaracija podsistema**: Ključna reč podsistem se koristi da označi **ime** i **id**. Takođe je moguće označiti ga kao **`KernelServer`** ako server treba da se izvršava u jezgru.
* **Uključivanja i uvozi**: MIG koristi C-preprocesor, tako da je moguće koristiti uvoze. Osim toga, moguće je koristiti `uimport` i `simport` za korisnički ili serverski generisani kod.
* **Deklaracije tipova**: Moguće je definisati tipove podataka iako će obično uvesti `mach_types.defs` i `std_types.defs`. Za prilagođene se može koristiti neka sintaksa:
* \[i`n/out]tran`: Funkcija koja treba da se prevede iz dolazne ili u odlaznu poruku
* `c[user/server]type`: Mapiranje na drugi C tip.
* `destructor`: Pozovi ovu funkciju kada se tip oslobodi.
* **Operacije**: Ovo su definicije RPC metoda. Postoje 5 različitih tipova:
* `routine`: Očekuje odgovor
* `simpleroutine`: Ne očekuje odgovor
* `procedure`: Očekuje odgovor
* `simpleprocedure`: Ne očekuje odgovor
* `function`: Očekuje odgovor

### Primer

Kreirajte fajl definicije, u ovom slučaju sa veoma jednostavnom funkcijom:

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

Imajte na umu da je prvi **argument port za povezivanje** i MIG će **automatski upravljati odgovarajućim portom** (osim ako se poziva `mig_get_reply_port()` u klijentskom kodu). Osim toga, **ID operacija** će biti **sekvencijalno** počevši od naznačenog ID podsistema (tako da ako je operacija zastarela, ona se briše i koristi se `skip` kako bi se i dalje koristio njen ID).

Sada koristite MIG da generišete server i klijentski kod koji će moći da komuniciraju međusobno kako bi pozvali funkciju Oduzimanje:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Biće kreirano nekoliko novih datoteka u trenutnom direktorijumu.

{% hint style="success" %}
Možete pronaći kompleksniji primer na vašem sistemu sa: `mdfind mach_port.defs`\
I možete ga kompajlirati iz istog foldera kao i datoteka sa: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

U datotekama **`myipcServer.c`** i **`myipcServer.h`** možete pronaći deklaraciju i definiciju strukture **`SERVERPREFmyipc_subsystem`**, koja u osnovi definiše funkciju koja će biti pozvana na osnovu primljenog ID-ja poruke (navedeno je početni broj 500):

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

MIG (Mach Interface Generator) is a tool used to define inter-process communication (IPC) for macOS. It generates client and server-side code for message-based IPC. By using MIG, developers can define the messages that can be sent between processes, making it a powerful tool for IPC on macOS.

To use MIG, you need to define an interface definition file (.defs) that specifies the messages and data structures for IPC. This file is then processed by MIG to generate the necessary C code for IPC communication.

MIG is commonly used in macOS for system services and kernel extensions that require IPC. Understanding how MIG works can be beneficial for security researchers and developers working on macOS security and privilege escalation techniques. 

### Example of a MIG Interface Definition File (.defs)

```c
routine myipc_server_routine_1(
    in int input_data,
    out int output_data
);
```

In this example, we define a MIG routine `myipc_server_routine_1` that takes an integer `input_data` as input and returns an integer `output_data` as output. This is a simple example to demonstrate how MIG interface definition files are structured.

By understanding MIG and how it is used for IPC in macOS, security researchers can analyze potential vulnerabilities related to inter-process communication and privilege escalation on the platform. 

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

Na osnovu prethodne strukture funkcija **`myipc_server_routine`** će dobiti **ID poruke** i vratiti odgovarajuću funkciju koja treba da se pozove:
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
U ovom primeru smo definisali samo 1 funkciju u definicijama, ali da smo definisali više funkcija, bile bi unutar niza **`SERVERPREFmyipc_subsystem`** i prva bi bila dodeljena ID-u **500**, druga ID-u **501**...

Ako se očekivalo da funkcija pošalje **odgovor**, funkcija `mig_internal kern_return_t __MIG_check__Reply__<name>` takođe bi postojala.

Zapravo je moguće identifikovati ovaj odnos u strukturi **`subsystem_to_name_map_myipc`** iz **`myipcServer.h`** (**`subsystem_to_name_map_***`** u drugim datotekama):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Konačno, još jedna važna funkcija koja će omogućiti rad servera biće **`myipc_server`**, koja će zapravo **pozvati funkciju** povezanu sa primljenim ID-om:

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

Proverite prethodno istaknute linije pristupaći funkciji koju treba pozvati prema ID-u.

Sledeći kod kreira jednostavan **server** i **klijent** gde klijent može pozvati funkcije oduzimanja sa servera:

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

### MojIPC klijent

Ovaj klijent će se povezati na server i pozvati funkciju `myipc_do`. 

```c
#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipc.h"

int main() {
    mach_port_t server_port;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "com.example.myipc_server", &server_port);
    if (kr != KERN_SUCCESS) {
        printf("Nemoguće pronaći server port\n");
        return 1;
    }

    myipc_do(server_port);

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

### NDR\_record

NDR\_record je izvezen od strane `libsystem_kernel.dylib`, i to je struktura koja omogućava MIG-u da **transformiše podatke tako da bude agnostik sistema** na kojem se koristi, pošto je MIG osmišljen da se koristi između različitih sistema (a ne samo na istom računaru).

Ovo je interesantno jer ako se `_NDR_record` pronađe u binarnom fajlu kao zavisnost (`jtool2 -S <binary> | grep NDR` ili `nm`), to znači da je binarni fajl MIG klijent ili server.

Štaviše, **MIG serveri** imaju tabelu dispečera u `__DATA.__const` (ili u `__CONST.__constdata` u macOS kernelu i `__DATA_CONST.__const` u drugim \*OS kernelima). Ovo se može izlistati sa **`jtool2`**.

A **MIG klijenti** će koristiti `__NDR_record` da pošalju sa `__mach_msg` serverima.

## Analiza Binarnog Fajla

### jtool

Pošto mnogi binarni fajlovi sada koriste MIG da izlože mach portove, interesantno je znati kako **identifikovati da je MIG korišćen** i **funkcije koje MIG izvršava** sa svakim ID-em poruke.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) može parsirati MIG informacije iz Mach-O binarnog fajla, pokazujući ID poruke i identifikujući funkciju za izvršavanje:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Osim toga, MIG funkcije su samo omotači stvarne funkcije koja se poziva, što znači da biste mogli pronaći stvarnu funkciju koja se poziva tako što ćete dobiti njen disasembli i pretražiti BL.
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Skupština

Ranije je pomenuto da će funkcija koja će se brinuti o **pozivanju odgovarajuće funkcije u zavisnosti od primljenog ID poruke** biti `myipc_server`. Međutim, obično nećete imati simbole binarnog koda (bez imena funkcija), pa je interesantno **proveriti kako izgleda dekompilirano** jer će uvek biti vrlo slično (kod ove funkcije je nezavisan od izloženih funkcija):

{% tabs %}
{% tab title="mojaipc_server dekompilirano 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Početne instrukcije za pronalaženje odgovarajućih pokazivača funkcija
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Poziv funkciji sign_extend_64 koja može pomoći u identifikaciji ove funkcije
// Ovo čuva u rax pokazivač na poziv koji treba pozvati
// Proverite upotrebu adrese 0x100004040 (niz adresa funkcija)
// 0x1f4 = 500 (početni ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, if vraća false, dok else poziva odgovarajuću funkciju i vraća true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Izračunata adresa koja poziva odgovarajuću funkciju sa 2 argumenta
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

{% tab title="mojaipc_server dekompilirano 2" %}
Ovo je ista funkcija dekompilirana u drugoj besplatnoj verziji Hopper-a:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Početne instrukcije za pronalaženje odgovarajućih pokazivača funkcija
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
// 0x1f4 = 500 (početni ID)
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
// Isto if else kao u prethodnoj verziji
// Proverite upotrebu adrese 0x100004040 (niz adresa funkcija)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Poziv izračunate adrese gde bi trebala biti funkcija
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

Zapravo, ako odete na funkciju **`0x100004000`** pronaći ćete niz struktura **`routine_descriptor`**. Prvi element strukture je **adresa** gde je **funkcija** implementirana, a **struktura zauzima 0x28 bajta**, tako da svakih 0x28 bajta (počevši od bajta 0) možete dobiti 8 bajtova i to će biti **adresa funkcije** koja će biti pozvana:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Ovi podaci mogu biti izvađeni [**korišćenjem ovog Hopper skripta**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
### Debug

Kod generisan od strane MIG takođe poziva `kernel_debug` kako bi generisao logove o operacijama prilikom ulaska i izlaska. Moguće ih je proveriti koristeći **`trace`** ili **`kdv`**: `kdv all | grep MIG`

## Reference

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
