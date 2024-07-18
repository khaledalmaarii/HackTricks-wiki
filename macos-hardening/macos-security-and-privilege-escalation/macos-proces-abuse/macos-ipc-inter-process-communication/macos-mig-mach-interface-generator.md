# macOS MIG - Generatore di Interfacce Mach

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Informazioni di Base

MIG è stato creato per **semplificare il processo di creazione del codice Mach IPC**. Fondamentalmente **genera il codice necessario** per far comunicare server e client con una definizione data. Anche se il codice generato è brutto, uno sviluppatore dovrà solo importarlo e il suo codice sarà molto più semplice rispetto a prima.

La definizione è specificata nel Linguaggio di Definizione dell'Interfaccia (IDL) utilizzando l'estensione `.defs`.

Queste definizioni hanno 5 sezioni:

* **Dichiarazione del sottosistema**: La parola chiave sottosistema è utilizzata per indicare il **nome** e l'**id**. È anche possibile contrassegnarlo come **`KernelServer`** se il server deve essere eseguito nel kernel.
* **Inclusioni e importazioni**: MIG utilizza il C-preprocessore, quindi è in grado di utilizzare le importazioni. Inoltre, è possibile utilizzare `uimport` e `simport` per il codice generato dall'utente o dal server.
* **Dichiarazioni di tipo**: È possibile definire tipi di dati anche se di solito importerà `mach_types.defs` e `std_types.defs`. Per quelli personalizzati si può utilizzare una certa sintassi:
* \[i`n/out]tran`: Funzione che deve essere tradotta da un messaggio in ingresso o verso un messaggio in uscita
* `c[user/server]type`: Mappatura verso un altro tipo di C.
* `destructor`: Chiama questa funzione quando il tipo viene rilasciato.
* **Operazioni**: Queste sono le definizioni dei metodi RPC. Ci sono 5 tipi diversi:
* `routine`: Si aspetta una risposta
* `simpleroutine`: Non si aspetta una risposta
* `procedure`: Si aspetta una risposta
* `simpleprocedure`: Non si aspetta una risposta
* `function`: Si aspetta una risposta

### Esempio

Crea un file di definizione, in questo caso con una funzione molto semplice:

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

Si noti che il primo **argomento è la porta da associare** e MIG gestirà **automaticamente la porta di risposta** (a meno che non venga chiamato `mig_get_reply_port()` nel codice client). Inoltre, l'**ID delle operazioni** sarà **sequenziale** a partire dall'ID del sottosistema indicato (quindi se un'operazione è deprecata, viene eliminata e viene utilizzato `skip` per continuare a utilizzare il suo ID).

Ora utilizzare MIG per generare il codice server e client che saranno in grado di comunicare tra loro per chiamare la funzione Sottrai:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Saranno creati diversi nuovi file nella directory corrente.

{% hint style="success" %}
Puoi trovare un esempio più complesso nel tuo sistema con: `mdfind mach_port.defs`\
E puoi compilarlo dalla stessa cartella del file con: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

Nei file **`myipcServer.c`** e **`myipcServer.h`** puoi trovare la dichiarazione e la definizione della struttura **`SERVERPREFmyipc_subsystem`**, che definisce essenzialmente la funzione da chiamare in base all'ID del messaggio ricevuto (abbiamo indicato un numero iniziale di 500):

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

{% tab title="myipcServer.h" %}Traduzione in corso...{% endtab %}
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

Basandosi sulla struttura precedente, la funzione **`myipc_server_routine`** otterrà l'**ID del messaggio** e restituirà la funzione corretta da chiamare:
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
In questo esempio abbiamo definito solo 1 funzione nelle definizioni, ma se avessimo definito più funzioni, sarebbero state all'interno dell'array di **`SERVERPREFmyipc_subsystem`** e la prima sarebbe stata assegnata all'ID **500**, la seconda all'ID **501**...

Se ci si aspettasse che la funzione inviasse una **risposta**, esisterebbe anche la funzione `mig_internal kern_return_t __MIG_check__Reply__<name>`.

Attualmente è possibile identificare questa relazione nella struttura **`subsystem_to_name_map_myipc`** da **`myipcServer.h`** (**`subsystem_to_name_map_***`** in altri file):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Infine, un'altra funzione importante per far funzionare il server sarà **`myipc_server`**, che è quella che effettivamente **chiama la funzione** relativa all'id ricevuto:

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
/* Dimensione minima: routine() la aggiornerà se diversa */
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

Controlla le righe evidenziate in precedenza accedendo alla funzione da chiamare tramite ID.

Il seguente è il codice per creare un semplice **server** e **client** in cui il client può chiamare le funzioni Sottrai dal server:

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

### Il record NDR

Il record NDR è esportato da `libsystem_kernel.dylib` ed è una struttura che consente a MIG di **trasformare i dati in modo che siano agnostici del sistema** in cui vengono utilizzati poiché MIG è stato pensato per essere utilizzato tra sistemi diversi (e non solo sulla stessa macchina).

Questo è interessante perché se `_NDR_record` viene trovato in un binario come dipendenza (`jtool2 -S <binary> | grep NDR` o `nm`), significa che il binario è un cliente o un server MIG.

Inoltre, i **server MIG** hanno la tabella di dispatch in `__DATA.__const` (o in `__CONST.__constdata` nel kernel macOS e in `__DATA_CONST.__const` in altri kernel \*OS). Questo può essere dumpato con **`jtool2`**.

E i **client MIG** utilizzeranno il `__NDR_record` per inviare con `__mach_msg` ai server.

## Analisi del Binario

### jtool

Poiché molti binari ora utilizzano MIG per esporre le porte mach, è interessante sapere come **identificare che è stato utilizzato MIG** e le **funzioni che MIG esegue** con ciascun ID del messaggio.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) può analizzare le informazioni MIG da un binario Mach-O indicando l'ID del messaggio e identificando la funzione da eseguire:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Inoltre, le funzioni MIG sono solo wrapper della funzione effettiva che viene chiamata, il che significa che ottenendo il suo disassemblaggio e cercando BL potresti essere in grado di trovare la funzione effettiva chiamata:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

È stato precedentemente menzionato che la funzione che si occuperà di **chiamare la funzione corretta a seconda dell'ID del messaggio ricevuto** era `myipc_server`. Tuttavia, di solito non si avranno i simboli del binario (nessun nome di funzione), quindi è interessante **controllare come appare decompilato** poiché sarà sempre molto simile (il codice di questa funzione è indipendente dalle funzioni esposte):

{% tabs %}
{% tab title="myipc_server decompiled 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Istruzioni iniziali per trovare i puntatori di funzione corretti
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Chiamata a sign_extend_64 che può aiutare a identificare questa funzione
// Questo memorizza in rax il puntatore alla chiamata che deve essere effettuata
// Controlla l'uso dell'indirizzo 0x100004040 (array degli indirizzi delle funzioni)
// 0x1f4 = 500 (l'ID di partenza)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Se - altrimenti, l'if restituisce false, mentre l'else chiama la funzione corretta e restituisce true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Indirizzo calcolato che chiama la funzione corretta con 2 argomenti
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

{% tab title="myipc_server decompiled 2" %}
Questa è la stessa funzione decompilata in una versione diversa di Hopper free:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Istruzioni iniziali per trovare i puntatori di funzione corretti
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
// 0x1f4 = 500 (l'ID di partenza)
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
// Stesso if else della versione precedente
// Controlla l'uso dell'indirizzo 0x100004040 (array degli indirizzi delle funzioni)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Chiamata all'indirizzo calcolato dove dovrebbe essere la funzione
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

Attualmente, se si accede alla funzione **`0x100004000`**, si troverà l'array di strutture **`routine_descriptor`**. Il primo elemento della struttura è l'**indirizzo** in cui la **funzione** è implementata, e la **struttura occupa 0x28 byte**, quindi ogni 0x28 byte (a partire dal byte 0) è possibile ottenere 8 byte e quello sarà l'**indirizzo della funzione** che verrà chiamato:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Questi dati possono essere estratti [**utilizzando questo script di Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
### Debug

Il codice generato da MIG chiama anche `kernel_debug` per generare log sulle operazioni in ingresso e in uscita. È possibile controllarli usando **`trace`** o **`kdv`**: `kdv all | grep MIG`

## References

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
