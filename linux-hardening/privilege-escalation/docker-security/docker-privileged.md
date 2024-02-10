# Docker --privileged

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* Bir **cybersecurity şirketinde** çalışıyor musunuz? **Şirketinizi HackTricks'te reklamını görmek** ister misiniz? veya **PEASS'ın en son sürümüne veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**The PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family), özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuzu keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>

## Etkileyenler

Bir ayrıcalıklı konteyner çalıştırdığınızda devre dışı bıraktığınız korumalar şunlardır:

### /dev'i bağlama

Ayrıcalıklı bir konteynerde, **tüm cihazlara `/dev/` üzerinden erişilebilir**. Bu nedenle, ana bilgisayarın diski **bağlayarak** kaçabilirsiniz.

{% tabs %}
{% tab title="Varsayılan konteyner içinde" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% tab title="Ayrıcalıklı Konteyner İçinde" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
{% endtab %}
{% endtabs %}

### Salt Okunur Çekirdek Dosya Sistemleri

Çekirdek dosya sistemleri, bir işlemin çekirdeğin davranışını değiştirmesini sağlayan bir mekanizma sağlar. Bununla birlikte, konteyner işlemleri için, çekirdeğe herhangi bir değişiklik yapmalarını önlemek istiyoruz. Bu nedenle, konteyner içindeki çekirdek dosya sistemlerini **salt okunur** olarak bağlarız, böylece konteyner işlemleri çekirdeği değiştiremez.
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% tab title="Ayrıcalıklı Konteyner İçinde" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Çekirdek dosya sistemlerinin üzerine maskeleme

**/proc** dosya sistemi seçici olarak yazılabilir olmasına rağmen, güvenlik için belirli bölümler **tmpfs** ile üzerlerine örtülerek yazma ve okuma erişiminden korunur, böylece konteyner işlemleri hassas alanlara erişemez.

{% hint style="info" %}
**tmpfs**, tüm dosyaları sanal bellekte depolayan bir dosya sistemidir. tmpfs, sabit diskinizde herhangi bir dosya oluşturmaz. Bu nedenle, bir tmpfs dosya sistemini ayrıldığınızda, içinde bulunan tüm dosyalar sonsuza dek kaybolur.
{% endhint %}

{% tabs %}
{% tab title="Varsayılan konteyner içinde" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% tab title="Ayrıcalıklı Konteyner İçinde" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux yetenekleri

Konteyner motorları, konteynerleri varsayılan olarak içeride ne olduğunu kontrol etmek için sınırlı sayıda yetenekle başlatır. Ayrıcalıklı olanlar **tüm yeteneklere** erişebilir. Yetenekler hakkında bilgi edinmek için okuyun:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Varsayılan konteyner içinde" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% tab title="Ayrıcalıklı Konteyner İçinde" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{% endtab %}
{% endtabs %}

`--cap-add` allows you to add specific capabilities to a container, while `--cap-drop` allows you to drop specific capabilities. Here are some commonly used capabilities:

- `SYS_ADMIN`: Allows various system administration tasks.
- `SYS_PTRACE`: Allows tracing and debugging of processes.
- `NET_ADMIN`: Allows network administration tasks.
- `SYS_MODULE`: Allows loading and unloading kernel modules.
- `SYS_RAWIO`: Allows direct access to raw I/O ports.

To add or drop capabilities, use the following syntax:

```bash
docker run --cap-add=<capability> <image>
docker run --cap-drop=<capability> <image>
```

For example, to add the `SYS_ADMIN` capability to a container:

```bash
docker run --cap-add=SYS_ADMIN <image>
```

To drop the `SYS_PTRACE` capability from a container:

```bash
docker run --cap-drop=SYS_PTRACE <image>
```

By manipulating the capabilities of a container, you can fine-tune its permissions and restrict its access to certain system resources. This can help improve the security of your Docker environment.
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% tab title="Ayrıcalıklı Konteyner İçinde" %}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{% endtab %}
{% endtabs %}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
Ayrıca, Docker (veya diğer CRIs) bir Kubernetes kümesinde kullanıldığında, seccomp filtresi varsayılan olarak devre dışı bırakılır.

### AppArmor

**AppArmor**, konteynerleri **sınırlı** bir dizi **kaynak** ile **program bazlı profiller** ile sınırlayan bir çekirdek geliştirmesidir. `--privileged` bayrağıyla çalıştırdığınızda, bu koruma devre dışı bırakılır.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

`--privileged` bayrağıyla bir konteyner çalıştırmak, **SELinux etiketlerini devre dışı bırakır** ve genellikle `unconfined` olan konteyner motorunun etiketini devralarak tam erişim sağlar. Köksüz modda `container_runtime_t` kullanılırken, kök modunda `spc_t` uygulanır.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Hangi Durumları Etkilemez

### Ad alanları (Namespaces)

Ad alanları, `--privileged` bayrağından etkilenmez. Güvenlik kısıtlamaları etkin olmasa da, örneğin sistemdeki veya ana ağda bulunan tüm işlemleri göremezler. Kullanıcılar, ad alanlarını devre dışı bırakmak için **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** konteyner motoru bayraklarını kullanabilirler.

{% tabs %}
{% tab title="Varsayılan ayrıcalıklı konteyner içinde" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="İçinde --pid=host Konteyner" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{% endtab %}
{% endtabs %}

### Kullanıcı ad alanı

**Varsayılan olarak, konteyner motorları, kök olmayan konteynerler için dosya sistemi bağlama ve birden fazla UID kullanma gerektiren durumlar dışında kullanıcı ad alanlarını kullanmaz**. Kök olmayan konteynerler için gerekli olan kullanıcı ad alanları, devre dışı bırakılamaz ve ayrıcalıkları kısıtlayarak güvenliği önemli ölçüde artırır.

## Referanslar

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> ile sıfırdan kahraman olmak için AWS hackleme öğrenin<strong>!</strong></summary>

* **Bir siber güvenlik şirketinde mi çalışıyorsunuz**? **Şirketinizi HackTricks'te reklamını yapmak** ister misiniz? veya **PEASS'ın en son sürümüne erişmek veya HackTricks'i PDF olarak indirmek** ister misiniz? [**ABONELİK PLANLARINI**](https://github.com/sponsors/carlospolop) kontrol edin!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) koleksiyonumuzdaki özel [**NFT'leri**](https://opensea.io/collection/the-peass-family) keşfedin
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* **[💬](https://emojipedia.org/speech-balloon/) Discord grubuna** katılın veya [**telegram grubuna**](https://t.me/peass) katılın veya **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**'u takip edin**.
* **Hacking hilelerinizi [hacktricks repo](https://github.com/carlospolop/hacktricks) ve [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)'ya PR göndererek paylaşın**.

</details>
