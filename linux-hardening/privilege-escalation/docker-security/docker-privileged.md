# Docker --privileged

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Šta utiče

Kada pokrenete kontejner kao privilegovan, ovo su zaštite koje onemogućavate:

### Montiranje /dev

U privilegovanom kontejneru, svi **uređaji mogu biti pristupljeni u `/dev/`**. Stoga možete **pobeći** tako što ćete **montirati** disk domaćina.

{% tabs %}
{% tab title="Unutar podrazumevanog kontejnera" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Unutar privilegovanog kontejnera" %}
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

### Datoteke sistema jezgra samo za čitanje

Datoteke sistema jezgra pružaju mehanizam za proces da modifikuje ponašanje jezgra. Međutim, kada su u pitanju procesi kontejnera, želimo da sprečimo njihovo menjanje jezgra. Stoga, montiramo datoteke sistema jezgra kao **samo za čitanje** unutar kontejnera, osiguravajući da procesi kontejnera ne mogu modifikovati jezgro.

{% tabs %}
{% tab title="Unutar podrazumevanog kontejnera" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Unutar privilegovanog kontejnera" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Maskiranje nad datotečnim sistemima jezgra

**/proc** datotečni sistem je selektivno zapisiv, ali iz bezbednosnih razloga, određeni delovi su zaštićeni od pisanja i čitanja preklapanjem sa **tmpfs**, osiguravajući da procesi kontejnera ne mogu pristupiti osetljivim oblastima.

{% hint style="info" %}
**tmpfs** je datotečni sistem koji čuva sve datoteke u virtuelnoj memoriji. tmpfs ne kreira nikakve datoteke na vašem hard disku. Dakle, ako odmontirate tmpfs datotečni sistem, sve datoteke koje se u njemu nalaze su izgubljene zauvek.
{% endhint %}

{% tabs %}
{% tab title="Unutar podrazumevanog kontejnera" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Unutar privilegovanog kontejnera" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux sposobnosti

Motori kontejnera pokreću kontejnere sa **ograničenim brojem sposobnosti** kako bi kontrolisali šta se dešava unutar kontejnera po defaultu. **Privilegovani** imaju **sve** **sposobnosti** dostupne. Da biste saznali više o sposobnostima, pročitajte:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Unutar defaultnog kontejnera" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Unutar privilegovanog kontejnera" %}
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

Možete manipulisati sposobnostima dostupnim kontejneru bez pokretanja u `--privileged` režimu koristeći `--cap-add` i `--cap-drop` zastavice.

### Seccomp

**Seccomp** je koristan za **ograničavanje** **syscalls** koje kontejner može pozvati. Podrazumevani seccomp profil je omogućen podrazumevano prilikom pokretanja docker kontejnera, ali u privilegovanom režimu je on onemogućen. Saznajte više o Seccomp-u ovde:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Inside default container" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Unutar privilegovanog kontejnera" %}
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
Takođe, imajte na umu da kada se Docker (ili drugi CRI) koriste u **Kubernetes** klasteru, **seccomp filter je onemogućen po defaultu**

### AppArmor

**AppArmor** je poboljšanje jezgra koje ograničava **kontejnere** na **ograničen** skup **resursa** sa **profilima po programu**. Kada pokrenete sa `--privileged` flagom, ova zaštita je onemogućena.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Pokretanje kontejnera sa `--privileged` zastavicom onemogućava **SELinux oznake**, uzrokujući da nasledi oznaku kontejnerskog motora, obično `unconfined`, što omogućava pun pristup sličan kontejnerskom motoru. U rootless režimu, koristi `container_runtime_t`, dok se u root režimu primenjuje `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Šta ne utiče

### Namespaces

Namespaces **NISU pogođeni** `--privileged` oznakom. Iako nemaju omogućena sigurnosna ograničenja, **ne vide sve procese na sistemu ili host mreži, na primer**. Korisnici mogu onemogućiti pojedinačne namespaces koristeći **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** oznake kontejnerskog motora.

{% tabs %}
{% tab title="Unutar podrazumevanog privilegovanog kontejnera" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Unutar --pid=host kontejnera" %}
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

### User namespace

**Podrazumevano, kontejnerski alati ne koriste korisničke imenske prostore, osim za kontejnere bez root privilegija**, koji ih zahtevaju za montiranje datotečnih sistema i korišćenje više UID-ova. Korisnički imenski prostori, koji su ključni za kontejnere bez root privilegija, ne mogu se onemogućiti i značajno poboljšavaju bezbednost ograničavanjem privilegija.

## References

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
