# Docker --privileged

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Wat beïnvloed

Wanneer jy 'n houer as bevoorregte uitvoer, is dit die beskermings wat jy deaktiveer:

### Monteer /dev

In 'n bevoorregte houer kan alle **toestelle in `/dev/`** toeganklik wees. Daarom kan jy **ontsnap** deur die **disk** van die gasheer te **monteer**.

{% tabs %}
{% tab title="Binne standaard houer" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Binne Bevoorregte Houer" %}
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

### Lees-slegs kern lêerstelsels

Kern lêerstelsels bied 'n mekanisme vir 'n proses om die gedrag van die kern te verander. egter, wanneer dit by houerprosesse kom, wil ons voorkom dat hulle enige veranderinge aan die kern aanbring. Daarom monteer ons kern lêerstelsels as **lees-slegs** binne die houer, wat verseker dat die houerprosesse nie die kern kan verander nie.

{% tabs %}
{% tab title="Binne standaard houer" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Binne Bevoorregte Houer" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Maskering oor kern lêerstelsels

Die **/proc** lêerstelsel is selektief skryfbaar, maar vir sekuriteit is sekere dele beskerm teen skryf- en lees toegang deur dit met **tmpfs** te oorlaai, wat verseker dat houerprosesse nie toegang tot sensitiewe areas het nie.

{% hint style="info" %}
**tmpfs** is 'n lêerstelsel wat al die lêers in virtuele geheue stoor. tmpfs skep nie enige lêers op jou hardeskyf nie. So as jy 'n tmpfs-lêerstelsel ontkoppel, gaan al die lêers wat daarin is vir altyd verlore.
{% endhint %}

{% tabs %}
{% tab title="Binne standaard houer" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Binne Bevoorregte Houer" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux vermoëns

Container enjinse begin die houers met 'n **beperkte aantal vermoëns** om te beheer wat binne die houer gebeur per standaard. **Bevoorregte** houers het **alle** die **vermoëns** beskikbaar. Om meer oor vermoëns te leer, lees:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Binne standaard houer" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Binne Bevoorregte Houer" %}
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

Jy kan die vermoëns wat beskikbaar is vir 'n houer manipuleer sonder om in `--privileged` modus te loop deur die `--cap-add` en `--cap-drop` vlae te gebruik.

### Seccomp

**Seccomp** is nuttig om die **syscalls** wat 'n houer kan aanroep te **beperk**. 'n Standaard seccomp-profiel is standaard geaktiveer wanneer docker-houers loop, maar in privilige-modus is dit gedeaktiveer. Leer meer oor Seccomp hier:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Binne standaard houer" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Binne Bevoorregte Houer" %}
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
Ook, let daarop dat wanneer Docker (of ander CRI's) in 'n **Kubernetes** kluster gebruik word, die **seccomp-filter is standaard gedeaktiveer**.

### AppArmor

**AppArmor** is 'n kernverbetering om **houers** te beperk tot 'n **beperkte** stel **hulpbronne** met **per-program profiele**. Wanneer jy met die `--privileged` vlag loop, is hierdie beskerming gedeaktiveer.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Die uitvoering van 'n houer met die `--privileged` vlag deaktiveer **SELinux etikette**, wat veroorsaak dat dit die etiket van die houer enjin oorneem, tipies `unconfined`, wat volle toegang toeken aan die houer enjin. In rootless-modus gebruik dit `container_runtime_t`, terwyl in root-modus `spc_t` toegepas word.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Wat Nie Beïnvloed Word Nie

### Namespaces

Namespaces word **NIE beïnvloed** deur die `--privileged` vlag. Alhoewel hulle nie die sekuriteitsbeperkings geaktiveer het nie, **sien hulle nie al die prosesse op die stelsel of die gasheer netwerk nie, byvoorbeeld**. Gebruikers kan individuele namespaces deaktiveer deur die **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** houer enjin vlae te gebruik.

{% tabs %}
{% tab title="Binne standaard bevoorregte houer" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Binne --pid=host Houer" %}
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

### Gebruiker naamruimte

**Standaard gebruik container enjin nie gebruiker naamruimtes nie, behalwe vir rootless houers**, wat dit benodig vir lêerstelsel montering en die gebruik van verskeie UID's. Gebruiker naamruimtes, wat noodsaaklik is vir rootless houers, kan nie gedeaktiveer word nie en verbeter sekuriteit aansienlik deur voorregte te beperk.

## Verwysings

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
