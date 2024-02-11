# Docker --bevoorreg

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Wat Affekteer Dit

Wanneer jy 'n houer as bevoorreg uitvoer, word hierdie beskermings gedeaktiveer:

### Monteer /dev

In 'n bevoorregte houer kan **alle toestelle in `/dev/`** benader word. Jy kan dus **ontsnap** deur die skandering van die bediener se skyf te **monteer**.

{% tabs %}
{% tab title="Binne standaard houer" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Binne die Bevoorregte Houer" %}
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

### Lees-slegs kernel-lêerstelsels

Kernel-lêerstelsels bied 'n meganisme vir 'n proses om die gedrag van die kernel te wysig. Tog wil ons voorkom dat houerprosesse enige veranderinge aan die kernel maak. Daarom monteer ons kernel-lêerstelsels as **lees-slegs** binne die houer, om te verseker dat die houerprosesse die kernel nie kan wysig nie.

{% tabs %}
{% tab title="Binne die verstekhouer" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Binne die Bevoorregte Houer" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Maskering oor kernel-lêersisteme

Die **/proc**-lêersisteem is selektief skryfbaar, maar vir sekuriteit is sekere dele beskerm teen skryf- en leestoegang deur dit met **tmpfs** te oorlê, wat verseker dat houerprosesse nie toegang tot sensitiewe areas kan verkry nie.

{% hint style="info" %}
**tmpfs** is 'n lêersisteem wat al die lêers in virtuele geheue stoor. tmpfs skep geen lêers op jou harde skyf nie. As jy 'n tmpfs-lêersisteem ontlaai, gaan al die lêers wat daarin woon, vir ewig verlore.
{% endhint %}

{% tabs %}
{% tab title="Binne die verstekhouer" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Binne die Bevoorregte Houer" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux-vermoëns

Houer-enjins begin die houers met 'n **beperkte aantal vermoëns** om te beheer wat binne die houer gebeur. **Bevoorregte** eenhede het **alle** die **vermoëns** toeganklik. Om meer te leer oor vermoëns, lees:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Binne die verstekhouer" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Binne die Bevoorregte Houer" %}
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

Jy kan die vermoëns wat beskikbaar is vir 'n houer manipuleer sonder om in `--privileged`-modus te loop deur die `--cap-add` en `--cap-drop` vlae te gebruik.

### Seccomp

**Seccomp** is nuttig om die **syscalls** wat 'n houer kan aanroep, te **beperk**. 'n Standaard seccomp-profiel is standaard geaktiveer wanneer docker-houers uitgevoer word, maar in bevoorregte modus is dit gedeaktiveer. Lees meer oor Seccomp hier:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Binne die standaard houer" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Binne die Bevoorregte Houer" %}
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
Verder moet daarop gelet word dat wanneer Docker (of ander CRIs) in 'n **Kubernetes**-groep gebruik word, die **seccomp-filter standaard gedeaktiveer** is.

### AppArmor

**AppArmor** is 'n kernel-verbetering om **houers** tot 'n **beperkte** stel **hulpbronne** met **per-program profiele** te beperk. Wanneer jy met die `--privileged` vlag hardloop, word hierdie beskerming gedeaktiveer.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Die uitvoer van 'n houer met die `--privileged` vlag deaktiveer **SELinux-etikette**, wat veroorsaak dat dit die etiket van die houermotor erf, tipies `unconfined`, wat volle toegang gee soortgelyk aan die houermotor. In rootless-modus gebruik dit `container_runtime_t`, terwyl in root-modus `spc_t` toegepas word.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Wat nie beïnvloed word nie

### Namespaces

Namespaces word **NIET beïnvloed** deur die `--privileged` vlag. Alhoewel hulle nie die sekuriteitsbeperkings geaktiveer het nie, **sien hulle nie al die prosesse op die stelsel of die gasheer-netwerk nie, byvoorbeeld**. Gebruikers kan individuele namespaces deaktiveer deur die **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** kontainer-enjin vlae te gebruik.

{% tabs %}
{% tab title="Binne die standaard bevoorregte houer" %}
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

### Gebruikersnaamruimte

**Standaard maak container-engines geen gebruik van gebruikersnaamruimtes, behalve voor rootless containers**, die ze nodig hebben voor het koppelen van bestandssystemen en het gebruik van meerdere UID's. Gebruikersnaamruimtes, die essentieel zijn voor rootless containers, kunnen niet worden uitgeschakeld en verbeteren de beveiliging aanzienlijk door privileges te beperken.

## Verwysings

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
