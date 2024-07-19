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

## Nini Kinachohusisha

Unapokimbia kontena kama la kibali, hizi ndizo ulinzi unazozima:

### Mount /dev

Katika kontena la kibali, **vifaa vyote vinaweza kufikiwa katika `/dev/`**. Hivyo unaweza **kutoroka** kwa **kuunganisha** diski ya mwenyeji.

{% tabs %}
{% tab title="Ndani ya kontena la kawaida" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Ndani ya Kontena la Kipekee" %}
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

### Mfumo wa faili wa kernel wa kusoma tu

Mifumo ya faili ya kernel inatoa njia kwa mchakato kubadilisha tabia ya kernel. Hata hivyo, linapokuja suala la michakato ya kontena, tunataka kuzuia mabadiliko yoyote kwenye kernel. Kwa hivyo, tunashikilia mifumo ya faili ya kernel kama **kusoma tu** ndani ya kontena, kuhakikisha kwamba michakato ya kontena haiwezi kubadilisha kernel.

{% tabs %}
{% tab title="Ndani ya kontena la default" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Ndani ya Kontena la Kipekee" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Kuficha juu ya mifumo ya faili ya kernel

Mfumo wa faili wa **/proc** unaweza kuandikwa kwa kuchagua lakini kwa usalama, sehemu fulani zimekingwa dhidi ya ufikiaji wa kuandika na kusoma kwa kuzifunika na **tmpfs**, kuhakikisha kwamba michakato ya kontena haiwezi kufikia maeneo nyeti.

{% hint style="info" %}
**tmpfs** ni mfumo wa faili unaohifadhi faili zote katika kumbukumbu ya virtual. tmpfs haaundai faili zozote kwenye diski yako ngumu. Hivyo ikiwa utaondoa mfumo wa faili wa tmpfs, faili zote zilizomo ndani yake zitapotea milele.
{% endhint %}

{% tabs %}
{% tab title="Ndani ya kontena la default" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Ndani ya Kontena la Privileged" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Uwezo wa Linux

Mifumo ya kontena inazindua kontena na **idadi ndogo ya uwezo** ili kudhibiti kile kinachotokea ndani ya kontena kwa kawaida. Wale **wenye mamlaka** wana **uwezo wote** unaopatikana. Ili kujifunza kuhusu uwezo soma:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Ndani ya kontena la kawaida" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Ndani ya Kontena la Kipekee" %}
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

Unaweza kudhibiti uwezo unaopatikana kwa kontena bila kukimbia katika hali ya `--privileged` kwa kutumia bendera za `--cap-add` na `--cap-drop`.

### Seccomp

**Seccomp** ni muhimu ili **kudhibiti** **syscalls** ambazo kontena linaweza kuita. Profaili ya seccomp ya kawaida imewezeshwa kwa default wakati wa kukimbia kontena za docker, lakini katika hali ya privileged imezimwa. Jifunze zaidi kuhusu Seccomp hapa:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Ndani ya kontena la kawaida" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Ndani ya Kontena la Kipekee" %}
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
Pia, kumbuka kwamba wakati Docker (au CRIs zingine) zinapotumika katika **Kubernetes** cluster, **seccomp filter imezimwa kwa default**

### AppArmor

**AppArmor** ni uboreshaji wa kernel ili kufunga **containers** kwenye seti **ndogo** ya **rasilimali** kwa kutumia **profiles za kila programu**. Unapokimbia na bendera `--privileged`, ulinzi huu unazimwa.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Kukimbia kontena na bendera `--privileged` kunazima **lebo za SELinux**, na kusababisha kurithi lebo ya injini ya kontena, kwa kawaida `unconfined`, ikitoa ufikiaji kamili sawa na injini ya kontena. Katika hali isiyo na mizizi, inatumia `container_runtime_t`, wakati katika hali ya mizizi, `spc_t` inatumika.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## What Doesn't Affect

### Namespaces

Namespaces **HAITHI** na bendera `--privileged`. Ingawa hazina vikwazo vya usalama vilivyowekwa, **haziona mchakato wote kwenye mfumo au mtandao wa mwenyeji, kwa mfano**. Watumiaji wanaweza kuzima namespaces binafsi kwa kutumia bendera za injini za kontena **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="Inside default privileged container" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Ndani ya --pid=host Container" %}
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

**Kwa default, injini za kontena hazitumi user namespaces, isipokuwa kwa kontena zisizo na mizizi**, ambazo zinahitaji user namespaces kwa ajili ya kuunganisha mfumo wa faili na kutumia UIDs nyingi. User namespaces, muhimu kwa kontena zisizo na mizizi, haziwezi kuzuiliwa na zinaongeza usalama kwa kiasi kikubwa kwa kupunguza mamlaka.

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
