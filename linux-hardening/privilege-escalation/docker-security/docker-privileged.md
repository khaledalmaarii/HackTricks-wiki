# Docker --privileged

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? Au ungependa kupata **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuatilie** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Athari za Docker --privileged

Unapotumia chombo kama chombo cha kudukua, hizi ni kinga ambazo unazima:

### Kufunga /dev

Katika chombo kilichopewa ruhusa, **vifaa vyote vinaweza kufikiwa katika `/dev/`**. Kwa hivyo unaweza **kutoroka** kwa **kufunga** diski ya mwenyeji.

{% tabs %}
{% tab title="Ndani ya chombo cha msingi" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Ndani ya Chombo cha Kuidhinishwa" %}
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

### Soma mfumo wa faili wa kernel kwa kusoma tu

Mifumo ya faili ya kernel hutoa njia kwa mchakato kubadilisha tabia ya kernel. Hata hivyo, linapokuja suala la mchakato wa kontena, tunataka kuzuia mabadiliko yoyote kwenye kernel. Kwa hiyo, tunafunga mifumo ya faili ya kernel kama **soma tu** ndani ya kontena, kuhakikisha kuwa mchakato wa kontena hauwezi kubadilisha kernel.
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Ndani ya Chombo cha Kuidhinishwa" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Kuficha mfumo wa faili wa kernel

Mfumo wa faili wa **/proc** unaweza kuandikwa kwa hiari lakini kwa usalama, sehemu fulani zimefichwa kutoka kwa ufikiaji wa kuandika na kusoma kwa kuzifunika na **tmpfs**, kuhakikisha mchakato wa kontena hauwezi kufikia maeneo nyeti.

{% hint style="info" %}
**tmpfs** ni mfumo wa faili ambao huhifadhi faili zote kwenye kumbukumbu ya kawaida. tmpfs haizalishi faili yoyote kwenye diski ngumu. Kwa hivyo, ikiwa unafuta mfumo wa faili wa tmpfs, faili zote zilizopo ndani yake zinapotea milele.
{% endhint %}

{% tabs %}
{% tab title="Ndani ya kontena ya msingi" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Ndani ya Chombo cha Kuidhinishwa" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Uwezo wa Linux

Injini za kontena huzindua kontena na **idadi ndogo ya uwezo** ili kudhibiti kinachoendelea ndani ya kontena kwa chaguo-msingi. Wale wenye **mamlaka** wana **uwezo wote** unaopatikana. Ili kujifunza kuhusu uwezo, soma:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Ndani ya kontena ya chaguo-msingi" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Ndani ya Chombo cha Kuidhinishwa" %}
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

Unaweza kubadilisha uwezo uliopo kwa chombo bila kuendesha kwa hali ya `--privileged` kwa kutumia bendera za `--cap-add` na `--cap-drop`.

### Seccomp

**Seccomp** ni muhimu kwa **kikomo** cha **syscalls** ambazo chombo kinaweza kuita. Profaili ya seccomp ya chaguo-msingi imeamilishwa kwa chombo cha docker, lakini katika hali ya kuheshimu, imelemazwa. Jifunze zaidi kuhusu Seccomp hapa:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Ndani ya chombo cha chaguo-msingi" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Ndani ya Chombo cha Kuidhinishwa" %}
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
Pia, tafadhali kumbuka kuwa wakati Docker (au CRIs nyingine) zinapotumiwa katika kikundi cha **Kubernetes**, kichujio cha **seccomp** kimelemazwa kwa chaguo-msingi.

### AppArmor

**AppArmor** ni uboreshaji wa kernel ambao unazuia **makontena** kwa seti **ndogo** ya **rasilimali** na **mipangilio ya programu-kwa-programu**. Wakati unapoendesha na bendera ya `--privileged`, kinga hii inalemazwa.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Kukimbia chombo na bendera ya `--privileged` inazima **lebo za SELinux**, ikisababisha kurithi lebo ya injini ya chombo, kawaida `unconfined`, ikitoa ufikiaji kamili kama injini ya chombo. Katika hali ya mizizi, inatumia `container_runtime_t`, wakati katika hali ya mizizi, `spc_t` inatumika.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Yasiyoathiri

### Majina ya Nafasi

Nafasi hazijaathiriwa na bendera ya `--privileged`. Ingawa hazina vikwazo vya usalama vilivyowezeshwa, **hazioni michakato yote kwenye mfumo au mtandao wa mwenyeji, kwa mfano**. Watumiaji wanaweza kulemaza nafasi binafsi kwa kutumia bendera za injini ya chombo cha **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="Ndani ya chombo cha kawaida kilicho na uwezo" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Ndani ya Kontena ya --pid=host" %}
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

### Nafasi ya Mtumiaji

**Kwa chaguo-msingi, injini za kontena hazitumii nafasi za mtumiaji, isipokuwa kwa kontena zisizo na mizizi**, ambayo inahitaji nafasi hizo kwa ajili ya kufunga mfumo wa faili na kutumia kitambulisho cha mtumiaji zaidi ya kimoja. Nafasi za mtumiaji, muhimu kwa kontena zisizo na mizizi, haiwezi kuzimwa na inaboresha usalama kwa kuzuia mamlaka.

## Marejeo

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikionekana katika HackTricks**? au ungependa kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **nifuate** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa [repo ya hacktricks](https://github.com/carlospolop/hacktricks) na [repo ya hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
