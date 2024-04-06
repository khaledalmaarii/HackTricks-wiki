# Docker --privileged

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium** [**hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Co wpływa

Kiedy uruchamiasz kontener jako uprzywilejowany, wyłączasz następujące zabezpieczenia:

### Montowanie /dev

W kontenerze uprzywilejowanym wszystkie **urządzenia są dostępne w `/dev/`**. Dlatego można **ujść** przez **zamontowanie** dysku hosta.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Wewnątrz kontenera z uprawnieniami" %}
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

### System call filtering

System calls are the interface between user space and the kernel. By filtering system calls, we can restrict the actions that container processes can perform. Docker provides a feature called **seccomp** that allows us to filter system calls and define a whitelist of allowed system calls for container processes.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Wewnątrz kontenera z uprawnieniami" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Maskowanie systemów plików jądra

System plików **/proc** jest selektywnie zapisywalny, ale dla bezpieczeństwa niektóre części są zabezpieczone przed zapisem i odczytem przez nałożenie na nie **tmpfs**, co zapewnia, że procesy kontenera nie mogą uzyskać dostępu do wrażliwych obszarów.

{% hint style="info" %}
**tmpfs** to system plików, który przechowuje wszystkie pliki w pamięci wirtualnej. tmpfs nie tworzy żadnych plików na dysku twardym. Jeśli odmontujesz system plików tmpfs, wszystkie pliki w nim zostaną utracone na zawsze.
{% endhint %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Wewnątrz kontenera z uprawnieniami" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linuxowe uprawnienia

Silniki kontenerów uruchamiają kontenery z **ograniczoną liczbą uprawnień**, aby kontrolować to, co dzieje się wewnątrz kontenera domyślnie. **Uprawnienia** uprzywilejowane mają dostęp do **wszystkich** **uprawnień**. Aby dowiedzieć się więcej o uprawnieniach, przeczytaj:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Wewnątrz kontenera z uprawnieniami" %}
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

Możesz manipulować dostępnymi możliwościami dla kontenera bez uruchamiania go w trybie `--privileged`, używając flag `--cap-add` i `--cap-drop`.

### Seccomp

**Seccomp** jest przydatny do **ograniczania** wywołań **syscalls**, które kontener może wywołać. Domyślny profil seccomp jest włączony domyślnie podczas uruchamiania kontenerów Docker, ale w trybie uprzywilejowanym jest wyłączony. Dowiedz się więcej o Seccomp tutaj:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="Wewnątrz kontenera z uprawnieniami" %}
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

Dodatkowo, należy zauważyć, że gdy Docker (lub inne CRIs) jest używany w klastrze **Kubernetes**, filtr **seccomp** jest domyślnie wyłączony.

### AppArmor

**AppArmor** to ulepszenie jądra, które ogranicza **kontenery** do **ograniczonego** zestawu **zasobów** za pomocą **profilów dla poszczególnych programów**. Gdy uruchamiasz z flagą `--privileged`, ta ochrona jest wyłączona.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```

### SELinux

Uruchomienie kontenera z flagą `--privileged` wyłącza **etykiety SELinux**, powodując dziedziczenie etykiety silnika kontenera, zwykle `unconfined`, co daje pełny dostęp podobny do silnika kontenera. W trybie bez uprawnień roota używane jest `container_runtime_t`, podczas gdy w trybie roota stosowane jest `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```

## Co nie ma wpływu

### Przestrzenie nazw

Przestrzenie nazw **NIE są dotknięte** flagą `--privileged`. Chociaż nie mają włączonych ograniczeń bezpieczeństwa, **nie widzą wszystkich procesów w systemie ani sieci hosta, na przykład**. Użytkownicy mogą wyłączyć poszczególne przestrzenie nazw, używając flag kontenerów silników **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="undefined" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Wewnątrz kontenera --pid=host" %}
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

### Przestrzeń nazw użytkownika

**Domyślnie, silniki kontenerów nie wykorzystują przestrzeni nazw użytkownika, z wyjątkiem kontenerów bez uprawnień root**, które wymagają ich do montowania systemu plików i korzystania z wielu UID. Przestrzenie nazw użytkownika, niezbędne dla kontenerów bez uprawnień root, nie mogą być wyłączone i znacznie zwiększają bezpieczeństwo poprzez ograniczenie uprawnień.

## Referencje

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć **reklamę swojej firmy w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do repozytorium** [**hacktricks**](https://github.com/carlospolop/hacktricks) **i** [**hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
