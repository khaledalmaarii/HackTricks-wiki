# Docker --privileged

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** senden.

</details>

## Was beeinflusst wird

Wenn Sie einen Container als privilegiert ausführen, werden die folgenden Schutzmaßnahmen deaktiviert:

### Mounten von /dev

In einem privilegierten Container können alle **Geräte in `/dev/`** zugegriffen werden. Dadurch können Sie durch **Mounten** der Festplatte des Hosts **ausbrechen**.

{% tabs %}
{% tab title="Im Standardcontainer" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% tab title="In einem privilegierten Container" %}
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

### Schreibgeschützte Kernel-Dateisysteme

Kernel-Dateisysteme bieten einen Mechanismus, um das Verhalten des Kernels zu ändern. Wenn es jedoch um Container-Prozesse geht, möchten wir verhindern, dass sie Änderungen am Kernel vornehmen. Daher mounten wir Kernel-Dateisysteme als **schreibgeschützt** innerhalb des Containers, um sicherzustellen, dass die Container-Prozesse den Kernel nicht ändern können.

{% tabs %}
{% tab title="Innerhalb des Standardcontainers" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% tab title="In einem privilegierten Container" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Maskierung über Kernel-Dateisysteme

Das **/proc**-Dateisystem ist selektiv beschreibbar, aber aus Sicherheitsgründen sind bestimmte Teile vor Schreib- und Lesezugriffen geschützt, indem sie mit **tmpfs** überlagert werden, um sicherzustellen, dass Container-Prozesse nicht auf sensible Bereiche zugreifen können.

{% hint style="info" %}
**tmpfs** ist ein Dateisystem, das alle Dateien im virtuellen Speicher speichert. tmpfs erstellt keine Dateien auf Ihrer Festplatte. Wenn Sie ein tmpfs-Dateisystem aushängen, gehen alle darin befindlichen Dateien für immer verloren.
{% endhint %}

{% tabs %}
{% tab title="Im Standardcontainer" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% tab title="In einem privilegierten Container" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Linux-Fähigkeiten

Container-Engines starten Container standardmäßig mit einer **begrenzten Anzahl von Fähigkeiten**, um zu kontrollieren, was innerhalb des Containers passiert. **Privilegierte** Container haben **alle** **Fähigkeiten** zugänglich. Um mehr über Fähigkeiten zu erfahren, lesen Sie:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Innerhalb des Standardcontainers" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% tab title="In einem privilegierten Container" %}
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

Sie können die für einen Container verfügbaren Fähigkeiten manipulieren, ohne im `--privileged`-Modus zu laufen, indem Sie die Flags `--cap-add` und `--cap-drop` verwenden.

### Seccomp

**Seccomp** ist nützlich, um die **Systemaufrufe** einzuschränken, die ein Container aufrufen kann. Ein Standard-Seccomp-Profil ist standardmäßig aktiviert, wenn Docker-Container ausgeführt werden, aber im privilegierten Modus ist es deaktiviert. Erfahren Sie hier mehr über Seccomp:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Innerhalb des Standardcontainers" %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="In einem privilegierten Container" %}
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
Auch beachten Sie, dass wenn Docker (oder andere CRIs) in einem **Kubernetes**-Cluster verwendet werden, ist der **seccomp-Filter standardmäßig deaktiviert**.

### AppArmor

**AppArmor** ist eine Kernel-Erweiterung, um **Container** auf eine **begrenzte** Anzahl von **Ressourcen** mit **programmspezifischen Profilen** einzuschränken. Wenn Sie mit dem `--privileged`-Flag ausführen, ist dieser Schutz deaktiviert.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Das Ausführen eines Containers mit dem `--privileged`-Flag deaktiviert **SELinux-Labels**, wodurch es das Label des Container-Engines erbt, normalerweise `unconfined`, was vollen Zugriff ähnlich wie der Container-Engine gewährt. Im rootless-Modus wird `container_runtime_t` verwendet, während im Root-Modus `spc_t` angewendet wird.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Was nicht beeinflusst wird

### Namespaces

Namespaces werden **NICHT von** dem `--privileged` Flag beeinflusst. Obwohl sie keine Sicherheitsbeschränkungen aktiviert haben, **sehen sie zum Beispiel nicht alle Prozesse im System oder im Host-Netzwerk**. Benutzer können einzelne Namespaces deaktivieren, indem sie die Container-Engine-Flags **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** verwenden.

{% tabs %}
{% tab title="Innerhalb des standardmäßigen privilegierten Containers" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% tab title="Innerhalb des --pid=host Containers" %}
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

### Benutzernamensraum

Standardmäßig verwenden Container-Engines keinen Benutzernamensraum, außer für rootless Container, die sie für das Einhängen des Dateisystems und die Verwendung mehrerer Benutzer-IDs benötigen. Benutzernamensräume, die für rootless Container unerlässlich sind, können nicht deaktiviert werden und verbessern die Sicherheit erheblich, indem sie Privilegien einschränken.

## Referenzen

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS erhalten oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das [hacktricks repo](https://github.com/carlospolop/hacktricks) und das [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)** einreichen.

</details>
