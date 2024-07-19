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

## Qué Afecta

Cuando ejecutas un contenedor como privilegiado, estas son las protecciones que estás deshabilitando:

### Montar /dev

En un contenedor privilegiado, **todos los dispositivos pueden ser accedidos en `/dev/`**. Por lo tanto, puedes **escapar** **montando** el disco del host.

{% tabs %}
{% tab title="Dentro del contenedor por defecto" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="Dentro del Contenedor Privilegiado" %}
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

### Sistemas de archivos del kernel de solo lectura

Los sistemas de archivos del kernel proporcionan un mecanismo para que un proceso modifique el comportamiento del kernel. Sin embargo, cuando se trata de procesos de contenedor, queremos evitar que realicen cambios en el kernel. Por lo tanto, montamos los sistemas de archivos del kernel como **solo lectura** dentro del contenedor, asegurando que los procesos del contenedor no puedan modificar el kernel.

{% tabs %}
{% tab title="Dentro del contenedor predeterminado" %}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="Dentro del Contenedor Privilegiado" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{% endtab %}
{% endtabs %}

### Enmascaramiento sobre sistemas de archivos del kernel

El sistema de archivos **/proc** es selectivamente escribible, pero por razones de seguridad, ciertas partes están protegidas del acceso de escritura y lectura al superponerlas con **tmpfs**, asegurando que los procesos del contenedor no puedan acceder a áreas sensibles.

{% hint style="info" %}
**tmpfs** es un sistema de archivos que almacena todos los archivos en memoria virtual. tmpfs no crea ningún archivo en tu disco duro. Así que si desmontas un sistema de archivos tmpfs, todos los archivos que residen en él se pierden para siempre.
{% endhint %}

{% tabs %}
{% tab title="Dentro del contenedor predeterminado" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="Dentro del Contenedor Privilegiado" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{% endtab %}
{% endtabs %}

### Capacidades de Linux

Los motores de contenedores lanzan los contenedores con un **número limitado de capacidades** para controlar lo que sucede dentro del contenedor por defecto. Los **privilegiados** tienen **todas** las **capacidades** accesibles. Para aprender sobre capacidades, lee:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="Dentro del contenedor por defecto" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="Dentro del Contenedor Privilegiado" %}
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

Puedes manipular las capacidades disponibles para un contenedor sin ejecutar en modo `--privileged` utilizando las banderas `--cap-add` y `--cap-drop`.

### Seccomp

**Seccomp** es útil para **limitar** las **syscalls** que un contenedor puede llamar. Un perfil de seccomp predeterminado está habilitado por defecto al ejecutar contenedores de docker, pero en modo privilegiado está deshabilitado. Aprende más sobre Seccomp aquí:

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

{% tab title="Dentro del Contenedor Privilegiado" %}
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
También, ten en cuenta que cuando Docker (u otros CRIs) se utilizan en un **Kubernetes** cluster, el **filtro seccomp está deshabilitado por defecto**.

### AppArmor

**AppArmor** es una mejora del kernel para confinar **contenedores** a un conjunto **limitado** de **recursos** con **perfiles por programa**. Cuando ejecutas con la bandera `--privileged`, esta protección está deshabilitada.

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Ejecutar un contenedor con la bandera `--privileged` desactiva las **etiquetas de SELinux**, haciendo que herede la etiqueta del motor de contenedores, típicamente `unconfined`, otorgando acceso completo similar al del motor de contenedores. En modo sin root, utiliza `container_runtime_t`, mientras que en modo root, se aplica `spc_t`.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Lo Que No Afecta

### Espacios de Nombres

Los espacios de nombres **NO se ven afectados** por la bandera `--privileged`. A pesar de que no tienen las restricciones de seguridad habilitadas, **no ven todos los procesos en el sistema o la red del host, por ejemplo**. Los usuarios pueden deshabilitar espacios de nombres individuales utilizando las banderas de motores de contenedor **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{% tabs %}
{% tab title="Dentro del contenedor privilegiado por defecto" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="Contenedor Inside --pid=host" %}
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

### Espacio de nombres de usuario

**Por defecto, los motores de contenedores no utilizan espacios de nombres de usuario, excepto para contenedores sin privilegios**, que los requieren para el montaje del sistema de archivos y el uso de múltiples UIDs. Los espacios de nombres de usuario, integrales para contenedores sin privilegios, no se pueden desactivar y mejoran significativamente la seguridad al restringir privilegios.

## Referencias

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
