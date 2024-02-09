# Docker --privileged

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者您想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>

## 影响

当您将容器以特权模式运行时，您将禁用以下保护措施：

### 挂载/dev

在特权容器中，所有**设备都可以在`/dev/`中访问**。 因此，您可以通过**挂载**主机的磁盘来**逃逸**。

{% tabs %}
{% tab title="默认容器内部" %}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{% endtab %}

{% tab title="特权容器内部" %}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
### 只读内核文件系统

内核文件系统提供了一个机制，允许进程修改内核的行为。然而，对于容器进程，我们希望阻止它们对内核进行任何更改。因此，我们在容器内将内核文件系统挂载为**只读**，确保容器进程无法修改内核。
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{% endtab %}

{% tab title="特权容器内部" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
### 遮蔽内核文件系统

**/proc** 文件系统是可选择性可写的，但为了安全起见，某些部分被用 **tmpfs** 遮蔽，确保容器进程无法访问敏感区域。

{% hint style="info" %}
**tmpfs** 是一个将所有文件存储在虚拟内存中的文件系统。tmpfs 不会在硬盘上创建任何文件。因此，如果卸载 tmpfs 文件系统，其中存储的所有文件将永远丢失。
{% endhint %}

{% tabs %}
{% tab title="默认容器内部" %}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{% endtab %}

{% tab title="特权容器内部" %}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
### Linux capabilities

容器引擎默认以**有限数量的功能**启动容器，以控制容器内部的操作。**特权容器**具有**所有**可访问的**功能**。要了解有关功能的信息，请阅读：

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="默认容器内部" %}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{% endtab %}

{% tab title="特权容器内部" %}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
### 特权提升

您可以通过使用`--cap-add`和`--cap-drop`标志来操纵容器中可用的功能，而无需在`--privileged`模式下运行。

### Seccomp

**Seccomp** 对于限制容器可以调用的**syscalls**非常有用。在运行docker容器时，默认情况下启用了默认的seccomp配置文件，但在特权模式下会被禁用。在这里了解更多关于Seccomp的信息：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{% endtab %}

{% tab title="特权容器内部" %}
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
此外，请注意，当Docker（或其他CRIs）在Kubernetes集群中使用时，默认情况下会禁用seccomp过滤器。

### AppArmor

**AppArmor**是一个内核增强功能，用于将容器限制在一组有限的资源上，并使用每个程序的配置文件。当您使用`--privileged`标志运行时，此保护将被禁用。

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

使用 `--privileged` 标志运行容器会禁用 **SELinux 标签**，导致容器继承容器引擎的标签，通常为 `unconfined`，从而获得类似容器引擎的完全访问权限。在非 root 模式下，使用 `container_runtime_t`，而在 root 模式下，则应用 `spc_t`。

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## 不受影响的内容

### 命名空间

命名空间**不受**`--privileged`标志的影响。尽管它们没有启用安全约束，**例如，它们不会看到系统上的所有进程或主机网络**。用户可以通过使用**`--pid=host`、`--net=host`、`--ipc=host`、`--uts=host`**容器引擎标志来禁用单个命名空间。

{% tabs %}
{% tab title="在默认特权容器内部" %}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{% endtab %}

{% tab title="在 --pid=host 容器内部" %}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
### 用户命名空间

**默认情况下，容器引擎不使用用户命名空间，除非是用于无根容器**，后者需要它们来进行文件系统挂载和使用多个UID。用户命名空间对于无根容器至关重要，无法禁用，并通过限制特权显著增强安全性。

## 参考

* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
