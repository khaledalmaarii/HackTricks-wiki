# CGroups

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

**Linux控制组**，也称为cgroups，是Linux内核的一个功能，允许您对一组进程的**系统资源进行限制**、监管和优先级排序。Cgroups提供了一种管理和隔离系统中一组进程的资源使用（CPU、内存、磁盘I/O、网络等）的方法。这对于许多目的都很有用，例如限制特定进程组可用的资源、将某些类型的工作负载与其他工作负载隔离开来，或者在不同进程组之间优先使用系统资源。

有**两个版本的cgroups**，即版本1和版本2，目前都在使用中，并且可以同时在系统上进行配置。cgroups版本1和版本2之间最**重要的区别**是后者引入了一种新的层次化组织方式，其中组可以以**树状结构**的形式进行排列，具有父子关系。这使得在不同进程组之间更加灵活和细粒度地控制资源分配成为可能。

除了新的层次化组织外，cgroups版本2还引入了**其他几个变化和改进**，例如支持**新的资源控制器**、更好地支持传统应用程序和改进的性能。

总体而言，cgroups**版本2提供了更多功能和更好的性能**，但在某些情况下，仍可能使用版本1，特别是在与旧系统的兼容性有关的情况下。

您可以通过查看/proc/\<pid>目录中的cgroup文件来列出任何进程的v1和v2 cgroups。您可以使用以下命令查看您的shell的cgroups：
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
如果您的系统上的输出**显著较短**，请不要惊慌；这只是意味着您可能**只有cgroups v2**。这里的每一行输出都以一个数字开头，表示不同的cgroup。以下是一些关于如何阅读它的指示：

* **数字2-12是用于cgroups v1**。其控制器在数字旁边列出。
* **数字1**也是用于**版本1**，但它没有控制器。这个cgroup仅用于**管理目的**（在这种情况下，systemd进行了配置）。
* 最后一行，**数字0**，用于**cgroups v2**。这里看不到任何控制器。在没有cgroups v1的系统上，这将是唯一的输出行。
* **名称是分层的，看起来像文件路径的一部分**。您可以在此示例中看到，一些cgroup的名称为/user.slice，而其他的为/user.slice/user-1000.slice/session-2.scope。
* 创建名称为/testcgroup的目的是为了显示在cgroups v1中，进程的cgroups可以完全独立。
* **在user.slice下的名称**中包含session的是登录会话，由systemd分配。当您查看shell的cgroups时，您会看到它们。您的**系统服务**的**cgroups**将位于**system.slice下**。

### 查看cgroups

通常通过**文件系统**访问cgroups。这与传统的Unix系统调用接口相反，后者用于与内核交互。\
要探索shell的cgroup设置，您可以查看`/proc/self/cgroup`文件以找到shell的cgroup，然后导航到`/sys/fs/cgroup`（或`/sys/fs/cgroup/unified`）目录，并查找与cgroup同名的**目录**。切换到此目录并查看周围的内容将允许您查看cgroup的各种**设置和资源使用信息**。

<figure><img src="../../../.gitbook/assets/image (10) (2).png" alt=""><figcaption></figcaption></figure>

在这里可能有许多文件，**主要的cgroup接口文件以`cgroup`开头**。首先查看`cgroup.procs`（使用cat命令即可），其中列出了cgroup中的进程。类似的文件`cgroup.threads`也包括线程。

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

大多数用于shell的cgroup都有这两个控制器，它们可以控制**使用的内存量**和**cgroup中的进程总数**。要与控制器交互，请查找与控制器前缀匹配的**文件**。例如，如果您想查看cgroup中运行的线程数，请查看pids.current：

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

**max的值表示此cgroup没有特定的限制**，但由于cgroups是分层的，可能会有一个子目录链中的cgroup对其进行限制。

### 操纵和创建cgroups

要将进程放入cgroup中，**将其PID作为root写入其`cgroup.procs`文件中：**
```shell-session
# echo pid > cgroup.procs
```
这是cgroups的工作方式。例如，如果您想要**限制cgroup的最大PID数量**（比如说，限制为3,000个PID），请按照以下步骤进行操作：
```shell-session
# echo 3000 > pids.max
```
**创建cgroups更加棘手**。从技术上讲，它就像在cgroup树的某个地方创建一个子目录一样简单；当你这样做时，内核会自动创建接口文件。如果一个cgroup没有进程，即使接口文件存在，你也可以使用rmdir删除该cgroup。可能会让你困惑的是关于cgroups的规则，包括：

* **只能将进程放在外层（“叶子”）cgroup中**。例如，如果你有名为/my-cgroup和/my-cgroup/my-subgroup的cgroups，你不能将进程放在/my-cgroup中，但可以放在/my-cgroup/my-subgroup中。（一个例外是如果cgroups没有控制器，但我们不深入讨论。）
* 一个cgroup**不能有不在其父cgroup中的控制器**。
* 你必须**显式地为子cgroup指定控制器**。你可以通过`cgroup.subtree_control`文件来实现这一点；例如，如果你想让一个子cgroup具有cpu和pids控制器，可以将+cpu +pids写入该文件。

这些规则的一个例外是在层次结构底部找到的**根cgroup**。你可以**将进程放在这个cgroup中**。你可能想这样做的一个原因是将一个进程从systemd的控制中分离出来。

即使没有启用任何控制器，你也可以通过查看其cpu.stat文件来查看cgroup的CPU使用情况：

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

因为这是cgroup整个生命周期内累积的CPU使用情况，所以你可以看到一个服务如何消耗处理器时间，即使它生成许多最终终止的子进程。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
