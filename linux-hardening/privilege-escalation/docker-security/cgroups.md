# CGroups

<details>

<summary><strong>从零到英雄学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

**Linux控制组**，也称为cgroups，是Linux内核的一个特性，允许您为一组进程**限制**、管理和优先级分配**系统资源**。Cgroups提供了一种方法来**管理和隔离**系统中一组进程的资源使用情况（CPU、内存、磁盘I/O、网络等）。这对于许多目的都很有用，例如限制特定进程组可用的资源，将某些类型的工作负载与其他工作负载隔离开来，或在不同进程组之间优先使用系统资源。

目前有**两个版本的cgroups**，1和2，它们都在使用中，并且可以在系统上同时配置。cgroups版本1和**版本2**之间最**显著的区别**是后者引入了cgroups的新的层次结构组织，其中组可以在具有父子关系的**树状结构**中排列。这允许对不同进程组之间资源分配进行更灵活和细致的控制。

除了新的层次结构组织，cgroups版本2还引入了**其他一些变化和改进**，例如对**新资源控制器**的支持，对传统应用程序的更好支持，以及性能的提高。

总体而言，cgroups **版本2提供的功能更多，性能更好**，但在需要与旧系统兼容的场景中，可能仍会使用版本1。

您可以通过查看/proc/\<pid>中的cgroup文件来列出任何进程的v1和v2 cgroups。您可以通过以下命令开始查看您的shell的cgroups：
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
如果您的系统上的**输出明显较短**，不要惊慌；这只意味着您可能只有**cgroups v2**。这里的每一行输出都以一个数字开头，代表一个不同的cgroup。以下是一些阅读它的指南：

* **数字2-12是针对cgroups v1的**。这些的**控制器**列在数字旁边。
* **数字1**也是针对**版本1**的，但它没有控制器。这个cgroup仅用于**管理目的**（在这种情况下，systemd配置了它）。
* 最后一行，**数字0**，是针对**cgroups v2**的。这里没有可见的控制器。在没有cgroups v1的系统上，这将是唯一的输出行。
* **名称是层次化的，看起来像文件路径的一部分**。您可以在此示例中看到，一些cgroup被命名为/user.slice，其他的则是/user.slice/user-1000.slice/session-2.scope。
* /testcgroup的名称是为了显示在cgroups v1中，进程的cgroups可以完全独立。
* **user.slice下的名称**包括session是登录会话，由systemd分配。当您查看shell的cgroups时，会看到它们。您的**系统服务的cgroups**将位于**system.slice下**。

### 查看cgroups

Cgroups通常**通过文件系统访问**。这与传统的Unix系统调用接口与内核交互形成对比。\
要探索shell的cgroup设置，您可以查看`/proc/self/cgroup`文件以找到shell的cgroup，然后导航到`/sys/fs/cgroup`（或`/sys/fs/cgroup/unified`）目录，并查找**与cgroup同名的目录**。切换到这个目录并四处查看，将允许您看到cgroup的各种**设置和资源使用信息**。

<figure><img src="../../../.gitbook/assets/image (10) (2) (2).png" alt=""><figcaption></figcaption></figure>

在这里可以有许多文件，**主要的cgroup接口文件以`cgroup`开头**。首先查看`cgroup.procs`（使用cat就可以），它列出了cgroup中的进程。一个类似的文件，`cgroup.threads`，还包括线程。

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

大多数用于shell的cgroups都有这两个控制器，它们可以控制**使用的内存量**和**cgroup中的进程总数**。要与控制器交互，请查找与控制器前缀匹配的**文件**。例如，如果您想查看cgroup中运行的线程数，请参阅pids.current：

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

**max值意味着这个cgroup没有特定的限制**，但由于cgroups是层次化的，子目录链下面的cgroup可能会限制它。

### 操作和创建cgroups

要将进程放入cgroup，**以root身份将其PID写入其`cgroup.procs`文件：**
```shell-session
# echo pid > cgroup.procs
```
```markdown
这就是对 cgroups 进行更改的方式。例如，如果您想要**限制 cgroup 的最大 PID 数量**（比如说，3,000 个 PIDs），请按照以下步骤操作：
```
```shell-session
# echo 3000 > pids.max
```
**创建 cgroups 较为复杂**。技术上来说，它和在 cgroup 树中的某处创建一个子目录一样简单；当你这样做时，内核会自动创建接口文件。如果一个 cgroup 没有进程，即使接口文件存在，你也可以使用 rmdir 删除 cgroup。可能会让你困惑的是管理 cgroups 的规则，包括：

* 你只能将**进程放在最外层（“叶子”）cgroups 中**。例如，如果你有名为 /my-cgroup 和 /my-cgroup/my-subgroup 的 cgroups，你不能将进程放在 /my-cgroup 中，但是 /my-cgroup/my-subgroup 是可以的。（例外情况是如果 cgroups 没有控制器，但我们不进一步探讨。）
* 一个 cgroup **不能有其父 cgroup 中不存在的控制器**。
* 你必须为子 cgroups 明确**指定控制器**。你可以通过 `cgroup.subtree_control` 文件来做到这一点；例如，如果你想让一个子 cgroup 拥有 cpu 和 pids 控制器，将 +cpu +pids 写入此文件。

这些规则的一个例外是位于层级结构底部的**根 cgroup**。你可以**将进程放在这个 cgroup 中**。你可能想这样做的一个原因是为了将进程从 systemd 的控制中分离出来。

即使没有启用控制器，你也可以通过查看其 cpu.stat 文件来了解 cgroup 的 CPU 使用情况：

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

因为这是 cgroup 整个生命周期内累积的 CPU 使用情况，即使它生成了许多最终终止的子进程，你也可以看到一个服务消耗处理器时间的情况。

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks 中看到你的公司广告** 或者 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享你的黑客技巧。**

</details>
