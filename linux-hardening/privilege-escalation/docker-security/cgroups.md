# CGroups

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

**Linux控制组**，或**cgroups**，是Linux内核的一个功能，允许在进程组之间分配、限制和优先处理系统资源，如CPU、内存和磁盘I/O。它们提供了一种机制，用于**管理和隔离进程集合的资源使用**，有助于资源限制、工作负载隔离以及在不同进程组之间进行资源优先处理。

**cgroups有两个版本**：版本1和版本2。两者可以同时在系统上使用。主要区别在于**cgroups版本2**引入了一个**分层、类似树状结构**，使得在进程组之间能够进行更细致和详细的资源分配。此外，版本2带来了各种增强功能，包括：

除了新的分层组织外，cgroups版本2还引入了**其他几项更改和改进**，如支持**新的资源控制器**、更好地支持传统应用程序和提高性能。

总体而言，**cgroups版本2提供了更多功能和更好的性能**，但在某些情况下仍可以使用版本1，特别是在需要与旧系统兼容时。

您可以通过查看进程的cgroup文件在/proc/\<pid>中列出任何进程的v1和v2 cgroups。您可以通过以下命令查看您的shell的cgroups开始。
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
```markdown
输出结构如下：

* **数字2-12**：cgroups v1，每行代表不同的cgroup。这些cgroup的控制器与数字相邻。
* **数字1**：也是cgroups v1，但仅用于管理目的（例如由systemd设置），不包含控制器。
* **数字0**：代表cgroups v2。未列出控制器，并且此行仅在仅运行cgroups v2的系统上出现。
* **名称是分层的**，类似文件路径，表示不同cgroups之间的结构和关系。
* **像/user.slice或/system.slice**这样的名称指定了cgroups的分类，其中user.slice通常用于systemd管理的登录会话，而system.slice用于系统服务。

### 查看cgroups

通常使用文件系统来访问**cgroups**，与传统用于内核交互的Unix系统调用接口不同。要调查shell的cgroup配置，应检查**/proc/self/cgroup**文件，其中显示了shell的cgroup。然后，通过导航到**/sys/fs/cgroup**（或**`/sys/fs/cgroup/unified`**）目录并找到与cgroup名称相同的目录，可以观察与cgroup相关的各种设置和资源使用信息。

![Cgroup文件系统](<../../../.gitbook/assets/image (1128).png>)

用于cgroups的关键接口文件以**cgroup**为前缀。可以使用诸如cat之类的标准命令查看的**cgroup.procs**文件列出了cgroup中的进程。另一个文件**cgroup.threads**包含线程信息。

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

管理shell的cgroups通常包括两个控制器，用于调节内存使用和进程计数。要与控制器交互，应查阅带有控制器前缀的文件。例如，**pids.current**将被引用以确定cgroup中线程的计数。

![Cgroup Memory](<../../../.gitbook/assets/image (677).png>)

数值中的**max**表示cgroup没有特定限制。但是，由于cgroups的分层性质，限制可能由目录层次结构中较低级别的cgroup强加。

### 操作和创建cgroups

通过**将其进程ID（PID）写入`cgroup.procs`文件**，将进程分配给cgroups。这需要root权限。例如，要添加一个进程：
```
```bash
echo [pid] > cgroup.procs
```
同样，**修改 cgroup 属性，比如设置 PID 限制**，是通过将期望的值写入相关文件来完成的。要为 cgroup 设置最大 3,000 个 PID：
```bash
echo 3000 > pids.max
```
**创建新的 cgroups** 包括在 cgroup 层次结构中创建一个新的子目录，这会促使内核自动生成必要的接口文件。尽管可以使用 `rmdir` 删除没有活动进程的 cgroups，请注意一些限制：

- **进程只能放置在叶子 cgroups 中**（即，在层次结构中最嵌套的 cgroups）。
- **一个 cgroup 不能拥有其父级中不存在的控制器**。
- **子 cgroups 的控制器必须在 `cgroup.subtree_control` 文件中显式声明**。例如，要在子 cgroup 中启用 CPU 和 PID 控制器：
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**根 cgroup** 是这些规则的一个例外，允许直接进程放置。这可以用来将进程从 systemd 管理中移除。

在 cgroup 中**监视 CPU 使用情况**是可能的，通过 `cpu.stat` 文件显示总 CPU 时间消耗，有助于跟踪服务的子进程的使用情况：

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>在 cpu.stat 文件中显示的 CPU 使用统计信息</p></figcaption></figure>

## 参考资料

* **书籍：《How Linux Works, 第3版：每个超级用户都应该了解的内容》作者 Brian Ward**
