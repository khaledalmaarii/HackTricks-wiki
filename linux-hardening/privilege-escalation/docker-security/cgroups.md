# CGroups

{% hint style="success" %}
学习并练习AWS Hacking：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 仓库提交 PR 来分享黑客技巧。**

</details>
{% endhint %}

## 基本信息

**Linux 控制组**，或称为 **cgroups**，是 Linux 内核的一个功能，允许在进程组之间分配、限制和优先处理系统资源，如 CPU、内存和磁盘 I/O。它们提供了一种机制，用于**管理和隔离进程集合的资源使用**，有助于资源限制、工作负载隔离以及在不同进程组之间进行资源优先处理。

**cgroups 有两个版本**：版本 1 和版本 2。两者可以同时在系统上使用。主要区别在于 **cgroups 版本 2** 引入了一个 **层次化、类似树状结构**，使得在进程组之间能够进行更精细和详细的资源分配。此外，版本 2 带来了各种增强功能，包括：

除了新的层次化组织外，cgroups 版本 2 还引入了**其他几项更改和改进**，如支持**新的资源控制器**、更好地支持传统应用程序和提高性能。

总体而言，cgroups **版本 2 提供了更多功能和更好的性能**，但在某些情况下仍可以使用版本 1，特别是在需要与旧系统兼容性的情况下。

您可以通过查看进程的 cgroup 文件在 /proc/\<pid> 中列出任何进程的 v1 和 v2 cgroups。您可以通过以下命令查看您的 shell 的 cgroups 开始：
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
### 查看 cgroups

文件系统通常用于访问 **cgroups**，与传统用于内核交互的 Unix 系统调用接口不同。要调查 shell 的 cgroup 配置，应检查 **/proc/self/cgroup** 文件，其中显示了 shell 的 cgroup。然后，通过导航到 **/sys/fs/cgroup**（或 **`/sys/fs/cgroup/unified`**）目录，并找到一个与 cgroup 名称相同的目录，可以观察与 cgroup 相关的各种设置和资源使用信息。

![Cgroup 文件系统](<../../../.gitbook/assets/image (1128).png>)

用于 cgroups 的关键接口文件以 **cgroup** 为前缀。**cgroup.procs** 文件可以使用像 cat 这样的标准命令查看，其中列出了 cgroup 中的进程。另一个文件 **cgroup.threads** 包含线程信息。

![Cgroup 进程](<../../../.gitbook/assets/image (281).png>)

管理 shell 的 cgroups 通常包括两个控制器，用于调节内存使用和进程计数。要与控制器交互，应查阅带有控制器前缀的文件。例如，**pids.current** 将被引用以确定 cgroup 中线程的计数。

![Cgroup 内存](<../../../.gitbook/assets/image (677).png>)

数值中的 **max** 表示 cgroup 没有特定限制。但是，由于 cgroups 的层次结构，限制可能由目录层次结构中较低级别的 cgroup 强加。

### 操纵和创建 cgroups

通过将其进程 ID（PID）写入 `cgroup.procs` 文件，将进程分配给 cgroups。这需要 root 权限。例如，要添加一个进程：
```bash
echo [pid] > cgroup.procs
```
同样，**修改 cgroup 属性，比如设置 PID 限制**，是通过将期望的值写入相关文件来完成的。要为 cgroup 设置最多 3,000 个 PID：
```bash
echo 3000 > pids.max
```
**创建新的 cgroups** 包括在 cgroup 层次结构中创建一个新的子目录，这会促使内核自动生成必要的接口文件。尽管可以使用 `rmdir` 删除没有活动进程的 cgroups，但要注意一些限制：

- **进程只能放置在叶子 cgroups 中**（即，在层次结构中最嵌套的 cgroups）。
- **一个 cgroup 不能拥有其父级中不存在的控制器**。
- **子 cgroups 的控制器必须在 `cgroup.subtree_control` 文件中显式声明**。例如，要在子 cgroup 中启用 CPU 和 PID 控制器：
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**根 cgroup** 是这些规则的一个例外，允许直接放置进程。这可以用来将进程从 systemd 管理中移除。

通过 `cpu.stat` 文件可以监视 cgroup 中的 CPU 使用情况，显示总 CPU 时间消耗，有助于跟踪服务的子进程的使用情况：

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>在 cpu.stat 文件中显示的 CPU 使用统计信息</p></figcaption></figure>

## 参考资料

* **书籍：《How Linux Works, 第3版：每个超级用户都应该了解的内容》作者 Brian Ward**
