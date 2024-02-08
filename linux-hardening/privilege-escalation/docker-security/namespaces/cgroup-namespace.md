# CGroup Namespace

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

CGroup命名空间是Linux内核的一个功能，为在命名空间内运行的进程提供**对cgroup层次结构的隔离**。Cgroups，即**控制组**，是一个内核功能，允许将进程组织成分层组，以管理和强制执行对系统资源（如CPU、内存和I/O）的**限制**。

虽然CGroup命名空间不像我们之前讨论的其他命名空间类型（PID、挂载、网络等）那样是一个单独的命名空间类型，但它与命名空间隔离的概念相关。**CGroup命名空间虚拟化了cgroup层次结构的视图**，因此在CGroup命名空间中运行的进程与在主机或其他命名空间中运行的进程对层次结构的视图不同。

### 工作原理：

1. 创建新的CGroup命名空间时，**它从基于创建进程的cgroup的cgroup层次结构视图开始**。这意味着在新的CGroup命名空间中运行的进程只会看到整个cgroup层次结构的子集，限于创建进程cgroup根目录下的cgroup子树。
2. 在CGroup命名空间中的进程将**将自己的cgroup视为层次结构的根**。这意味着从命名空间内部进程的角度来看，他们自己的cgroup会显示为根目录，他们无法看到或访问自己子树之外的cgroup。
3. CGroup命名空间不直接提供资源隔离；**它们仅提供cgroup层次结构视图的隔离**。**资源控制和隔离仍由cgroup**子系统（例如cpu、内存等）本身执行。

有关CGroups的更多信息，请查看：

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
通过挂载一个新的 `/proc` 文件系统实例，如果使用参数 `--mount-proc`，可以确保新的挂载命名空间对该命名空间特定的进程信息具有准确和隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当执行 `unshare` 时没有使用 `-f` 选项时，会遇到错误，这是由于 Linux 处理新 PID（进程 ID）命名空间的方式。以下是关键细节和解决方案：

1. **问题解释**：
- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，发起新 PID 命名空间创建的进程（称为“unshare”进程）不会进入新的命名空间；只有它的子进程会。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程位于原始 PID 命名空间中。
- 在新命名空间中，`/bin/bash` 的第一个子进程变为 PID 1。当此进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 具有接管孤立进程的特殊角色。Linux 内核随后会在该命名空间中禁用 PID 分配。

2. **后果**：
- 在新命名空间中，PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清除。这导致在创建新进程时，`alloc_pid` 函数无法分配新的 PID，从而产生“无法分配内存”错误。

3. **解决方案**：
- 可以通过在 `unshare` 中使用 `-f` 选项来解决此问题。此选项使 `unshare` 在创建新 PID 命名空间后分叉出一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身成为新命名空间中的 PID 1。然后，`/bin/bash` 及其子进程安全地包含在这个新命名空间中，防止 PID 1 的过早退出，并允许正常的 PID 分配。

通过确保 `unshare` 使用 `-f` 标志运行，可以正确维护新的 PID 命名空间，使 `/bin/bash` 及其子进程能够在不遇到内存分配错误的情况下运行。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查您的进程位于哪个命名空间
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### 查找所有CGroup命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入 CGroup 命名空间

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
此外，**只有root用户才能进入另一个进程命名空间**。而且，**没有指向其他命名空间的描述符**（比如`/proc/self/ns/cgroup`），**无法进入**其他命名空间。

## 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
