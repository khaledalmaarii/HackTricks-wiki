# CGroup 命名空间

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

cgroup 命名空间是 Linux 内核功能，为运行在命名空间内的进程提供 **cgroup 层级结构的隔离**。cgroup，即 **控制组**，是一种内核功能，允许将进程组织成层次化的组，以管理和执行 **系统资源的限制**，如 CPU、内存和 I/O。

虽然 cgroup 命名空间不是我们之前讨论的其他类型的独立命名空间（如 PID、挂载、网络等），但它们与命名空间隔离的概念相关。**cgroup 命名空间虚拟化了 cgroup 层级结构的视图**，因此在 cgroup 命名空间中运行的进程与在主机或其他命名空间中运行的进程相比，有一个不同的层级结构视图。

### 它是如何工作的：

1. 当创建一个新的 cgroup 命名空间时，**它以创建进程的 cgroup 为基础开始显示 cgroup 层级结构的视图**。这意味着在新的 cgroup 命名空间中运行的进程只能看到整个 cgroup 层级结构的一个子集，限于创建进程的 cgroup 的子树根。
2. 在 cgroup 命名空间内的进程将**看到它们自己的 cgroup 作为层级结构的根**。这意味着，从命名空间内部进程的角度来看，它们自己的 cgroup 显示为根，它们无法看到或访问它们自己子树之外的 cgroup。
3. cgroup 命名空间不直接提供资源隔离；**它们只提供 cgroup 层级结构视图的隔离**。**资源控制和隔离仍然由 cgroup** 子系统（例如 cpu、内存等）本身执行。

有关 CGroups 的更多信息，请查看：

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
通过挂载一个新的 `/proc` 文件系统实例，如果你使用参数 `--mount-proc`，你可以确保新的挂载命名空间有一个**准确且独立的特定于该命名空间的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果你在没有 `-f` 的情况下运行前面的命令，你会遇到这个错误。\
这个错误是由于 PID 1 进程在新命名空间中退出所导致的。

在 bash 开始运行后，bash 将分叉出几个新的子进程来做一些事情。如果你在没有 `-f` 的情况下运行 unshare，bash 将会和当前的 "unshare" 进程有相同的 pid。当前的 "unshare" 进程调用 unshare 系统调用，创建一个新的 pid 命名空间，但是当前的 "unshare" 进程并不在新的 pid 命名空间中。这是 linux 内核的预期行为：进程 A 创建一个新的命名空间，进程 A 本身不会被放入新的命名空间，只有进程 A 的子进程会被放入新的命名空间。所以当你运行：
```
unshare -p /bin/bash
```
unshare 进程将执行 /bin/bash，而 /bin/bash 会分叉出几个子进程，bash 的第一个子进程将成为新命名空间的 PID 1，并且子进程在完成其任务后将退出。因此，新命名空间的 PID 1 退出。

PID 1 进程具有特殊功能：它应该成为所有孤儿进程的父进程。如果根命名空间中的 PID 1 进程退出，内核将会出现 panic。如果子命名空间中的 PID 1 进程退出，linux 内核将调用 disable\_pid\_allocation 函数，该函数将清除该命名空间中的 PIDNS\_HASH\_ADDING 标志。当 linux 内核创建一个新进程时，内核将调用 alloc\_pid 函数在一个命名空间中分配一个 PID，如果没有设置 PIDNS\_HASH\_ADDING 标志，alloc\_pid 函数将返回一个 -ENOMEM 错误。这就是你得到 "Cannot allocate memory" 错误的原因。

你可以通过使用 '-f' 选项来解决这个问题：
```
unshare -fp /bin/bash
```
如果你使用 `-f` 选项运行 unshare，unshare 将在创建新的 pid 命名空间后分叉一个新进程。并在新进程中运行 /bin/bash。新进程将成为新 pid 命名空间的 pid 1。然后 bash 也将分叉几个子进程来完成一些工作。由于 bash 本身是新 pid 命名空间的 pid 1，它的子进程可以在没有任何问题的情况下退出。

从 [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory) 复制

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程在哪个命名空间中
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
{% endcode %}

### 进入 CGroup 命名空间
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
```markdown
另外，您只能**以 root 身份才能进入另一个进程的命名空间**。而且您**不能** **进入**其他命名空间**如果没有指向它的描述符**（如 `/proc/self/ns/cgroup`）。

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
```
