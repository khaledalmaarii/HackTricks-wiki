# CGroup 命名空间

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

cgroup 命名空间是 Linux 内核功能，为运行在命名空间内的进程提供 **cgroup 层级结构的隔离**。cgroup，即 **控制组** 的简称，是内核功能，允许将进程组织成层级结构的组，以管理和执行 **系统资源的限制**，如 CPU、内存和 I/O。

虽然 cgroup 命名空间不是我们之前讨论的其他类型的独立命名空间（如 PID、挂载、网络等），但它们与命名空间隔离概念相关。**cgroup 命名空间虚拟化了 cgroup 层级结构的视图**，因此在 cgroup 命名空间内运行的进程与在宿主或其他命名空间内运行的进程相比，有不同的层级结构视图。

### 它是如何工作的：

1. 当创建一个新的 cgroup 命名空间时，**它以基于创建进程的 cgroup 的 cgroup 层级结构视图开始**。这意味着在新的 cgroup 命名空间中运行的进程将只看到整个 cgroup 层级结构的一个子集，限于创建进程的 cgroup 的子树根。
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

当没有使用 `-f` 选项执行 `unshare` 时，会遇到错误，这是由于 Linux 处理新的 PID（进程 ID）命名空间的方式。关键细节和解决方案如下：

1. **问题解释**：
- Linux 内核允许一个进程使用 `unshare` 系统调用来创建新的命名空间。然而，启动创建新的 PID 命名空间的进程（称为 "unshare" 进程）并不进入新的命名空间；只有它的子进程会进入。
- 执行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程都在原始的 PID 命名空间中。
- `/bin/bash` 在新命名空间中的第一个子进程成为 PID 1。当这个进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 有收养孤儿进程的特殊角色。Linux 内核随后会在该命名空间中禁用 PID 分配。

2. **后果**：
- 在新命名空间中 PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清理。这导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，产生 "无法分配内存" 错误。

3. **解决方案**：
- 通过使用 `unshare` 的 `-f` 选项可以解决这个问题。这个选项使 `unshare` 在创建新的 PID 命名空间后 fork 一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。`/bin/bash` 及其子进程随后安全地包含在这个新命名空间内，防止了 PID 1 的过早退出，并允许正常的 PID 分配。

通过确保 `unshare` 带有 `-f` 标志运行，新的 PID 命名空间被正确维护，允许 `/bin/bash` 及其子进程在不遇到内存分配错误的情况下操作。

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
### 进入 CGroup 命名空间
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
您只能**以 root 身份进入另一个进程的命名空间**。而且您**不能** **进入** 其他没有描述符指向的命名空间（如 `/proc/self/ns/cgroup`）。

# 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF 版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
