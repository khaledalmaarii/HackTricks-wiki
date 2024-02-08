# PID Namespace

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

PID（进程标识符）命名空间是Linux内核中的一个功能，通过为一组进程提供自己独特的PID集合，使这些进程能够与其他命名空间中的PID分离，从而实现进程隔离。这在容器化中特别有用，因为进程隔离对于安全和资源管理至关重要。

创建新的PID命名空间时，该命名空间中的第一个进程被分配为PID 1。该进程成为新命名空间的“init”进程，并负责管理命名空间内的其他进程。在该命名空间内创建的每个后续进程将在该命名空间内具有唯一的PID，这些PID将独立于其他命名空间中的PID。

从PID命名空间内的进程的角度来看，它只能看到同一命名空间中的其他进程。它不知道其他命名空间中的进程，也无法使用传统的进程管理工具（例如`kill`、`wait`等）与其进行交互。这提供了一定程度的隔离，有助于防止进程相互干扰。

### 工作原理：

1. 当创建新进程（例如通过使用`clone()`系统调用）时，可以将该进程分配给新的或现有的PID命名空间。**如果创建了新的命名空间，该进程将成为该命名空间的“init”进程**。
2. **内核**维护着新命名空间中PID与父命名空间（即创建新命名空间的命名空间）中相应PID之间的**映射**。这种映射**允许内核在必要时转换PID**，例如在不同命名空间中的进程之间发送信号时。
3. **PID命名空间内的进程只能看到并与同一命名空间中的其他进程交互**。它们不知道其他命名空间中的进程，它们的PID在其命名空间内是唯一的。
4. 当**销毁PID命名空间**（例如当命名空间的“init”进程退出时），**该命名空间内的所有进程都将被终止**。这确保了与命名空间相关的所有资源都得到适当清理。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当使用`unshare`命令而没有使用`-f`选项时，由于Linux处理新PID（进程ID）命名空间的方式，会遇到错误。以下是关键细节和解决方案：

1. **问题解释**：
- Linux内核允许进程使用`unshare`系统调用创建新的命名空间。然而，发起新PID命名空间创建的进程（称为“unshare”进程）不会进入新的命名空间；只有它的子进程会进入。
- 运行`%unshare -p /bin/bash%`会在与`unshare`相同的进程中启动`/bin/bash`。因此，`/bin/bash`及其子进程位于原始PID命名空间中。
- 在新命名空间中，`/bin/bash`的第一个子进程成为PID 1。当此进程退出时，如果没有其他进程，它会触发命名空间的清理，因为PID 1具有接管孤立进程的特殊角色。Linux内核随后会在该命名空间中禁用PID分配。

2. **后果**：
- 在新命名空间中，PID 1的退出导致`PIDNS_HASH_ADDING`标志被清除。这导致`alloc_pid`函数在创建新进程时无法分配新的PID，从而产生“无法分配内存”错误。

3. **解决方案**：
- 可以通过在`unshare`命令中使用`-f`选项来解决此问题。此选项使`unshare`在创建新PID命名空间后fork一个新进程。
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身成为新命名空间中的PID 1。然后，`/bin/bash`及其子进程安全地包含在这个新命名空间中，防止PID 1过早退出并允许正常的PID分配。

通过确保`unshare`使用`-f`标志运行，新PID命名空间将得到正确维护，从而使`/bin/bash`及其子进程能够正常运行，避免遇到内存分配错误。

</details>

通过使用参数`--mount-proc`挂载`/proc`文件系统的新实例，确保新的挂载命名空间具有**准确且独立的进程信息视图，特定于该命名空间**。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查您的进程位于哪个命名空间
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### 查找所有PID命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

请注意，来自初始（默认）PID命名空间的root用户可以查看所有进程，甚至是在新PID命名空间中的进程，这就是为什么我们可以看到所有PID命名空间。

### 进入PID命名空间内部
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
当您从默认命名空间进入PID命名空间时，您仍然可以看到所有进程。来自该PID命名空间的进程将能够看到PID命名空间上的新bash。

此外，只有**root用户**才能**进入另一个进程的PID命名空间**。您**无法**在没有指向其的描述符的情况下**进入**其他命名空间（例如`/proc/self/ns/pid`）

## 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**上**关注我。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
