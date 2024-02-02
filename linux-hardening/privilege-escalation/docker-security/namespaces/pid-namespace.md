# PID 命名空间

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

PID（进程标识符）命名空间是 Linux 内核中的一个特性，它通过允许一组进程拥有自己的唯一 PID 集，与其他命名空间中的 PID 分开，从而提供进程隔离。这在容器化中特别有用，其中进程隔离对于安全和资源管理至关重要。

当创建一个新的 PID 命名空间时，该命名空间中的第一个进程被分配 PID 1。这个进程成为新命名空间的 "init" 进程，并负责管理命名空间内的其他进程。命名空间内创建的每个后续进程都将在该命名空间内拥有一个唯一的 PID，这些 PID 将独立于其他命名空间中的 PID。

从 PID 命名空间内的进程的角度来看，它只能看到同一命名空间中的其他进程。它不知道其他命名空间中的进程，也不能使用传统的进程管理工具（例如，`kill`、`wait` 等）与它们交互。这提供了一定程度的隔离，有助于防止进程相互干扰。

### 工作原理：

1. 当创建一个新进程时（例如，使用 `clone()` 系统调用），可以将进程分配给一个新的或现有的 PID 命名空间。**如果创建了一个新的命名空间，该进程成为该命名空间的 "init" 进程**。
2. **内核** 维护一个 **新命名空间中的 PID 与父命名空间中相应 PID 的映射**（即，新命名空间是从哪个命名空间创建的）。这种映射 **允许内核在必要时转换 PID**，例如在不同命名空间中的进程之间发送信号时。
3. **PID 命名空间内的进程只能看到并与同一命名空间内的其他进程交互**。它们不知道其他命名空间中的进程，它们的 PID 在其命名空间内是唯一的。
4. 当 **PID 命名空间被销毁**（例如，当命名空间的 "init" 进程退出时），**该命名空间内的所有进程都将被终止**。这确保了与命名空间相关的所有资源都得到了妥善清理。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果您在没有 `-f` 的情况下运行前面的命令，您将会遇到这个错误。\
该错误是由于 PID 1 进程在新的命名空间中退出所导致的。

在 bash 开始运行后，bash 将会 fork 几个新的子进程来做一些事情。如果您在没有 `-f` 的情况下运行 unshare，bash 将会和当前的 "unshare" 进程拥有相同的 pid。当前的 "unshare" 进程调用 unshare 系统调用，创建一个新的 pid 命名空间，但是当前的 "unshare" 进程并不在新的 pid 命名空间中。这是 linux 内核的预期行为：进程 A 创建一个新的命名空间，进程 A 本身不会被放入新的命名空间，只有进程 A 的子进程会被放入新的命名空间。所以当您运行：

</details>
```
unshare -p /bin/bash
```
unshare 进程将执行 /bin/bash，而 /bin/bash 会分叉出几个子进程，bash 的第一个子进程将成为新命名空间的 PID 1，并且子进程在完成其任务后将退出。因此，新命名空间的 PID 1 退出。

PID 1 进程具有特殊功能：它应该成为所有孤儿进程的父进程。如果根命名空间中的 PID 1 进程退出，内核将会出现恐慌。如果子命名空间中的 PID 1 进程退出，linux 内核将调用 disable\_pid\_allocation 函数，该函数将清除该命名空间中的 PIDNS\_HASH\_ADDING 标志。当 linux 内核创建一个新进程时，内核将调用 alloc\_pid 函数在命名空间中分配一个 PID，如果没有设置 PIDNS\_HASH\_ADDING 标志，alloc\_pid 函数将返回一个 -ENOMEM 错误。这就是你得到 "Cannot allocate memory" 错误的原因。

你可以通过使用 '-f' 选项来解决这个问题：
```
unshare -fp /bin/bash
```
如果你使用 `-f` 选项运行 unshare，unshare 将在创建新的 pid 命名空间后分叉一个新进程。并在新进程中运行 /bin/bash。新进程将成为新 pid 命名空间的 pid 1。然后 bash 也将分叉几个子进程来完成一些工作。由于 bash 本身是新 pid 命名空间的 pid 1，它的子进程可以在没有任何问题的情况下退出。

摘自 [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

如果你使用参数 `--mount-proc` 挂载 `/proc` 文件系统的新实例，你确保新的挂载命名空间具有**针对该命名空间特定的进程信息的准确和隔离视图**。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程在哪个命名空间中
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### 查找所有 PID 命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

请注意，初始（默认）PID 命名空间中的 root 用户可以看到所有进程，即使是新的 PID 命名空间中的进程，这就是为什么我们可以看到所有 PID 命名空间。

### 进入一个 PID 命名空间
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
当您从默认命名空间进入 PID 命名空间时，您仍然能够看到所有进程。而且该 PID 命名空间中的进程将能够看到新的 bash 在 PID 命名空间上。

此外，您只能**以 root 身份进入另一个进程的 PID 命名空间**。而且您**不能** **进入**其他命名空间**没有指向它的描述符**（如 `/proc/self/ns/pid`）

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
