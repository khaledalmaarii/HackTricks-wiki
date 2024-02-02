# IPC 命名空间

<details>

<summary><strong>从零开始学习 AWS 黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 基本信息

IPC（进程间通信）命名空间是 Linux 内核的一个特性，它提供了 System V IPC 对象（如消息队列、共享内存段和信号量）的**隔离**。这种隔离确保了**不同 IPC 命名空间中的进程无法直接访问或修改彼此的 IPC 对象**，在进程组之间提供了额外的安全性和隐私性。

### 工作原理：

1. 当创建一个新的 IPC 命名空间时，它会从一个**完全隔离的 System V IPC 对象集合**开始。这意味着在新的 IPC 命名空间中运行的进程默认无法访问或干扰其他命名空间或宿主系统中的 IPC 对象。
2. 在命名空间内创建的 IPC 对象只对该命名空间内的进程可见并且**可访问**。每个 IPC 对象在其命名空间内由一个唯一的键标识。尽管在不同的命名空间中键可能相同，但对象本身是隔离的，不能跨命名空间访问。
3. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或者使用带有 `CLONE_NEWIPC` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间关联的 IPC 对象。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
通过挂载一个新的 `/proc` 文件系统实例，如果你使用参数 `--mount-proc`，你可以确保新的挂载命名空间有一个**准确且独立的特定于该命名空间的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果你在没有 `-f` 的情况下运行前面的命令，你会遇到这个错误。\
这个错误是由于在新命名空间中 PID 1 进程退出引起的。

在 bash 开始运行后，bash 将分叉出几个新的子进程来做一些事情。如果你在没有 `-f` 的情况下运行 unshare，bash 将拥有与当前 "unshare" 进程相同的 pid。当前的 "unshare" 进程调用 unshare 系统调用，创建一个新的 pid 命名空间，但当前的 "unshare" 进程并不在新的 pid 命名空间中。这是 linux 内核的预期行为：进程 A 创建一个新的命名空间，进程 A 本身不会被放入新的命名空间，只有进程 A 的子进程会被放入新的命名空间。所以当你运行：
```
unshare -p /bin/bash
```
`unshare` 进程将执行 `/bin/bash`，而 `/bin/bash` 会分叉出几个子进程，bash 的第一个子进程将成为新命名空间的 PID 1，并且子进程在完成其任务后将退出。因此，新命名空间的 PID 1 退出。

PID 1 进程具有特殊功能：它应该成为所有孤儿进程的父进程。如果根命名空间中的 PID 1 进程退出，内核将会出现恐慌。如果子命名空间中的 PID 1 进程退出，Linux 内核将调用 `disable_pid_allocation` 函数，这将清除该命名空间中的 `PIDNS_HASH_ADDING` 标志。当 Linux 内核创建一个新进程时，内核将调用 `alloc_pid` 函数在命名空间中分配一个 PID，如果没有设置 `PIDNS_HASH_ADDING` 标志，`alloc_pid` 函数将返回一个 -ENOMEM 错误。这就是您收到“无法分配内存”错误的原因。

您可以通过使用 '-f' 选项来解决此问题：
```
unshare -fp /bin/bash
```
如果您使用 '-f' 选项运行 unshare，unshare 将在创建新的 pid 命名空间后分叉一个新进程。并在新进程中运行 /bin/bash。新进程将成为新 pid 命名空间的 pid 1。然后 bash 也会分叉几个子进程来完成一些工作。由于 bash 本身是新 pid 命名空间的 pid 1，其子进程可以无问题地退出。

摘自 [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程在哪个命名空间中
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### 查找所有IPC命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### 进入 IPC 命名空间
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
你只能**以 root 身份进入另一个进程的命名空间**。而且你**不能**在**没有指向它的描述符**的情况下**进入**其他命名空间（例如 `/proc/self/ns/net`）。

### 创建 IPC 对象
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
<details>

<summary><strong>从零到英雄学习AWS黑客技术，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
