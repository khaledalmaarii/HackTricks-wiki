# IPC Namespace

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

- 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

IPC（进程间通信）命名空间是Linux内核的一个功能，提供对System V IPC对象（如消息队列、共享内存段和信号量）的**隔离**。这种隔离确保**不同IPC命名空间中的进程不能直接访问或修改彼此的IPC对象**，为进程组之间提供了额外的安全性和隐私层。

### 工作原理：

1. 创建新IPC命名空间时，它将以一个**完全隔离的System V IPC对象集合**开始。这意味着运行在新IPC命名空间中的进程默认情况下无法访问或干扰其他命名空间或主机系统中的IPC对象。
2. 在命名空间内创建的IPC对象仅对该命名空间内的进程**可见和可访问**。每个IPC对象在其命名空间内由唯一键标识。尽管在不同命名空间中键可能相同，但对象本身是隔离的，无法跨命名空间访问。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWIPC`标志的`unshare()`或`clone()`系统调用创建新命名空间。当进程移动到新命名空间或创建新命名空间时，它将开始使用与该命名空间关联的IPC对象。

## 实验：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
通过挂载一个新的 `/proc` 文件系统实例，如果使用参数 `--mount-proc`，可以确保新的挂载命名空间对该命名空间特定的进程信息具有准确和隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当执行 `unshare` 时没有使用 `-f` 选项时，会出现错误，这是由于 Linux 处理新 PID（进程 ID）命名空间的方式。以下是关键细节和解决方案：

1. **问题解释**：
- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，发起新 PID 命名空间创建的进程（称为“unshare”进程）不会进入新的命名空间；只有它的子进程会。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程位于原始 PID 命名空间中。
- 在新命名空间中，`/bin/bash` 的第一个子进程变为 PID 1。当此进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 具有接管孤立进程的特殊角色。Linux 内核随后会禁用该命名空间中的 PID 分配。

2. **后果**：
- 在新命名空间中，PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清除。这会导致在创建新进程时 `alloc_pid` 函数无法分配新的 PID，从而产生“无法分配内存”错误。

3. **解决方案**：
- 可以通过在 `unshare` 中使用 `-f` 选项来解决此问题。此选项使 `unshare` 在创建新 PID 命名空间后分叉出一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身成为新命名空间中的 PID 1。然后，`/bin/bash` 及其子进程安全地包含在这个新命名空间中，防止 PID 1 的过早退出，并允许正常的 PID 分配。

通过确保 `unshare` 使用 `-f` 标志运行，可以正确维护新的 PID 命名空间，使 `/bin/bash` 及其子进程能够正常运行，避免遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查您的进程位于哪个命名空间
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
此外，只有**作为root用户**才能**进入另一个进程命名空间**。而且，**没有指向它的描述符**（如`/proc/self/ns/net`），**无法进入**其他命名空间。

### 创建IPC对象
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
## 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
