# IPC 命名空间

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告** 吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF 版本** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 基本信息

IPC（进程间通信）命名空间是 Linux 内核的一个功能，它提供了对 System V IPC 对象（如消息队列、共享内存段和信号量）的**隔离**。这种隔离确保了运行在**不同 IPC 命名空间中的进程不能直接访问或修改彼此的 IPC 对象**，为进程组之间提供了额外的安全性和隐私保护。

### 工作原理：

1. 创建新的 IPC 命名空间时，它会以一个**完全隔离的 System V IPC 对象集合**开始。这意味着运行在新 IPC 命名空间中的进程默认情况下无法访问或干扰其他命名空间或主机系统中的 IPC 对象。
2. 在命名空间内创建的 IPC 对象只对该命名空间内的进程**可见且可访问**。每个 IPC 对象在其命名空间内由唯一的键标识。尽管在不同的命名空间中可能存在相同的键，但这些对象本身是隔离的，无法跨命名空间访问。
3. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或者使用带有 `CLONE_NEWIPC` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到新的命名空间或创建新的命名空间时，它将开始使用与该命名空间关联的 IPC 对象。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
通过挂载一个新的`/proc`文件系统，如果使用`--mount-proc`参数，您可以确保新的挂载命名空间具有与该命名空间特定的进程信息的准确和隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果您在没有使用`-f`的情况下运行上一行命令，您将会得到该错误。\
该错误是由于新的命名空间中的PID 1进程退出引起的。

在bash开始运行后，bash会fork出几个新的子进程来执行一些操作。如果您在unshare命令中没有使用`-f`，bash的PID将与当前的"unshare"进程相同。当前的"unshare"进程调用unshare系统调用，创建一个新的PID命名空间，但当前的"unshare"进程不在新的PID命名空间中。这是Linux内核的预期行为：进程A创建一个新的命名空间，进程A本身不会被放入新的命名空间中，只有进程A的子进程会被放入新的命名空间中。因此，当您运行：
```
unshare -p /bin/bash
```
unshare -f will fork a new process and make it the PID 1 of the new namespace. This way, the PID 1 process will not exit and the "Cannot allocate memory" error will be avoided.
```
unshare -fp /bin/bash
```
如果你使用`-f`选项运行`unshare`命令，`unshare`将在创建新的pid命名空间后fork一个新进程。然后在新进程中运行`/bin/bash`。新进程将成为新pid命名空间的pid 1。然后bash将fork几个子进程来执行一些任务。由于bash本身是新pid命名空间的pid 1，它的子进程可以正常退出。

从[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)复制

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查进程所在的命名空间

To check which namespace your process is in, you can use the following command:

要检查进程所在的命名空间，可以使用以下命令：

```bash
ls -l /proc/<PID>/ns/ipc
```

Replace `<PID>` with the process ID of the target process. This command will display the inode number of the IPC namespace associated with the process.

将 `<PID>` 替换为目标进程的进程ID。该命令将显示与进程关联的IPC命名空间的inode号码。

### &#x20;View all IPC namespaces

### &#x20;查看所有IPC命名空间

To view all IPC namespaces on the system, you can use the following command:

要查看系统上的所有IPC命名空间，可以使用以下命令：

```bash
ls -l /proc/*/ns/ipc
```

This command will display the inode numbers of all IPC namespaces present on the system.

该命令将显示系统上所有IPC命名空间的inode号码。

### &#x20;Switch to a different IPC namespace

### &#x20;切换到不同的IPC命名空间

To switch to a different IPC namespace, you can use the following command:

要切换到不同的IPC命名空间，可以使用以下命令：

```bash
nsenter -t <PID> -i
```

Replace `<PID>` with the process ID of the target process. This command will enter the IPC namespace of the specified process.

将 `<PID>` 替换为目标进程的进程ID。该命令将进入指定进程的IPC命名空间。

### &#x20;Summary

### &#x20;总结

In this section, we learned how to check which namespace a process is in, view all IPC namespaces on the system, and switch to a different IPC namespace. Understanding and manipulating namespaces can be useful for privilege escalation and container breakout techniques.

在本节中，我们学习了如何检查进程所在的命名空间，查看系统上的所有IPC命名空间以及切换到不同的IPC命名空间。了解和操作命名空间对于特权升级和容器逃逸技术非常有用。
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
{% code %}

### 进入 IPC 命名空间内部

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
此外，只有当您是root用户时，才能进入另一个进程的命名空间。而且，如果没有指向其他命名空间的描述符（例如`/proc/self/ns/net`），则无法进入其他命名空间。

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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
