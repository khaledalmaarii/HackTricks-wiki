# PID 命名空间

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告**吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或 **关注**我在 **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 基本信息

PID（进程标识符）命名空间是 Linux 内核中的一个功能，通过为一组进程提供自己独立的一组唯一 PID，与其他命名空间中的 PID 分开，实现进程隔离。这在容器化中特别有用，其中进程隔离对于安全和资源管理至关重要。

当创建一个新的 PID 命名空间时，该命名空间中的第一个进程被分配为 PID 1。该进程成为新命名空间的 "init" 进程，并负责管理命名空间内的其他进程。在该命名空间内创建的每个后续进程都将在该命名空间内具有唯一的 PID，这些 PID 与其他命名空间中的 PID 是独立的。

从 PID 命名空间内的进程的角度来看，它只能看到同一命名空间内的其他进程。它不知道其他命名空间中的进程，并且不能使用传统的进程管理工具（如 `kill`、`wait` 等）与它们进行交互。这提供了一定程度的隔离，有助于防止进程相互干扰。

### 工作原理：

1. 当创建一个新进程（例如使用 `clone()` 系统调用）时，该进程可以分配给一个新的或现有的 PID 命名空间。**如果创建了一个新的命名空间，该进程将成为该命名空间的 "init" 进程**。
2. **内核**维护着新命名空间中的 PID 与父命名空间（即创建新命名空间的命名空间）中相应 PID 之间的映射。**这个映射允许内核在必要时转换 PID**，例如在不同命名空间中的进程之间发送信号时。
3. **PID 命名空间内的进程只能看到和与同一命名空间内的其他进程进行交互**。它们不知道其他命名空间中的进程，并且它们的 PID 在其命名空间内是唯一的。
4. 当销毁一个 **PID 命名空间**（例如当命名空间的 "init" 进程退出时），**该命名空间内的所有进程都将被终止**。这确保了与命名空间相关的所有资源都被正确清理。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果你在没有使用`-f`的情况下运行上一行命令，你将会得到这个错误。\
这个错误是由于新的命名空间中的PID 1进程退出引起的。

在bash开始运行后，它会fork出几个新的子进程来执行一些操作。如果你在没有使用`-f`的情况下运行unshare命令，bash的PID将与当前的"unshare"进程相同。当前的"unshare"进程调用unshare系统调用，创建一个新的PID命名空间，但当前的"unshare"进程并不在新的PID命名空间中。这是Linux内核的预期行为：进程A创建一个新的命名空间，进程A本身不会被放入新的命名空间中，只有进程A的子进程会被放入新的命名空间中。所以当你运行：
```
unshare -p /bin/bash
```
unshare进程将执行/bin/bash，并且/bin/bash会fork出几个子进程，bash的第一个子进程将成为新命名空间的PID 1，并在完成任务后退出。因此，新命名空间的PID 1退出。

PID 1进程有一个特殊的功能：它应该成为所有孤儿进程的父进程。如果根命名空间中的PID 1进程退出，内核将会崩溃。如果子命名空间中的PID 1进程退出，Linux内核将调用disable\_pid\_allocation函数，该函数将清除该命名空间中的PIDNS\_HASH\_ADDING标志。当Linux内核创建一个新进程时，内核将调用alloc\_pid函数在命名空间中分配一个PID，如果PIDNS\_HASH\_ADDING标志未设置，alloc\_pid函数将返回-ENOMEM错误。这就是为什么会出现"Cannot allocate memory"错误的原因。

您可以通过使用'-f'选项来解决此问题：
```
unshare -fp /bin/bash
```
如果你使用`-f`选项运行unshare命令，unshare将在创建新的pid命名空间后fork一个新进程。并在新进程中运行`/bin/bash`。新进程将成为新pid命名空间的pid 1。然后bash将fork几个子进程来执行一些任务。由于bash本身是新pid命名空间的pid 1，它的子进程可以正常退出。

从[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)复制

</details>

通过挂载一个新的`/proc`文件系统实例，如果你使用`--mount-proc`参数，你可以确保新的挂载命名空间具有对该命名空间特定的进程信息的准确和隔离的视图。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查进程所在的命名空间

To check which namespace your process is in, you can use the following command:

要检查进程所在的命名空间，可以使用以下命令：

```bash
ls -l /proc/<PID>/ns
```

Replace `<PID>` with the process ID of the process you want to check.

将 `<PID>` 替换为要检查的进程的进程ID。

This command will list the namespaces associated with the process. The output will include files representing different namespaces such as `pid`, `net`, `ipc`, `uts`, and `mnt`. Each file will have a unique inode number if the process is in that particular namespace.

该命令将列出与进程关联的命名空间。输出将包括表示不同命名空间的文件，如 `pid`、`net`、`ipc`、`uts` 和 `mnt`。如果进程在特定的命名空间中，每个文件都将具有唯一的inode号。

For example, if you want to check the namespaces of a process with PID 1234, you would run:

例如，如果要检查PID为1234的进程的命名空间，可以运行以下命令：

```bash
ls -l /proc/1234/ns
```

This will display the namespaces associated with the process.
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

请注意，初始（默认）PID命名空间的root用户可以查看所有进程，即使是在新的PID命名空间中的进程，这就是为什么我们可以看到所有的PID命名空间。

### 进入PID命名空间内部
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
当您从默认命名空间进入PID命名空间时，您仍然可以看到所有进程。而PID命名空间中的进程将能够看到PID命名空间上的新bash。

此外，您只能在作为root用户的情况下进入另一个进程的PID命名空间。而且，如果没有指向其他命名空间的描述符（例如`/proc/self/ns/pid`），则无法进入其他命名空间。
