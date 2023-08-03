# UTS命名空间

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 基本信息

UTS（UNIX Time-Sharing System）命名空间是Linux内核的一个功能，它提供了对两个系统标识符的**隔离**：**主机名**和**NIS**（网络信息服务）域名。这种隔离允许每个UTS命名空间具有其**独立的主机名和NIS域名**，这在容器化场景中特别有用，其中每个容器应该显示为具有自己主机名的独立系统。

### 工作原理：

1. 当创建一个新的UTS命名空间时，它会从其父命名空间中**复制主机名和NIS域名**。这意味着，在创建时，新的命名空间**与其父命名空间共享相同的标识符**。然而，命名空间内主机名或NIS域名的任何后续更改都不会影响其他命名空间。
2. UTS命名空间内的进程可以使用`sethostname()`和`setdomainname()`系统调用**更改主机名和NIS域名**。这些更改仅对命名空间本身有效，不会影响其他命名空间或主机系统。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWUTS`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建新的命名空间时，它将开始使用与该命名空间关联的主机名和NIS域名。

## 实验室：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
通过挂载一个新的`/proc`文件系统，如果使用`--mount-proc`参数，你可以确保新的挂载命名空间具有**准确且隔离的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果你在不加`-f`的情况下运行上一行命令，你将会得到这个错误。\
这个错误是由于新的命名空间中的PID 1进程退出引起的。

在bash开始运行后，bash会fork出几个新的子进程来执行一些操作。如果你在unshare命令中没有加上`-f`，bash的PID将与当前的"unshare"进程相同。当前的"unshare"进程调用unshare系统调用，创建一个新的PID命名空间，但当前的"unshare"进程不在新的PID命名空间中。这是Linux内核的预期行为：进程A创建一个新的命名空间，进程A本身不会被放入新的命名空间中，只有进程A的子进程会被放入新的命名空间中。因此，当你运行：
```
unshare -p /bin/bash
```
unshare -f will fork a new process instead of exec /bin/bash, so the PID 1 of the new namespace will not exit. This way, the PID 1 process will continue to function as the parent process for orphan processes, preventing the kernel panic and the "Cannot allocate memory" error.
```
unshare -fp /bin/bash
```
如果你使用`-f`选项运行`unshare`命令，`unshare`将在创建新的pid命名空间后fork一个新进程。然后在新进程中运行`/bin/bash`。新进程将成为新pid命名空间的pid 1。然后bash将fork几个子进程来执行一些任务。由于bash本身是新pid命名空间的pid 1，它的子进程可以正常退出。

摘自[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

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

Replace `<PID>` with the process ID of the target process. This command will display the symbolic links to the different namespaces that the process is associated with.

将 `<PID>` 替换为目标进程的进程ID。该命令将显示与进程关联的不同命名空间的符号链接。

You can also use the `readlink` command to get the actual path of the symbolic link:

您还可以使用 `readlink` 命令获取符号链接的实际路径：

```bash
readlink /proc/<PID>/ns/<NAMESPACE>
```

Replace `<PID>` with the process ID and `<NAMESPACE>` with the desired namespace (e.g., `uts`, `ipc`, `net`, `pid`, `mnt`, `user`).

将 `<PID>` 替换为进程ID，将 `<NAMESPACE>` 替换为所需的命名空间（例如 `uts`、`ipc`、`net`、`pid`、`mnt`、`user`）。

By checking the namespaces, you can determine the isolation level of your process and identify any potential vulnerabilities or security risks.
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### 查找所有的UTS命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### 进入 UTS 命名空间内部

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
此外，只有在以root权限运行时，才能进入另一个进程的命名空间。而且，如果没有指向其他命名空间的描述符（例如`/proc/self/ns/uts`），则无法进入其他命名空间。

### 更改主机名
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
