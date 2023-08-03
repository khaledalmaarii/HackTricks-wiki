# CGroup 命名空间

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家 **网络安全公司** 工作吗？你想在 HackTricks 中看到你的 **公司广告** 吗？或者你想获得 **PEASS 的最新版本或下载 HackTricks 的 PDF 版本** 吗？请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者在 **Twitter** 上 **关注** 我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 基本信息

CGroup 命名空间是 Linux 内核的一个功能，为在命名空间内运行的进程提供 **cgroup 层次结构的隔离**。Cgroups（控制组）是一种内核功能，允许将进程组织成分层组，以管理和强制执行对系统资源（如 CPU、内存和 I/O）的 **限制**。

虽然 CGroup 命名空间不像我们之前讨论的其他命名空间类型（PID、mount、network 等）那样是一个单独的命名空间类型，但它们与命名空间隔离的概念相关。**CGroup 命名空间虚拟化了 cgroup 层次结构的视图**，因此在 CGroup 命名空间中运行的进程与在主机或其他命名空间中运行的进程相比，对层次结构的视图是不同的。

### 工作原理：

1. 创建新的 CGroup 命名空间时，**它以基于创建进程的 cgroup 的 cgroup 层次结构视图开始**。这意味着在新的 CGroup 命名空间中运行的进程只能看到整个 cgroup 层次结构的子集，限于创建进程的 cgroup 的子树。
2. CGroup 命名空间内的进程将 **将自己的 cgroup 视为层次结构的根**。这意味着从命名空间内部进程的角度来看，它们自己的 cgroup 看起来是根，它们无法看到或访问自己子树之外的 cgroup。
3. CGroup 命名空间不直接提供资源隔离；**它们只提供 cgroup 层次结构视图的隔离**。**资源控制和隔离仍由 cgroup 子系统**（如 cpu、memory 等）**强制执行**。

有关 CGroups 的更多信息，请查看：

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
通过使用`--mount-proc`参数挂载一个新的`/proc`文件系统，您可以确保新的挂载命名空间具有与该命名空间特定的进程信息的准确且隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果您在没有使用`-f`的情况下运行上一行代码，您将会得到该错误。\
该错误是由于新的命名空间中的PID 1进程退出引起的。

在bash开始运行后，bash会fork出几个新的子进程来执行一些操作。如果您在没有使用`-f`的情况下运行unshare命令，bash的PID将与当前的"unshare"进程相同。当前的"unshare"进程调用unshare系统调用，创建一个新的PID命名空间，但当前的"unshare"进程不在新的PID命名空间中。这是Linux内核的预期行为：进程A创建一个新的命名空间，进程A本身不会被放入新的命名空间中，只有进程A的子进程会被放入新的命名空间中。因此，当您运行：
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
cat /proc/$PID/ns/* | grep cgroup
```

Replace `$PID` with the process ID of the target process. This command will display the cgroup namespace of the process.

将`$PID`替换为目标进程的进程ID。该命令将显示进程的cgroup命名空间。
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
{% code %}

### 进入 CGroup 命名空间

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
此外，只有**root用户**才能**进入另一个进程的命名空间**。而且，**没有指向其他命名空间的描述符**（例如`/proc/self/ns/cgroup`），你**无法进入**其他命名空间。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
