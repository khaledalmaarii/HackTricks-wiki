# 网络命名空间

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 基本信息

网络命名空间是 Linux 内核的一个功能，它提供了网络栈的隔离，允许**每个网络命名空间拥有独立的网络配置**、接口、IP 地址、路由表和防火墙规则。这种隔离在各种场景中非常有用，比如容器化，其中每个容器应该有自己的网络配置，独立于其他容器和主机系统。

### 工作原理：

1. 创建新的网络命名空间时，它会以**完全隔离的网络栈**开始，除了回环接口（lo）之外，**没有网络接口**。这意味着运行在新网络命名空间中的进程默认情况下无法与其他命名空间或主机系统中的进程通信。
2. 可以创建和在网络命名空间之间移动**虚拟网络接口**，如 veth 对。这允许在命名空间之间或命名空间与主机系统之间建立网络连接。例如，veth 对的一端可以放置在容器的网络命名空间中，另一端可以连接到主机命名空间中的**桥接器**或另一个网络接口，为容器提供网络连接。
3. 命名空间内的网络接口可以拥有它们自己的**IP 地址、路由表和防火墙规则**，独立于其他命名空间。这允许不同网络命名空间中的进程具有不同的网络配置，并且可以像在不同的网络系统上运行一样操作。
4. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或者使用带有 `CLONE_NEWNET` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到新的命名空间或创建新的命名空间时，它将开始使用与该命名空间关联的网络配置和接口。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
通过使用`--mount-proc`参数挂载一个新的`/proc`文件系统，您可以确保新的挂载命名空间具有与该命名空间特定的进程信息的准确且隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果您在不使用`-f`的情况下运行上一行代码，您将会得到该错误。\
该错误是由于新的命名空间中的PID 1进程退出引起的。

在bash开始运行后，bash会fork出几个新的子进程来执行一些操作。如果您在unshare命令中没有使用`-f`，bash的PID将与当前的"unshare"进程相同。当前的"unshare"进程调用unshare系统调用，创建一个新的PID命名空间，但当前的"unshare"进程不在新的PID命名空间中。这是Linux内核的预期行为：进程A创建一个新的命名空间，进程A本身不会被放入新的命名空间中，只有进程A的子进程会被放入新的命名空间中。因此，当您运行：
```
unshare -p /bin/bash
```
unshare -f will fork a new process and execute /bin/bash in the new namespace. This way, the new process becomes PID 1 of the new namespace and the original process can exit without causing any issues.
```
unshare -fp /bin/bash
```
如果你使用`-f`选项运行`unshare`命令，`unshare`将在创建新的pid命名空间后fork一个新进程。然后在新进程中运行`/bin/bash`。新进程将成为新pid命名空间的pid 1。然后bash将fork几个子进程来执行一些任务。由于bash本身是新pid命名空间的pid 1，它的子进程可以正常退出。

摘自[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;检查进程所在的命名空间

To check which namespace your process is in, you can use the following command:

要检查进程所在的命名空间，可以使用以下命令：

```bash
ls -l /proc/<PID>/ns/net
```

Replace `<PID>` with the process ID of the desired process. This command will display the symbolic link to the network namespace of the process.

将 `<PID>` 替换为所需进程的进程 ID。该命令将显示进程的网络命名空间的符号链接。
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### 查找所有网络命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### 进入网络命名空间

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
此外，只有**root用户**才能**进入另一个进程的命名空间**。而且，**没有指向其他命名空间的描述符**（如`/proc/self/ns/net`），你**无法进入**其他命名空间。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
