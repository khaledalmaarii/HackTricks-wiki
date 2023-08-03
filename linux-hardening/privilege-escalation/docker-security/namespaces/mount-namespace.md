# 挂载命名空间

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 基本信息

挂载命名空间是 Linux 内核的一个功能，它提供了一组进程所见的文件系统挂载点的隔离。每个挂载命名空间都有自己的文件系统挂载点，而**对一个命名空间中挂载点的更改不会影响其他命名空间**。这意味着在不同挂载命名空间中运行的进程可以对文件系统层次结构有不同的视图。

挂载命名空间在容器化中特别有用，每个容器应该有自己的文件系统和配置，与其他容器和主机系统隔离开来。

### 工作原理：

1. 创建新的挂载命名空间时，它会使用**父命名空间的挂载点的副本进行初始化**。这意味着，在创建时，新的命名空间与其父命名空间共享相同的文件系统视图。然而，命名空间内的挂载点的任何后续更改都不会影响父命名空间或其他命名空间。
2. 当进程在其命名空间内修改挂载点，例如挂载或卸载文件系统时，**更改仅在该命名空间内生效**，不会影响其他命名空间。这使得每个命名空间都可以拥有自己独立的文件系统层次结构。
3. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或者使用带有 `CLONE_NEWNS` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到新的命名空间或创建新的命名空间时，它将开始使用与该命名空间关联的挂载点。
4. **文件描述符和 inode 在命名空间之间共享**，这意味着如果一个命名空间中的进程有一个指向文件的打开文件描述符，它可以将该文件描述符传递给另一个命名空间中的进程，**两个进程都可以访问同一个文件**。然而，由于挂载点的差异，两个命名空间中的文件路径可能不相同。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
通过使用`--mount-proc`参数挂载一个新的`/proc`文件系统，您可以确保新的挂载命名空间具有与该命名空间特定的进程信息的准确且隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果您在没有使用`-f`的情况下运行上一行代码，您将会得到该错误。\
该错误是由于新的命名空间中的PID 1进程退出引起的。

在bash开始运行后，bash会fork出几个新的子进程来执行一些操作。如果您在unshare命令中没有使用`-f`，bash的PID将与当前的"unshare"进程相同。当前的"unshare"进程调用unshare系统调用，创建一个新的PID命名空间，但当前的"unshare"进程不在新的PID命名空间中。这是Linux内核的预期行为：进程A创建一个新的命名空间，进程A本身不会被放入新的命名空间中，只有进程A的子进程会被放入新的命名空间中。因此，当您运行：
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
ls -l /proc/<PID>/ns/
```

Replace `<PID>` with the process ID of the target process. This command will list the namespaces associated with the process.

将 `<PID>` 替换为目标进程的进程ID。该命令将列出与该进程关联的命名空间。
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### 查找所有挂载命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### 进入一个 Mount 命名空间

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
此外，只有当您是root用户时，才能进入另一个进程的命名空间。而且，如果没有指向其他命名空间的描述符（例如`/proc/self/ns/mnt`），则无法进入其他命名空间。

由于新的挂载点只能在命名空间内访问，因此命名空间可能包含只能从其中访问的敏感信息。

### 挂载某个内容
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者你想要**获取最新版本的 PEASS 或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
