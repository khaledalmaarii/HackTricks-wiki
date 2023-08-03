# 用户命名空间

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF 版本**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## 基本信息

用户命名空间是 Linux 内核的一个功能，**提供用户和组 ID 映射的隔离**，允许每个用户命名空间拥有自己的**用户和组 ID 集合**。这种隔离使得在不同用户命名空间中运行的进程可以**具有不同的特权和所有权**，即使它们在数值上共享相同的用户和组 ID。

用户命名空间在容器化中特别有用，每个容器应该有自己独立的用户和组 ID 集合，以实现容器与主机系统之间更好的安全性和隔离性。

### 工作原理：

1. 创建新的用户命名空间时，它**从一个空的用户和组 ID 映射集合开始**。这意味着在新的用户命名空间中运行的任何进程**最初都没有超出命名空间的特权**。
2. 可以在新命名空间和父（或主机）命名空间之间建立 ID 映射。这**允许新命名空间中的进程具有与父命名空间中的用户和组 ID 对应的特权和所有权**。然而，ID 映射可以限制在特定范围和 ID 子集之间，从而对在新命名空间中的进程授予的特权进行细粒度控制。
3. 在用户命名空间内，**进程可以拥有完全的根特权（UID 0），用于命名空间内的操作**，同时在命名空间外部具有有限的特权。这允许**容器在其自己的命名空间中以类似根用户的能力运行，而不在主机系统上具有完全的根特权**。
4. 进程可以使用 `setns()` 系统调用在命名空间之间移动，或者使用带有 `CLONE_NEWUSER` 标志的 `unshare()` 或 `clone()` 系统调用创建新的命名空间。当进程移动到新的命名空间或创建新的命名空间时，它将开始使用与该命名空间关联的用户和组 ID 映射。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
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
unshare -f will fork a new process before exec /bin/bash, so the new process becomes PID 1 of the new namespace. This way, even if the subprocess exits, the PID 1 process will still be alive, preventing the "Cannot allocate memory" error.
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
要使用用户命名空间，Docker守护程序需要使用**`--userns-remap=default`**启动（在Ubuntu 14.04中，可以通过修改`/etc/default/docker`文件，然后执行`sudo service docker restart`来实现）

### &#x20;检查进程所在的命名空间
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
可以使用以下命令在Docker容器中检查用户映射：
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
或者从主机上使用：
```bash
cat /proc/<pid>/uid_map
```
### 查找所有用户命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### 进入用户命名空间

{% endcode %}
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
此外，只有当你是root用户时，你才能进入另一个进程的命名空间。而且，如果没有指向其他命名空间的描述符（如`/proc/self/ns/user`），你将无法进入其他命名空间。

### 创建新的用户命名空间（带映射）

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### 恢复特权

在用户命名空间的情况下，**当创建一个新的用户命名空间时，进入该命名空间的进程将在该命名空间内被授予一整套特权**。这些特权允许进程执行特权操作，如**挂载文件系统**、创建设备或更改文件的所有权，但**仅限于其用户命名空间的上下文**。

例如，当您在用户命名空间中拥有`CAP_SYS_ADMIN`特权时，您可以执行通常需要此特权的操作，如挂载文件系统，但仅限于您的用户命名空间的上下文。您使用此特权执行的任何操作都不会影响主机系统或其他命名空间。

{% hint style="warning" %}
因此，即使在新的用户命名空间中获得一个新进程**将使您恢复所有的特权**（CapEff: 000001ffffffffff），您实际上只能**使用与命名空间相关的特权**（例如挂载），而不是所有特权。因此，仅凭这一点是不足以逃离 Docker 容器的。
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
