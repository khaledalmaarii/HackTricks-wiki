# UTS Namespace

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

- 如果您想看到您的**公司在HackTricks中被广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

UTS（UNIX Time-Sharing System）命名空间是Linux内核的一个功能，提供了两个系统标识符的**隔离**：**主机名**和**NIS**（网络信息服务）域名。这种隔离允许每个UTS命名空间具有其**独立的主机名和NIS域名**，在容器化场景中特别有用，其中每个容器应该看起来像一个具有自己主机名的独立系统。

### 工作原理：

1. 创建新的UTS命名空间时，它会从其父命名空间**复制主机名和NIS域名**。这意味着，在创建时，新命名空间**与其父命名空间共享相同的标识符**。但是，在命名空间内对主机名或NIS域名进行的任何后续更改都不会影响其他命名空间。
2. 在UTS命名空间内，进程可以使用`sethostname()`和`setdomainname()`系统调用**更改主机名和NIS域名**。这些更改仅在命名空间内部有效，不会影响其他命名空间或主机系统。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWUTS`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间关联的主机名和NIS域名。

## 实验：

### 创建不同的命名空间

#### 命令行
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
通过使用参数`--mount-proc`挂载`/proc`文件系统的新实例，确保新的挂载命名空间具有**准确且独立的进程信息视图，特定于该命名空间**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当执行`unshare`时没有使用`-f`选项时，会遇到错误，这是由于Linux处理新PID（进程ID）命名空间的方式。以下是关键细节和解决方案：

1. **问题解释**：
- Linux内核允许进程使用`unshare`系统调用创建新的命名空间。然而，发起新PID命名空间创建的进程（称为“unshare”进程）不会进入新的命名空间；只有它的子进程会。
- 运行`%unshare -p /bin/bash%`会在与`unshare`相同的进程中启动`/bin/bash`。因此，`/bin/bash`及其子进程位于原始PID命名空间中。
- 在新命名空间中，`/bin/bash`的第一个子进程变为PID 1。当此进程退出时，如果没有其他进程，它会触发命名空间的清理，因为PID 1具有接管孤立进程的特殊角色。Linux内核随后会在该命名空间中禁用PID分配。

2. **后果**：
- 在新命名空间中，PID 1的退出导致`PIDNS_HASH_ADDING`标志的清除。这会导致`alloc_pid`函数在创建新进程时无法分配新的PID，从而产生“无法分配内存”错误。

3. **解决方案**：
- 可以通过在`unshare`中使用`-f`选项来解决此问题。此选项使`unshare`在创建新PID命名空间后fork一个新进程。
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身成为新命名空间中的PID 1。然后，`/bin/bash`及其子进程安全地包含在此新命名空间中，防止PID 1过早退出，并允许正常的PID分配。

通过确保`unshare`使用`-f`标志运行，新的PID命名空间得以正确维护，使`/bin/bash`及其子进程能够正常运行，避免遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查您的进程位于哪个命名空间
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### 查找所有 UTS 命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### 进入 UTS 命名空间
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
此外，只有**root用户**才能**进入另一个进程命名空间**。而且，**没有指向它的描述符**（如`/proc/self/ns/uts`），你**无法**进入其他命名空间。

### 更改主机名
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。 

</details>
