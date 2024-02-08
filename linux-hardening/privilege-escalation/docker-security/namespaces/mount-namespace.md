# 挂载命名空间

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

挂载命名空间是Linux内核的一个功能，提供了一组进程看到的文件系统挂载点的隔离。每个挂载命名空间都有自己的文件系统挂载点集，**一个命名空间中对挂载点的更改不会影响其他命名空间**。这意味着在不同挂载命名空间中运行的进程可以对文件系统层次结构有不同的视图。

挂载命名空间在容器化中特别有用，每个容器应该有自己的文件系统和配置，与其他容器和主机系统隔离开来。

### 工作原理：

1. 创建新的挂载命名空间时，它会使用**父命名空间的挂载点的副本进行初始化**。这意味着在创建时，新命名空间与其父命名空间共享相同的文件系统视图。但是，命名空间内的挂载点的任何后续更改都不会影响父命名空间或其他命名空间。
2. 当进程修改其命名空间内的挂载点，例如挂载或卸载文件系统时，**更改仅限于该命名空间**，不会影响其他命名空间。这允许每个命名空间拥有自己独立的文件系统层次结构。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWNS`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个新的命名空间时，它将开始使用与该命名空间关联的挂载点。
4. **文件描述符和inode在命名空间之间共享**，这意味着如果一个命名空间中的进程有指向文件的打开文件描述符，它可以将该文件描述符**传递给另一个命名空间中的进程**，**两个进程将访问同一个文件**。但是，由于挂载点的差异，两个命名空间中文件的路径可能不相同。

## 实验：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
通过使用参数`--mount-proc`挂载`/proc`文件系统的新实例，确保新的挂载命名空间具有**准确且独立的进程信息视图，特定于该命名空间**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当执行`unshare`时没有使用`-f`选项时，会遇到错误，这是由于Linux处理新PID（进程ID）命名空间的方式。以下是关键细节和解决方案：

1. **问题解释**：
- Linux内核允许进程使用`unshare`系统调用创建新的命名空间。然而，发起新PID命名空间创建的进程（称为“unshare”进程）不会进入新的命名空间；只有它的子进程会。
- 运行`%unshare -p /bin/bash%`会在与`unshare`相同的进程中启动`/bin/bash`。因此，`/bin/bash`及其子进程位于原始PID命名空间中。
- 在新命名空间中，`/bin/bash`的第一个子进程变为PID 1。当此进程退出时，如果没有其他进程，它会触发命名空间的清理，因为PID 1具有接管孤立进程的特殊角色。然后Linux内核将在该命名空间中禁用PID分配。

2. **后果**：
- 在新命名空间中，PID 1的退出导致`PIDNS_HASH_ADDING`标志的清除。这导致`alloc_pid`函数在创建新进程时无法分配新的PID，从而产生“无法分配内存”错误。

3. **解决方案**：
- 可以通过在`unshare`中使用`-f`选项来解决此问题。此选项使`unshare`在创建新PID命名空间后fork一个新进程。
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身成为新命名空间中的PID 1。然后，`/bin/bash`及其子进程安全地包含在此新命名空间中，防止PID 1过早退出，并允许正常的PID分配。

通过确保`unshare`使用`-f`标志运行，新的PID命名空间将得到正确维护，使`/bin/bash`及其子进程能够正常运行，而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查您的进程位于哪个命名空间
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
{% endcode %}

### 进入挂载命名空间
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
此外，只有**root用户**才能**进入另一个进程命名空间**。而且，**没有指向它的描述符**（如`/proc/self/ns/mnt`），你**无法**进入其他命名空间。

由于新挂载点只能在命名空间内访问，因此可能存在包含只能从中访问的敏感信息的命名空间。

### 挂载某物
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
## 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。 

</details>
