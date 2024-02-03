# 挂载命名空间

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

挂载命名空间是Linux内核功能，它为一组进程看到的文件系统挂载点提供隔离。每个挂载命名空间都有自己的文件系统挂载点集合，**一个命名空间中的挂载点变化不会影响其他命名空间**。这意味着在不同挂载命名空间中运行的进程可以有不同的文件系统层次视图。

挂载命名空间在容器化中特别有用，其中每个容器都应该有自己的文件系统和配置，与其他容器和宿主系统隔离。

### 它是如何工作的：

1. 创建新的挂载命名空间时，它会用**其父命名空间的挂载点副本**进行初始化。这意味着，在创建时，新命名空间与其父命名空间共享相同的文件系统视图。然而，随后在命名空间内对挂载点的任何更改都不会影响父命名空间或其他命名空间。
2. 当进程在其命名空间内修改挂载点，例如挂载或卸载文件系统时，**更改仅限于该命名空间**，不会影响其他命名空间。这允许每个命名空间拥有自己独立的文件系统层次结构。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWNS`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间关联的挂载点。
4. **文件描述符和索引节点在命名空间之间共享**，这意味着如果一个命名空间中的进程打开了一个指向文件的文件描述符，它可以**传递该文件描述符**给另一个命名空间中的进程，**两个进程将访问同一个文件**。然而，由于挂载点的差异，文件的路径在两个命名空间中可能不同。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
通过挂载一个新的`/proc`文件系统实例，如果你使用参数`--mount-proc`，你确保新的挂载命名空间有一个**准确且独立的特定于该命名空间的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当`unshare`在没有`-f`选项的情况下执行时，会遇到错误，这是由于Linux处理新的PID（进程ID）命名空间的方式。关键细节和解决方案如下：

1. **问题解释**：
- Linux内核允许进程使用`unshare`系统调用创建新的命名空间。然而，启动创建新的PID命名空间的进程（称为"unshare"进程）不会进入新的命名空间；只有其子进程会进入。
- 运行`%unshare -p /bin/bash%`会在`unshare`相同的进程中启动`/bin/bash`。因此，`/bin/bash`及其子进程位于原始的PID命名空间中。
- `/bin/bash`在新命名空间中的第一个子进程成为PID 1。当这个进程退出时，如果没有其他进程，它会触发命名空间的清理，因为PID 1有收养孤儿进程的特殊角色。Linux内核将禁用该命名空间中的PID分配。

2. **后果**：
- 在新命名空间中PID 1的退出导致清除`PIDNS_HASH_ADDING`标志。这导致`alloc_pid`函数在创建新进程时无法分配新的PID，产生"无法分配内存"错误。

3. **解决方案**：
- 问题可以通过使用`unshare`的`-f`选项来解决。这个选项使`unshare`在创建新的PID命名空间后分叉一个新进程。
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身在新命名空间中成为PID 1。`/bin/bash`及其子进程随后安全地包含在这个新命名空间内，防止PID 1的过早退出并允许正常的PID分配。

通过确保`unshare`运行时带有`-f`标志，新的PID命名空间被正确维护，允许`/bin/bash`及其子进程在不遇到内存分配错误的情况下操作。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程在哪个命名空间中
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
也可以只有在你是**root**时才能**进入另一个进程的命名空间**。而且你**不能**在**没有指向它的描述符**的情况下**进入**其他命名空间（比如`/proc/self/ns/mnt`）。

因为新的挂载只能在其命名空间内访问，所以有可能一个命名空间包含了只能从它访问的敏感信息。

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
# 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
