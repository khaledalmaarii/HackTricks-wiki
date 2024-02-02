# 挂载命名空间

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

挂载命名空间是Linux内核功能，它为一组进程看到的文件系统挂载点提供隔离。每个挂载命名空间都有自己的文件系统挂载点集合，**一个命名空间中的挂载点变化不会影响其他命名空间**。这意味着在不同挂载命名空间中运行的进程可以有不同的文件系统层次视图。

挂载命名空间在容器化中特别有用，其中每个容器都应该有自己的文件系统和配置，与其他容器和宿主系统隔离。

### 工作原理：

1. 当创建一个新的挂载命名空间时，它会用**其父命名空间的挂载点的副本**进行初始化。这意味着，在创建时，新命名空间与其父命名空间共享相同的文件系统视图。然而，任何后续对命名空间内挂载点的更改都不会影响父命名空间或其他命名空间。
2. 当进程在其命名空间内修改挂载点，例如挂载或卸载文件系统时，**变化仅限于该命名空间**，不会影响其他命名空间。这允许每个命名空间拥有自己独立的文件系统层次结构。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWNS`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间关联的挂载点。
4. **文件描述符和索引节点在命名空间之间共享**，这意味着如果一个命名空间中的进程打开了一个指向文件的文件描述符，它可以**传递该文件描述符**给另一个命名空间中的进程，**两个进程将访问同一个文件**。然而，由于挂载点的差异，文件的路径在两个命名空间中可能不同。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
通过挂载一个新的`/proc`文件系统实例，如果你使用参数`--mount-proc`，你可以确保新的挂载命名空间有一个**准确且独立的特定于该命名空间的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

如果你在没有`-f`的情况下运行前面的命令，你会遇到这个错误。\
这个错误是由于在新命名空间中PID 1进程退出引起的。

在bash开始运行后，bash会fork出几个新的子进程来做一些事情。如果你在没有`-f`的情况下运行unshare，bash将会和当前的"unshare"进程有相同的pid。当前的"unshare"进程调用unshare系统调用，创建一个新的pid命名空间，但是当前的"unshare"进程并不在新的pid命名空间中。这是linux内核的预期行为：进程A创建一个新的命名空间，进程A本身不会被放入新的命名空间，只有进程A的子进程会被放入新的命名空间。所以当你运行：
```
unshare -p /bin/bash
```
`unshare` 进程将执行 `/bin/bash`，而 `/bin/bash` 会分叉出几个子进程，bash 的第一个子进程将成为新命名空间的 PID 1，并且子进程在完成其任务后将退出。因此，新命名空间的 PID 1 退出。

PID 1 进程具有特殊功能：它应该成为所有孤儿进程的父进程。如果根命名空间中的 PID 1 进程退出，内核将会出现恐慌。如果子命名空间中的 PID 1 进程退出，linux 内核将调用 `disable_pid_allocation` 函数，该函数将清除该命名空间中的 `PIDNS_HASH_ADDING` 标志。当 linux 内核创建新进程时，内核将调用 `alloc_pid` 函数在命名空间中分配一个 PID，如果没有设置 `PIDNS_HASH_ADDING` 标志，`alloc_pid` 函数将返回一个 -ENOMEM 错误。这就是你得到“无法分配内存”错误的原因。

你可以通过使用 '-f' 选项来解决这个问题：
```
unshare -fp /bin/bash
```
如果你使用 `-f` 选项运行 unshare，unshare 将在创建新的 pid 命名空间后分叉一个新进程。并在新进程中运行 /bin/bash。新进程将成为新 pid 命名空间的 pid 1。然后 bash 也会分叉几个子进程来完成一些工作。由于 bash 本身是新 pid 命名空间的 pid 1，它的子进程可以无问题地退出。

摘自 [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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
### 挂载某物

此外，您只能**如果您是root，则进入另一个进程的命名空间**。而且您**不能**在没有指向它的描述符（如`/proc/self/ns/mnt`）的情况下**进入**其他命名空间。

因为新的挂载只能在命名空间内访问，所以命名空间可能包含只能从中访问的敏感信息。
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

<summary><strong>从零到英雄学习AWS黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
