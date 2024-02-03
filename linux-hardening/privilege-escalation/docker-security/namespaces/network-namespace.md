# 网络命名空间

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 基本信息

网络命名空间是Linux内核的一个特性，它提供了网络堆栈的隔离，允许**每个网络命名空间拥有自己独立的网络配置**、接口、IP地址、路由表和防火墙规则。这种隔离在各种场景中都很有用，例如容器化，其中每个容器都应该有自己的网络配置，独立于其他容器和宿主系统。

### 它是如何工作的：

1. 当创建一个新的网络命名空间时，它会从一个**完全隔离的网络堆栈**开始，除了回环接口(lo)之外**没有网络接口**。这意味着在新的网络命名空间中运行的进程默认无法与其他命名空间或宿主系统中的进程通信。
2. 可以创建**虚拟网络接口**，如veth对，并在网络命名空间之间移动。这允许在命名空间之间或命名空间与宿主系统之间建立网络连接。例如，veth对的一端可以放置在容器的网络命名空间中，另一端可以连接到宿主命名空间中的**桥接**或另一个网络接口，为容器提供网络连接。
3. 命名空间内的网络接口可以拥有自己的**IP地址、路由表和防火墙规则**，独立于其他命名空间。这允许不同网络命名空间中的进程拥有不同的网络配置，并且操作起来就像它们运行在独立的网络系统上一样。
4. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWNET`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间关联的网络配置和接口。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
通过挂载一个新的`/proc`文件系统实例，如果你使用参数`--mount-proc`，你确保了新的挂载命名空间有一个**准确且独立的特定于该命名空间的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当`unshare`在没有`-f`选项的情况下执行时，会遇到错误，这是由于Linux处理新的PID（进程ID）命名空间的方式。关键细节和解决方案如下：

1. **问题解释**：
- Linux内核允许一个进程使用`unshare`系统调用来创建新的命名空间。然而，启动创建新的PID命名空间的进程（称为"unshare"进程）并不进入新的命名空间；只有它的子进程会进入。
- 运行`%unshare -p /bin/bash%`会在与`unshare`相同的进程中启动`/bin/bash`。因此，`/bin/bash`及其子进程都在原始的PID命名空间中。
- `/bin/bash`在新命名空间中的第一个子进程成为PID 1。当这个进程退出时，如果没有其他进程，它会触发命名空间的清理，因为PID 1有收养孤儿进程的特殊角色。Linux内核将会在该命名空间中禁用PID分配。

2. **后果**：
- 在新命名空间中PID 1的退出导致清理`PIDNS_HASH_ADDING`标志。这导致`alloc_pid`函数在创建新进程时无法分配新的PID，产生"无法分配内存"错误。

3. **解决方案**：
- 问题可以通过使用`unshare`的`-f`选项来解决。这个选项使`unshare`在创建新的PID命名空间后分叉一个新进程。
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身在新命名空间中成为PID 1。`/bin/bash`及其子进程然后安全地包含在这个新命名空间内，防止PID 1的过早退出并允许正常的PID分配。

通过确保`unshare`运行时带有`-f`标志，新的PID命名空间被正确维护，允许`/bin/bash`及其子进程在不遇到内存分配错误的情况下操作。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### 检查您的进程在哪个命名空间中
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
### 进入网络命名空间
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
您只能**以 root 身份进入另一个进程的命名空间**。而且您**不能** **进入**其他没有描述符指向的命名空间（如 `/proc/self/ns/net`）。

# 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您希望在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
