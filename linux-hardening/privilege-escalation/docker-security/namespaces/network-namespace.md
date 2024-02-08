# 网络命名空间

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

网络命名空间是Linux内核的一个功能，提供网络堆栈的隔离，允许**每个网络命名空间拥有独立的网络配置**、接口、IP地址、路由表和防火墙规则。这种隔离在各种场景中非常有用，比如容器化，其中每个容器应该有自己独立的网络配置，独立于其他容器和主机系统。

### 工作原理：

1. 创建新的网络命名空间时，它会以一个**完全隔离的网络堆栈**开始，除了回环接口（lo）外**没有网络接口**。这意味着运行在新网络命名空间中的进程默认情况下无法与其他命名空间中的进程或主机系统通信。
2. **虚拟网络接口**，如veth对，可以被创建并在网络命名空间之间移动。这允许在命名空间之间或在命名空间和主机系统之间建立网络连接。例如，veth对的一端可以放置在容器的网络命名空间中，另一端可以连接到主机命名空间中的**桥接器**或另一个网络接口，为容器提供网络连接。
3. 命名空间内的网络接口可以拥有它们**自己的IP地址、路由表和防火墙规则**，独立于其他命名空间。这允许不同网络命名空间中的进程拥有不同的网络配置，并且可以像在独立网络系统上运行一样操作。
4. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWNET`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个新的命名空间时，它将开始使用与该命名空间关联的网络配置和接口。

## 实验：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
通过使用参数`--mount-proc`挂载`/proc`文件系统的新实例，确保新的挂载命名空间对该命名空间特定的进程信息具有准确且隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当执行`unshare`时没有使用`-f`选项时，会出现错误，这是由于Linux处理新PID（进程ID）命名空间的方式。以下是关键细节和解决方案：

1. **问题解释**：
- Linux内核允许进程使用`unshare`系统调用创建新的命名空间。然而，发起新PID命名空间创建的进程（称为“unshare”进程）不会进入新的命名空间；只有它的子进程会。
- 运行`%unshare -p /bin/bash%`会在与`unshare`相同的进程中启动`/bin/bash`。因此，`/bin/bash`及其子进程位于原始PID命名空间中。
- 在新命名空间中，`/bin/bash`的第一个子进程变为PID 1。当此进程退出时，如果没有其他进程，它会触发命名空间的清理，因为PID 1具有接管孤立进程的特殊角色。然后Linux内核会禁用该命名空间中的PID分配。

2. **后果**：
- 在新命名空间中，PID 1的退出导致`PIDNS_HASH_ADDING`标志的清除。这会导致`alloc_pid`函数在创建新进程时无法分配新的PID，从而产生“无法分配内存”错误。

3. **解决方案**：
- 可以通过在`unshare`中使用`-f`选项来解决此问题。此选项使`unshare`在创建新PID命名空间后fork一个新进程。
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身成为新命名空间中的PID 1。然后，`/bin/bash`及其子进程安全地包含在这个新命名空间中，防止PID 1过早退出，并允许正常的PID分配。

通过确保`unshare`使用`-f`标志运行，新的PID命名空间得以正确维护，使`/bin/bash`及其子进程能够正常运行，避免遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;检查您的进程位于哪个命名空间
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

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
此外，**只有 root 用户才能进入另一个进程命名空间**。而且，**没有指向它的描述符**（如 `/proc/self/ns/net`），**无法进入**其他命名空间。

## 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS 红队专家）</strong></a><strong>！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 PDF 版本的 HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFT**](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) 上 **关注** 我。
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
