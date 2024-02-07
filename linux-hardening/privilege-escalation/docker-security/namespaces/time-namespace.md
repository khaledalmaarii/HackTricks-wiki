# 时间命名空间

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

Linux中的时间命名空间允许对系统单调和开机时间时钟进行每个命名空间的偏移。它通常用于Linux容器中，在容器内更改日期/时间并在从检查点或快照恢复后调整时钟。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
通过使用`--mount-proc`参数挂载一个新的`/proc`文件系统实例，确保新的挂载命名空间对该命名空间特定的进程信息具有准确且隔离的视图。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当执行`unshare`时没有使用`-f`选项时，会遇到错误，这是由于Linux处理新PID（进程ID）命名空间的方式。以下是关键细节和解决方案：

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
```
### &#x20;检查您的进程位于哪个命名空间
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### 查找所有时间命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入时间命名空间

{% endcode %}
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
也，只有**root用户**才能**进入另一个进程命名空间**。而且，**没有指向它的描述符**（如`/proc/self/ns/net`），你**无法**进入其他命名空间。
