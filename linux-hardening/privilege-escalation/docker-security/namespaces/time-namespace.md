# 时间命名空间

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在 **HackTricks中看到您的公司广告** 或 **下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

时间命名空间允许为系统单调时钟和启动时间时钟设置每个命名空间的偏移量。时间命名空间适用于Linux容器，允许在容器内更改日期/时间，并在从检查点/快照恢复后调整容器内的时钟。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
通过挂载一个新的`/proc`文件系统实例，如果你使用参数`--mount-proc`，你确保了新的挂载命名空间有一个**准确且独立的特定于该命名空间的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当`unshare`在没有`-f`选项的情况下执行时，由于Linux处理新PID（进程ID）命名空间的方式，会遇到一个错误。关键细节和解决方案如下：

1. **问题解释**：
- Linux内核允许一个进程使用`unshare`系统调用来创建新的命名空间。然而，启动创建新PID命名空间的进程（称为"unshare"进程）并不进入新的命名空间；只有它的子进程会进入。
- 运行`%unshare -p /bin/bash%`会在与`unshare`相同的进程中启动`/bin/bash`。因此，`/bin/bash`及其子进程都在原始的PID命名空间中。
- `/bin/bash`在新命名空间中的第一个子进程成为PID 1。当这个进程退出时，如果没有其他进程，它会触发命名空间的清理，因为PID 1有收养孤儿进程的特殊角色。Linux内核将会在该命名空间中禁用PID分配。

2. **后果**：
- 在新命名空间中PID 1的退出导致`PIDNS_HASH_ADDING`标志的清理。这导致`alloc_pid`函数在创建新进程时无法分配新的PID，产生"无法分配内存"错误。

3. **解决方案**：
- 通过使用`unshare`的`-f`选项可以解决这个问题。这个选项使`unshare`在创建新的PID命名空间后分叉一个新进程。
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身在新命名空间中成为PID 1。`/bin/bash`及其子进程随后安全地包含在这个新命名空间内，防止了PID 1的过早退出，并允许正常的PID分配。

通过确保`unshare`运行时带有`-f`标志，新的PID命名空间被正确维护，允许`/bin/bash`及其子进程在不遇到内存分配错误的情况下操作。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程在哪个命名空间中
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
{% endcode %}

### 进入时间命名空间
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
```markdown
另外，您只能**以 root 身份进入另一个进程的命名空间**。而且您**不能** **进入**没有描述符指向的其他命名空间（如 `/proc/self/ns/net`）。

# 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的**公司广告**或**下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来**分享您的黑客技巧**。

</details>
```
