# 用户命名空间

<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在 **HackTricks中看到你的公司广告** 或 **下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>

## 基本信息

用户命名空间是Linux内核的一个特性，它**提供了用户和组ID映射的隔离**，允许每个用户命名空间拥有其**自己的一套用户和组ID**。这种隔离使得在不同用户命名空间中运行的进程即使在数值上共享相同的用户和组ID，也能**拥有不同的权限和所有权**。

用户命名空间在容器化中特别有用，每个容器应该有其独立的用户和组ID集，允许在容器和宿主系统之间提供更好的安全性和隔离。

### 工作原理：

1. 当创建一个新的用户命名空间时，它**从一个空的用户和组ID映射集开始**。这意味着在新用户命名空间中运行的任何进程将**最初在命名空间外没有权限**。
2. 可以在新命名空间中的用户和组ID与父级（或宿主）命名空间中的ID之间建立映射。这**允许新命名空间中的进程拥有与父命名空间中的用户和组ID相对应的权限和所有权**。然而，ID映射可以限制为特定范围和ID子集，允许对新命名空间中进程所授予的权限进行细粒度控制。
3. 在用户命名空间内，**进程可以拥有完全的root权限（UID 0）来进行命名空间内的操作**，同时在命名空间外仍然拥有有限的权限。这允许**容器在其自己的命名空间内以类似root的能力运行，而不在宿主系统上拥有完全的root权限**。
4. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWUSER`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间关联的用户和组ID映射。

## 实验室：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
通过挂载一个新的 `/proc` 文件系统实例，如果你使用参数 `--mount-proc`，你可以确保新的挂载命名空间有一个**准确且独立的特定于该命名空间的进程信息视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当 `unshare` 在没有 `-f` 选项的情况下执行时，会遇到错误，这是由于 Linux 处理新的 PID（进程 ID）命名空间的方式。关键细节和解决方案如下：

1. **问题解释**：
- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，启动创建新的 PID 命名空间的进程（称为 "unshare" 进程）不会进入新的命名空间；只有其子进程会进入。
- 执行 `%unshare -p /bin/bash%` 会在 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程位于原始的 PID 命名空间中。
- `/bin/bash` 在新命名空间中的第一个子进程成为 PID 1。当这个进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 有收养孤儿进程的特殊角色。Linux 内核将会在该命名空间中禁用 PID 分配。

2. **后果**：
- 在新命名空间中 PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清理。这导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，产生 "无法分配内存" 错误。

3. **解决方案**：
- 通过使用 `-f` 选项与 `unshare` 一起，可以解决这个问题。这个选项使 `unshare` 在创建新的 PID 命名空间后分叉一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。`/bin/bash` 及其子进程随后安全地包含在这个新命名空间内，防止 PID 1 的过早退出，并允许正常的 PID 分配。

通过确保 `unshare` 带有 `-f` 标志运行，新的 PID 命名空间得到正确维护，允许 `/bin/bash` 及其子进程在不遇到内存分配错误的情况下操作。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
要使用用户命名空间，Docker 守护进程需要以 **`--userns-remap=default`** 启动（在 ubuntu 14.04 中，可以通过修改 `/etc/default/docker` 然后执行 `sudo service docker restart` 来完成）

### 检查你的进程在哪个命名空间内
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
可以使用以下命令从docker容器检查用户映射：
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
或者从宿主机使用：
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
### 进入用户命名空间
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
同样，您只能**如果您是root**，才能**进入另一个进程的命名空间**。而且您**不能**在**没有指向它的描述符**的情况下**进入**其他命名空间（例如`/proc/self/ns/user`）。

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
### 恢复能力

在用户命名空间的情况下，**当创建一个新的用户命名空间时，进入该命名空间的进程将在该命名空间内获得一整套能力**。这些能力允许进程执行特权操作，例如**挂载**文件系统、创建设备或更改文件的所有权，但**仅限于其用户命名空间的上下文中**。

例如，当你在用户命名空间内拥有`CAP_SYS_ADMIN`能力时，你可以执行通常需要此能力的操作，如挂载文件系统，但仅限于你的用户命名空间的上下文内。你使用这个能力执行的任何操作都不会影响宿主系统或其他命名空间。

{% hint style="warning" %}
因此，即使在新的用户命名空间中获取一个新进程**将会让你恢复所有的能力**（CapEff: 000001ffffffffff），你实际上**只能使用与命名空间相关的能力**（例如挂载），而不能使用所有能力。所以，仅凭这一点并不足以从Docker容器中逃逸。
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
# 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

其他支持 HackTricks 的方式：

* 如果您希望在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF 版本**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFT 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>
