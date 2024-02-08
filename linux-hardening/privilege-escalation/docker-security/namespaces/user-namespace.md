# 用户命名空间

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

- 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
- 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
- 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
- **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 基本信息

用户命名空间是Linux内核的一个功能，**提供用户和组ID映射的隔离**，允许每个用户命名空间拥有**自己的用户和组ID集合**。这种隔离使得在不同用户命名空间中运行的进程可以**拥有不同的特权和所有权**，即使它们在数字上共享相同的用户和组ID。

用户命名空间在容器化中特别有用，每个容器应该有自己独立的用户和组ID集合，从而在容器和主机系统之间实现更好的安全性和隔离。

### 工作原理：

1. 创建新用户命名空间时，它**从一个空的用户和组ID映射集开始**。这意味着在新用户命名空间中运行的任何进程**最初在命名空间外部没有特权**。
2. 可以在新命名空间和父（或主机）命名空间之间建立ID映射。这**允许新命名空间中的进程具有与父命名空间中的用户和组ID相对应的特权和所有权**。但是，ID映射可以限制为特定范围和ID子集，从而对在新命名空间中的进程授予的特权进行精细控制。
3. 在用户命名空间内，**进程可以拥有完整的根特权（UID 0）用于命名空间内的操作**，同时在命名空间外部具有有限特权。这允许**容器在其自己的命名空间中以类似根用户的能力运行，而不会在主机系统上具有完整的根特权**。
4. 进程可以使用`setns()`系统调用在命名空间之间移动，或者使用带有`CLONE_NEWUSER`标志的`unshare()`或`clone()`系统调用创建新命名空间。当进程移动到新命名空间或创建一个时，它将开始使用与该命名空间关联的用户和组ID映射。

## 实验：

### 创建不同的命名空间

#### 命令行界面
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
通过使用参数`--mount-proc`挂载`/proc`文件系统的新实例，确保新的挂载命名空间具有**准确且独立的进程信息视图，特定于该命名空间**。

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
- 执行`%unshare -fp /bin/bash%`确保`unshare`命令本身成为新命名空间中的PID 1。然后，`/bin/bash`及其子进程安全地包含在此新命名空间中，防止PID 1过早退出，并允许正常的PID分配。

通过确保`unshare`使用`-f`标志运行，新的PID命名空间得以正确维护，使`/bin/bash`及其子进程能够正常运行，避免遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
要使用用户命名空间，Docker 守护程序需要使用 **`--userns-remap=default`** 启动（在 Ubuntu 14.04 中，可以通过修改 `/etc/default/docker` 然后执行 `sudo service docker restart` 来完成）

### &#x20;检查您的进程位于哪个命名空间
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
可以使用以下命令检查 Docker 容器中的用户映射：
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
或者从主机执行：
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
{% endcode %}

### 进入用户命名空间
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
另外，只有**作为root用户**才能**进入另一个进程命名空间**。而且，**没有指向它的描述符**（比如`/proc/self/ns/user`），你**无法进入**其他命名空间。

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
### 恢复权限

在用户命名空间的情况下，**当创建一个新的用户命名空间时，进入该命名空间的进程将在该命名空间内被授予完整的权限集**。这些权限允许进程执行特权操作，如**挂载文件系统**、创建设备或更改文件所有权，但**仅限于其用户命名空间的上下文**。

例如，当您在用户命名空间中拥有`CAP_SYS_ADMIN`权限时，您可以执行通常需要此权限的操作，比如挂载文件系统，但仅限于您的用户命名空间的上下文。您使用此权限执行的任何操作都不会影响主机系统或其他命名空间。

{% hint style="warning" %}
因此，即使在新的用户命名空间中获得一个新进程**将使您恢复所有权限**（CapEff: 000001ffffffffff），实际上您**只能使用与命名空间相关的权限**（例如挂载），而不是所有权限。因此，仅凭这一点是不足以逃离 Docker 容器的。
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
## 参考资料
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>从零开始学习AWS黑客技术</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。 

</details>
