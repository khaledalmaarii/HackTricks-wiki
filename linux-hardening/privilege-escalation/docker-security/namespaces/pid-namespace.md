# PID Namespace

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}

## Basic Information

PID（进程标识符）命名空间是Linux内核中的一个特性，通过使一组进程拥有自己独特的PID集合，从而提供进程隔离，这些PID与其他命名空间中的PID是分开的。这在容器化中尤其有用，因为进程隔离对于安全性和资源管理至关重要。

当创建一个新的PID命名空间时，该命名空间中的第一个进程被分配PID 1。这个进程成为新命名空间的“init”进程，负责管理该命名空间内的其他进程。在命名空间内创建的每个后续进程将拥有该命名空间内的唯一PID，这些PID将独立于其他命名空间中的PID。

从PID命名空间内进程的角度来看，它只能看到同一命名空间中的其他进程。它无法感知其他命名空间中的进程，也无法使用传统的进程管理工具（例如，`kill`，`wait`等）与它们交互。这提供了一种隔离级别，有助于防止进程之间的相互干扰。

### How it works:

1. 当创建一个新进程时（例如，通过使用`clone()`系统调用），该进程可以被分配到一个新的或现有的PID命名空间。**如果创建了一个新的命名空间，该进程将成为该命名空间的“init”进程**。
2. **内核**维护一个**新命名空间中的PID与父命名空间中相应PID之间的映射**（即，从中创建新命名空间的命名空间）。这个映射**允许内核在必要时翻译PID**，例如，在不同命名空间中的进程之间发送信号时。
3. **PID命名空间内的进程只能看到并与同一命名空间中的其他进程交互**。它们无法感知其他命名空间中的进程，并且它们的PID在其命名空间内是唯一的。
4. 当**PID命名空间被销毁**（例如，当命名空间的“init”进程退出时），**该命名空间内的所有进程都将被终止**。这确保与命名空间相关的所有资源都得到适当清理。

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当 `unshare` 在没有 `-f` 选项的情况下执行时，由于 Linux 处理新 PID（进程 ID）命名空间的方式，会遇到错误。关键细节和解决方案如下：

1. **问题解释**：
- Linux 内核允许一个进程使用 `unshare` 系统调用创建新的命名空间。然而，启动新 PID 命名空间创建的进程（称为“unshare”进程）并不会进入新的命名空间；只有它的子进程会进入。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程处于原始 PID 命名空间中。
- 新命名空间中 `/bin/bash` 的第一个子进程成为 PID 1。当该进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 具有收养孤儿进程的特殊角色。然后，Linux 内核将禁用该命名空间中的 PID 分配。

2. **后果**：
- 新命名空间中 PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清理。这导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，从而产生“无法分配内存”的错误。

3. **解决方案**：
- 通过在 `unshare` 中使用 `-f` 选项可以解决此问题。此选项使 `unshare` 在创建新 PID 命名空间后分叉一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。`/bin/bash` 及其子进程随后安全地包含在这个新命名空间中，防止 PID 1 提前退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，使得 `/bin/bash` 及其子进程能够正常运行，而不会遇到内存分配错误。

</details>

通过挂载新的 `/proc` 文件系统实例，如果使用参数 `--mount-proc`，您可以确保新的挂载命名空间具有 **特定于该命名空间的进程信息的准确和隔离的视图**。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查您的进程所在的命名空间
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### 查找所有 PID 命名空间

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

请注意，初始（默认）PID 命名空间中的 root 用户可以看到所有进程，甚至是新 PID 命名空间中的进程，这就是我们可以看到所有 PID 命名空间的原因。

### 进入 PID 命名空间内部
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
当你从默认命名空间进入一个PID命名空间时，你仍然能够看到所有的进程。而来自该PID命名空间的进程将能够看到新的bash进程。

此外，你**只能在你是root的情况下进入另一个进程的PID命名空间**。并且你**不能**在没有指向它的**描述符**的情况下**进入**其他命名空间（如`/proc/self/ns/pid`）。

## References
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
</details>
{% endhint %}
