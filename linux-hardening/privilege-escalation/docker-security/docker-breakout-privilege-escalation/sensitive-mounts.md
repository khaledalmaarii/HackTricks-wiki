<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


(_**此信息来自**_ [_**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**_](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts))

由于缺乏命名空间支持，`/proc`和`/sys`的暴露提供了一个重要的攻击面和信息泄露源。`procfs`和`sysfs`中的许多文件都存在容器逃逸、主机修改或基本信息泄露的风险，这可能会促成其他攻击。

为了滥用这些技术，可能只需要**错误配置类似于`-v /proc:/host/proc`**，因为**AppArmor不保护`/host/proc`，因为AppArmor是基于路径的**

# procfs

## /proc/sys

`/proc/sys`通常允许访问修改内核变量，通常通过`sysctl(2)`进行控制。

### /proc/sys/kernel/core\_pattern

[/proc/sys/kernel/core\_pattern](https://man7.org/linux/man-pages/man5/core.5.html)定义了一个在生成核心文件时（通常是程序崩溃）执行的程序，并且如果此文件的第一个字符是管道符号`|`，则将核心文件作为标准输入传递给该程序。此程序由root用户运行，并且允许最多128个字节的命令行参数。这将允许在容器主机中轻松执行代码，只要发生任何崩溃和核心文件生成（可以在许多恶意操作中简单地丢弃核心文件）。
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes #For testing
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern
sleep 5 && ./crash &
```
### /proc/sys/kernel/modprobe

[/proc/sys/kernel/modprobe](https://man7.org/linux/man-pages/man5/proc.5.html) 包含内核模块加载器的路径，当加载内核模块时，会调用该加载器，例如通过 [modprobe](https://man7.org/linux/man-pages/man8/modprobe.8.html) 命令。通过执行任何触发内核尝试加载内核模块的操作（例如使用加密 API 加载当前未加载的加密模块，或使用 ifconfig 加载当前未使用的设备的网络模块），可以获得代码执行权限。
```bash
# Check if you can directly access modprobe
ls -l `cat /proc/sys/kernel/modprobe`
```
### /proc/sys/vm/panic\_on\_oom

[/proc/sys/vm/panic\_on\_oom](https://man7.org/linux/man-pages/man5/proc.5.html) 是一个全局标志，确定当内存不足（OOM）时，内核是否会发生崩溃（而不是调用OOM killer）。这更像是一种拒绝服务（DoS）攻击，而不是容器逃逸，但它同样暴露了一种只应该对主机可用的能力。

### /proc/sys/fs

[/proc/sys/fs](https://man7.org/linux/man-pages/man5/proc.5.html) 目录包含了与文件系统的各个方面相关的一系列选项和信息，包括配额、文件句柄、inode 和 dentry 信息。对该目录的写访问将允许对主机进行各种拒绝服务攻击。

### /proc/sys/fs/binfmt\_misc

[/proc/sys/fs/binfmt\_misc](https://man7.org/linux/man-pages/man5/proc.5.html) 允许执行各种杂项二进制格式，通常意味着可以根据其魔数为非本机二进制格式（如 Java）注册各种解释器。您可以使内核执行一个二进制文件，将其注册为处理程序。\
您可以在 [https://github.com/toffan/binfmt\_misc](https://github.com/toffan/binfmt\_misc) 找到一个漏洞利用程序：_Poor man's rootkit, leverage_ [_binfmt\_misc_](https://github.com/torvalds/linux/raw/master/Documentation/admin-guide/binfmt-misc.rst) _的_ [_credentials_](https://github.com/torvalds/linux/blame/3bdb5971ffc6e87362787c770353eb3e54b7af30/Documentation/binfmt\_misc.txt#L62) _选项，通过任何 suid 二进制文件（以及获取 root shell）来升级权限，如果 `/proc/sys/fs/binfmt_misc/register` 是可写的。

有关此技术的更详细解释，请参阅 [https://www.youtube.com/watch?v=WBC7hhgMvQQ](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

## /proc/config.gz

[/proc/config.gz](https://man7.org/linux/man-pages/man5/proc.5.html) 根据 `CONFIG_IKCONFIG_PROC` 设置，它提供了运行中内核配置选项的压缩版本。这可能使受损或恶意的容器能够轻松发现和攻击内核中启用的易受攻击的区域。

## /proc/sysrq-trigger

`Sysrq` 是一种旧的机制，可以通过特殊的 `SysRq` 键盘组合来调用。这可以允许立即重启系统、发出 `sync(2)`、将所有文件系统重新挂载为只读、调用内核调试器和其他操作。

如果客户机没有正确隔离，它可以通过向 `/proc/sysrq-trigger` 文件写入字符来触发 [sysrq](https://www.kernel.org/doc/html/v4.11/admin-guide/sysrq.html) 命令。
```bash
# Reboot the host
echo b > /proc/sysrq-trigger
```
## /proc/kmsg

[/proc/kmsg](https://man7.org/linux/man-pages/man5/proc.5.html) 可以公开内核环形缓冲区消息，通常通过 `dmesg` 访问。公开这些信息可以帮助进行内核利用，触发内核地址泄漏（可用于帮助击败内核地址空间布局随机化（KASLR）），并且可以泄露有关内核、硬件、被阻止的数据包和其他系统详细信息的一般信息披露。

## /proc/kallsyms

[/proc/kallsyms](https://man7.org/linux/man-pages/man5/proc.5.html) 包含动态和可加载模块的内核导出符号及其地址位置的列表。这还包括内核映像在物理内存中的位置，这对于内核利用开发很有帮助。通过这些位置，可以定位内核的基地址或偏移量，从而可以克服内核地址空间布局随机化（KASLR）。

对于将 `kptr_restrict` 设置为 `1` 或 `2` 的系统，此文件将存在，但不提供任何地址信息（尽管列出符号的顺序与内存中的顺序相同）。

## /proc/\[pid]/mem

[/proc/\[pid\]/mem](https://man7.org/linux/man-pages/man5/proc.5.html) 公开了与内核内存设备 `/dev/mem` 的接口。虽然 PID 命名空间可以通过此 `procfs` 向量防止某些攻击，但这个区域在历史上一直是容易受到攻击的，然后被认为是安全的，然后再次被发现存在特权升级的漏洞。

## /proc/kcore

[/proc/kcore](https://man7.org/linux/man-pages/man5/proc.5.html) 代表系统的物理内存，以 ELF 核心格式表示（通常在核心转储文件中找到）。它不允许对该内存进行写入。读取此文件的能力（仅限特权用户）可以泄漏主机系统和其他容器的内存内容。

报告的大文件大小表示体系结构的最大可寻址内存量，并且在读取它时可能会导致问题（或根据软件的脆弱性而导致崩溃）。

[2019 年转储 /proc/kcore](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)

## /proc/kmem

`/proc/kmem` 是 [/dev/kmem](https://man7.org/linux/man-pages/man4/kmem.4.html) 的替代接口（直接访问被 cgroup 设备白名单阻止），它是一个表示内核虚拟内存的字符设备文件。它允许读取和写入，从而直接修改内核内存。

## /proc/mem

`/proc/mem` 是 [/dev/mem](https://man7.org/linux/man-pages/man4/kmem.4.html) 的替代接口（直接访问被 cgroup 设备白名单阻止），它是一个表示系统物理内存的字符设备文件。它允许读取和写入，从而修改所有内存。（与 `kmem` 相比，它需要稍微更多的技巧，因为需要先将虚拟地址解析为物理地址）。

## /proc/sched\_debug

`/proc/sched_debug` 是一个特殊文件，返回整个系统的进程调度信息。此信息包括来自所有命名空间的进程名称、进程 ID，以及进程 cgroup 标识符。这有效地绕过了 PID 命名空间的保护，并且可以在非特权容器中被利用，因此可以被其他/世界可读取。

## /proc/\[pid]/mountinfo

[/proc/\[pid\]/mountinfo](https://man7.org/linux/man-pages/man5/proc.5.html) 包含进程的挂载命名空间中的挂载点信息。它公开了容器 `rootfs` 或镜像的位置。

# sysfs

## /sys/kernel/uevent\_helper

`uevent` 是内核在添加或删除设备时触发的事件。值得注意的是，可以通过写入 `/sys/kernel/uevent_helper` 来修改 `uevent_helper` 的路径。然后，当触发 `uevent` 时（也可以通过从用户空间写入文件，如 `/sys/class/mem/null/uevent`），恶意的 `uevent_helper` 将被执行。
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

访问ACPI和各种硬件设置以进行温度控制，通常在笔记本电脑或游戏主板中找到。这可能导致对容器主机的DoS攻击，甚至可能导致物理损坏。

## /sys/kernel/vmcoreinfo

此文件可能泄漏内核地址，可用于击败KASLR。

## /sys/kernel/security

在`/sys/kernel/security`中挂载了`securityfs`接口，允许配置Linux安全模块。这允许配置[AppArmor策略](https://gitlab.com/apparmor/apparmor/-/wikis/Kernel\_interfaces#securityfs-syskernelsecurityapparmor)，因此访问此接口可能允许容器禁用其MAC系统。

## /sys/firmware/efi/vars

`/sys/firmware/efi/vars`公开了与NVRAM中的EFI变量交互的接口。虽然这对于大多数服务器通常不相关，但EFI变得越来越流行。权限弱点甚至导致一些笔记本电脑变砖。

## /sys/firmware/efi/efivars

`/sys/firmware/efi/efivars`提供了一个接口，用于写入用于UEFI引导参数的NVRAM。修改它们可能导致主机机器无法启动。

## /sys/kernel/debug

`debugfs`提供了一个“无规则”接口，内核（或内核模块）可以创建可由用户空间访问的调试接口。它过去存在过许多安全问题，并且文件系统背后的“无规则”准则经常与安全约束发生冲突。

# 参考资料

* [理解和加固Linux容器](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [滥用特权和非特权Linux容器](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
