# DDexec / EverythingExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 上下文

在Linux中，为了运行一个程序，它必须作为一个文件存在，通过文件系统层次结构以某种方式可访问（这就是`execve()`的工作原理）。这个文件可以存在于磁盘上或内存中（tmpfs，memfd），但你需要一个文件路径。这使得在Linux系统上控制要运行的内容变得非常容易，它可以轻松检测到威胁和攻击者的工具，或者防止他们尝试执行任何自己的内容（例如，不允许非特权用户在任何地方放置可执行文件）。

但是这种技术可以改变这一切。如果你无法启动你想要的进程... **那么你就劫持一个已经存在的进程**。

这种技术允许你**绕过常见的保护技术，如只读、noexec、文件名白名单、哈希白名单...**

## 依赖项

最终脚本依赖于以下工具才能工作，它们需要在你攻击的系统中可访问（默认情况下，你可以在任何地方找到它们）：
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## 技术

如果您能任意修改进程的内存，那么您就可以接管它。这可以用于劫持已存在的进程并用另一个程序替换它。我们可以通过使用`ptrace()`系统调用（需要您能够执行系统调用或在系统上有gdb可用）或者更有趣的是，写入`/proc/$pid/mem`来实现这一点。

文件`/proc/$pid/mem`是进程的整个地址空间的一对一映射（例如，在x86-64中从`0x0000000000000000`到`0x7ffffffffffff000`）。这意味着从该文件的偏移量`x`读取或写入与在虚拟地址`x`处读取或修改内容是相同的。

现在，我们需要解决四个基本问题：

* 通常只有root和文件的程序所有者才能修改它。
* ASLR。
* 如果我们尝试读取或写入未映射到程序地址空间的地址，将会收到I/O错误。

这些问题有解决方案，虽然它们不是完美的，但是很好：

* 大多数shell解释器允许创建文件描述符，然后将其继承给子进程。我们可以创建一个指向shell的`mem`文件的fd，并具有写权限...因此使用该fd的子进程将能够修改shell的内存。
* ASLR甚至不是一个问题，我们可以检查shell的`maps`文件或procfs中的任何其他文件，以获取有关进程的地址空间的信息。
* 因此，我们需要在文件上执行`lseek()`。从shell中，除非使用臭名昭著的`dd`，否则无法执行此操作。

### 更详细地说

这些步骤相对简单，不需要任何专业知识来理解它们：

* 解析我们想要运行的二进制文件和加载器，找出它们需要的映射。然后编写一个"shell"代码，它将执行与内核在每次调用`execve()`时执行的相同步骤（广义上）：
* 创建这些映射。
* 将二进制文件读入其中。
* 设置权限。
* 最后，使用程序的参数初始化堆栈，并放置辅助向量（加载器所需）。
* 跳转到加载器并让它完成剩下的工作（加载程序所需的库）。
* 从`syscall`文件中获取进程在执行系统调用后将返回的地址。
* 用我们的shellcode（通过`mem`，我们可以修改不可写的页面）覆盖该位置，该位置将是可执行的。
* 将要运行的程序传递给进程的stdin（将由上述"shell"代码`read()`）。
* 此时，由加载器负责加载我们程序所需的库并跳转到它。

**请查看**[**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)**中的工具**

## EverythingExec

截至2022年12月12日，我已经找到了一些替代`dd`的方法，其中之一是`tail`，它是当前用于通过`mem`文件进行`lseek()`的默认程序（这是使用`dd`的唯一目的）。这些替代方法包括：
```bash
tail
hexdump
cmp
xxd
```
通过设置变量`SEEKER`，您可以更改使用的搜索器，例如：
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
如果你发现脚本中没有实现的另一个有效的搜索器，你仍然可以使用它，设置`SEEKER_ARGS`变量：
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
阻止这个，EDRs。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
