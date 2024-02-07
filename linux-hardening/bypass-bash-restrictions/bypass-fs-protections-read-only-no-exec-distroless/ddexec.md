# DDexec / EverythingExec

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

## 上下文

在Linux中，为了运行程序，它必须作为一个文件存在，必须通过文件系统层次结构的某种方式访问（这就是`execve()`的工作原理）。这个文件可以存在于磁盘上或内存中（tmpfs，memfd），但你需要一个文件路径。这使得在Linux系统上控制运行什么变得非常容易，也很容易检测威胁和攻击者的工具，或者防止它们尝试执行任何自己的东西（例如，不允许非特权用户在任何地方放置可执行文件）。

但是这项技术可以改变所有这一切。如果您无法启动想要的进程... **那么您就劫持一个已经存在的进程**。

这项技术允许您**绕过常见的保护技术，如只读、noexec、文件名白名单、哈希白名单...**

## 依赖关系

最终脚本依赖于以下工具才能正常工作，它们需要在您攻击的系统中可访问（默认情况下，您将在任何地方找到它们）：
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

如果您能任意修改进程的内存，则可以接管该进程。这可以用来劫持已经存在的进程并用另一个程序替换它。我们可以通过使用`ptrace()`系统调用（需要您能够执行系统调用或在系统上有gdb可用）或者更有趣的是，写入`/proc/$pid/mem`来实现这一点。

文件`/proc/$pid/mem`是进程整个地址空间的一对一映射（例如从`0x0000000000000000`到`0x7ffffffffffff000`在x86-64中）。这意味着从该文件的偏移`x`读取或写入与在虚拟地址`x`处读取或修改内容是相同的。

现在，我们需要面对四个基本问题：

- 通常只有root和文件的程序所有者可以修改它。
- ASLR。
- 如果我们尝试读取或写入未映射在程序地址空间中的地址，我们将收到I/O错误。

这些问题有解决方案，尽管它们不是完美的，但还是不错的：

- 大多数shell解释器允许创建文件描述符，然后将其继承给子进程。我们可以创建一个指向shell的`mem`文件的具有写权限的fd...因此使用该fd的子进程将能够修改shell的内存。
- ASLR甚至不是问题，我们可以检查shell的`maps`文件或procfs中的任何其他文件，以获取有关进程地址空间的信息。
- 因此，我们需要在文件上执行`lseek()`。从shell中，除非使用臭名昭著的`dd`，否则无法执行此操作。

### 更详细地

这些步骤相对简单，不需要任何专业知识来理解它们：

- 解析我们想要运行的二进制文件和加载器，找出它们需要的映射。然后编写一个“shell”代码，它将执行大致相同的步骤，即内核在每次调用`execve()`时执行的步骤：
- 创建这些映射。
- 将二进制文件读入其中。
- 设置权限。
- 最后，使用程序参数初始化堆栈，并放置加载器所需的辅助向量。
- 跳转到加载器，让它完成剩下的工作（加载程序所需的库）。
- 从`syscall`文件中获取进程在执行系统调用后将返回的地址。
- 用我们的shell代码覆盖该位置，该位置将是可执行的（通过`mem`，我们可以修改不可写的页面）。
- 将要运行的程序传递给进程的stdin（将由该“shell”代码`read()`）。
- 到这一步，加载器将加载我们程序所需的必要库并跳转到它。

**查看工具** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

有几种替代方案可以替代`dd`，其中之一是`tail`，目前是用于通过`mem`文件`lseek()`的默认程序（这是使用`dd`的唯一目的）。这些替代方案包括：
```bash
tail
hexdump
cmp
xxd
```
通过设置变量 `SEEKER`，您可以更改所使用的搜索器，例如：
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
如果您发现另一个有效的 seeker 没有在脚本中实现，您仍然可以使用它，设置 `SEEKER_ARGS` 变量：
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
阻止这个，EDRs。

# 参考
* [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我们的**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
