# DDexec / EverythingExec

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS 红队专家)</strong></a><strong>从零开始学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 **HackTricks 中看到您的公司广告** 或 **下载 HackTricks 的 PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs 集合**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来分享您的黑客技巧。

</details>

## 上下文

在 Linux 中，为了运行程序，它必须以文件形式存在，必须通过文件系统层次结构以某种方式访问（这只是 `execve()` 的工作方式）。这个文件可能驻留在磁盘上或在 ram 中（tmpfs, memfd），但您需要一个文件路径。这使得控制在 Linux 系统上运行的内容变得非常容易，便于检测威胁和攻击者的工具，或者完全阻止他们尝试执行任何东西（例如，不允许非特权用户在任何地方放置可执行文件）。

但这项技术在此改变了所有这些。如果你不能启动你想要的进程... **那么你就劫持一个已经存在的**。

这项技术允许您**绕过常见的保护技术，如只读、noexec、文件名白名单、哈希白名单等...**

## 依赖项

最终脚本依赖于以下工具才能工作，它们需要在您正在攻击的系统中可访问（默认情况下，您将在任何地方找到它们）：
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

如果您能够任意修改进程的内存，那么您就可以接管它。这可以用来劫持一个已存在的进程并用另一个程序替换它。我们可以通过使用 `ptrace()` 系统调用来实现这一点（这要求您能够执行系统调用或系统上有 gdb 可用），或者更有趣的是，写入 `/proc/$pid/mem`。

文件 `/proc/$pid/mem` 是进程整个地址空间的一对一映射（_例如_ 在 x86-64 中从 `0x0000000000000000` 到 `0x7ffffffffffff000`）。这意味着在偏移量 `x` 处读取或写入此文件与读取或修改虚拟地址 `x` 处的内容相同。

现在，我们面临四个基本问题：

* 通常，只有 root 和文件程序所有者可以修改它。
* ASLR。
* 如果我们尝试读取或写入程序地址空间中未映射的地址，我们将得到 I/O 错误。

这些问题都有解决方案，虽然不完美，但是有效：

* 大多数 shell 解释器允许创建文件描述符，然后这些文件描述符会被子进程继承。我们可以创建一个指向具有写权限的 shell 的 `mem` 文件的 fd...所以使用该 fd 的子进程将能够修改 shell 的内存。
* ASLR 甚至不是问题，我们可以检查 shell 的 `maps` 文件或 procfs 中的任何其他文件，以获得有关进程地址空间的信息。
* 所以我们需要对文件进行 `lseek()`。从 shell 这不能做到，除非使用臭名昭著的 `dd`。

### 更详细地

步骤相对简单，不需要任何专业知识就能理解：

* 解析我们想要运行的二进制文件和加载器，找出它们需要什么映射。然后制作一个 "shell"代码，它将大致执行内核在每次调用 `execve()` 时所做的相同步骤：
* 创建所述映射。
* 将二进制文件读入它们。
* 设置权限。
* 最后用程序的参数初始化栈，并放置辅助向量（加载器所需）。
* 跳入加载器，让它完成剩下的工作（加载程序所需的库）。
* 从 `syscall` 文件中获取进程在执行的系统调用后将返回的地址。
* 用我们的 shellcode 覆盖那个将会是可执行的位置（通过 `mem` 我们可以修改不可写的页面）。
* 将我们想要运行的程序传递给进程的 stdin（将由所述 "shell"代码 `read()`）。
* 此时，加载器负责加载我们程序所需的库并跳入其中。

**查看工具在** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

截至 2022 年 12 月 12 日，我发现了几种替代 `dd` 的方法，其中一种是 `tail`，目前是用来通过 `mem` 文件进行 `lseek()` 的默认程序（这是使用 `dd` 的唯一目的）。所述替代方法包括：
```bash
tail
hexdump
cmp
xxd
```
设置变量 `SEEKER`，您可以更改使用的搜索器，_例如_：
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
如果您找到了脚本中未实现的另一个有效的seeker，您仍然可以通过设置`SEEKER_ARGS`变量来使用它：
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
```markdown
阻止这个，EDRs。

<details>

<summary><strong>从零开始学习AWS黑客技术，成为</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF版本**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上[**关注**我](https://twitter.com/carlospolopm)**。**
* **通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>
```
