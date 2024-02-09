<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个有用的程序，可以找到运行游戏内存中保存重要值的位置并进行更改。\
当您下载并运行它时，会显示如何使用该工具的教程。如果您想学习如何使用该工具，强烈建议您完成教程。

# 您要搜索什么？

![](<../../.gitbook/assets/image (580).png>)

这个工具非常有用，可以找到程序内存中某个值（通常是数字）的存储位置。\
通常数字以**4字节**形式存储，但您也可以找到**double**或**float**格式，或者您可能想查找与数字**不同的内容**。因此，您需要确保选择您要搜索的内容：

![](<../../.gitbook/assets/image (581).png>)

您还可以指定**不同类型**的**搜索**：

![](<../../.gitbook/assets/image (582).png>)

您还可以选中复选框**在扫描内存时停止游戏**：

![](<../../.gitbook/assets/image (584).png>)

## 快捷键

在_**编辑 --> 设置 --> 快捷键**_中，您可以为不同目的设置不同的**快捷键**，比如**停止**游戏（如果您想扫描内存的某个时刻非常有用）。其他选项也可用：

![](<../../.gitbook/assets/image (583).png>)

# 修改值

一旦您**找到**了您要**查找的值**的位置（关于此更多信息请参见以下步骤），您可以通过双击它，然后双击其值来**修改它**：

![](<../../.gitbook/assets/image (585).png>)

最后，**勾选复选框**以在内存中完成修改：

![](<../../.gitbook/assets/image (586).png>)

对内存的**更改**将立即**应用**（请注意，直到游戏再次使用此值之前，该值**不会在游戏中更新**）。

# 搜索值

因此，我们假设有一个重要值（比如您的用户生命值）您想要改进，并且您正在查找内存中的此值）

## 通过已知更改

假设您正在寻找值100，您**执行扫描**以搜索该值，然后找到许多匹配项：

![](<../../.gitbook/assets/image (587).png>)

然后，您执行某些操作使**值更改**，然后**停止**游戏并**执行****下一个扫描**：

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine将搜索**从100变为新值**的**值**。恭喜，您**找到**了您要查找的值的**地址**，现在可以修改它。\
_如果仍然有几个值，请执行某些操作再次修改该值，并执行另一个“下一个扫描”以过滤地址。_

## 未知值，已知更改

在这种情况下，您**不知道值**，但您知道**如何使其更改**（甚至知道更改的值），您可以搜索您的数字。

因此，首先执行类型为“**未知初始值**”的扫描：

![](<../../.gitbook/assets/image (589).png>)

然后，使值更改，指示**值如何更改**（在我的情况下，减少了1），然后执行**下一个扫描**：

![](<../../.gitbook/assets/image (590).png>)

您将看到**以选定方式修改的所有值**：

![](<../../.gitbook/assets/image (591).png>)

找到您的值后，您可以修改它。

请注意，有**许多可能的更改**，您可以根据需要**多次执行这些步骤**以过滤结果：

![](<../../.gitbook/assets/image (592).png>)

## 随机内存地址 - 查找代码

到目前为止，我们学会了如何找到存储值的地址，但很可能在**游戏的不同执行中，该地址在内存的不同位置**。因此，让我们看看如何始终找到该地址。

使用提到的一些技巧，找到当前游戏存储重要值的地址。然后（如果您愿意停止游戏），在找到的**地址**上**右键单击**，然后选择“**查找访问此地址的内容**”或“**查找写入此地址的内容**”：

![](<../../.gitbook/assets/image (593).png>)

**第一个选项**有助于了解**代码的哪些部分**正在**使用**此**地址**（这对于更多事情如**知道在哪里可以修改游戏的代码**非常有用）。\
**第二个选项**更**具体**，在这种情况下将更有帮助，因为我们有兴趣知道**这个值是从哪里写入的**。

选择其中一个选项后，**调试器**将**附加**到程序，并将显示一个新的**空窗口**。现在，**玩**游戏并**修改**该**值**（无需重新启动游戏）。**窗口**应该**填满**正在**修改**值的**地址**：

![](<../../.gitbook/assets/image (594).png>)

现在您找到了修改值的地址，您可以**随意修改代码**（Cheat Engine允许您快速将其修改为NOPs）：

![](<../../.gitbook/assets/image (595).png>)

因此，您现在可以修改代码，使其不影响您的数字，或者始终以积极方式影响。

## 随机内存地址 - 查找指针

按照前面的步骤，找到您感兴趣的值的位置。然后，使用“**查找写入此地址的内容**”找出哪个地址写入此值，然后双击该地址以获取反汇编视图：

![](<../../.gitbook/assets/image (596).png>)

然后，执行新的扫描**搜索“\[\]”之间的十六进制值**（在这种情况下为$edx的值）：

![](<../../.gitbook/assets/image (597).png>)

（_如果出现多个，通常需要最小地址的一个）\
现在，我们已经**找到将修改我们感兴趣的值的指针**。

单击“**手动添加地址**”：

![](<../../.gitbook/assets/image (598).png>)

现在，选中“指针”复选框，并将找到的地址添加到文本框中（在此场景中，上一个图像中找到的地址是“Tutorial-i386.exe”+2426B0）：

![](<../../.gitbook/assets/image (599).png>)

（请注意，您输入指针地址后，第一个“地址”将自动填充）

单击“确定”，将创建一个新指针：

![](<../../.gitbook/assets/image (600).png>)

现在，每当您修改该值时，**即使值所在的内存地址不同，您也会修改重要值**。

## 代码注入

代码注入是一种技术，其中您将一段代码注入目标进程，然后重新路由代码执行以通过您编写的代码（例如给您积分而不是扣除积分）。

因此，假设您已找到正在减少玩家生命值的地址：

![](<../../.gitbook/assets/image (601).png>)

单击“显示反汇编器”以获取**反汇编代码**。\
然后，单击**CTRL+a**调用自动组装窗口，并选择_**模板 --> 代码注入**_

![](<../../.gitbook/assets/image (602).png>)

填写**要修改的指令的地址**（通常会自动填充）：

![](<../../.gitbook/assets/image (603).png>)

将生成一个模板：

![](<../../.gitbook/assets/image (604).png>)

因此，在“**newmem**”部分插入您的新汇编代码，并从“**originalcode**”中删除原始代码（如果您不希望执行它）。在此示例中，注入的代码将添加2点而不是减去1：

![](<../../.gitbook/assets/image (605).png>)

**单击执行等等，您的代码应该被注入到程序中，改变功能的行为！**

# **参考**

* **Cheat Engine教程，完成它以学习如何开始使用Cheat Engine**



<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我们 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
