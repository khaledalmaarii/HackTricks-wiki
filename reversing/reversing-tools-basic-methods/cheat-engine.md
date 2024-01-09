<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个有用的程序，用于找到重要值在运行中的游戏内存中的保存位置，并更改它们。\
当您下载并运行它时，会**呈现**一个如何使用该工具的**教程**。如果您想学习如何使用该工具，强烈建议完成它。

# 您在寻找什么？

![](<../../.gitbook/assets/image (580).png>)

此工具非常有用，用于找到**某些值**（通常是一个数字）**存储在程序内存中的位置**。\
**通常数字**以**4字节**形式存储，但您也可能以**双精度**或**浮点**格式找到它们，或者您可能想要寻找**与数字不同的东西**。因此，您需要确保您**选择**您想要**搜索的内容**：

![](<../../.gitbook/assets/image (581).png>)

您还可以指示**不同**类型的**搜索**：

![](<../../.gitbook/assets/image (582).png>)

您还可以勾选框以**在扫描内存时停止游戏**：

![](<../../.gitbook/assets/image (584).png>)

## 快捷键

在 _**编辑 --> 设置 --> 快捷键**_ 中，您可以设置不同的**快捷键**用于不同的目的，如**停止**游戏（如果您在某个时刻想要扫描内存，这非常有用）。其他选项可用：

![](<../../.gitbook/assets/image (583).png>)

# 修改值

一旦您**找到**了您正在**寻找的值**的位置（在接下来的步骤中会有更多关于这个的内容），您可以通过双击它，然后双击它的值来**修改它**：

![](<../../.gitbook/assets/image (585).png>)

最后**标记复选框**以在内存中完成修改：

![](<../../.gitbook/assets/image (586).png>)

**内存中的更改**将立即**应用**（请注意，直到游戏再次使用这个值，游戏中的值**不会更新**）。

# 搜索值

所以，我们假设有一个重要的值（比如您用户的生命值）您想要提高，您正在内存中寻找这个值）

## 通过已知变化

假设您正在寻找值100，您**执行扫描**搜索该值，并找到了很多匹配项：

![](<../../.gitbook/assets/image (587).png>)

然后，您做了一些事情使得**值发生变化**，然后您**停止**游戏并**执行**一个**下一次扫描**：

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine将搜索**从100变为新值的值**。恭喜，您**找到**了您正在寻找的值的**地址**，您现在可以修改它。\
_如果您仍然有几个值，做一些事情再次修改那个值，并执行另一个"下一次扫描"来过滤地址。_

## 未知值，已知变化

在您**不知道值**但知道**如何使其变化**（甚至知道变化的值）的情况下，您可以寻找您的数字。

所以，首先执行一个类型为“**未知初始值**”的扫描：

![](<../../.gitbook/assets/image (589).png>)

然后，使值发生变化，指明**值是如何变化的**（在我的案例中它减少了1）并执行一个**下一次扫描**：

![](<../../.gitbook/assets/image (590).png>)

您将被呈现**以选定方式修改的所有值**：

![](<../../.gitbook/assets/image (591).png>)

一旦您找到了您的值，您可以修改它。

请注意，有很多**可能的变化**，您可以根据需要执行这些**步骤尽可能多**以过滤结果：

![](<../../.gitbook/assets/image (592).png>)

## 随机内存地址 - 查找代码

到目前为止，我们学习了如何找到存储值的地址，但很有可能在**游戏的不同执行中，该地址位于内存的不同位置**。所以让我们找出如何总是找到那个地址。

使用一些提到的技巧，找到您当前游戏正在存储重要值的地址。然后（如果您愿意可以停止游戏）在找到的**地址**上**右键单击**，选择“**找出访问此地址的内容**”或“**找出写入此地址的内容**”：

![](<../../.gitbook/assets/image (593).png>)

**第一个选项**对于知道哪些**代码部分**正在**使用**这个**地址**很有用（这对于更多事情如**知道您可以在哪里修改游戏代码**很有用）。\
**第二个选项**更**具体**，在这种情况下将更有帮助，因为我们感兴趣的是知道**这个值是从哪里被写入的**。

选择其中一个选项后，**调试器**将**附加**到程序上，并且一个新的**空窗口**将出现。现在，**玩**游戏并**修改**那个**值**（不重启游戏）。**窗口**应该会被**填满**正在**修改**该**值**的**地址**：

![](<../../.gitbook/assets/image (594).png>)

现在您找到了正在修改值的地址，您可以**随心所欲地修改代码**（Cheat Engine允许您快速将其修改为NOPs）：

![](<../../.gitbook/assets/image (595).png>)

所以，您现在可以修改它，使得代码不会影响您的数字，或者总是以积极的方式影响。

## 随机内存地址 - 查找指针

按照前面的步骤，找到您感兴趣的值所在的位置。然后，使用“**找出写入此地址的内容**”找出哪个地址写入了这个值，并双击它以获取反汇编视图：

![](<../../.gitbook/assets/image (596).png>)

然后，执行一个新的扫描**搜索“\[]”之间的十六进制值**（在这种情况下是$edx的值）：

![](<../../.gitbook/assets/image (597).png>)

（_如果出现几个，通常需要地址最小的那个_）\
现在，我们已经**找到了将修改我们感兴趣的值的指针**。

点击“**手动添加地址**”：

![](<../../.gitbook/assets/image (598).png>)

现在，勾选“指针”复选框，并在文本框中添加找到的地址（在这个场景中，前面图片中找到的地址是“Tutorial-i386.exe”+2426B0）：

![](<../../.gitbook/assets/image (599).png>)

（注意第一个“地址”是自动从您输入的指针地址中填充的）

点击确定，一个新的指针将被创建：

![](<../../.gitbook/assets/image (600).png>)

现在，每次您修改那个值，您都在**修改重要的值，即使值所在的内存地址不同。**

## 代码注入

代码注入是一种技术，您将一段代码注入到目标进程中，然后重新路由代码的执行，通过您自己编写的代码（比如给您加分而不是减分）。

所以，想象一下您已经找到了减去玩家生命值1点的地址：

![](<../../.gitbook/assets/image (601).png>)

点击显示反汇编器以获取**反汇编代码**。\
然后，点击**CTRL+a**调用自动组装窗口并选择 _**模板 --> 代码注入**_

![](<../../.gitbook/assets/image (602).png>)

填写**您想要修改的指令的地址**（这通常是自动填充的）：

![](<../../.gitbook/assets/image (603).png>)

将生成一个模板：

![](<../../.gitbook/assets/image (604).png>)

所以，在“**newmem**”部分插入您的新汇编代码，并从“**originalcode**”中删除原始代码，如果您不希望它被执行**。**在这个例子中，注入的代码将增加2分而不是减去1分：

![](<../../.gitbook/assets/image (605).png>)

**点击执行等等，您的代码应该被注入程序中，改变功能的行为！**

# **参考资料**

* **Cheat Engine教程，完成它以学习如何开始使用Cheat Engine**



<details>

<summary><strong>通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>从零开始学习AWS黑客攻击成为英雄！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>
