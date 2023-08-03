<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) 是一个有用的程序，可以找到正在运行的游戏内存中保存的重要值的位置并进行更改。\
当你下载并运行它时，会出现一个教程，告诉你如何使用这个工具。如果你想学习如何使用这个工具，强烈建议你完成教程。

# 你在寻找什么？

![](<../../.gitbook/assets/image (580).png>)

这个工具非常有用，可以找到程序内存中某个值（通常是一个数字）的存储位置。\
通常数字以4字节的形式存储，但你也可以找到以双精度或浮点格式存储的数字，或者你可能想寻找与数字不同的东西。因此，你需要确保选择你想要搜索的内容：

![](<../../.gitbook/assets/image (581).png>)

你还可以指定不同类型的搜索：

![](<../../.gitbook/assets/image (582).png>)

你还可以勾选框，在扫描内存时停止游戏：

![](<../../.gitbook/assets/image (584).png>)

## 快捷键

在_**编辑 --> 设置 --> 快捷键**_中，你可以为不同的目的设置不同的**快捷键**，比如停止游戏（如果你想扫描内存的某个时刻非常有用）。还有其他选项可用：

![](<../../.gitbook/assets/image (583).png>)

# 修改值

一旦你找到了你要查找的值的位置（关于这一点，后面的步骤会有更多介绍），你可以双击它来修改它，然后双击它的值：

![](<../../.gitbook/assets/image (585).png>)

最后，勾选复选框以在内存中进行修改：

![](<../../.gitbook/assets/image (586).png>)

对内存的修改将立即生效（请注意，直到游戏再次使用这个值，该值在游戏中不会更新）。

# 搜索值

所以，我们假设有一个重要的值（比如你的用户的生命值），你想要改进它，你正在寻找这个值在内存中的位置）

## 通过已知的变化

假设你正在寻找值100，你执行一个搜索以查找该值，你找到了很多匹配项：

![](<../../.gitbook/assets/image (587).png>)

然后，你做一些事情使值改变，你停止游戏并执行下一个搜索：

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine将搜索从100到新值的值。恭喜，你找到了你要找的值的地址，现在你可以修改它。\
_如果你仍然有几个值，做一些修改以再次修改该值，并执行另一个"下一个搜索"来过滤地址。_

## 未知值，已知变化

在这种情况下，你不知道值，但你知道如何使它改变（甚至知道变化的值），你可以寻找你的数字。

所以，首先执行一个类型为"**未知初始值**"的搜索：

![](<../../.gitbook/assets/image (589).png>)

然后，使值改变，指示值的改变方式（在我的例子中，它减少了1），并执行一个**下一个搜索**：

![](<../../.gitbook/assets/image (590).png>)

你将看到所有以所选方式修改的值：

![](<../../.gitbook/assets/image (591).png>)

一旦你找到了你的值，你可以修改它。

请注意，有很多可能的变化，你可以根据需要多次执行这些步骤来过滤结果：

![](<../../.gitbook/assets/image (592).png>)
## 随机内存地址 - 查找代码

到目前为止，我们已经学会了如何找到存储值的地址，但是在游戏的不同执行中，该地址很可能在内存的不同位置。因此，让我们找出如何始终找到该地址。

使用之前提到的一些技巧，找到当前游戏存储重要值的地址。然后（如果希望停止游戏），在找到的地址上**右键单击**，选择“**查找访问此地址的内容**”或“**查找写入此地址的内容**”：

![](<../../.gitbook/assets/image (593).png>)

第一个选项对于了解代码的哪些部分正在使用此地址很有用（对于其他一些事情也很有用，比如了解可以修改游戏代码的位置）。第二个选项更具体，在这种情况下更有帮助，因为我们想知道这个值是从哪里被写入的。

选择其中一个选项后，调试器将附加到程序上，并出现一个新的空窗口。现在，**玩游戏**并**修改**该**值**（不重新启动游戏）。该**窗口**应该被**填充**了**修改**该**值**的**地址**：

![](<../../.gitbook/assets/image (594).png>)

现在，您找到了修改该值的地址，您可以随意修改代码（Cheat Engine允许您快速将其修改为NOP）：

![](<../../.gitbook/assets/image (595).png>)

因此，您现在可以修改它，以便代码不会影响您的数字，或者始终以积极的方式影响。

## 随机内存地址 - 查找指针

按照前面的步骤，找到您感兴趣的值所在的位置。然后，使用“**查找写入此地址的内容**”找出写入此值的地址，并双击它以获取反汇编视图：

![](<../../.gitbook/assets/image (596).png>)

然后，执行新的扫描，**搜索“\[\]”之间的十六进制值**（在本例中为$edx的值）：

![](<../../.gitbook/assets/image (597).png>)

（如果出现多个，通常需要最小的地址）\
现在，我们找到了将修改我们感兴趣的值的指针。

单击“**手动添加地址**”：

![](<../../.gitbook/assets/image (598).png>)

现在，单击“指针”复选框，并将找到的地址添加到文本框中（在此场景中，先前图像中找到的地址是“Tutorial-i386.exe”+2426B0）：

![](<../../.gitbook/assets/image (599).png>)

（注意，第一个“地址”是根据您输入的指针地址自动填充的）

单击“确定”，将创建一个新的指针：

![](<../../.gitbook/assets/image (600).png>)

现在，每当您修改该值时，即使存储该值的内存地址不同，您也会修改重要值。

## 代码注入

代码注入是一种技术，您将一段代码注入到目标进程中，然后将代码的执行重定向到您自己编写的代码（例如，给您加分而不是扣分）。

因此，假设您已经找到了将您的玩家生命减1的地址：

![](<../../.gitbook/assets/image (601).png>)

单击“显示反汇编器”以获取**反汇编代码**。\
然后，单击**CTRL+a**调用自动汇编窗口，并选择_**模板 --> 代码注入**_

![](<../../.gitbook/assets/image (602).png>)

填写**要修改的指令的地址**（通常会自动填充）：

![](<../../.gitbook/assets/image (603).png>)

将生成一个模板：

![](<../../.gitbook/assets/image (604).png>)

因此，在“**newmem**”部分插入您的新汇编代码，并从“**originalcode**”中删除原始代码（如果您不希望执行它）。在此示例中，注入的代码将添加2个点而不是减去1个点：

![](<../../.gitbook/assets/image (605).png>)

**单击执行等等，您的代码应该被注入到程序中，改变功能的行为！**

# **参考资料**

* **Cheat Engine教程，完成它以了解如何开始使用Cheat Engine**



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks衣物**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧**。

</details>
