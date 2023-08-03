# INE课程和eLearnSecurity认证评价

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## eLearnSecurity移动应用渗透测试员（eMAPT）和相应的INE课程

### 课程：[**Android和移动应用渗透测试**](https://my.ine.com/CyberSecurity/courses/cfd5ec2b/android-mobile-app-pentesting)

这门课程是为了**准备eMAPT证书考试**而设计的。它将教你**Android的基础知识**，应用程序的工作原理，Android应用程序的**最敏感的组件**，以及如何**配置和使用**主要的**工具**来测试应用程序。目标是**让你能够在实际生活中对Android应用程序进行渗透测试**。

我发现这门课程对于**没有任何经验的Android应用程序渗透测试人员**来说是一门很好的课程。然而，**如果**你是一个在这个领域有**经验**的人，并且你有机会接触到这门课程，我也建议你**去看一看**。这是我的情况，即使我有几年的Android应用程序渗透测试经验，**这门课程还教会了我一些我不知道的Android基础知识和一些新技巧**。

最后，关于这门课程还有**两点需要注意**：它有很好的实验室来练习你所学到的知识，然而，它**并没有解释你在Android应用程序中可能遇到的所有漏洞**。不过，这并不是问题，因为**它教会了你基础知识，以便能够理解其他Android漏洞**。\
此外，一旦你完成了这门课程（或之前），你可以去[**Hacktricks Android应用程序渗透测试部分**](../mobile-pentesting/android-app-pentesting/)学习更多技巧。

### 课程：[**iOS和移动应用渗透测试**](https://my.ine.com/CyberSecurity/courses/089d060b/ios-mobile-app-pentesting)

当我学习这门课程时，我对iOS应用程序没有太多经验，我发现这门课程是一个很好的资源，可以让我快速入门，所以如果你有机会学习这门课程，不要错过机会。与前一门课程一样，这门课程将教你**iOS的基础知识**，应用程序的工作原理，应用程序的**最敏感的组件**，以及如何**配置和使用**主要的**工具**来测试应用程序。\
然而，与Android课程相比，这门课程有一个非常重要的区别，如果你想进行实验室练习，我建议你**获取一个越狱的iOS设备或支付一些好的iOS模拟器**。

与前一门课程一样，这门课程有一些非常有用的实验室来练习你所学到的知识，但它并没有解释iOS应用程序的所有可能漏洞。然而，这并不是问题，因为**它教会了你基础知识，以便能够理解其他iOS漏洞**。\
此外，一旦你完成了这门课程（或之前），你可以去[**Hacktricks iOS应用程序渗透测试部分**](../mobile-pentesting/ios-pentesting/)学习更多技巧。

### [eMAPT](https://elearnsecurity.com/product/emapt-certification/)

> eLearnSecurity移动应用渗透测试员（eMAPT）认证是通过基于场景的考试来展示网络安全专家具备高级移动应用程序安全知识的认证。

这个证书的目标是**展示**你能够进行常见的**移动应用程序渗透测试**。

在考试中，你会**获得两个有漏洞的Android应用程序**，你需要**创建**一个**Android应用程序**，自动**利用**这些漏洞。为了**通过考试**，你需要**发送**这个**利用应用程序**（apk和代码），并且它必须**利用其他应用程序的漏洞**。

完成[**关于Android应用程序渗透测试的INE课程**](https://my.ine.com/CyberSecurity/courses/cfd5ec2b/android-mobile-app-pentesting)已经**足够**找到应用程序的漏洞。我发现考试中更“复杂”的部分是编写一个利用漏洞的Android应用程序。然而，作为Java开发人员有一些经验，并在互联网上寻找关于我想做的事情的教程，**我能够在几个小时内完成考试**。他们给你7天的时间来完成考试，所以如果你找到了漏洞，你将有足够的时间来开发利用应用程序。

在这次考试中，**我错过了利用更多漏洞的机会**，然而，**我对编写Android应用程序来利用漏洞的“恐惧”减少了一些**。所以它感觉就像是**课程的另一部分，来完善你在Android应用程序渗透测试方面的知识**。
## eLearnSecurity Web application Penetration Tester eXtreme (eWPTXv2)和相关的INE课程

### 课程：[**Web应用程序渗透测试eXtreme**](https://my.ine.com/CyberSecurity/courses/630a470a/web-application-penetration-testing-extreme)

这门课程旨在为您准备**eWPTXv2**证书考试。即使在上这门课之前我已经作为Web渗透测试员工作了几年，但它还是教会了我一些关于“奇怪”的Web漏洞和绕过保护的**很棒的黑客技巧**。此外，该课程包含了一些非常好的实验室，您可以在其中练习所学的知识，这对于完全理解漏洞非常有帮助。

我认为这门课**不适合Web黑客的初学者**（还有其他INE课程，如[**Web应用程序渗透测试**](https://my.ine.com/CyberSecurity/courses/38316560/web-application-penetration-testing)**）。**然而，如果您不是初学者，无论您认为自己在Web黑客方面的水平如何，**我绝对建议您看一下这门课**，因为我确信您会像我一样学到新的东西。

## eLearnSecurity认证数字取证专业人员（eCDFP）和相应的INE课程

### 课程：[**认证数字取证专业人员**](https://ine.com/learning/certifications/internal/elearnsecurity-certified-digital-forensics-professional)

这门课程是为了**准备eCDFP证书考试**。它将教您**数字取证的基础知识**，操作系统的工作原理，可以用于进行数字取证的操作系统的**最有价值的组件**，以及如何**配置和使用**主要的**工具**进行数字取证。目标是**让您能够在实际生活中进行数字取证**。

我发现这门课程非常适合**没有任何数字取证经验**的人。然而，**如果**您是一个**有经验**的人，并且可以访问这门课程，我也建议您**看一下**。当我上这门课时，这正是我的情况，即使我有几年的数字取证经验，**这门课程也教会了我一些很棒的基础知识和一些新的技巧**。

最后，注意这门课程的**两个重要事项**：它有**很棒的实验室**可以练习所学的知识。它还为您提供了开始进行**数字取证**并在实际场景中独立进行的基线。

### [eWPTXv2](https://elearnsecurity.com/product/ewptxv2-certification/)

> eLearnSecurity Web应用程序渗透测试员eXtreme（eWAPTX）是我们最高级的Web应用程序渗透测试认证。eWPTX考试要求学生进行一次专家级渗透测试，然后由INE的网络安全讲师进行评估。学生需要提供一份完整的报告，详细说明他们发现的所有漏洞，以及如何利用这些漏洞和如何修复它们，以通过考试。

考试由**几个充满漏洞的Web应用程序**组成。为了通过考试，您需要利用Web漏洞来攻击几台机器。然而，请注意，仅仅攻击机器是不足以通过考试的，您需要**发送一份详细的专业渗透测试报告**，详细说明所有发现的漏洞，如何利用它们以及如何修复它们。\
我报告了**超过10个独特的漏洞**（其中大多数是高/严重漏洞，并且分布在Web的不同位置），包括读取标志的漏洞和多种获得RCE的方法，我通过了考试。

**我报告的所有漏洞都可以在**[**Web应用程序渗透测试eXtreme课程**](https://my.ine.com/CyberSecurity/courses/630a470a/web-application-penetration-testing-extreme)**中找到解释**。然而，为了通过这个考试，我认为您**不仅需要了解Web漏洞**，还需要**有经验来利用它们**。因此，如果您正在上这门课程，至少要通过实验室进行练习，并可能在其他平台上玩耍，以提高您利用Web漏洞的技能。

## 课程：**Google云平台上的数据科学**

\
这是一门非常有趣的基础课程，教您如何使用Google提供的ML环境，使用诸如big-query（用于存储和加载结果）、Google深度学习API（Google Vision API、Google Speech API、Google Natural Language API和Google Video Intelligence API）甚至如何训练自己的模型。

## 课程：**使用scikit-learn进行机器学习入门**

在课程[**使用scikit-learn进行机器学习入门**](https://my.ine.com/DataScience/courses/58c4e71b/machine-learning-with-scikit-learn-starter-pass)中，您将学习如何使用scikit-learn创建机器学习模型，正如名称所示。

这对于没有使用过scikit-learn的人来说是绝对推荐的（但要了解Python）。

## **课程：分类算法**

[**分类算法课程**](https://my.ine.com/DataScience/courses/2c6de5ea/classification-algorithms)是一个非常适合刚开始学习机器学习的人的课程。在这里，您将找到有关您需要了解的主要分类算法的信息，以及一些数学概念，如**逻辑回归**和**梯度下降**，**KNN**，**SVM**和**决策树**。

它还展示了如何使用scikit-learn创建模型。

## 课程：**决策树**

[**决策树课程**](https://my.ine.com/DataScience/courses/83fcfd52/decision-trees)对于提高我对**决策树和回归树**的了解非常有用，以及它们何时有用，它们的工作原理以及如何正确调整它们。

它还解释了如何使用scikit-learn创建树模型，不同的技术来**衡量创建的模型的好坏**以及如何**可视化树**。

我唯一发现的缺点是在某些情况下，对于所使用的算法如何工作的数学解释有些不足。然而，这门课程对于正在学习机器学习的人非常有用。

##

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 您在**网络安全公司**工作吗？您想在HackTricks中看到您的**公司广告**吗？或者您想获得最新版本的PEASS或下载PDF格式的HackTricks吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFT](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
- **加入** [💬](https://emojipedia.org/speech-balloon/) [Discord 群组](https://discord.gg/hRep4RUj7f) 或 [Telegram 群组](https://t.me/peass)，或者在 Twitter 上 **关注我** [🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[@carlospolopm](https://twitter.com/hacktricks_live)**。**

- **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
