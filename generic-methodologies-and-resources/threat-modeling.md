# 威胁建模

## 威胁建模

欢迎来到HackTricks关于威胁建模的全面指南！在这个关键的网络安全方面，我们将识别、理解和制定对系统潜在漏洞的策略。本文提供了一份逐步指南，其中包含了真实世界的示例、有用的软件和易于理解的解释。非常适合初学者和有经验的从业人员，希望加强他们的网络安全防御能力。

### 常用场景

1. **软件开发**：作为安全软件开发生命周期（SSDLC）的一部分，威胁建模有助于在开发的早期阶段**识别潜在的漏洞来源**。
2. **渗透测试**：渗透测试执行标准（PTES）框架要求在进行测试之前进行威胁建模，以了解系统的漏洞。

### 威胁模型简介

威胁模型通常以图表、图像或其他形式的可视化说明来表示，这些说明描述了应用程序的计划架构或现有构建。它类似于**数据流图**，但其关键区别在于其面向安全的设计。

威胁模型通常包含以红色标记的元素，表示潜在的漏洞、风险或障碍。为了简化风险识别的过程，采用了CIA（机密性、完整性、可用性）三元组，这是许多威胁建模方法的基础，其中STRIDE是最常用的方法之一。然而，选择的方法可能因具体的上下文和要求而有所不同。

### CIA三元组

CIA三元组是信息安全领域广泛认可的模型，代表机密性（Confidentiality）、完整性（Integrity）和可用性（Availability）。这三个支柱构成了许多安全措施和政策的基础，包括威胁建模方法。

1. **机密性**：确保数据或系统不被未经授权的个人访问。这是安全的核心方面，需要适当的访问控制、加密和其他措施来防止数据泄露。
2. **完整性**：数据在其生命周期内的准确性、一致性和可信度。这个原则确保数据不被未经授权的人篡改或篡改。它通常涉及校验和哈希等数据验证方法。
3. **可用性**：确保数据和服务在需要时对授权用户可访问。这通常涉及冗余、容错和高可用性配置，以确保系统即使在面临干扰时也能正常运行。

### 威胁建模方法

1. **STRIDE**：由微软开发，STRIDE是**欺骗、篡改、否认、信息泄露、拒绝服务和权限提升**的首字母缩写。每个类别代表一种威胁类型，这种方法通常在程序或系统的设计阶段用于识别潜在威胁。
2. **DREAD**：这是微软的另一种用于已识别威胁的风险评估方法。DREAD代表**损害潜力、可重现性、可利用性、受影响的用户和可发现性**。对这些因素进行评分，并将结果用于优先考虑已识别的威胁。
3. **PASTA**（攻击模拟和威胁分析过程）：这是一个包含七个步骤的**以风险为中心**的方法。它包括定义和识别安全目标、创建技术范围、应用程序分解、威胁分析、漏洞分析和风险/分类评估。
4. **Trike**：这是一种以风险管理为重点的方法，侧重于保护资产。它从**风险管理**的角度出发，考虑威胁和漏洞。
5. **VAST**（可视化、敏捷和简单的威胁建模）：这种方法旨在更易于理解，并集成到敏捷开发环境中。它结合了其他方法的要素，并侧重于**威胁的可视化表示**。
6. **OCTAVE**（运营关键威胁、资产和漏洞评估）：由CERT协调中心开发，该框架针对**组织风险评估而非特定系统或软件**。

## 工具

有几种可用的工具和软件解决方案可以**辅助**创建和管理威胁模型。以下是一些您可能考虑的工具。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

一款先进的跨平台、多功能GUI网络蜘蛛/爬虫，适用于网络安全专业人员。Spider Suite可用于攻击面映射和分析。

**用法**

1. 选择一个URL并进行爬行

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 查看图形

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP的一个开源项目，Threat Dragon是一个包含系统图形化和规则引擎自动生成威胁/缓解措施的Web和桌面应用程序。

**用法**

1. 创建新项目

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

有时它可能看起来像这样：

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 启动新项目

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 保存新项目

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 创建您的模型

您可以使用SpiderSuite Crawler等工具来给您灵感，一个基本的模型可能如下所示

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

对实体的一点解释：

* 进程（实体本身，如Web服务器或Web功能）
* 演员（人员，如网站访问者、用户或管理员）
* 数据流线（交互指示器）
* 信任边界（不同的网络段或范围）
* 存储（存储数据的地方，如数据库）

5. 创建威胁（步骤1）

首先，您必须选择要向其添加威胁的层

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

现在您可以创建威胁

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

请记住，演员威胁和进程威胁之间存在区别。如果您向演员添加威胁，那么您只能选择“欺骗”和“否认”。然而，在我们的示例中，我们向进程实体添加威胁，因此在威胁创建框中我们将看到以下内容：

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完成

现在，您完成的模型应该看起来像这样。这就是您如何使用OWASP Threat Dragon创建一个简单的威胁模型。

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Microsoft威胁建模工具](https://aka.ms/threatmodelingtool)

这是微软提供的免费工具，可帮助在软件项目的设计阶段发现威胁。它使用STRIDE方法论，特别适用于在微软的技术栈上进行开发的人员。
