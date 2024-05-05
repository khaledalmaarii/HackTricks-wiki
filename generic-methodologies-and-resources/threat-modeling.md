# 威胁建模

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) 是一个由**暗网**推动的搜索引擎，提供**免费**功能，用于检查公司或其客户是否已受到**窃取恶意软件**的**威胁**。

WhiteIntel的主要目标是打击由信息窃取恶意软件导致的账户劫持和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}

***

## 威胁建模

欢迎来到HackTricks关于威胁建模的全面指南！探索这个关键的网络安全方面，我们在这里识别、理解并制定对抗系统潜在漏洞的策略。本文提供了一步一步的指南，包含了现实世界的示例、有用的软件和易于理解的解释。适用于初学者和有经验的从业者，希望加强他们的网络安全防御。

### 常用场景

1. **软件开发**：作为安全软件开发生命周期（SSDLC）的一部分，威胁建模有助于在开发的早期阶段**识别潜在的漏洞来源**。
2. **渗透测试**：渗透测试执行标准（PTES）框架要求在进行测试之前进行威胁建模，以了解系统的漏洞。

### 威胁模型简介

威胁模型通常以图表、图像或其他形式的视觉展示来表示，展示了应用程序的计划架构或现有构建。它类似于**数据流图**，但其关键区别在于其面向安全的设计。

威胁模型通常包含用红色标记的元素，表示潜在的漏洞、风险或障碍。为了简化风险识别过程，通常采用CIA（机密性、完整性、可用性）三元组，构成许多威胁建模方法的基础，STRIDE是其中最常见的之一。然而，选择的方法可能会根据具体的上下文和要求而有所不同。

### CIA三元组

CIA三元组是信息安全领域中广泛认可的模型，代表机密性、完整性和可用性。这三个支柱构成了许多安全措施和政策的基础，包括威胁建模方法。

1. **机密性**：确保数据或系统不被未经授权的个人访问。这是安全的核心方面，需要适当的访问控制、加密和其他措施来防止数据泄露。
2. **完整性**：数据在其生命周期中的准确性、一致性和可信度。这一原则确保数据不会被未经授权的方进行更改或篡改。通常涉及校验和哈希等数据验证方法。
3. **可用性**：确保数据和服务在需要时对授权用户可访问。这通常涉及冗余、容错和高可用配置，以确保即使面临中断，系统也能继续运行。

### 威胁建模方法

1. **STRIDE**：由微软开发，STRIDE是**欺骗、篡改、否认、信息披露、服务拒绝和权限提升**的首字母缩写。每个类别代表一种威胁类型，这种方法通常用于程序或系统设计阶段，以识别潜在威胁。
2. **DREAD**：这是微软的另一种用于已识别威胁的风险评估方法。DREAD代表**破坏潜力、可重现性、可利用性、受影响用户和可发现性**。对这些因素进行评分，并使用结果对已识别的威胁进行优先排序。
3. **PASTA**（攻击模拟和威胁分析过程）：这是一个七步骤的**以风险为中心**的方法。它包括定义和识别安全目标、创建技术范围、应用程序分解、威胁分析、漏洞分析和风险/分类评估。
4. **Trike**：这是一个以风险管理为基础的方法，侧重于保护资产。它从**风险管理**的角度出发，查看威胁和漏洞。
5. **VAST**（可视化、敏捷和简单威胁建模）：这种方法旨在更易于访问，并集成到敏捷开发环境中。它结合了其他方法的元素，侧重于**威胁的可视化呈现**。
6. **OCTAVE**（运营关键威胁、资产和漏洞评估）：由CERT协调中心开发，该框架旨在进行**组织风险评估，而不是特定系统或软件**。

## 工具

有几种可用的工具和软件解决方案可**帮助**创建和管理威胁模型。以下是您可能考虑的一些工具。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

一款先进的跨平台、多功能GUI网络蜘蛛/爬虫，适用于网络安全专业人员。Spider Suite可用于攻击面映射和分析。

**用法**

1. 选择一个URL并爬取

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 查看图表

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

来自OWASP的开源项目，Threat Dragon是一个包含系统图示和规则引擎以自动生成威胁/缓解措施的Web和桌面应用程序。

**用法**

1. 创建新项目

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

有时看起来可能像这样：

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 启动新项目

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 保存新项目

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 创建您的模型

您可以使用工具如SpiderSuite爬虫来给您灵感，一个基本模型可能看起来像这样

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

对实体的简要解释：

* 过程（实体本身，如Web服务器或Web功能）
* 演员（人员，如网站访问者、用户或管理员）
* 数据流线（交互指示器）
* 信任边界（不同的网络段或范围。）
* 存储（数据存储的地方，如数据库）

5. 创建威胁（步骤1）

首先，您必须选择要向其添加威胁的层

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

现在您可以创建威胁

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

请注意，演员威胁和过程威胁之间存在区别。如果您向演员添加威胁，那么您只能选择“欺骗”和“否认”。然而，在我们的示例中，我们向过程实体添加威胁，因此我们将在威胁创建框中看到这一点：

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完成

现在您完成的模型应该看起来像这样。这就是您如何使用OWASP Threat Dragon制作简单的威胁模型。
### [Microsoft威胁建模工具](https://aka.ms/threatmodelingtool)

这是微软提供的免费工具，可帮助在软件项目的设计阶段发现威胁。它使用STRIDE方法论，特别适用于在微软平台上开发的人员。

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) 是一个由**暗网**支持的搜索引擎，提供免费功能，用于检查公司或其客户是否受到**窃取恶意软件**的**威胁**。

WhiteIntel的主要目标是打击由窃取信息恶意软件导致的账户劫持和勒索软件攻击。

您可以访问他们的网站并免费尝试他们的引擎：

{% embed url="https://whiteintel.io" %}
