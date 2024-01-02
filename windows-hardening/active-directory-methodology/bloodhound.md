# BloodHound & 其他 AD 枚举工具

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 如果你在**网络安全公司**工作，想在**HackTricks**上看到你的**公司广告**，或者想要获取**PEASS最新版本或下载HackTricks的PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列。
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) 来自 Sysinternal Suite：

> 一个高级的 Active Directory (AD) 查看器和编辑器。你可以使用 AD Explorer 轻松导航 AD 数据库，定义收藏位置，查看对象属性和属性而无需打开对话框，编辑权限，查看对象的架构，并执行复杂的搜索，这些搜索可以保存并重新执行。

### 快照

AD Explorer 可以创建 AD 的快照，以便你可以离线检查。\
它可以用来离线发现漏洞，或者比较 AD DB 随时间不同状态。

你将需要用户名、密码和连接方向（需要任何 AD 用户）。

要获取 AD 的快照，请转到 `File` --> `Create Snapshot` 并为快照输入名称。

## ADRecon

****[**ADRecon**](https://github.com/adrecon/ADRecon) 是一个工具，它从 AD 环境中提取并结合各种工件。这些信息可以在一个**特别格式化**的 Microsoft Excel **报告**中呈现，其中包括带有指标的摘要视图，以便于分析，并提供目标 AD 环境当前状态的整体图景。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound 是一个由嵌入式 React 前端（使用 [Sigma.js](https://www.sigmajs.org/)）和基于 [Go](https://go.dev/) 的 REST API 后端组成的单体式网络应用程序。它部署了一个 [Postgresql](https://www.postgresql.org/) 应用数据库和一个 [Neo4j](https://neo4j.com) 图形数据库，并通过 [SharpHound](https://github.com/BloodHoundAD/SharpHound) 和 [AzureHound](https://github.com/BloodHoundAD/AzureHound) 数据收集器获取数据。
>
>BloodHound 利用图论揭示 Active Directory 或 Azure 环境中隐藏的、通常是无意的关系。攻击者可以使用 BloodHound 轻松识别那些否则难以迅速识别的高度复杂的攻击路径。防御者可以使用 BloodHound 识别并消除这些相同的攻击路径。蓝队和红队都可以使用 BloodHound 轻松深入了解 Active Directory 或 Azure 环境中的权限关系。
>
>BloodHound CE 由 [BloodHound Enterprise Team](https://bloodhoundenterprise.io) 创建和维护。最初的 BloodHound 是由 [@\_wald0](https://www.twitter.com/\_wald0), [@CptJesus](https://twitter.com/CptJesus), 和 [@harmj0y](https://twitter.com/harmj0y) 创建的。
>
>来自 [https://github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)

因此，[Bloodhound](https://github.com/SpecterOps/BloodHound) 是一个神奇的工具，它可以自动枚举域，保存所有信息，找到可能的权限提升路径，并使用图表显示所有信息。

Booldhound 由两个主要部分组成：**数据收集器**和**可视化应用程序**。

**数据收集器**用于**枚举域并提取所有信息**，以一种可视化应用程序能够理解的格式。

**可视化应用程序使用 neo4j** 显示所有信息之间的关系，并显示域中不同的权限提升方式。

### 安装
BloodHound CE 创建后，整个项目为了使用 Docker 而更新，以便使用。最简单的开始方式是使用其预配置的 Docker Compose 配置。

1. 安装 Docker Compose。这应该包含在 [Docker Desktop](https://www.docker.com/products/docker-desktop/) 安装中。
2. 运行：
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. 在 Docker Compose 的终端输出中找到随机生成的密码。
4. 在浏览器中，导航至 http://localhost:8080/ui/login。使用用户名 admin 和日志中的随机生成密码登录。

完成这些操作后，你需要更改随机生成的密码，新界面就绪后，你可以直接从中下载摄取器。

### SharpHound

他们有几个选项，但如果你想从加入域的 PC 上运行 SharpHound，使用你当前的用户并提取所有信息，你可以执行：
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> 您可以在[此处](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)阅读更多关于**CollectionMethod**和循环会话的信息

如果您希望使用不同的凭据执行SharpHound，您可以创建一个CMD netonly会话，并从那里运行SharpHound：
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**了解更多关于Bloodhound的信息，请访问ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## 传统Bloodhound
### 安装

1. Bloodhound

要安装可视化应用程序，您需要安装**neo4j**和**bloodhound应用程序**。\
最简单的安装方法是：
```
apt-get install bloodhound
```
您可以**从[这里](https://neo4j.com/download-center/#community)下载neo4j社区版**。

1. 数据收集器

您可以从以下位置下载数据收集器：

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. 学习图形路径

Bloodhound附带多种查询，以突出显示敏感的妥协路径。可以添加自定义查询，以增强对象之间的搜索和关联等！

这个仓库有一系列不错的查询：https://github.com/CompassSecurity/BloodHoundQueries

安装过程：
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### 可视化应用程序执行

下载/安装所需应用程序后，让我们开始启动它们。\
首先，你需要**启动neo4j数据库**：
```bash
./bin/neo4j start
#or
service neo4j start
```
首次启动此数据库时，您需要访问 [http://localhost:7474/browser/](http://localhost:7474/browser/)。系统会要求您输入默认凭据（neo4j:neo4j），并且您将**需要更改密码**，因此请更改密码并牢记。

现在，启动**bloodhound应用程序**：
```bash
./BloodHound-linux-x64
#or
bloodhound
```
您将被提示输入数据库凭证：**neo4j:\<您的新密码>**

然后bloodhound将准备好摄取数据。

![](<../../.gitbook/assets/image (171) (1).png>)

### **Python bloodhound**

如果您有域凭证，您可以在任何平台上运行**python bloodhound数据摄取器**，因此您不需要依赖Windows。\
从[https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)下载，或者执行`pip3 install bloodhound`
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
如果您通过proxychains运行它，请添加`--dns-tcp`以便通过代理进行DNS解析工作。
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

此脚本将通过LDAP**安静地枚举Active Directory域**，解析用户、管理员、组等。

在[**SilentHound github**](https://github.com/layer8secure/SilentHound)查看。

### RustHound

用Rust编写的BloodHound，[**在这里查看**](https://github.com/OPENCYBER-FR/RustHound)。

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) 是一个工具，用于发现与Active Directory关联的**组策略**中的**漏洞**。\
你需要使用**任何域用户**从域内的主机**运行group3r**。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

**[**PingCastle**](https://www.pingcastle.com/documentation/)** 评估 AD 环境的安全状况，并提供带有图表的精美**报告**。

要运行它，可以执行二进制文件 `PingCastle.exe`，它将启动一个**交互式会话**，呈现一个选项菜单。默认使用的选项是 **`healthcheck`**，它将建立**域**的基线**概览**，并找出**配置错误**和**漏洞**。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在 HackTricks 中看到你的**公司广告**吗？或者你想要访问**PEASS 最新版本或下载 HackTricks 的 PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现 [**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **Twitter** 上**关注**我 [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
