# BloodHound & 其他 AD 枚举工具

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在 **网络安全公司** 工作吗？ 想要在 HackTricks 中看到您的 **公司广告**？ 或者想要访问 **PEASS 的最新版本或下载 PDF 格式的 HackTricks**？ 请查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family) 集合 [**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord 群组**](https://discord.gg/hRep4RUj7f) 或 **电报群组** 或 **关注** 我的 **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享您的黑客技巧**。

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) 来自 Sysinternal Suite：

> 一个高级的 Active Directory (AD) 查看器和编辑器。您可以使用 AD Explorer 轻松浏览 AD 数据库，定义喜爱的位置，查看对象属性和属性而无需打开对话框，编辑权限，查看对象的模式，并执行可以保存和重新执行的复杂搜索。

### 快照

AD Explorer 可以创建 AD 的快照，以便您可以离线检查。\
它可用于离线发现漏洞，或比较 AD 数据库在不同时间点的不同状态。

您将需要用户名、密码和连接方向（需要任何 AD 用户）。

要对 AD 进行快照，转到 `File` --> `Create Snapshot` 并输入快照的名称。

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) 是一个从 AD 环境中提取和组合各种工件的工具。该信息可以呈现在一个 **特别格式化** 的 Microsoft Excel **报告** 中，其中包括摘要视图和指标，以便分析并提供目标 AD 环境当前状态的整体图片。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound是一个庞大的Web应用程序，由嵌入式React前端与[Sigma.js](https://www.sigmajs.org/)以及基于[Go](https://go.dev/)的REST API后端组成。它部署了一个[Postgresql](https://www.postgresql.org/)应用程序数据库和一个[Neo4j](https://neo4j.com)图形数据库，并由[SharpHound](https://github.com/BloodHoundAD/SharpHound)和[AzureHound](https://github.com/BloodHoundAD/AzureHound)数据收集器提供数据。
>
>BloodHound使用图论来揭示Active Directory或Azure环境中隐藏且通常意外的关系。攻击者可以使用BloodHound轻松识别高度复杂的攻击路径，否则将无法快速识别。防御者可以使用BloodHound识别并消除相同的攻击路径。蓝队和红队都可以使用BloodHound轻松获得对Active Directory或Azure环境中特权关系的更深入了解。
>
>BloodHound CE由[BloodHound Enterprise Team](https://bloodhoundenterprise.io)创建和维护。最初的BloodHound由[@\_wald0](https://www.twitter.com/\_wald0)、[@CptJesus](https://twitter.com/CptJesus)和[@harmj0y](https://twitter.com/harmj0y)创建。
>
>来自[https://github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)

因此，[Bloodhound](https://github.com/SpecterOps/BloodHound)是一个令人惊叹的工具，可以自动枚举域，保存所有信息，找到可能的特权升级路径，并使用图形显示所有信息。

Booldhound由两个主要部分组成：**摄取器**和**可视化应用程序**。

**摄取器**用于**枚举域并提取所有信息**，以便可视化应用程序理解。

**可视化应用程序使用neo4j**显示所有信息的关系以及显示域中提升特权的不同方式。

### 安装
在创建BloodHound CE之后，整个项目已更新以便使用Docker更轻松。开始的最简单方法是使用其预配置的Docker Compose配置。

1. 安装Docker Compose。这应该包含在[Docker Desktop](https://www.docker.com/products/docker-desktop/)安装中。
2. 运行：
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. 在Docker Compose的终端输出中找到随机生成的密码。
4. 在浏览器中，导航至 http://localhost:8080/ui/login。使用用户名admin和日志中随机生成的密码登录。

完成后，您需要更改随机生成的密码，然后新界面将准备就绪，您可以直接从中下载ingestors。

### SharpHound

它们有几个选项，但如果您想要从加入域的PC上运行SharpHound，使用当前用户并提取所有信息，您可以执行：
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> 您可以在[此处](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)阅读有关**CollectionMethod**和循环会话的更多信息。

如果您希望使用不同凭据执行SharpHound，可以创建一个CMD netonly会话，并从那里运行SharpHound：
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**在 ired.team 了解更多关于 Bloodhound。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## 传统 Bloodhound
### 安装

1. Bloodhound

要安装可视化应用程序，您需要安装 **neo4j** 和 **bloodhound 应用程序**。\
最简单的方法就是执行以下操作：
```
apt-get install bloodhound
```
您可以从[这里](https://neo4j.com/download-center/#community)下载neo4j的社区版本。

1. Ingestors

您可以从以下位置下载Ingestors：

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. 从图中学习路径

Bloodhound带有各种查询，用于突出显示敏感的妥协路径。可以添加自定义查询以增强搜索和对象之间的关联等功能！

此存储库具有一组不错的查询：https://github.com/CompassSecurity/BloodHoundQueries

安装过程：
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### 可视化应用程序执行

在下载/安装所需的应用程序之后，让我们开始它们。\
首先，您需要**启动 neo4j 数据库**：
```bash
./bin/neo4j start
#or
service neo4j start
```
第一次启动此数据库时，您需要访问[http://localhost:7474/browser/](http://localhost:7474/browser/)。您将被要求输入默认凭据 (neo4j:neo4j)，并且**必须更改密码**，请更改密码并记住它。

现在，启动**bloodhound 应用程序**：
```bash
./BloodHound-linux-x64
#or
bloodhound
```
你将被提示输入数据库凭据：**neo4j:\<您的新密码>**

然后 BloodHound 将准备好接收数据。

![](<../../.gitbook/assets/image (171) (1).png>)


### **Python BloodHound**

如果您有域凭据，您可以从任何平台运行一个 **Python BloodHound 数据摄取器**，因此您不需要依赖于 Windows。\
从 [https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) 下载它或执行 `pip3 install bloodhound`
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
如果您通过proxychains运行它，请添加`--dns-tcp`以使DNS解析通过代理工作。
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

这个脚本将通过LDAP**静默枚举Active Directory域**，解析用户、管理员、组等。

在[**SilentHound github**](https://github.com/layer8secure/SilentHound)中查看。

### RustHound

Rust中的BloodHound，[**在这里查看**](https://github.com/OPENCYBER-FR/RustHound)。

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) 是一个用于查找Active Directory关联**组策略**中**漏洞**的工具。\
您需要**使用任何域用户**从域内主机上**运行group3r**。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

****[**PingCastle**](https://www.pingcastle.com/documentation/) **评估AD环境的安全姿态**，并提供带有图表的**报告**。

要运行它，可以执行二进制文件 `PingCastle.exe`，它将启动一个**交互式会话**，呈现选项菜单。要使用的默认选项是**`healthcheck`**，它将建立**域**的基线**概述**，并查找**配置错误**和**漏洞**。&#x20;
