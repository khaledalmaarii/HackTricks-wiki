# BloodHound和其他AD枚举工具

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)来自Sysinternal Suite：

> 一个高级的Active Directory（AD）查看器和编辑器。您可以使用AD Explorer轻松浏览AD数据库，定义喜欢的位置，查看对象属性和属性而无需打开对话框，编辑权限，查看对象的模式，并执行可以保存和重新执行的复杂搜索。

### 快照

AD Explorer可以创建AD的快照，以便您可以离线检查它。\
它可以用于离线发现漏洞，或者比较AD数据库在不同时间点的不同状态。

您需要提供用户名、密码和连接方向（需要任何AD用户）。

要对AD进行快照，请转到`File` --> `Create Snapshot`并输入快照的名称。

## ADRecon

****[**ADRecon**](https://github.com/adrecon/ADRecon)是一个从AD环境中提取和组合各种工件的工具。信息可以以**特殊格式**的Microsoft Excel **报告**呈现，其中包括摘要视图和指标，以便于分析并提供目标AD环境的整体情况。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

> BloodHound是一个基于[Linkurious](http://linkurio.us)构建的单页Javascript Web应用程序，使用[Electron](http://electron.atom.io)编译，由PowerShell摄取器提供数据给[Neo4j](https://neo4j.com)数据库。
>
> BloodHound使用图论来揭示Active Directory环境中隐藏且常常无意的关系。攻击者可以使用BloodHound轻松识别高度复杂的攻击路径，否则很难快速识别。防御者可以使用BloodHound识别和消除这些攻击路径。蓝队和红队都可以使用BloodHound轻松获得对Active Directory环境中特权关系的更深入理解。
>
> BloodHound由[@_wald0](https://www.twitter.com/_wald0)，[@CptJesus](https://twitter.com/CptJesus)和[@harmj0y](https://twitter.com/harmj0y)开发。
>
> 来自[https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

所以，[BloodHound](https://github.com/BloodHoundAD/BloodHound)是一个令人惊叹的工具，可以自动枚举域，保存所有信息，找到可能的特权升级路径，并使用图形显示所有信息。

BloodHound由两个主要部分组成：**摄取器**和**可视化应用程序**。

**摄取器**用于**枚举域并提取所有信息**，以一种可被可视化应用程序理解的格式。

**可视化应用程序使用neo4j**来展示所有信息的关联性，并展示在域中升级特权的不同方式。

### 安装

1. BloodHound

要安装可视化应用程序，您需要安装**neo4j**和**bloodhound应用程序**。\
最简单的方法就是执行以下操作：
```
apt-get install bloodhound
```
你可以从[这里](https://neo4j.com/download-center/#community)下载neo4j的社区版本。

1. Ingestors

你可以从以下链接下载Ingestors：

* https://github.com/BloodHoundAD/SharpHound/releases
* https://github.com/BloodHoundAD/BloodHound/releases
* https://github.com/fox-it/BloodHound.py

1. 从图中学习路径

Bloodhound提供了各种查询来突出显示敏感的入侵路径。你可以添加自定义查询来增强搜索和对象之间的关联等功能！

这个仓库有一个很好的查询集合：https://github.com/CompassSecurity/BloodHoundQueries

安装过程：
```
$ curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/BloodHound_Custom_Queries/customqueries.json"
```
### 可视化应用程序执行

在下载/安装所需的应用程序之后，让我们开始它们。\
首先，您需要**启动neo4j数据库**：
```bash
./bin/neo4j start
#or
service neo4j start
```
第一次启动此数据库时，您需要访问[http://localhost:7474/browser/](http://localhost:7474/browser/)。您将被要求使用默认凭据（neo4j:neo4j），并且您将被**要求更改密码**，请更改密码并确保记住它。

现在，启动**bloodhound应用程序**：
```bash
./BloodHound-linux-x64
#or
bloodhound
```
您将被提示输入数据库凭据：**neo4j:\<您的新密码>**

然后，BloodHound将准备好接收数据。

![](<../../.gitbook/assets/image (171) (1).png>)

### SharpHound

他们有几个选项，但如果您想从加入域的计算机上运行SharpHound，并使用当前用户提取所有信息，可以执行以下操作：
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> 您可以在此处阅读有关**CollectionMethod**和循环会话的更多信息 [here](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html)

如果您希望使用不同的凭据执行SharpHound，可以创建一个CMD netonly会话并从那里运行SharpHound：
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**了解更多关于Bloodhound的信息，请访问ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

**Windows Silent**

### **Python bloodhound**

如果您拥有域凭据，您可以在任何平台上运行**python bloodhound摄取器**，因此您不需要依赖于Windows。\
从[https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)下载它，或者执行`pip3 install bloodhound`。
```bash
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all
```
如果你正在通过proxychains运行它，请添加`--dns-tcp`以使DNS解析通过代理工作。
```bash
proxychains bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all --dns-tcp
```
### Python SilentHound

这个脚本将通过LDAP**静默地枚举Active Directory域**，解析用户、管理员、组等。

在[**SilentHound github**](https://github.com/layer8secure/SilentHound)上查看。

### RustHound

Rust中的BloodHound，[**在这里查看**](https://github.com/OPENCYBER-FR/RustHound)。

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) 是一个用于查找Active Directory关联的**组策略**中的**漏洞**的工具。\
您需要使用**任何域用户**从域内的主机上**运行group3r**。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

****[**PingCastle**](https://www.pingcastle.com/documentation/) **评估AD环境的安全状况**，并提供了一个带有图表的漂亮**报告**。

要运行它，可以执行二进制文件`PingCastle.exe`，它将启动一个**交互式会话**，呈现一个选项菜单。默认选项是使用**`healthcheck`**，它将建立一个**域**的基线**概述**，并查找**配置错误**和**漏洞**。&#x20;

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks的衣物**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或在**Twitter**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
