# BloodHound & 其他 AD 枚举工具

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 想要在 HackTricks 中看到您的**公司广告**？ 或者想要访问**PEASS 的最新版本或下载 PDF 格式的 HackTricks**？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或在 **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** 上关注**我。
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享您的黑客技巧**。

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) 来自 Sysinternal Suite：

> 一个高级的 Active Directory (AD) 查看器和编辑器。您可以使用 AD Explorer 轻松浏览 AD 数据库，定义喜爱的位置，查看对象属性和属性而无需打开对话框，编辑权限，查看对象的模式，并执行可保存和重新执行的复杂搜索。

### 快照

AD Explorer 可以创建 AD 的快照，以便您可以离线检查。\
它可用于离线发现漏洞，或比较 AD 数据库在不同时间点的不同状态。

您需要提供用户名、密码和连接方向（需要任何 AD 用户）。

要对 AD 进行快照，转到 `File` --> `Create Snapshot` 并输入快照的名称。

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) 是一个从 AD 环境中提取和组合各种工件的工具。该信息可以呈现在一个**特别格式化**的 Microsoft Excel **报告**中，其中包括摘要视图和指标，以便分析并提供目标 AD 环境当前状态的整体图片。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound是一个单页Javascript Web应用程序，构建在[Linkurious](http://linkurio.us/)之上，使用[Electron](http://electron.atom.io/)编译，通过C#数据收集器向Neo4j数据库提供数据。

BloodHound使用图论来揭示Active Directory或Azure环境中隐藏且通常是意外的关系。攻击者可以使用BloodHound轻松识别高度复杂的攻击路径，否则将无法快速识别。防御者可以使用BloodHound识别并消除相同的攻击路径。蓝队和红队都可以使用BloodHound轻松获得对Active Directory或Azure环境中特权关系的更深入理解。

因此，[Bloodhound](https://github.com/BloodHoundAD/BloodHound)是一个令人惊叹的工具，可以自动枚举域，保存所有信息，找到可能的特权升级路径，并使用图形显示所有信息。

Booldhound由2个主要部分组成：**摄取器**和**可视化应用程序**。

**摄取器**用于**枚举域并提取所有信息**，以一种可被可视化应用程序理解的格式。

**可视化应用程序使用neo4j**来展示所有信息之间的关系，并展示在域中升级特权的不同方式。

### 安装
在创建BloodHound CE之后，整个项目已更新以便通过Docker轻松使用。开始的最简单方法是使用其预配置的Docker Compose配置。

1. 安装Docker Compose。这应该包含在[Docker Desktop](https://www.docker.com/products/docker-desktop/)安装中。
2. 运行：
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. 在Docker Compose的终端输出中找到随机生成的密码。
4. 在浏览器中，导航至 http://localhost:8080/ui/login。使用用户名admin和日志中生成的随机密码登录。

完成后，您需要更改随机生成的密码，然后新界面将准备就绪，您可以直接从中下载ingestors。

### SharpHound

它们有几个选项，但如果您想要从加入域的PC上运行SharpHound，使用当前用户并提取所有信息，可以执行以下操作：
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


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) 是一个用于查找 Active Directory 关联的 **Group Policy** 中的 **漏洞** 的工具。\
您需要使用 **任何域用户** 从域内主机上 **运行 group3r**。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **评估AD环境的安全状况**，并提供带有图表的**报告**。

要运行它，可以执行二进制文件 `PingCastle.exe`，它将启动一个**交互式会话**，显示一个选项菜单。要使用的默认选项是**`healthcheck`**，它将建立**域**的基线**概述**，并查找**配置错误**和**漏洞**。&#x20;
