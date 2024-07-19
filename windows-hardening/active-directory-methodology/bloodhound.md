# BloodHound & Other AD Enum Tools

{% hint style="success" %}
学习和实践 AWS 黑客技术：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks 培训 AWS 红队专家 (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
学习和实践 GCP 黑客技术：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks 培训 GCP 红队专家 (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>支持 HackTricks</summary>

* 查看 [**订阅计划**](https://github.com/sponsors/carlospolop)!
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass) 或 **关注** 我们的 **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub 仓库提交 PR 分享黑客技巧。

</details>
{% endhint %}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) 来自 Sysinternal Suite：

> 一个高级的 Active Directory (AD) 查看器和编辑器。您可以使用 AD Explorer 轻松浏览 AD 数据库，定义收藏位置，查看对象属性和属性而无需打开对话框，编辑权限，查看对象的架构，并执行可以保存和重新执行的复杂搜索。

### 快照

AD Explorer 可以创建 AD 的快照，以便您可以离线检查。\
它可以用于离线发现漏洞，或比较 AD 数据库在不同时间的不同状态。

您需要提供用户名、密码和连接方向（任何 AD 用户都是必需的）。

要创建 AD 的快照，请转到 `File` --> `Create Snapshot` 并输入快照的名称。

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) 是一个从 AD 环境中提取和组合各种工件的工具。信息可以以 **特别格式化** 的 Microsoft Excel **报告** 形式呈现，其中包括带有指标的摘要视图，以便于分析并提供目标 AD 环境当前状态的整体图景。
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

来自 [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound 是一个单页面的 Javascript 网络应用，建立在 [Linkurious](http://linkurio.us/) 之上，使用 [Electron](http://electron.atom.io/) 编译，并通过 C# 数据收集器提供 [Neo4j](https://neo4j.com/) 数据库。

BloodHound 使用图论来揭示 Active Directory 或 Azure 环境中隐藏的、通常是无意的关系。攻击者可以使用 BloodHound 轻松识别高度复杂的攻击路径，这些路径在其他情况下将无法快速识别。防御者可以使用 BloodHound 识别并消除这些相同的攻击路径。蓝队和红队都可以使用 BloodHound 更深入地理解 Active Directory 或 Azure 环境中的权限关系。

因此，[Bloodhound](https://github.com/BloodHoundAD/BloodHound) 是一个惊人的工具，可以自动枚举域，保存所有信息，查找可能的权限提升路径，并使用图形显示所有信息。

BloodHound 由两个主要部分组成：**ingestors** 和 **可视化应用**。

**ingestors** 用于 **枚举域并提取所有信息**，以可视化应用能够理解的格式。

**可视化应用使用 neo4j** 来展示所有信息之间的关系，并展示在域中提升权限的不同方式。

### 安装
在创建 BloodHound CE 后，整个项目进行了更新，以便于使用 Docker。开始的最简单方法是使用其预配置的 Docker Compose 配置。

1. 安装 Docker Compose。这应该包含在 [Docker Desktop](https://www.docker.com/products/docker-desktop/) 安装中。
2. 运行：
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. 在 Docker Compose 的终端输出中找到随机生成的密码。  
4. 在浏览器中，导航到 http://localhost:8080/ui/login。使用用户名 admin 和日志中的随机生成密码登录。  

之后，您需要更改随机生成的密码，您将准备好新的界面，从中可以直接下载 ingestors。  

### SharpHound  

他们有几个选项，但如果您想从加入域的 PC 上运行 SharpHound，使用您当前的用户并提取所有信息，您可以这样做：
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> 您可以在[这里](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)阅读更多关于**CollectionMethod**和循环会话的信息。

如果您希望使用不同的凭据执行SharpHound，您可以创建一个CMD netonly会话并从那里运行SharpHound：
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**了解更多关于 Bloodhound 的信息，请访问 ired.team。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) 是一个用于查找与 **组策略** 相关的 Active Directory 中的 **漏洞** 的工具。\
您需要使用 **任何域用户** 从域内的主机上 **运行 group3r**。
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **评估AD环境的安全态势**并提供一个漂亮的**报告**和图表。

要运行它，可以执行二进制文件`PingCastle.exe`，它将启动一个**交互式会话**，呈现选项菜单。默认选项是**`healthcheck`**，它将建立一个**域**的基线**概述**，并查找**错误配置**和**漏洞**。&#x20;

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
