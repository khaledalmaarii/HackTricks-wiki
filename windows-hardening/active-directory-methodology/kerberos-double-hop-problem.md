# Kerberos双跳问题

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

## 简介

当攻击者尝试在两个**跳跃**之间使用**Kerberos身份验证**时，就会出现Kerberos“双跳”问题，例如使用**PowerShell**/**WinRM**。

当通过**Kerberos**进行**身份验证**时，**凭据**不会被缓存在**内存**中。因此，即使用户正在运行进程，如果您运行mimikatz，您也**找不到用户的凭据**。

这是因为连接Kerberos时会执行以下步骤：

1. 用户1提供凭据，**域控制器**返回一个Kerberos **TGT**给用户1。
2. 用户1使用**TGT**请求一个**服务票证**以**连接**到Server1。
3. 用户1**连接**到**Server1**并提供**服务票证**。
4. **Server1**既没有缓存用户1的凭据，也没有用户1的**TGT**。因此，当来自Server1的用户1尝试登录到第二个服务器时，他**无法进行身份验证**。

### 无限制委派

如果PC中启用了**无限制委派**，则不会发生这种情况，因为**服务器**将获得访问它的每个用户的**TGT**。此外，如果使用了无限制委派，您可能可以从中** compromise the Domain Controller**。\
[**在无限制委派页面中获取更多信息**](unconstrained-delegation.md)。

### CredSSP

另一个建议给**系统管理员**避免此问题的选项是[**明显不安全的**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **凭据安全支持提供程序**。多年来，启用CredSSP一直是各种论坛中提到的解决方案。来自微软的说法：

_“CredSSP身份验证将用户凭据从本地计算机委派到远程计算机。这种做法增加了远程操作的安全风险。如果远程计算机受到损害，当凭据传递给它时，这些凭据可以用于控制网络会话。”_

如果在生产系统、敏感网络等地方发现**启用了CredSSP**，建议将其禁用。快速检查CredSSP状态的方法是运行`Get-WSManCredSSP`。如果启用了WinRM，还可以远程执行此命令。
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 解决方法

### 调用命令 <a href="#invoke-command" id="invoke-command"></a>

这种方法有点像“处理”双跳问题，而不是完全解决它。它不依赖于任何配置，您可以直接从攻击者的计算机上运行它。基本上是一个**嵌套的 `Invoke-Command`**。

这将在**第二台服务器上运行 `hostname`**：
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
您还可以与第一个服务器建立**PS-Session**，然后简单地从那里使用`Invoke-Command`和`$cred`运行它，而不是嵌套它。尽管如此，从攻击者的计算机运行可以集中任务：
```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```
### 注册PSSession配置

如果不使用 **`evil-winrm`** 而是使用 **`Enter-PSSession`** 命令，您可以使用 **`Register-PSSessionConfiguration`** 并重新连接以绕过双跳问题：
```powershell
# Register a new PS Session configuration
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
# Restar WinRM
Restart-Service WinRM
# Get a PSSession
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
# Check that in this case the TGT was sent and is in memory of the PSSession
klist
# In this session you won't have the double hop problem anymore
```
### 端口转发 <a href="#portproxy" id="portproxy"></a>

由于我们在中间目标**bizintel: 10.35.8.17**上拥有本地管理员权限，您可以添加一个端口转发规则，将您的请求发送到最终/第三个服务器**secdev: 10.35.8.23**。

可以快速使用**netsh**提取一个一行命令并添加规则。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```
所谓的**第一个服务器**正在监听端口5446，并将命中5446端口的请求转发到**第二个服务器**的5985端口（也称为WinRM）。

然后在Windows防火墙中打开一个口子，这也可以通过一个快速的netsh命令完成。
```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
现在建立会话，这将把我们转发到**第一个服务器**。

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

**端口转发 WinRM** 请求似乎也可以在使用**`winrs.exe`**时工作。如果您意识到 PowerShell 正在被监视，这可能是一个更好的选择。下面的命令将“**secdev**”作为 `hostname` 的结果带回。
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### Kerberos双跳问题

像`Invoke-Command`一样，这可以很容易地编写脚本，以便攻击者可以简单地将系统命令作为参数发出。一个通用的批处理脚本示例_winrm.bat_：

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

这种方法需要在第一个服务器上安装[OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH)。在Windows上安装OpenSSH可以**完全通过CLI**完成，而且时间不长 - 而且不会被标记为恶意软件！

当然，在某些情况下，这可能不可行，过于繁琐，或者可能是一种一般的OpSec风险。

这种方法在跳板机设置上可能特别有用 - 可以访问一个否则无法访问的网络。一旦建立了SSH连接，用户/攻击者可以根据需要发起尽可能多的`New-PSSession`对分段网络进行操作，而无需遇到双跳问题。

当配置为在OpenSSH中使用**密码身份验证**（而不是密钥或Kerberos）时，**登录类型为8**，也就是_网络明文登录_。这并不意味着您的密码是明文传输的 - 实际上它是通过SSH加密的。到达目的地后，通过其[身份验证包](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN)将其解密为明文，以便您的会话进一步请求有价值的TGT！

这允许中间服务器代表您请求和获取一个TGT，以便在中间服务器上本地存储。然后，您的会话可以使用此TGT对其他服务器进行身份验证（PS远程）。

#### OpenSSH安装场景

从github下载最新的[OpenSSH发行版zip](https://github.com/PowerShell/Win32-OpenSSH/releases)到您的攻击机，并将其移动过去（或直接下载到跳板机）。

将zip文件解压到您想要的位置。然后，运行安装脚本 - `Install-sshd.ps1`

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

最后，只需添加一个防火墙规则来**打开端口22**。验证SSH服务已安装并启动。这两个服务都需要运行才能使SSH正常工作。

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

如果收到`Connection reset`错误，请更新权限以允许**Everyone: 读取和执行**根OpenSSH目录。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 参考资料

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 您在**网络安全公司**工作吗？ 想要在HackTricks中看到您的**公司广告**？ 或者您想要访问**PEASS的最新版本或下载HackTricks的PDF**？ 请查看[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上**🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* 通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享您的黑客技巧。

</details>
