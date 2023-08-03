# Kerberos双跳问题

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

## 简介

当攻击者尝试在两个跳跃中使用**Kerberos身份验证**时，就会出现Kerberos“双跳”问题，例如使用**PowerShell**/**WinRM**。

当通过**Kerberos**进行**身份验证**时，**凭据**不会被缓存在**内存**中。因此，即使用户正在运行进程，如果你运行mimikatz，你也**找不到用户的凭据**。

这是因为当使用Kerberos连接时，以下是步骤：

1. 用户1提供凭据，**域控制器**返回一个Kerberos **TGT**给用户1。
2. 用户1使用**TGT**请求一个**服务票据**以**连接**到Server1。
3. 用户1**连接**到**Server1**并提供**服务票据**。
4. **Server1**没有缓存用户1的凭据或用户1的**TGT**。因此，当来自Server1的用户1尝试登录到第二个服务器时，他**无法进行身份验证**。

### 无限制委派

如果PC上启用了**无限制委派**，则不会发生这种情况，因为**服务器**将**获取**每个访问它的用户的**TGT**。此外，如果使用无限制委派，你可能可以从中**妥协域控制器**。\
[**在无限制委派页面上获取更多信息**](unconstrained-delegation.md)。

### CredSSP

另一个建议的选项是**系统管理员**避免这个问题的方法是[**明显不安全**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7)的**凭证安全支持提供程序**（CredSSP）。启用CredSSP是多年来各种论坛上提到的解决方案。来自Microsoft的说法：

_“CredSSP身份验证将用户凭据从本地计算机委派给远程计算机。这种做法增加了远程操作的安全风险。如果远程计算机受到攻击，当凭据传递给它时，凭据可以用于控制网络会话。”_

如果在生产系统、敏感网络等地方发现**启用了CredSSP**，建议将其禁用。可以通过运行`Get-WSManCredSSP`快速检查CredSSP状态。如果启用了WinRM，还可以远程执行该命令。
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 解决方法

### 调用命令 <a href="#invoke-command" id="invoke-command"></a>

这种方法可以说是在处理双跳问题时的一种“合作方式”，并不是真正解决问题的方法。它不依赖于任何配置，你可以直接从攻击者的机器上运行它。它基本上是一个**嵌套的`Invoke-Command`**。

这将在**第二台服务器上运行** **`hostname`**：
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
您还可以与第一个服务器建立一个**PS-Session**，然后直接从那里使用`Invoke-Command`和`$cred`运行命令，而不是嵌套执行。尽管如此，从攻击者的机器上运行可以集中任务：
```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```
### 注册 PSSession 配置

如果不使用 **`evil-winrm`**，而是使用 **`Enter-PSSession`** 命令，您可以使用 **`Register-PSSessionConfiguration`** 并重新连接以绕过双跳问题：
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

由于我们在中间目标 **bizintel: 10.35.8.17** 上拥有本地管理员权限，您可以添加一个端口转发规则，将您的请求发送到最终/第三个服务器 **secdev: 10.35.8.23**。

可以使用 **netsh** 快速提取一个一行命令并添加规则。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```
所以**第一个服务器**正在监听端口5446，并将命中5446端口的请求转发到**第二个服务器**的5985端口（也称为WinRM）。

然后，在Windows防火墙中打开一个洞，这也可以通过一个简洁的netsh命令完成。
```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
现在建立会话，它将把我们转发到**第一个服务器**。

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

当使用**`winrs.exe`**时，**端口转发 WinRM** 请求似乎也可以工作。如果你意识到 PowerShell 正在被监视，这可能是一个更好的选择。下面的命令将返回`hostname`的结果为“**secdev**”。
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
就像`Invoke-Command`一样，这可以很容易地通过脚本化来实现，以便攻击者可以将系统命令作为参数发出。一个通用的批处理脚本示例_winrm.bat_：

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

这种方法需要在第一个服务器上安装[OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH)。在Windows上安装OpenSSH可以**完全通过CLI**完成，而且不需要太多时间 - 而且它不会被标记为恶意软件！

当然，在某些情况下，这可能不可行，过于繁琐，或者可能是一种一般的OpSec风险。

这种方法在跳板机设置上可能特别有用 - 可以访问一个否则无法访问的网络。一旦建立了SSH连接，用户/攻击者可以根据需要发起多个`New-PSSession`来针对分段网络进行操作，而不会遇到双跳问题。

当配置OpenSSH使用**密码身份验证**（而不是密钥或Kerberos）时，**登录类型为8**，也就是_网络明文登录_。这并不意味着您的密码以明文形式发送 - 实际上它是通过SSH加密的。到达目的地后，它通过其[身份验证包](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN)解密为明文，以便为您的会话进一步请求有价值的TGT！

这允许中间服务器代表您请求和获取一个TGT，并在中间服务器上本地存储。然后，您的会话可以使用此TGT对其他服务器进行身份验证（PS远程）。

#### OpenSSH安装场景

从github下载最新的[OpenSSH发布zip](https://github.com/PowerShell/Win32-OpenSSH/releases)到您的攻击机，并将其移动到（或直接下载到）跳板机。

将zip文件解压到您想要的位置。然后，运行安装脚本 - `Install-sshd.ps1`

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

最后，只需添加一个防火墙规则来**打开端口22**。验证SSH服务是否已安装，并启动它们。这两个服务都需要运行才能使SSH工作。

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

如果收到`Connection reset`错误，请更新权限以允许根OpenSSH目录上的**Everyone: Read & Execute**。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 参考资料

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks 云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在 HackTricks 中**宣传你的公司**吗？或者想要**获取 PEASS 的最新版本或下载 HackTricks 的 PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram 群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks 仓库**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud 仓库**](https://github.com/carlospolop/hacktricks-cloud) **提交 PR 来分享你的黑客技巧。**

</details>
