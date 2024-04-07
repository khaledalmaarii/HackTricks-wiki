# Kerberos双跳问题

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

* 您在**网络安全公司**工作吗？ 想要看到您的**公司在HackTricks中做广告**吗？ 或者您想要访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？ 请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入** [**💬**](https://emojipedia.org/speech-balloon/) **Discord群组**](https://discord.gg/hRep4RUj7f) 或**电报群组**或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 简介

当攻击者尝试在两个**跳跃**之间使用**Kerberos身份验证**时，就会出现Kerberos“双跳”问题，例如使用**PowerShell**/**WinRM**。

当通过**Kerberos**进行**身份验证**时，**凭据**不会被缓存在**内存**中。因此，即使用户正在运行进程，如果您运行mimikatz，您也**找不到用户在计算机上的凭据**。

这是因为连接Kerberos时会执行以下步骤：

1. User1提供凭据，**域控制器**返回一个Kerberos **TGT**给User1。
2. User1使用**TGT**请求一个**服务票证**以**连接**到Server1。
3. User1**连接**到**Server1**并提供**服务票证**。
4. **Server1**没有缓存User1的凭据或User1的**TGT**。因此，当来自Server1的User1尝试登录到第二个服务器时，他**无法进行身份验证**。

### 无限制委派

如果PC上启用了**无限制委派**，则不会发生这种情况，因为**服务器**将获得访问它的每个用户的**TGT**。此外，如果使用无限制委派，您可能可以从中**妥协域控制器**。\
[**在无限制委派页面了解更多信息**](unconstrained-delegation.md)。

### CredSSP

另一种避免此问题的方式是[**明显不安全的**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7)**凭据安全支持提供程序**。来自Microsoft的说法：

> CredSSP身份验证将用户凭据从本地计算机委派到远程计算机。这种做法增加了远程操作的安全风险。如果远程计算机受到损害，当凭据传递给它时，这些凭据可以用于控制网络会话。

强烈建议在生产系统、敏感网络和类似环境中禁用**CredSSP**，因为存在安全风险。要确定**CredSSP**是否已启用，可以运行`Get-WSManCredSSP`命令。此命令允许**检查CredSSP状态**，甚至可以在启用**WinRM**的情况下远程执行。
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## 解决方法

### 调用命令

为了解决双跳问题，提出了一种涉及嵌套`Invoke-Command`的方法。这并不能直接解决问题，但提供了一种无需特殊配置的解决方法。该方法允许通过从初始攻击机器执行的PowerShell命令或通过与第一台服务器先前建立的PS-Session，在第二台服务器上执行一个命令（`hostname`）。以下是操作步骤：
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### 注册 PSSession 配置

绕过双跳问题的解决方案涉及使用 `Register-PSSessionConfiguration` 与 `Enter-PSSession`。这种方法需要与 `evil-winrm` 不同的方法，并允许创建一个不受双跳限制影响的会话。
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### 端口转发

对于中间目标上的本地管理员，端口转发允许将请求发送到最终服务器。使用 `netsh`，可以添加一个端口转发规则，同时还需要添加一个Windows防火墙规则来允许转发的端口。
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe`可以用于转发WinRM请求，如果担心PowerShell监控，这可能是一个不太容易被检测到的选项。下面的命令演示了它的用法：
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

在第一个服务器上安装 OpenSSH 可以解决双跳问题，特别适用于跳板机场景。此方法需要在 Windows 上进行 CLI 安装和设置 OpenSSH。当配置为密码认证时，这允许中间服务器代表用户获取 TGT。

#### OpenSSH 安装步骤

1. 下载并将最新的 OpenSSH 发行版 zip 移动到目标服务器。
2. 解压缩并运行 `Install-sshd.ps1` 脚本。
3. 添加防火墙规则以打开端口 22 并验证 SSH 服务正在运行。

要解决 `Connection reset` 错误，可能需要更新权限以允许每个人在 OpenSSH 目录上具有读取和执行访问权限。
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## 参考资料

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* 您在**网络安全公司**工作吗？您想看到您的**公司在HackTricks中被广告**吗？或者您想访问**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 发现我们的独家[NFTs收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) **Discord群组**](https://discord.gg/hRep4RUj7f) 或**电报群组**](https://t.me/peass) 或在**Twitter**上关注我 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* 通过向[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享您的黑客技巧。**

</details>
