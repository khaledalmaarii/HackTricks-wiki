# Kontrolelys - Plaaslike Windows Voorregverhoging

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

### **Die beste instrument om te soek na Windows plaaslike voorregverhogingsvektore:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Stelselinligting](windows-local-privilege-escalation/#system-info)

* [ ] Verkry [**stelselinligting**](windows-local-privilege-escalation/#system-info)
* [ ] Soek na **kernel** [**uitbuitings deur middel van skripte**](windows-local-privilege-escalation/#version-exploits)
* [ ] Gebruik **Google om te soek** vir kernel **uitbuitings**
* [ ] Gebruik **searchsploit om te soek** vir kernel **uitbuitings**
* [ ] Interessante inligting in [**omgewingsveranderlikes**](windows-local-privilege-escalation/#environment)?
* [ ] Wagwoorde in [**PowerShell-geskiedenis**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Interessante inligting in [**Internet-instellings**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Skywe**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS-uitbuiting**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Logging/AV-opname](windows-local-privilege-escalation/#enumeration)

* [ ] Kontroleer [**Oudit** ](windows-local-privilege-escalation/#audit-settings)en [**WEF** ](windows-local-privilege-escalation/#wef)instellings
* [ ] Kontroleer [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Kontroleer of [**WDigest** ](windows-local-privilege-escalation/#wdigest)aktief is
* [ ] [**LSA-beskerming**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Gekaspte geloofsbriewe**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Kontroleer of enige [**AV**](windows-av-bypass)
* [ ] [**AppLocker-beleid**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Gebruikersvoorregte**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Kontroleer [**huidige** gebruiker **voorregte**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Is jy 'n [**lid van enige bevoorregte groep**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Kontroleer of jy een van hierdie tokens geaktiveer het: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Gebruikersessies**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Kontroleer[ **gebruikershuise**](windows-local-privilege-escalation/#home-folders) (toegang?)
* [ ] Kontroleer [**Wagwoordbeleid**](windows-local-privilege-escalation/#password-policy)
* [ ] Wat is[ **binne die Knipbord**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Netwerk](windows-local-privilege-escalation/#network)

* [ ] Kontroleer **huidige** [**netwerk** **inligting**](windows-local-privilege-escalation/#network)
* [ ] Kontroleer **verskuilde plaaslike dienste** wat beperk is tot die buitewêreld

### [Lopende Prosesse](windows-local-privilege-escalation/#running-processes)

* [ ] Prosesse binêre [**lêer- en vouerregte**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Geheue Wagwoordontginning**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Onveilige GUI-programme**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Dienste](windows-local-privilege-escalation/#services)

* [ ] [Kan jy enige diens **verander**?](windows-local-privilege-escalation#permissions)
* [ ] [Kan jy die **binêre** wat deur enige **diens** **uitgevoer** word, **verander**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Kan jy die **registreer** van enige **diens** **verander**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Kan jy voordeel trek uit enige **ongekwoteerde diens** binêre **pad**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Toepassings**](windows-local-privilege-escalation/#applications)

* [ ] **Skryf** [**regte op geïnstalleerde toepassings**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Begin-toepassings**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Kwesbare** [**Drywers**](windows-local-privilege-escalation/#drivers)

### [DLL-ontvoering](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Kan jy **skryf in enige vouer binne die PAD**?
* [ ] Is daar enige bekende diensbinêre wat probeer om enige nie-bestaande DLL te laai?
* [ ] Kan jy **skryf** in enige **binêre vouer**?
### [Netwerk](windows-local-privilege-escalation/#network)

* [ ] Enumereer die netwerk (aandele, interfaces, roetes, bure, ...)
* [ ] Neem 'n spesiale kyk na netwerkdienste wat op localhost (127.0.0.1) luister

### [Windows Legitieme Inligting](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)legitieme inligting
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) legitieme inligting wat jy kan gebruik?
* [ ] Interessante [**DPAPI legitieme inligting**](windows-local-privilege-escalation/#dpapi)?
* [ ] Wagwoorde van gestoorde [**Wifi-netwerke**](windows-local-privilege-escalation/#wifi)?
* [ ] Interessante inligting in [**gestoorde RDP-verbindings**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Wagwoorde in [**onlangs uitgevoerde opdragte**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager) wagwoorde?
* [ ] [**AppCmd.exe** bestaan](windows-local-privilege-escalation/#appcmd-exe)? Legitieme inligting?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL-kantlaai?

### [Lêers en Register (Legitieme Inligting)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Legitieme inligting**](windows-local-privilege-escalation/#putty-creds) **en** [**SSH-gashere sleutels**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH-sleutels in die register**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Wagwoorde in [**ongeagte lêers**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Enige [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) rugsteun?
* [ ] [**Cloud legitieme inligting**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) lêer?
* [ ] [**Cached GPP-wagwoord**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Wagwoord in [**IIS-webkonfigurasie-lêer**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Interessante inligting in [**web** **lêers**](windows-local-privilege-escalation/#logs)?
* [ ] Wil jy [**legitieme inligting van die gebruiker vra**](windows-local-privilege-escalation/#ask-for-credentials)?
* [ ] Interessante [**lêers binne die Recycle Bin**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Ander [**register wat legitieme inligting bevat**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Binne [**Blaaierdata**](windows-local-privilege-escalation/#browsers-history) (dbs, geskiedenis, bladmerke, ...)?
* [ ] [**Generiese wagwoordsoektog**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) in lêers en register
* [ ] [**Hulpmiddels**](windows-local-privilege-escalation/#tools-that-search-for-passwords) om outomaties na wagwoorde te soek

### [Uitgelek Handlers](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Het jy toegang tot enige handler van 'n proses wat deur 'n administrateur uitgevoer word?

### [Pypkliënt-impersonasie](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Kyk of jy dit kan misbruik

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
