# Lista - Lokalno eskaliranje privilegija na Windowsu

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### **Najbolji alat za pronalaženje vektora lokalnog eskaliranja privilegija na Windowsu:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/#system-info)

* [ ] Dobiti [**informacije o sistemu**](windows-local-privilege-escalation/#system-info)
* [ ] Pretražiti **kernel** [**eksploite koristeći skripte**](windows-local-privilege-escalation/#version-exploits)
* [ ] Koristiti **Google pretragu** za pronalaženje kernel **eksploita**
* [ ] Koristiti **searchsploit pretragu** za pronalaženje kernel **eksploita**
* [ ] Interesantne informacije u [**env varijablama**](windows-local-privilege-escalation/#environment)?
* [ ] Lozinke u [**PowerShell istoriji**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Interesantne informacije u [**Internet podešavanjima**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Diskovi**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS eksploit**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumeracija logovanja/AV-a](windows-local-privilege-escalation/#enumeration)

* [ ] Proveriti [**Audit** ](windows-local-privilege-escalation/#audit-settings)i [**WEF** ](windows-local-privilege-escalation/#wef)podešavanja
* [ ] Proveriti [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Proveriti da li je [**WDigest** ](windows-local-privilege-escalation/#wdigest)aktivan
* [ ] [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Keširane lozinke**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Proveriti da li postoji neki [**AV**](windows-av-bypass)
* [ ] [**AppLocker Policy**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Korisničke privilegije**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Proveriti [**trenutne** korisničke **privilegije**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Proveriti da li imate omogućene [neke od ovih tokena](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Korisničke sesije**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Proveriti[ **korisničke foldere**](windows-local-privilege-escalation/#home-folders) (pristup?)
* [ ] Proveriti [**Password Policy**](windows-local-privilege-escalation/#password-policy)
* [ ] Šta se nalazi [**u Clipboard-u**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/#network)

* [ ] Proveriti **trenutne** [**informacije o mreži**](windows-local-privilege-escalation/#network)
* [ ] Proveriti **skrivene lokalne servise** ograničene prema spolja

### [Pokrenuti procesi](windows-local-privilege-escalation/#running-processes)

* [ ] Dozvole fajlova i foldera za procese [**file and folders permissions**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Izvlačenje lozinki iz memorije**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Nesigurne GUI aplikacije**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Servisi](windows-local-privilege-escalation/#services)

* [ ] [Možete li **izmeniti neki servis**?](windows-local-privilege-escalation#permissions)
* [ ] [Možete li **izmeniti** binarni **fajl** koji se **izvršava** od strane nekog **servisa**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Možete li **izmeniti** registar nekog **servisa**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Možete li iskoristiti neki **servis sa neispravnim putem** do binarnog fajla?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplikacije**](windows-local-privilege-escalation/#applications)

* [ ] **Dozvole za pisanje na instalirane aplikacije**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Aplikacije koje se pokreću pri startovanju**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Ranjivi** [**drajveri**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Možete li **pisati u bilo koji folder unutar PATH-a**?
* [ ] Da li postoji poznati servisni binarni fajl koji **pokušava da učita ne-postojeću DLL**?
* [ ] Možete li **pisati** u bilo koji **binarni folder**?
### [Mreža](windows-local-privilege-escalation/#mreža)

* [ ] Nabrojite mrežu (deljenje, interfejsi, rute, susedi, ...)
* [ ] Posebno obratite pažnju na mrežne servise koji slušaju na lokalnom računaru (127.0.0.1)

### [Windows akreditacije](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)akreditacije
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) akreditacije koje biste mogli koristiti?
* [ ] Interesantne [**DPAPI akreditacije**](windows-local-privilege-escalation/#dpapi)?
* [ ] Lozinke sačuvanih [**Wifi mreža**](windows-local-privilege-escalation/#wifi)?
* [ ] Interesantne informacije u [**sačuvanim RDP konekcijama**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Lozinke u [**nedavno pokrenutim komandama**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Lozinke iz [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] [**AppCmd.exe** postoji](windows-local-privilege-escalation/#appcmd-exe)? Akreditacije?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Učitavanje DLL datoteka sa strane?

### [Datoteke i registar (akreditacije)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Akreditacije**](windows-local-privilege-escalation/#putty-creds) **i** [**SSH host ključevi**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH ključevi u registru**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Lozinke u [**neprisutnim datotekama**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Bilo kakva **SAM & SYSTEM** rezerva?
* [ ] [**Cloud akreditacije**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Datoteka [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Lozinka u [**IIS Web konfiguracionoj datoteci**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Interesantne informacije u [**web** **logovima**](windows-local-privilege-escalation/#logs)?
* [ ] Da li želite da [**zatražite akreditacije**](windows-local-privilege-escalation/#ask-for-credentials) od korisnika?
* [ ] Interesantne [**datoteke u Recycle Binu**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Ostali [**registri koji sadrže akreditacije**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Unutar [**Browser podataka**](windows-local-privilege-escalation/#browsers-history) (baze podataka, istorija, obeleživači, ...)?
* [ ] [**Pretraga generičkih lozinki**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) u datotekama i registru
* [ ] [**Alati**](windows-local-privilege-escalation/#tools-that-search-for-passwords) za automatsko pretraživanje lozinki

### [Procureni handleri](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Imate li pristup bilo kom handleru procesa pokrenutog od strane administratora?

### [Impersonacija klijenta imenovane cijevi](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Proverite da li možete zloupotrebiti to

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Pogledajte [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
