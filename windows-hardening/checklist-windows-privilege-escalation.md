# Lista - Lokalno eskaliranje privilegija u Windows-u

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### **Najbolji alat za traženje vektora lokalnog eskaliranja privilegija u Windows-u:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacije o sistemu](windows-local-privilege-escalation/#system-info)

* [ ] Dobiti [**Informacije o sistemu**](windows-local-privilege-escalation/#system-info)
* [ ] Pretražiti **kernel** [**eksploate korišćenjem skripti**](windows-local-privilege-escalation/#version-exploits)
* [ ] Koristiti **Google za pretragu** kernel **eksploata**
* [ ] Koristiti **searchsploit za pretragu** kernel **eksploata**
* [ ] Interesantne informacije u [**env varijablama**](windows-local-privilege-escalation/#environment)?
* [ ] Lozinke u [**PowerShell istoriji**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Interesantne informacije u [**Internet postavkama**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Diskovi**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS eksploatacija**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumeracija Logovanja/AV-a](windows-local-privilege-escalation/#enumeration)

* [ ] Proveriti [**Audit** ](windows-local-privilege-escalation/#audit-settings)i [**WEF** ](windows-local-privilege-escalation/#wef)postavke
* [ ] Proveriti [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Proveriti da li je [**WDigest** ](windows-local-privilege-escalation/#wdigest)aktivan
* [ ] [**LSA Zaštita**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Zaštita Kredencijala**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Keširane Kredencijale**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Proveriti da li postoji neki [**AV**](windows-av-bypass)
* [**AppLocker Politika**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Korisničke Privilegije**](windows-local-privilege-escalation/#users-and-groups)
* Proveriti [**trenutne** korisničke **privilegije**](windows-local-privilege-escalation/#users-and-groups)
* Da li ste [**član neke privilegovane grupe**](windows-local-privilege-escalation/#privileged-groups)?
* Proveriti da li su vam omogućeni neki od ovih tokena (windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**Korisničke Sesije**](windows-local-privilege-escalation/#logged-users-sessions)?
* Proveriti [**korisničke direktorijume**](windows-local-privilege-escalation/#home-folders) (pristup?)
* Proveriti [**Politiku Lozinke**](windows-local-privilege-escalation/#password-policy)
* Šta je [**unutar Clipboard-a**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Mreža](windows-local-privilege-escalation/#network)

* Proveriti **trenutne** [**mrežne informacije**](windows-local-privilege-escalation/#network)
* Proveriti **skrivene lokalne servise** ograničene prema spolja

### [Pokrenuti Procesi](windows-local-privilege-escalation/#running-processes)

* Dozvole fajlova i foldera za procese binarne [**datoteke**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Izvlačenje lozinki iz memorije**](windows-local-privilege-escalation/#memory-password-mining)
* [**Nesigurne GUI aplikacije**](windows-local-privilege-escalation/#insecure-gui-apps)
* Ukrasti kredencijale sa **interesantnim procesima** putem `ProcDump.exe` ? (firefox, chrome, itd ...)

### [Servisi](windows-local-privilege-escalation/#services)

* [Možete li **modifikovati neki servis**?](windows-local-privilege-escalation#permissions)
* [Možete li **modifikovati** binarni **fajl** koji se **izvršava** od strane nekog **servisa**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [Možete li **modifikovati** registar nekog **servisa**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [Možete li iskoristiti neki **servis sa neispravnim putem do binarnog fajla**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplikacije**](windows-local-privilege-escalation/#applications)

* **Dozvole za pisanje na instalirane aplikacije**](windows-local-privilege-escalation/#write-permissions)
* [**Aplikacije koje se pokreću pri startovanju**](windows-local-privilege-escalation/#run-at-startup)
* **Ranjivi** [**Driveri**](windows-local-privilege-escalation/#drivers)

### [DLL Preusmeravanje](windows-local-privilege-escalation/#path-dll-hijacking)

* Možete li **pisati u bilo kojem folderu unutar PATH**?
* Postoji li neki poznati servisni binarni fajl koji **pokušava da učita neki nepostojeći DLL**?
* Možete li **pisati** u bilo kojem **folderu sa binarnim fajlovima**?
### [Mreža](windows-local-privilege-escalation/#network)

* [ ] Nabrojite mrežu (deljenje, interfejsi, rute, susedi, ...)
* [ ] Posebno obratite pažnju na mrežne servise koji osluškuju na lokalnom računaru (127.0.0.1)

### [Windows Kredencijali](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials) kredencijali
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) kredencijali koje možete koristiti?
* [ ] Interesantni [**DPAPI kredencijali**](windows-local-privilege-escalation/#dpapi)?
* [ ] Lozinke sačuvanih [**Wifi mreža**](windows-local-privilege-escalation/#wifi)?
* [ ] Interesantne informacije u [**sačuvanim RDP konekcijama**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Lozinke u [**nedavno pokrenutim komandama**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Upravljač kredencijalima za daljinsku radnu površinu**](windows-local-privilege-escalation/#remote-desktop-credential-manager) lozinke?
* [ ] [**AppCmd.exe** postoji](windows-local-privilege-escalation/#appcmd-exe)? Kredencijali?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Učitavanje DLL datoteka sa strane?

### [Fajlovi i Registar (Kredencijali)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Kredencijali**](windows-local-privilege-escalation/#putty-creds) **i** [**SSH host ključevi**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH ključevi u registru**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Lozinke u [**neprisutnim fajlovima**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Bilo kakav [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) rezervni primerak?
* [ ] [**Cloud kredencijali**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Datoteka [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Keširana GPP lozinka**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Lozinka u [**IIS Web konfiguracionoj datoteci**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Interesantne informacije u [**web** **logovima**](windows-local-privilege-escalation/#logs)?
* [ ] Da li želite da [**zatražite kredencijale**](windows-local-privilege-escalation/#ask-for-credentials) od korisnika?
* [ ] Interesantni [**fajlovi unutar Recycle Bin-a**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Ostali [**registri koji sadrže kredencijale**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Unutar [**Podataka pretraživača**](windows-local-privilege-escalation/#browsers-history) (baze podataka, istorija, obeleživači, ...)?
* [**Opšta pretraga lozinki**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) u fajlovima i registru
* [**Alati**](windows-local-privilege-escalation/#tools-that-search-for-passwords) za automatsko pretraživanje lozinki

### [Procureni Handleri](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Imate li pristup bilo kom handleru procesa pokrenutog od strane administratora?

### [Imitacija Klijenta Cevi](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Proverite da li možete zloupotrebiti to

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi** ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
