# Orodha - Kupandisha Mamlaka ya Ndani kwa Windows

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kikundi cha Usalama cha Kujitahidi**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Zana bora ya kutafuta njia za kupandisha mamlaka ya ndani kwa Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Maelezo ya Mfumo](windows-local-privilege-escalation/#system-info)

* [ ] Pata [**Maelezo ya Mfumo**](windows-local-privilege-escalation/#system-info)
* [ ] Tafuta **mabadiliko ya kernel** [**kwa kutumia hati za scripts**](windows-local-privilege-escalation/#version-exploits)
* [ ] Tumia **Google kutafuta** mabadiliko ya kernel
* [ ] Tumia **searchsploit kutafuta** mabadiliko ya kernel
* [ ] Maelezo ya kuvutia katika [**vars za mazingira**](windows-local-privilege-escalation/#environment)?
* [ ] Nywila katika [**historia ya PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Maelezo ya kuvutia katika [**vipimo vya mtandao**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Drives**](windows-local-privilege-escalation/#drives)?
* [**Udukuzi wa WSUS**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Uorodheshaji wa Kuingia/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Angalia [**Uorodheshaji** ](windows-local-privilege-escalation/#audit-settings)na [**WEF** ](windows-local-privilege-escalation/#wef)vipimo
* [ ] Angalia [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Angalia ikiwa [**WDigest** ](windows-local-privilege-escalation/#wdigest)ipo
* [ ] [**Ulinzi wa LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [**Guard ya Vitambulisho**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [**Vitambulisho vilivyohifadhiwa**](windows-local-privilege-escalation/#cached-credentials)?
* Angalia ikiwa kuna [**AV yoyote**](windows-av-bypass)
* [**Sera ya AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Mamlaka ya Mtumiaji**](windows-local-privilege-escalation/#users-and-groups)
* Angalia [**mamlaka ya mtumiaji wa sasa**](windows-local-privilege-escalation/#users-and-groups)
* Je, wewe ni [**mwanachama wa kikundi cha mamlaka**](windows-local-privilege-escalation/#privileged-groups)?
* Angalia ikiwa una [mojawapo ya vitufe hivi vimezimwa](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**Vikao vya Watumiaji**](windows-local-privilege-escalation/#logged-users-sessions)?
* Angalia[ **nyumba za watumiaji**](windows-local-privilege-escalation/#home-folders) (upatikanaji?)
* Angalia [**Sera ya Nywila**](windows-local-privilege-escalation/#password-policy)
* Ni[ **nini ndani ya Ubao wa Kunakili**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Mtandao](windows-local-privilege-escalation/#network)

* Angalia **habari za sasa za** [**mtandao**](windows-local-privilege-escalation/#network)
* Angalia **huduma za ndani zilizofichwa** zilizozuiwa kwa nje

### [Mchakato Unaoendeshwa](windows-local-privilege-escalation/#running-processes)

* Mchakato wa faili za programu [**ruhusa za faili na folda**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Uchimbaji wa Nywila za Kumbukumbu**](windows-local-privilege-escalation/#memory-password-mining)
* [**Programu za GUI zisizo salama**](windows-local-privilege-escalation/#insecure-gui-apps)
* Pora vitambulisho na **mchakato wa kuvutia** kupitia `ProcDump.exe` ? (firefox, chrome, nk ...)

### [Huduma](windows-local-privilege-escalation/#services)

* [ ] [Je, unaweza **kurekebisha huduma yoyote**?](windows-local-privilege-escalation#permissions)
* [ ] [Je, unaweza **kurekebisha** **faili** inayo **tekelezwa** na huduma yoyote **?**](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Je, unaweza **kurekebisha** **usajili** wa huduma yoyote **?**](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Je, unaweza kunufaika na **njia ya faili ya huduma** isiyo na nukuu **?**](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Programu**](windows-local-privilege-escalation/#applications)

* [ ] **Andika** [**ruhusa kwenye programu zilizosanikishwa**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Programu za Kuanza**](windows-local-privilege-escalation/#run-at-startup)
* **Madereva** [**Dhaifu**](windows-local-privilege-escalation/#drivers)
### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Je, unaweza **kuandika kwenye folda yoyote ndani ya PATH**?
* [ ] Kuna binary ya huduma inayojulikana ambayo **jaribu kupakia DLL ambayo haipo**?
* [ ] Je, unaweza **kuandika** kwenye **folda za binaries** yoyote?

### [Mtandao](windows-local-privilege-escalation/#network)

* [ ] Tafuta mtandao (kushirikiana, interfaces, njia, majirani, ...)
* [ ] Angalia kwa umakini huduma za mtandao zinazosikiliza kwenye localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)credentials
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) credentials unaweza kutumia?
* [ ] [**DPAPI credentials**](windows-local-privilege-escalation/#dpapi) za kuvutia?
* [ ] Nywila za mitandao iliyohifadhiwa [**Wifi networks**](windows-local-privilege-escalation/#wifi)?
* [ ] Taarifa za kuvutia katika [**kumbukumbu za RDP zilizohifadhiwa**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Nywila katika [**amri zilizotekelezwa hivi karibuni**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager) nywila?
* [ ] [**AppCmd.exe** ipo](windows-local-privilege-escalation/#appcmd-exe)? Credentials?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? DLL Side Loading?

### [Faili na Usajili (Credentials)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/#putty-creds) **na** [**SSH host keys**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH keys katika usajili**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Nywila katika [**faili za kiotomatiki**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Backup yoyote ya [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Cloud credentials**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Faili ya [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Nywila katika [**faili ya usanidi wa wavuti ya IIS**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Taarifa za kuvutia katika [**logs za wavuti**](windows-local-privilege-escalation/#logs)?
* [ ] Je, unataka [**kuomba nywila**](windows-local-privilege-escalation/#ask-for-credentials) kwa mtumiaji?
* [ ] Taarifa za kuvutia [**katika faili zilizopo kwenye Recycle Bin**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Usajili mwingine una [**nywila**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Ndani ya [**data ya kivinjari**](windows-local-privilege-escalation/#browsers-history) (dbs, historia, alamisho, ...)?
* [**Generic password search**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) katika faili na usajili
* [**Tools**](windows-local-privilege-escalation/#tools-that-search-for-passwords) za kutafuta nywila kiotomatiki

### [Leaked Handlers](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Je, una ufikiaji wa kifaa chochote cha mchakato ulioendeshwa na msimamizi?

### [Pipe Client Impersonation](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Angalia kama unaweza kutumia hilo

**Kikundi cha Usalama cha Kujitahidi**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
