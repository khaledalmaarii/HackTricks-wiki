# Orodha - Kupandisha Kiwango cha Mamlaka kwenye Windows

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

### **Zana bora ya kutafuta njia za kupandisha kiwango cha mamlaka kwenye Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Maelezo ya Mfumo](windows-local-privilege-escalation/#system-info)

* [ ] Pata [**Maelezo ya Mfumo**](windows-local-privilege-escalation/#system-info)
* [ ] Tafuta **mashambulizi ya kernel** [**kwa kutumia hati**](windows-local-privilege-escalation/#version-exploits)
* [ ] Tumia **Google kutafuta** mashambulizi ya kernel
* [ ] Tumia **searchsploit kutafuta** mashambulizi ya kernel
* [ ] Taarifa muhimu katika [**mazingira ya env**](windows-local-privilege-escalation/#environment)?
* [ ] Manenosiri katika [**historia ya PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Taarifa muhimu katika [**vipimo vya mtandao**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Drives**](windows-local-privilege-escalation/#drives)?
* [ ] [**Shambulio la WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Ukaguzi wa Kumbukumbu/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Angalia mipangilio ya [**Ukaguzi** ](windows-local-privilege-escalation/#audit-settings)na [**WEF** ](windows-local-privilege-escalation/#wef)
* [ ] Angalia [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Angalia ikiwa [**WDigest** ](windows-local-privilege-escalation/#wdigest)ipo
* [ ] [**Ulinzi wa LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Mlinzi wa Vitambulisho**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Vitambulisho Vilivyohifadhiwa**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Angalia ikiwa kuna [**AV**](windows-av-bypass) yoyote
* [ ] [**Sera ya AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Haki za Mtumiaji**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Angalia [**haki za sasa** za mtumiaji](windows-local-privilege-escalation/#users-and-groups)
* [ ] Je, wewe ni [**mwanachama wa kikundi chenye haki za juu**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Angalia ikiwa una [mojawapo ya vitufe hivi vilivyowezeshwa](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Vikao vya Watumiaji**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Angalia[ **nyumbani kwa watumiaji**](windows-local-privilege-escalation/#home-folders) (upatikanaji?)
* [ ] Angalia [**Sera ya Nenosiri**](windows-local-privilege-escalation/#password-policy)
* [ ] Ni[ **nini kwenye Ubao wa Klipu**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Mtandao](windows-local-privilege-escalation/#network)

* [ ] Angalia **taarifa ya sasa ya mtandao** [**mtandao**](windows-local-privilege-escalation/#network)
* [ ] Angalia **huduma za ndani zilizofichwa** zilizozuiwa kwa nje

### [Mchakato Unaoendelea](windows-local-privilege-escalation/#running-processes)

* [ ] Mchakato wa faili za [**faili na ruhusa za folda**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Uchimbaji wa Nenosiri la Kumbukumbu**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Programu za GUI zisizo salama**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Huduma](windows-local-privilege-escalation/#services)

* [ ] [Je, unaweza **kurekebisha huduma yoyote**?](windows-local-privilege-escalation#permissions)
* [ ] [Je, unaweza **kurekebisha** **faili** inayotekelezwa na **huduma** yoyote?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Je, unaweza **kurekebisha** **sajili** ya **huduma** yoyote?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Je, unaweza kutumia **njia ya huduma** isiyo na nukuu?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Programu**](windows-local-privilege-escalation/#applications)

* [ ] **Andika** [**ruhusa kwenye programu zilizosanikishwa**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Programu za Kuanza**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Madereva** [**Hatarishi**](windows-local-privilege-escalation/#drivers)

### [Udukuzi wa DLL](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Je, unaweza **kuandika kwenye folda yoyote ndani ya PATH**?
* [ ] Je, kuna huduma inayojulikana ya binary ambayo **inajaribu kupakia DLL isiyo wazi**?
* [ ] Je, unaweza **kuandika** kwenye **folda za binary** yoyote?
### [Mtandao](windows-local-privilege-escalation/#mtandao)

* [ ] Tathmini mtandao (kushirikiana, viunganishi, njia, majirani, ...)
* [ ] Angalia kwa makini huduma za mtandao zinazosikiliza kwenye localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)vyeti
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) vyeti unavyoweza kutumia?
* [ ] Vyeti vya [**DPAPI vyeti**](windows-local-privilege-escalation/#dpapi) vinavyovutia?
* [ ] Manenosiri ya mtandao wa [**Wifi uliowekwa**](windows-local-privilege-escalation/#wifi)?
* [ ] Habari inayovutia katika [**Unganisho za RDP zilizohifadhiwa**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Manenosiri katika [**amri zilizotekelezwa hivi karibuni**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Meneja wa Vyeti vya Mbali wa Desktop**](windows-local-privilege-escalation/#remote-desktop-credential-manager) manenosiri?
* [ ] [**AppCmd.exe** ipo](windows-local-privilege-escalation/#appcmd-exe)? Vyeti?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Upakiaji wa Upande wa DLL?

### [Faili na Usajili (Credentials)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Vyeti**](windows-local-privilege-escalation/#putty-creds) **na** [**Vidokezo vya mwenyeji wa SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] Vyeti vya [**SSH kwenye usajili**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Manenosiri katika [**faili zisizo na msimamizi**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Backup yoyote ya [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Vyeti vya Wingu**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Faili ya [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Nenosiri la GPP lililohifadhiwa**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Nenosiri katika [**Faili ya Usanidi wa Wavuti ya IIS**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Habari inayovutia katika [**magogo ya wavuti**](windows-local-privilege-escalation/#logs)?
* [ ] Je! Unataka [**kuomba vyeti**](windows-local-privilege-escalation/#ask-for-credentials) kwa mtumiaji?
* [ ] Habari inayovutia katika [**faili ndani ya Recycle Bin**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Usajili mwingine wowote unaotumia vyeti [**vinavyohifadhiwa**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Ndani ya [**Data ya Kivinjari**](windows-local-privilege-escalation/#browsers-history) (dbs, historia, alamisho, ...)?
* [ ] [**Utafutaji wa nenosiri la jumla**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) katika faili na usajili
* [ ] [**Zana**](windows-local-privilege-escalation/#tools-that-search-for-passwords) za kutafuta manenosiri kiotomatiki

### [Leaked Handlers](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Je! Una ufikiaji wa kifaa chochote cha mchakato unaotekelezwa na msimamizi?

### [Pipe Client Impersonation](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Angalia ikiwa unaweza kuitumia

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
