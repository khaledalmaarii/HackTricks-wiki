# Misbruik van Tokens

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-opslag](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-opslag](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokens

As jy nie weet wat Windows-toegangstokens is nie, lees hierdie bladsy voordat jy voortgaan:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Miskien kan jy bevoorregtings eskaleer deur die tokens wat jy reeds het te misbruik**

### SeImpersonatePrivilege

Dit is 'n voorreg wat deur enige proses gehou word en die nabootsing (maar nie die skepping) van enige token toelaat, mits 'n handgreep daartoe verkry kan word. 'n Bevoorregte token kan van 'n Windows-diens (DCOM) verkry word deur dit te induseer om NTLM-outentifikasie teen 'n uitbuiting uit te voer, wat daaropvolgend die uitvoering van 'n proses met SISTEEM-bevoorregtinge moontlik maak. Hierdie kwesbaarheid kan uitgebuit word met verskeie gereedskap soos [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat vereis dat winrm gedeaktiveer word), [SweetPotato](https://github.com/CCob/SweetPotato), en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Dit is baie soortgelyk aan **SeImpersonatePrivilege**, dit sal dieselfde metode gebruik om 'n bevoorregte token te kry.\
Dan, hierdie voorreg laat toe om 'n primêre token toe te ken aan 'n nuwe/opgeskorte proses. Met die bevoorregte nabootsingstoken kan jy 'n primêre token aflei (DuplicateTokenEx).\
Met die token kan jy 'n **nuwe proses** skep met 'CreateProcessAsUser' of 'n proses opgeskort skep en die token **instel** (gewoonlik kan jy nie die primêre token van 'n lopende proses wysig nie).

### SeTcbPrivilege

As jy hierdie token geaktiveer het, kan jy **KERB\_S4U\_LOGON** gebruik om 'n **nabootsingstoken** vir enige ander gebruiker te kry sonder om die geloofsbriewe te ken, **'n willekeurige groep** (administrateurs) by die token te voeg, die **integriteitsvlak** van die token na "**medium**" te stel, en hierdie token aan die **huidige draad** toe te ken (SetThreadToken).

### SeBackupPrivilege

Die stelsel word veroorsaak om alle leestoegangbeheer tot enige lêer (beperk tot leesoperasies) te verleen deur hierdie voorreg. Dit word gebruik vir die **lees van die wagwoordhasse van plaaslike Administrateur**-rekeninge uit die register, waarna gereedskap soos "**psexec**" of "**wmicexec**" met die has (Pass-the-Hash-tegniek) gebruik kan word. Hierdie tegniek faal egter onder twee toestande: wanneer die plaaslike Administrateur-rekening gedeaktiveer is, of wanneer 'n beleid van krag is wat administratiewe regte van plaaslike Administrateurs wat vanaf 'n afstand koppel, verwyder.

Jy kan hierdie voorreg **misbruik** met:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* volg **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Of soos verduidelik in die **bevoorregtingseskalerings met Backup-operateurs**-afdeling van:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Toestemming vir **skryftoegang** tot enige stelsellêer, ongeag die lêer se Toegangsbeheerlys (ACL), word deur hierdie voorreg verskaf. Dit bied talryke moontlikhede vir eskalasie, insluitend die vermoë om **dienste te wysig**, DLL-ontvoering uit te voer, en **afleiers** in te stel via Beeldlêeruitvoeringsopsies onder verskeie ander tegnieke.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is 'n kragtige toestemming, veral nuttig wanneer 'n gebruiker die vermoë het om tokens na te boots, maar ook in die afwesigheid van SeImpersonatePrivilege. Hierdie vermoë steun op die vermoë om 'n token na te boots wat dieselfde gebruiker voorstel en waarvan die integriteitsvlak nie die integriteitsvlak van die huidige proses oorskry nie.

**Kernpunte:**
- **Nabootsing sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege vir EoP te benut deur tokens na te boots onder spesifieke toestande.
- **Voorwaardes vir Tokennabootsing:** Suksesvolle nabootsing vereis dat die teikentoken aan dieselfde gebruiker behoort en 'n integriteitsvlak het wat minder of gelyk is aan die integriteitsvlak van die proses wat probeer naboots.
- **Skepping en Wysiging van Nabootsingstokens:** Gebruikers kan 'n nabootsingstoken skep en dit verbeter deur 'n bevoorregte groep se SID (Sekuriteitsidentifiseerder) by te voeg.

### SeLoadDriverPrivilege

Hierdie voorreg maak dit moontlik om **toestelbestuurders te laai en te ontlas** met die skepping van 'n registerinskrywing met spesifieke waardes vir `ImagePath` en `Type`. Aangesien direkte skryftoegang tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is, moet `HKCU` (HKEY_CURRENT_USER) eerder gebruik word. Om egter `HKCU` vir die kernel herkenbaar te maak vir bestuurderkonfigurasie, moet 'n spesifieke pad gevolg word.

Hierdie pad is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, waar `<RID>` die Relatiewe Identifiseerder van die huidige gebruiker is. Binne `HKCU` moet hierdie hele pad geskep word, en twee waardes moet ingestel word:
- `ImagePath`, wat die pad na die binêre uitvoering is
- `Type`, met 'n waarde van `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Stappe om te volg:**
1. Kry toegang tot `HKCU` in plaas van `HKLM` as gevolg van beperkte skryftoegang.
2. Skep die pad `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` binne `HKCU`, waar `<RID>` die Relatiewe Identifiseerder van die huidige gebruiker verteenwoordig.
3. Stel die `ImagePath` in op die uitvoeringspad van die binêre.
4. Ken die `Type` toe as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Sy primêre funksie laat 'n proses toe om **eienaarskap van 'n voorwerp te aanvaar**, wat die vereiste vir uitdruklike diskresionêre toegang omseil deur die voorsiening van WRITE_OWNER-toegangsregte. Die proses behels eerstens die versekering van eienaarskap van die beoogde registerleutel vir skryfdoeleindes, en dan die verandering van die DACL om skryfoperasies moontlik te maak.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Hierdie voorreg maak dit moontlik om **ander prosesse te debug**, insluitend om te lees en skryf in die geheue. Verskeie strategieë vir geheue-inspuiting, wat in staat is om die meeste antivirus- en gasheerindringingsvoorkomingsoplossings te ontduik, kan met hierdie voorreg gebruik word.

#### Gooi geheue

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) van die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) gebruik om die geheue van 'n proses **vas te lê**. Spesifiek kan dit van toepassing wees op die **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** proses, wat verantwoordelik is vir die stoor van gebruikersgeldeenhede sodra 'n gebruiker suksesvol op 'n stelsel ingeteken het.

Jy kan dan hierdie dump in mimikatz laai om wagwoorde te verkry:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

As jy 'n `NT SYSTEM`-skul wil kry, kan jy gebruik maak van:

- ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
- ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Kontroleer voorregte
```
whoami /priv
```
Die **tokens wat as Uitgeskakel verskyn** kan geaktiveer word, jy kan eintlik _Geaktiveerde_ en _Uitgeskakelde_ tokens misbruik.

### Aktiveer Al die tokens

As jy tokens uitgeskakel het, kan jy die skripsie [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Of die **skripsie** ingesluit in hierdie [**pos**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabel

Volledige token voorregte spiekbrief by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), opsomming hieronder sal slegs direkte maniere lys om die voorreg te misbruik om 'n administrateur-sessie te verkry of sensitiewe lêers te lees.

| Voorreg                    | Impak       | Gereedskap              | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                     | Opmerkings                                                                                                                                                                                                                                                                                                                      |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Derdeparty-gereedskap    | _"Dit sou 'n gebruiker in staat stel om tokens te impersoneer en te priviligeer na nt-stelsel met behulp van gereedskap soos potato.exe, rottenpotato.exe en juicypotato.exe"_                                                                                                                                                                                                      | Dankie [Aurélien Chalot](https://twitter.com/Defte\_) vir die opdatering. Ek sal probeer om dit binnekort na iets meer resepagtig te herskryf.                                                                                                                                                                                        |
| **`SeBackup`**             | **Bedreiging**  | _**Ingeboude opdragte**_ | Lees sensitiewe lêers met `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Mag meer interessant wees as jy %WINDIR%\MEMORY.DMP kan lees<br><br>- <code>SeBackupPrivilege</code> (en robocopy) is nie nuttig wanneer dit kom by oop lêers nie.<br><br>- Robocopy vereis beide SeBackup en SeRestore om met die /b parameter te werk.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Derdeparty-gereedskap    | Skep willekeurige token insluitende plaaslike administrateur-regte met `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliseer die `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | Skripsie te vind by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Derdeparty-gereedskap    | <p>1. Laai foutiewe kernelbestuurder soos <code>szkg64.sys</code><br>2. Benut die bestuurder se kwesbaarheid<br><br>Alternatiewelik kan die voorreg gebruik word om sekuriteitsverwante bestuurders met die `ftlMC` ingeboude opdrag te aflaai. bv.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Die <code>szkg64</code> kwesbaarheid word gelys as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Die <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">benuttingskode</a> is geskep deur <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Lanceer PowerShell/ISE met die SeRestore voorreg teenwoordig.<br>2. Aktiveer die voorreg met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Sluit die konsole af en druk Win+U</p> | <p>Aanval kan deur sommige AV-programmatuur opgespoor word.</p><p'Alternatiewe metode berus op die vervanging van diens-binêre lêers wat in "Program-lêers" gestoor word met dieselfde voorreg</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ingeboude opdragte**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Sluit die konsole af en druk Win+U</p>                                                                                                                                       | <p>Aanval kan deur sommige AV-programmatuur opgespoor word.</p><p>Alternatiewe metode berus op die vervanging van diens-binêre lêers wat in "Program-lêers" gestoor word met dieselfde voorreg.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Derdeparty-gereedskap    | <p>Manipuleer tokens om plaaslike administrateur-regte ingesluit te hê. Mag SeImpersonate benodig.</p><p>Om geverifieer te word.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Verwysing

* Neem 'n kyk na hierdie tabel wat Windows-tokens definieer: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Neem 'n kyk na [**hierdie dokument**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) oor privesc met tokens.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
