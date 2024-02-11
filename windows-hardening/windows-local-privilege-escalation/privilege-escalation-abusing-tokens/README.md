# Misbruik van Tokens

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokens

As jy **nie weet wat Windows Access Tokens is nie**, lees hierdie bladsy voordat jy voortgaan:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Miskien kan jy bevoorregte regte verhoog deur die tokens wat jy reeds het te misbruik**

### SeImpersonatePrivilege

Hierdie is 'n voorreg wat deur enige proses gehou word en die nabootsing (maar nie die skepping) van enige token toelaat, mits 'n handvatsel daarvoor verkry kan word. 'n Bevoorregte token kan verkry word van 'n Windows-diens (DCOM) deur dit te verlei om NTLM-verifikasie teen 'n uitbuiting uit te voer, wat die uitvoering van 'n proses met SYSTEM-regte moontlik maak. Hierdie kwesbaarheid kan uitgebuit word met behulp van verskeie gereedskap soos [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (wat winrm moet deaktiveer), [SweetPotato](https://github.com/CCob/SweetPotato) en [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

Dit is baie soortgelyk aan **SeImpersonatePrivilege**, dit sal dieselfde metode gebruik om 'n bevoorregte token te verkry.\
Hierdie voorreg maak dit dan moontlik om 'n primêre token toe te ken aan 'n nuwe/opgeskorte proses. Met die bevoorregte nabootsingstoken kan jy 'n primêre token aflei (DuplicateTokenEx).\
Met die token kan jy 'n **nuwe proses** skep met 'CreateProcessAsUser' of 'n proses opgeskort skep en die token **stel** (in die algemeen kan jy nie die primêre token van 'n lopende proses wysig nie).

### SeTcbPrivilege

As jy hierdie token geaktiveer het, kan jy **KERB\_S4U\_LOGON** gebruik om 'n **nabootsingstoken** vir enige ander gebruiker te verkry sonder om die geloofsbriewe te ken, **'n willekeurige groep** (admins) by die token te voeg, die **integriteitsvlak** van die token na "**medium**" te stel, en hierdie token aan die **huidige draad** toe te ken (SetThreadToken).

### SeBackupPrivilege

Die stelsel word veroorsaak om **alle leestoegang**-beheer aan enige lêer (beperk tot leesbewerkings) te verleen deur hierdie voorreg. Dit word gebruik om die wagwoordhasings van plaaslike Administrateur-rekeninge uit die register te lees, waarna gereedskap soos "**psexec**" of "**wmicexec**" met die has (Pass-the-Hash-tegniek) gebruik kan word. Hierdie tegniek misluk egter onder twee voorwaardes: wanneer die plaaslike Administrateur-rekening gedeaktiveer is, of wanneer 'n beleid van krag is wat administratiewe regte van plaaslike Administrateurs wat op afstand verbind, verwyder.
Jy kan hierdie voorreg **misbruik** met:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* deur **IppSec** te volg in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Of soos verduidelik in die **voorregte-escalasie met Backup Operators**-afdeling van:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

Hierdie voorreg bied toestemming vir **skryftoegang** tot enige stelsel-lêer, ongeag die toegangsbeheerlys (ACL) van die lêer. Dit skep tallose moontlikhede vir escalasie, insluitend die vermoë om **dienste te wysig**, DLL Hijacking uit te voer, en **afsyfers** in te stel via Image File Execution Options, onder verskeie ander tegnieke.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is 'n kragtige toestemming, veral nuttig wanneer 'n gebruiker die vermoë het om tokens na te boots, maar ook in die afwesigheid van SeImpersonatePrivilege. Hierdie vermoë steun op die vermoë om 'n token na te boots wat dieselfde gebruiker voorstel en waarvan die integriteitsvlak nie die integriteitsvlak van die huidige proses oorskry nie.

**Kernpunte:**
- **Nabootsing sonder SeImpersonatePrivilege:** Dit is moontlik om SeCreateTokenPrivilege te benut vir EoP deur tokens na te boots onder spesifieke voorwaardes.
- **Voorwaardes vir Token Nabootsing:** Suksesvolle nabootsing vereis dat die teikentoken aan dieselfde gebruiker behoort en 'n integriteitsvlak het wat minder of gelyk is aan die integriteitsvlak van die proses wat nabootsing probeer.
- **Skepping en Wysiging van Nabootsings-Tokens:** Gebruikers kan 'n nabootsings-token skep en dit verbeter deur 'n SID (Security Identifier) van 'n bevoorregte groep by te voeg.

### SeLoadDriverPrivilege

Hierdie voorreg maak dit moontlik om toestelbestuurders te **laai en te verwyder** deur 'n registerinskrywing te skep met spesifieke waardes vir `ImagePath` en `Type`. Aangesien direkte skryftoegang tot `HKLM` (HKEY_LOCAL_MACHINE) beperk is
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
Meer maniere om hierdie voorreg te misbruik is beskikbaar in [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Dit is soortgelyk aan **SeRestorePrivilege**. Sy primêre funksie stel 'n proses in staat om **eienaarskap van 'n voorwerp** oor te neem, deur die vereiste vir uitdruklike diskresionêre toegang te omseil deur die voorsiening van WRITE_OWNER-toegangsregte. Die proses behels om eers eienaarskap van die beoogde register sleutel te verseker vir skryfdoeleindes, en dan die DACL te verander om skryfoperasies moontlik te maak.
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

Hierdie voorreg maak dit moontlik om ander prosesse te **debu**g, insluitend om te lees en skryf in die geheue. Verskeie strategieë vir geheue-inspuiting, wat in staat is om die meeste antivirus- en host-indringingsvoorkomingsoplossings te omseil, kan met hierdie voorreg gebruik word.

#### Dump geheue

Jy kan [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) van die [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) gebruik om die geheue van 'n proses vas te vang. Spesifiek kan dit van toepassing wees op die **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))** proses, wat verantwoordelik is vir die stoor van gebruikerslegitimasie sodra 'n gebruiker suksesvol op 'n stelsel ingeteken het.

Jy kan dan hierdie dump in mimikatz laai om wagwoorde te verkry:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

As jy 'n `NT SYSTEM` skulp wil kry, kan jy gebruik maak van:

* ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
* ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Kontroleer voorregte

To begin with, it is important to check the privileges of the current user in order to identify potential opportunities for privilege escalation. This can be done using various methods:

### 1. Whoami

The `whoami` command can be used to display the username and group membership of the current user. This information can help determine the level of privileges the user possesses.

```plaintext
whoami
```

### 2. Net user

The `net user` command can be used to retrieve detailed information about user accounts on the system, including their group memberships and privileges.

```plaintext
net user [username]
```

### 3. Systeminfo

The `systeminfo` command provides a wealth of information about the system, including the current user's privileges. Look for the "User Name" field to identify the current user and their associated privileges.

```plaintext
systeminfo
```

### 4. Task Manager

The Task Manager can also be used to check the privileges of the current user. Open Task Manager and navigate to the "Details" tab. Right-click on the column headers and select "Select Columns." Check the "Elevated" box to display the elevated privileges of processes.

### 5. PowerShell

PowerShell provides several commands that can be used to check user privileges. For example, the following command displays the current user's group memberships:

```plaintext
(Get-Command net).Definition | Select-String -Pattern "net\.exe"
```

These methods can help identify potential avenues for privilege escalation by revealing the current user's privileges and group memberships.
```
whoami /priv
```
Die **tokens wat as Uitgeschakel verskyn** kan geaktiveer word, en jy kan eintlik _Geaktiveerde_ en _Uitgeschakelde_ tokens misbruik.

### Aktiveer al die tokens

As jy uitgeschakelde tokens het, kan jy die skrip [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) gebruik om al die tokens te aktiveer:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Of die **skrip** ingebed in hierdie [**pos**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabel

Volledige tokenvoorregte-kaartjie by [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), 'n opsomming hieronder sal slegs direkte maniere lys om die voorreg te misbruik om 'n administratiewe sessie te verkry of sensitiewe lêers te lees.

| Voorreg                    | Impak       | Gereedskap              | Uitvoeringspad                                                                                                                                                                                                                                                                                                                                     | Opmerkings                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Derdeparty-gereedskap    | _"Dit sal 'n gebruiker in staat stel om tokens te impersoneer en na nt-stelsel te priviligeer deur gebruik te maak van hulpmiddels soos potato.exe, rottenpotato.exe en juicypotato.exe"_                                                                                                                                                                                                      | Dankie [Aurélien Chalot](https://twitter.com/Defte\_) vir die opdatering. Ek sal probeer om dit binnekort na iets soos 'n resep te herskryf.                                                                                                                                                                                        |
| **`SeBackup`**             | **Bedreiging**  | _**Ingeboude opdragte**_ | Lees sensitiewe lêers met `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Mag interessanter wees as jy %WINDIR%\MEMORY.DMP kan lees<br><br>- <code>SeBackupPrivilege</code> (en robocopy) is nie nuttig wanneer dit kom by die oopmaak van lêers nie.<br><br>- Robocopy vereis beide SeBackup en SeRestore om met die /b-parameter te werk.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Derdeparty-gereedskap    | Skep willekeurige token, insluitend plaaslike administratiewe regte met `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliseer die `lsass.exe`-token.                                                                                                                                                                                                                                                                                                                   | Skrip kan gevind word by [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Derdeparty-gereedskap    | <p>1. Laai foutiewe kernbestuurder soos <code>szkg64.sys</code><br>2. Misbruik die bestuurder se kwesbaarheid<br><br>Alternatiewelik kan die voorreg gebruik word om sekuriteitsverwante bestuurders met die ingeboude opdrag <code>ftlMC</code> te ontlas. bv.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. Die <code>szkg64</code> kwesbaarheid word gelys as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. Die <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">misbruik-kode</a> is geskep deur <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Begin PowerShell/ISE met die teenwoordigheid van die SeRestore-voorreg.<br>2. Aktiveer die voorreg met <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Hernoem utilman.exe na utilman.old<br>4. Hernoem cmd.exe na utilman.exe<br>5. Sluit die konsole af en druk Win+U</p> | <p>Aanval kan deur sommige AV-programmatuur opgespoor word.</p><p'Alternatiewe metode berus op die vervanging van diensbinêre lêers wat in "Program Files" gestoor word met dieselfde voorreg</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ingeboude opdragte**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Hernoem cmd.exe na utilman.exe<br>4. Sluit die konsole af en druk Win+U</p>                                                                                                                                       | <p>Aanval kan deur sommige AV-programmatuur opgespoor word.</p><p>Alternatiewe metode berus op die vervanging van diensbinêre lêers wat in "Program Files" gestoor word met dieselfde voorreg.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Derdeparty-gereedskap    | <p>Manipuleer tokens om plaaslike administratiewe regte in te sluit. Mag SeImpersonate vereis.</p><p>Moet geverifieer word.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Verwysing

* Kyk na hierdie tabel wat Windows-tokens definieer: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Kyk na [**hierdie dokument**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) oor priviligeer met tokens.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
