# Toegangstokens

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Toegangstokens

Elke **gebruiker wat aangemeld is** op die stelsel **besit 'n toegangstoken met sekuriteitsinligting** vir daardie aanmeldsessie. Die stelsel skep 'n toegangstoken wanneer die gebruiker aanmeld. **Elke proses wat uitgevoer word** namens die gebruiker **het 'n kopie van die toegangstoken**. Die token identifiseer die gebruiker, die gebruiker se groepe, en die gebruiker se voorregte. 'n Token bevat ook 'n aanmeld-SID (Security Identifier) wat die huidige aanmeldsessie identifiseer.

Jy kan hierdie inligting sien deur `whoami /all` uit te voer.
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
of deur _Process Explorer_ van Sysinternals te gebruik (kies proses en toegang "Security" tabblad):

![](<../../.gitbook/assets/image (321).png>)

### Plaaslike administrateur

Wanneer 'n plaaslike administrateur aanmeld, word **twee toegangstokens geskep**: Een met administratiewe regte en 'n ander met normale regte. **Standaard**, wanneer hierdie gebruiker 'n proses uitvoer, word die een met **gewone** (nie-administratiewe) **regte gebruik**. Wanneer hierdie gebruiker iets probeer **uitvoer** as administrateur ("Run as Administrator" byvoorbeeld), sal die **UAC** gebruik word om vir toestemming te vra.\
As jy meer wil [**leer oor die UAC, lees hierdie bladsy**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Gebruikersimpersonasie van geloofsbriewe

As jy **geldige geloofsbriewe van enige ander gebruiker** het, kan jy 'n **nuwe aanmeldsessie** skep met daardie geloofsbriewe:
```
runas /user:domain\username cmd.exe
```
Die **toegangsteken** het ook 'n **verwysing** na die aanmeldsessies binne die **LSASS**, dit is nuttig as die proses toegang tot sekere netwerkobjekte benodig.\
Jy kan 'n proses lanceer wat **verskillende geloofsbriewe gebruik om toegang tot netwerkdienste te verkry** deur die volgende te doen:
```
runas /user:domain\username /netonly cmd.exe
```
Dit is nuttig as jy nuttige geloofsbriewe het om toegang tot voorwerpe in die netwerk te verkry, maar daardie geloofsbriewe is nie geldig binne die huidige gasheer nie, aangesien dit slegs in die netwerk gebruik sal word (in die huidige gasheer sal jou huidige gebruikersbevoegdhede gebruik word).

### Tipes tokens

Daar is twee tipes tokens beskikbaar:

* **Primêre Token**: Dit dien as 'n verteenwoordiging van 'n proses se sekuriteitsgeloofsbriewe. Die skepping en assosiasie van primêre tokens met prosesse is aksies wat verhoogde bevoegdhede vereis en die beginsel van bevoegdheidsskeiding beklemtoon. Tipies is 'n outentiseringsdiens verantwoordelik vir token-skepping, terwyl 'n aanmeldingsdiens dit hanteer met die assosiasie daarvan met die gebruiker se bedryfstelsel-skulp. Dit is die moeite werd om op te merk dat prosesse die primêre token van hul ouerproses by skepping erf.

* **Impersonation Token**: Gee 'n bedieningsprogram die vermoë om tydelik die identiteit van die kliënt oor te neem om veilige voorwerpe te benader. Hierdie meganisme is verdeel in vier vlakke van werking:
- **Anoniem**: Verleen bedieningstoegang soortgelyk aan dié van 'n ongeïdentifiseerde gebruiker.
- **Identifikasie**: Stel die bedieningsprogram in staat om die identiteit van die kliënt te verifieer sonder om dit vir voorwerptoegang te gebruik.
- **Impersonasie**: Maak dit vir die bedieningsprogram moontlik om onder die identiteit van die kliënt te werk.
- **Delegasie**: Soortgelyk aan Impersonasie, maar sluit die vermoë in om hierdie identiteitsaannames na afgeleë stelsels uit te brei waarmee die bedieningsprogram interaksie het, om geloofsbewaring te verseker.

#### Impersonate Tokens

Met behulp van die _**incognito**_ module van metasploit kan jy, as jy genoeg bevoegdhede het, ander tokens maklik **lys** en **impersonate**. Dit kan nuttig wees om **handelinge uit te voer asof jy die ander gebruiker is**. Met hierdie tegniek kan jy ook **bevoegdhede eskaleer**.

### Token Bevoegdhede

Leer watter **token bevoegdhede misbruik kan word om bevoegdhede te eskaleer:**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

Neem 'n kykie na [**al die moontlike token bevoegdhede en sommige definisies op hierdie eksterne bladsy**](https://github.com/gtworek/Priv2Admin).

## Verwysings

Leer meer oor tokens in hierdie tutoriale: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) en [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
