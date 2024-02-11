# Windows Kredensiaalbeskerming

## Kredensiaalbeskerming

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## WDigest

Die [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396) protokol, wat met Windows XP bekendgestel is, is ontwerp vir outentisering via die HTTP-protokol en is **standaard geaktiveer op Windows XP tot Windows 8.0 en Windows Server 2003 tot Windows Server 2012**. Hierdie verstekinstelling lei tot **plain-text wagwoordberging in LSASS** (Local Security Authority Subsystem Service). 'n Aanvaller kan Mimikatz gebruik om hierdie kredensiale te **onttrek** deur die volgende uit te voer:
```bash
sekurlsa::wdigest
```
Om hierdie funksie af of aan te skakel, moet die _**UseLogonCredential**_ en _**Negotiate**_ register sleutels binne _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ op "1" gestel word. As hierdie sleutels **afwesig of op "0" gestel** is, is WDigest **uitgeschakel**.
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA-beskerming

Vanaf **Windows 8.1** het Microsoft die veiligheid van LSA verbeter om **onbevoegde geheugenlesings of kode-inspuitings deur onbetroubare prosesse te blokkeer**. Hierdie verbetering belemmer die tipiese werking van opdragte soos `mimikatz.exe sekurlsa:logonpasswords`. Om hierdie verbeterde beskerming **te aktiveer**, moet die _**RunAsPPL**_-waarde in _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ aangepas word na 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Oorsteek

Dit is moontlik om hierdie beskerming te oorsteek deur die gebruik van die Mimikatz-bestuurder mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Credential Guard

**Credential Guard**, 'n funksie wat eksklusief is vir **Windows 10 (Enterprise en Education-weergawes)**, verbeter die veiligheid van masjienlegitimasie deur gebruik te maak van **Virtual Secure Mode (VSM)** en **Virtualization Based Security (VBS)**. Dit maak gebruik van CPU-virtualiseringsextensies om sleutelprosesse binne 'n beskermde geheue-omgewing te isoleer, weg van die bereik van die hoof-bedryfstelsel. Hierdie isolasie verseker dat selfs die kernel nie toegang tot die geheue in VSM kan verkry nie, en beskerm sodoende legitimasie teen aanvalle soos **pass-the-hash**. Die **Local Security Authority (LSA)** werk binne hierdie veilige omgewing as 'n trustlet, terwyl die **LSASS**-proses in die hoof-bedryfstelsel slegs as 'n kommunikeerder met die LSA van die VSM optree.

Standaard is **Credential Guard** nie aktief nie en vereis handmatige aktivering binne 'n organisasie. Dit is krities vir die verbetering van veiligheid teenoor hulpmiddels soos **Mimikatz**, wat belemmer word in hul vermoë om legitimasie te onttrek. Nietemin kan kwesbaarhede steeds uitgebuit word deur die byvoeging van aangepaste **Security Support Providers (SSP)** om legitimasie in duidelike teks vas te vang tydens aanmeldingspogings.

Om die aktiveringsstatus van **Credential Guard** te verifieer, kan die registerleutel **_LsaCfgFlags_** onder **_HKLM\System\CurrentControlSet\Control\LSA_** ondersoek word. 'n Waarde van "**1**" dui op aktivering met **UEFI-sluiting**, "**2**" sonder sluiting, en "**0**" dui daarop dat dit nie geaktiveer is nie. Hierdie registerkontrole, alhoewel 'n sterk aanduiding, is nie die enigste stap vir die aktivering van Credential Guard nie. Gedetailleerde leiding en 'n PowerShell-skrips vir die aktivering van hierdie funksie is aanlyn beskikbaar.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Vir 'n omvattende begrip en instruksies oor die aktivering van **Credential Guard** in Windows 10 en die outomatiese aktivering daarvan in verenigbare stelsels van **Windows 11 Enterprise en Education (weergawe 22H2)**, besoek [Microsoft se dokumentasie](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Verdere besonderhede oor die implementering van aangepaste SSP's vir kredensievaslegging word verskaf in [hierdie gids](../active-directory-methodology/custom-ssp.md).


## RDP RestrictedAdmin-modus

**Windows 8.1 en Windows Server 2012 R2** het verskeie nuwe sekuriteitskenmerke ingevoer, insluitend die **_Restricted Admin-modus vir RDP_**. Hierdie modus is ontwerp om sekuriteit te verbeter deur die risiko's wat verband hou met **[pass the hash](https://blog.ahasayen.com/pass-the-hash/)**-aanvalle te verminder.

Tradisioneel word jou legitimasie-inligting wanneer jy via RDP met 'n afgeleë rekenaar verbind, op die teikenrekenaar gestoor. Dit stel 'n beduidende sekuriteitsrisiko in, veral wanneer rekeninge met verhoogde bevoegdhede gebruik word. Met die bekendstelling van die **_Restricted Admin-modus_** word hierdie risiko aansienlik verminder.

Wanneer jy 'n RDP-verbinding inisieer deur die opdrag **mstsc.exe /RestrictedAdmin** te gebruik, word verifikasie na die afgeleë rekenaar uitgevoer sonder dat jou legitimasie-inligting daarop gestoor word. Hierdie benadering verseker dat, in die geval van 'n malware-infeksie of as 'n kwaadwillige gebruiker toegang tot die afgeleë bediener verkry, jou legitimasie-inligting nie in gevaar gebring word nie, aangesien dit nie op die bediener gestoor word nie.

Dit is belangrik om daarop te let dat in die **Restricted Admin-modus** pogings om netwerkbronne vanuit die RDP-sessie te benader nie jou persoonlike legitimasie-inligting gebruik nie; in plaas daarvan word die **identiteit van die masjien** gebruik.

Hierdie kenmerk is 'n belangrike stap vorentoe in die beveiliging van afgeleë skermverbindinge en die beskerming van sensitiewe inligting teen blootstelling in geval van 'n sekuriteitskending.

![](../../.gitbook/assets/ram.png)

Vir meer gedetailleerde inligting besoek [hierdie bron](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).


## Gekasieerde Legitimasie-inligting

Windows beveilig **domeinlegitimasie-inligting** deur die **Local Security Authority (LSA)**, wat aanmeldprosesse ondersteun met sekuriteitsprotokolle soos **Kerberos** en **NTLM**. 'n Sleutelkenmerk van Windows is sy vermoë om die **laaste tien domein-aanmeldings** te kasieer om te verseker dat gebruikers steeds toegang tot hul rekenaars kan verkry selfs as die **domeinbeheerder aflyn is**—'n voordeel vir draagbare rekenaargebruikers wat dikwels weg is van hul maatskappy se netwerk.

Die aantal gekasieerde aanmeldings kan aangepas word deur 'n spesifieke **registervoorwerp of groepriglyn**. Om hierdie instelling te sien of te verander, word die volgende opdrag gebruik:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Toegang tot hierdie gekaapte geloofsbriewe word streng beheer, met slegs die **SYSTEM**-rekening wat die nodige toestemmings het om dit te sien. Administrateurs wat toegang tot hierdie inligting benodig, moet dit doen met SYSTEM-gebruikersbevoegdhede. Die geloofsbriewe word gestoor by: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kan gebruik word om hierdie gekaapte geloofsbriewe te onttrek deur die opdrag `lsadump::cache` te gebruik.

Vir verdere besonderhede verskaf die oorspronklike [bron](http://juggernaut.wikidot.com/cached-credentials) omvattende inligting.

## Beskermde Gebruikers

Lidmaatskap in die **Beskermde Gebruikers-groep** bring verskeie sekuriteitsverbeterings vir gebruikers mee, wat verseker dat hoër vlakke van beskerming teen geloofsbriewe-diefstal en misbruik verkry word:

- **Geloofsbriewe-delegasie (CredSSP)**: Selfs as die Groepbeleid-instelling vir **Toelaat om standaardgeloofsbriewe te delegeren** geaktiveer is, sal die klaarteks geloofsbriewe van Beskermde Gebruikers nie gekaap word nie.
- **Windows Digest**: Vanaf **Windows 8.1 en Windows Server 2012 R2** sal die stelsel nie klaarteks geloofsbriewe van Beskermde Gebruikers in die cache stoor nie, ongeag die status van Windows Digest.
- **NTLM**: Die stelsel sal nie die klaarteks geloofsbriewe of NT eenrigtingfunksies (NTOWF) van Beskermde Gebruikers in die cache stoor nie.
- **Kerberos**: Vir Beskermde Gebruikers sal Kerberos-verifikasie nie **DES** of **RC4-sleutels** genereer nie, en dit sal ook nie klaarteks geloofsbriewe of langtermynsleutels stoor buite die aanvanklike Tikkie-Verlening-Tikkie (TGT)-verkryging nie.
- **Aflyn Aanmelding**: Beskermde Gebruikers sal nie 'n gekaapte verifieerder by aanmelding of ontgrendeling hê nie, wat beteken dat aflyn aanmelding nie ondersteun word vir hierdie rekeninge nie.

Hierdie beskermings word geaktiveer sodra 'n gebruiker, wat 'n lid van die **Beskermde Gebruikers-groep** is, by die toestel aanmeld. Dit verseker dat kritieke sekuriteitsmaatreëls in plek is om teen verskeie metodes van geloofsbriewe-kompromittering te beskerm.

Vir meer gedetailleerde inligting, raadpleeg die amptelike [dokumentasie](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabel van** [**die dokumentasie**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
