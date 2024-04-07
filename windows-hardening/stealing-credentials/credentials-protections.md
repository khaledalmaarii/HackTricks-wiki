# Windows Geloofsbriewe Beskerming

## Gelooofsbriewe Beskerming

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat** Kontroleer die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## WDigest

Die [WDigest](https://technet.microsoft.com/pt-pt/library/cc778868\(v=ws.10\).aspx?f=255\&MSPPError=-2147217396) protokol, wat met Windows XP ingevoer is, is ontwerp vir outentisering via die HTTP-protokol en is **standaard geaktiveer op Windows XP tot Windows 8.0 en Windows Server 2003 tot Windows Server 2012**. Hierdie verstekinstelling lei tot **plain-text wagwoordberging in LSASS** (Local Security Authority Subsystem Service). 'n Aanvaller kan Mimikatz gebruik om **hierdie geloofsbriewe te onttrek** deur die volgende uit te voer:
```bash
sekurlsa::wdigest
```
Om hierdie kenmerk af of aan te skakel, moet die _**UseLogonCredential**_ en _**Negotiate**_ register sleutels binne _**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ op "1" ingestel word. As hierdie sleutels **afwesig is of op "0" ingestel is**, is WDigest **uitgeskakel**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA-beskerming

Vanaf **Windows 8.1** het Microsoft die veiligheid van LSA verbeter om **onbevoegde geheue-lees of kode-inspuitings deur onvertroude prosesse te blokkeer**. Hierdie verbetering hinder die tipiese werking van bevele soos `mimikatz.exe sekurlsa:logonpasswords`. Om hierdie verbeterde beskerming te **aktiveer**, moet die _**RunAsPPL**_ waarde in _**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ aangepas word na 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Oorweging

Dit is moontlik om hierdie beskerming te omseil deur die gebruik van die Mimikatz-bestuurder mimidrv.sys:

![](../../.gitbook/assets/mimidrv.png)

## Geloofsbriewe-Wag

**Geloofsbriewe-Wag**, 'n kenmerk wat eksklusief is vir **Windows 10 (Enterprise en Onderwys-uitgawes)**, verbeter die sekuriteit van masjien-geloofsbriewe deur die gebruik van **Virtuele Sekuriteitsmodus (VSM)** en **Virtuele Gebaseerde Sekuriteit (VBS)**. Dit maak gebruik van CPU-virtueleksie-uitbreidings om sleutelprosesse binne 'n beskermde geheue-omgewing te isoleer, weg van die hoofbedryfstelsel se bereik. Hierdie isolasie verseker dat selfs die kernel nie toegang tot die geheue in VSM kan kry nie, wat geloofsbriewe effektief teen aanvalle soos **oor-die-hashing** beskerm. Die **Plaaslike Sekuriteitsowerheid (LSA)** werk binne hierdie veilige omgewing as 'n vertroueling, terwyl die **LSASS**-proses in die hoof-OS slegs as 'n kommunikeerder met die VSM se LSA optree.

Standaard is **Geloofsbriewe-Wag** nie aktief nie en vereis handmatige aktivering binne 'n organisasie. Dit is krities vir die verbetering van sekuriteit teen gereedskap soos **Mimikatz**, wat belemmer word in hul vermoë om geloofsbriewe te onttrek. Tog kan kwesbaarhede steeds uitgebuit word deur die byvoeging van aangepaste **Sekuriteitsondersteuningsverskaffers (SSP)** om geloofsbriewe in die teks duidelik tydens aanmeldingspogings vas te lê.

Om **Geloofsbriewe-Wag** se aktiveringsstatus te verifieer, kan die registerleutel _**LsaCfgFlags**_ onder _**HKLM\System\CurrentControlSet\Control\LSA**_ nagegaan word. 'n Waarde van "**1**" dui op aktivering met **UEFI-slot**, "**2**" sonder slot, en "**0**" dui daarop dat dit nie geaktiveer is nie. Hierdie registerkontrole, alhoewel 'n sterk aanduiding, is nie die enigste stap vir die aktivering van Geloofsbriewe-Wag nie. Gedetailleerde leiding en 'n PowerShell-skrip vir die aktivering van hierdie kenmerk is aanlyn beskikbaar.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Vir 'n omvattende begrip en instruksies oor die aktivering van **Credential Guard** in Windows 10 en die outomatiese aktivering in verenigbare stelsels van **Windows 11 Enterprise en Education (weergawe 22H2)**, besoek [Microsoft se dokumentasie](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Verdere besonderhede oor die implementering van aangepaste SSP's vir kredensievangste word verskaf in [hierdie gids](../active-directory-methodology/custom-ssp.md).

## RDP Beperkte Admin-modus

**Windows 8.1 en Windows Server 2012 R2** het verskeie nuwe sekuriteitskenmerke ingevoer, insluitend die _**Beperkte Admin-modus vir RDP**_. Hierdie modus is ontwerp om sekuriteit te verbeter deur die risiko's wat verband hou met [**hash deurgee**](https://blog.ahasayen.com/pass-the-hash/) aanvalle te verminder.

Tradisioneel, wanneer jy via RDP met 'n afgeleë rekenaar verbind, word jou geloofsbriewe op die teikengreep gestoor. Dit skep 'n beduidende sekuriteitsrisiko, veral wanneer rekeninge met verhoogde voorregte gebruik word. Met die bekendstelling van die _**Beperkte Admin-modus**_ word hierdie risiko egter aansienlik verminder.

Wanneer 'n RDP-verbindings geïnisieer word deur die opdrag **mstsc.exe /RestrictedAdmin** te gebruik, word verifikasie na die afgeleë rekenaar uitgevoer sonder om jou geloofsbriewe daarop te stoor. Hierdie benadering verseker dat, in die geval van 'n malware-infeksie of as 'n skadelike gebruiker toegang tot die afgeleë bediener verkry, jou geloofsbriewe nie gekompromitteer word nie, aangesien hulle nie op die bediener gestoor word nie.

Dit is belangrik om daarop te let dat in **Beperkte Admin-modus** pogings om netwerkbronne vanuit die RDP-sessie te benader nie jou persoonlike geloofsbriewe sal gebruik nie; in plaas daarvan word die **identiteit van die masjien** gebruik.

Hierdie kenmerk is 'n beduidende stap vorentoe in die beveiliging van afgeleë skakelverbindings en die beskerming van sensitiewe inligting teen blootstelling in geval van 'n sekuriteitsversteuring.

![](../../.gitbook/assets/RAM.png)

Vir meer gedetailleerde inligting besoek [hierdie bron](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Gekasieerde Geldeenhede

Windows beveilig **domein-geloofsbriewe** deur die **Plaaslike Sekuriteitsowerheid (LSA)**, wat aanmeldingsprosesse ondersteun met sekuriteitsprotokolle soos **Kerberos** en **NTLM**. 'n Sleutelkenmerk van Windows is sy vermoë om die **laaste tien domein-aanmeldings** te kaseer om te verseker dat gebruikers steeds toegang tot hul rekenaars kan verkry selfs as die **domeinbeheerder aflyn** is—'n voordeel vir draagbare rekenaargebruikers wat dikwels weg van hul maatskappy se netwerk is.

Die aantal gekasieerde aanmeldings is aanpasbaar deur 'n spesifieke **register sleutel of groepbeleid**. Om hierdie instelling te sien of te verander, word die volgende opdrag gebruik:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Toegang tot hierdie gekaapte geloofsbriewe word streng beheer, met slegs die **SYSTEM**-rekening wat die nodige regte het om dit te sien. Administrateurs wat hierdie inligting moet raadpleeg, moet dit doen met SYSTEM-gebruikersregte. Die geloofsbriewe word gestoor by: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kan gebruik word om hierdie gekaapte geloofsbriewe te onttrek deur die bevel `lsadump::cache` te gebruik.

Vir verdere besonderhede, bied die oorspronklike [bron](http://juggernaut.wikidot.com/cached-credentials) omvattende inligting.

## Beskermde Gebruikers

Lidmaatskap van die **Beskermde Gebruikersgroep** bring verskeie sekuriteitsverbeteringe vir gebruikers, wat verseker dat hoër vlakke van beskerming teen geloofsbriewe-diefstal en -misbruik gehandhaaf word:

* **Geloofsbriewe-delegasie (CredSSP)**: Selfs as die Groepbeleid-instelling vir **Toelaat dat standaardgeldelegering** geaktiveer is, sal die platte teks geloofsbriewe van Beskermde Gebruikers nie gekaap word nie.
* **Windows Digest**: Beginnende vanaf **Windows 8.1 en Windows Server 2012 R2**, sal die stelsel nie die platte teks geloofsbriewe van Beskermde Gebruikers kaps nie, ongeag die Windows Digest-status.
* **NTLM**: Die stelsel sal nie die platte teks geloofsbriewe of NT eenrigtingfunksies (NTOWF) van Beskermde Gebruikers kaps nie.
* **Kerberos**: Vir Beskermde Gebruikers sal Kerberos-verifikasie nie **DES** of **RC4-sleutels** genereer nie, en dit sal ook nie die platte teks geloofsbriewe of langtermynsleutels verder as die aanvanklike Kaartjie-Verlening-Kaartjie (TGT) verkryging kaps nie.
* **Aflyn Aanmelding**: Beskermde Gebruikers sal nie 'n gekaapte verifieerder hê wat geskep word by aanmelding of ontgrendeling nie, wat beteken dat aflyn aanmelding nie ondersteun word vir hierdie rekeninge nie.

Hierdie beskermings word geaktiveer sodra 'n gebruiker, wat 'n lid is van die **Beskermde Gebruikersgroep**, op die toestel aanmeld. Dit verseker dat kritieke sekuriteitsmaatreëls in plek is om teen verskeie metodes van geloofsbriewe-kompromittering te beskerm.

Vir meer gedetailleerde inligting, raadpleeg die amptelike [dokumentasie](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabel van** [**die dokumente**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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
