# Fisiese Aanvalle

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## BIOS-wagwoordherwinning en Sisteemsekuriteit

Die **terugstel van die BIOS** kan op verskeie maniere bereik word. Die meeste moederborde bevat 'n **battery** wat, wanneer dit vir ongeveer **30 minute** verwyder word, die BIOS-instellings sal terugstel, insluitend die wagwoord. Alternatiewelik kan 'n **jumper op die moederbord** aangepas word om hierdie instellings terug te stel deur spesifieke pennaaldjies te verbind.

Vir situasies waar hardeware-aanpassings nie moontlik of prakties is nie, bied **sagtewarehulpmiddels** 'n oplossing. Deur 'n stelsel van 'n **Live CD/USB** met verspreidings soos **Kali Linux** te hardloop, het jy toegang tot hulpmiddels soos **_killCmos_** en **_CmosPWD_**, wat kan help met BIOS-wagwoordherwinning.

In gevalle waar die BIOS-wagwoord onbekend is, sal die invoer van dit verkeerd **drie keer** tipies lei tot 'n foutkode. Hierdie kode kan gebruik word op webwerwe soos [https://bios-pw.org](https://bios-pw.org) om moontlik 'n bruikbare wagwoord te herwin.

### UEFI-sekuriteit

Vir moderne stelsels wat **UEFI** in plaas van tradisionele BIOS gebruik, kan die hulpmiddel **chipsec** gebruik word om UEFI-instellings te analiseer en te wysig, insluitend die deaktivering van **Secure Boot**. Dit kan gedoen word met die volgende bevel:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM-analise en Koue Ontploffingsaanvalle

RAM behou data kort nadat die krag afgesny is, gewoonlik vir **1 tot 2 minute**. Hierdie volharding kan verleng word tot **10 minute** deur koue stowwe, soos vloeibare stikstof, toe te pas. Gedurende hierdie verlengde tydperk kan 'n **geheue-afvoer** geskep word met behulp van hulpmiddels soos **dd.exe** en **volatility** vir analise.

### Direkte Geheue Toegang (DMA) Aanvalle

**INCEPTION** is 'n hulpmiddel wat ontwerp is vir **fisiese geheue-manipulasie** deur DMA, wat kompatibel is met interfaces soos **FireWire** en **Thunderbolt**. Dit maak dit moontlik om inlogprosedures te omseil deur geheue te verander om enige wagwoord te aanvaar. Dit is egter nie effektief teen **Windows 10**-stelsels nie.

### Live CD/USB vir Sisteemtoegang

Die verandering van stelsel-binêre lêers soos **_sethc.exe_** of **_Utilman.exe_** met 'n kopie van **_cmd.exe_** kan 'n opdragvenster met stelselbevoegdhede voorsien. Hulpmiddels soos **chntpw** kan gebruik word om die **SAM**-lêer van 'n Windows-installasie te wysig, wat wagwoordveranderinge moontlik maak.

**Kon-Boot** is 'n hulpmiddel wat dit vergemaklik om in te teken op Windows-stelsels sonder om die wagwoord te ken deur tydelik die Windows-kernel of UEFI te wysig. Meer inligting is beskikbaar by [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Hantering van Windows-sekuriteitskenmerke

#### Opstart- en Herstelafkortings

- **Supr**: Toegang tot BIOS-instellings.
- **F8**: Betree herstelmodus.
- Deur **Shift** te druk na die Windows-banier kan outomatiese aanmelding omseil word.

#### SLEGS USB-toestelle

Toestelle soos **Rubber Ducky** en **Teensyduino** dien as platforms vir die skep van **slegte USB**-toestelle wat in staat is om voorafbepaalde ladinge uit te voer wanneer dit aan 'n teikenskerm gekoppel word.

#### Volume Shadow Copy

Administrateurbevoegdhede maak dit moontlik om kopieë van sensitiewe lêers, insluitend die **SAM**-lêer, te skep deur middel van PowerShell.

### Omseiling van BitLocker-versleuteling

BitLocker-versleuteling kan moontlik omseil word as die **herstelwagwoord** gevind word binne 'n geheue-afvoerlêer (**MEMORY.DMP**). Hulpmiddels soos **Elcomsoft Forensic Disk Decryptor** of **Passware Kit Forensic** kan vir hierdie doel gebruik word.

### Maatskaplike Ingenieurswese vir Herstelsleuteltoevoeging

'n Nuwe BitLocker-herstelsleutel kan deur maatskaplike ingenieurswese-taktieke bygevoeg word, deur 'n gebruiker te oortuig om 'n opdrag uit te voer wat 'n nuwe herstelsleutel wat uit nulle bestaan, byvoeg, en sodoende die dekripsieproses vereenvoudig.

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
