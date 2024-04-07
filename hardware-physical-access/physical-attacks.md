# Fisiese Aanvalle

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## BIOS Wagwoordherwinning en Stelselsekuriteit

Die **herstel van die BIOS** kan op verskeie maniere bereik word. Die meeste moederborde bevat 'n **battery** wat, wanneer dit vir ongeveer **30 minute** verwyder word, die BIOS-instellings, insluitend die wagwoord, sal herstel. Alternatief kan 'n **jumper op die moederbord** aangepas word om hierdie instellings te herstel deur spesifieke penne te verbind.

Vir situasies waar hardeware-aanpassings nie moontlik of prakties is nie, bied **sagtewaretools** 'n oplossing. Die hardloop van 'n stelsel van 'n **Live CD/USB** met verspreidings soos **Kali Linux** bied toegang tot gereedskap soos **_killCmos_** en **_CmosPWD_**, wat kan help met BIOS-wagwoordherwinning.

In gevalle waar die BIOS-wagwoord onbekend is, sal die verkeerde invoer daarvan **drie keer** tipies lei tot 'n foutkode. Hierdie kode kan op webwerwe soos [https://bios-pw.org](https://bios-pw.org) gebruik word om moontlik 'n bruikbare wagwoord te herwin.

### UEFI-sekuriteit

Vir moderne stelsels wat **UEFI** in plaas van tradisionele BIOS gebruik, kan die gereedskap **chipsec** gebruik word om UEFI-instellings te analiseer en te wysig, insluitend die deaktivering van **Secure Boot**. Dit kan gedoen word met die volgende bevel:

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM-analise en Koue-aanvalle op die Klok

RAM behou data kort na kragonderbreking, gewoonlik vir **1 tot 2 minute**. Hierdie volharding kan verleng word tot **10 minute** deur koue stowwe, soos vloeibare stikstof, toe te pas. Gedurende hierdie verlengde tydperk kan 'n **geheue-uitstorting** geskep word met gereedskap soos **dd.exe** en **volatility** vir analise.

### Direkte Geheue-toegang (DMA) Aanvalle

**INCEPTION** is 'n gereedskap wat ontwerp is vir **fisiese geheue-manipulasie** deur DMA, wat kompatibel is met koppelvlakke soos **FireWire** en **Thunderbolt**. Dit maak dit moontlik om inlogprosedures te omseil deur geheue te patch om enige wagwoord te aanvaar. Dit is egter ondoeltreffend teenoor **Windows 10**-stelsels.

### Live CD/USB vir Stelseltoegang

Die verandering van stelsel-binêre lêers soos **_sethc.exe_** of **_Utilman.exe_** met 'n kopie van **_cmd.exe_** kan 'n opdragpunt met stelselbevoegdhede bied. Gereedskap soos **chntpw** kan gebruik word om die **SAM**-lêer van 'n Windows-installasie te wysig, wat wagwoordveranderinge moontlik maak.

**Kon-Boot** is 'n gereedskap wat die aanmelding by Windows-stelsels vergemaklik sonder om die wagwoord te ken deur tydelik die Windows-kernel of UEFI te wysig. Meer inligting kan gevind word by [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Hantering van Windows-sekuriteitskenmerke

#### Kortpaaie vir Opstart en Herstel

- **Supr**: Toegang tot BIOS-instellings.
- **F8**: Betree Herstelmodus.
- Deur na die Windows-banner **Shift** te druk, kan outomatiese aanmelding omseil word.

#### SLEAGTE USB-toestelle

Toestelle soos **Rubber Ducky** en **Teensyduino** dien as platforms vir die skep van **slegte USB**-toestelle, wat in staat is om voorafbepaalde vragte uit te voer wanneer dit aan 'n teikenkoerier gekoppel word.

#### Volume Shadow Copy

Administrateursbevoegdhede maak die skep van kopieë van sensitiewe lêers, insluitend die **SAM**-lêer, deur PowerShell moontlik.

### Om BitLocker-versleuteling te omseil

BitLocker-versleuteling kan moontlik omseil word as die **herstelwagwoord** binne 'n geheue-uitstortlêer (**MEMORY.DMP**) gevind word. Gereedskap soos **Elcomsoft Forensic Disk Decryptor** of **Passware Kit Forensic** kan vir hierdie doel gebruik word.

### Maatskaplike Ingenieurswese vir die Byvoeging van Herstelsleutel

'n Nuwe BitLocker-herstelsleutel kan deur maatskaplike ingenieurswese-taktieke bygevoeg word, deur 'n gebruiker te oortuig om 'n opdrag uit te voer wat 'n nuwe herstelsleutel van nulle byvoeg, wat sodoende die dekripsieproses vereenvoudig.

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
