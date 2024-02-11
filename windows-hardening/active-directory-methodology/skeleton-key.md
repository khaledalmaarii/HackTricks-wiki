# Skeleton Sleutel

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

## Skeleton Sleutelaanval

Die **Skeleton Sleutelaanval** is 'n gesofistikeerde tegniek wat aanvallers in staat stel om **Active Directory-outentifikasie te omseil** deur 'n meesterwagwoord in die domeinbeheerder in te spuit. Dit stel die aanvaller in staat om as enige gebruiker te **outentifiseer sonder hul wagwoord**, wat hulle onbeperkte toegang tot die domein gee.

Dit kan uitgevoer word met behulp van [Mimikatz](https://github.com/gentilkiwi/mimikatz). Om hierdie aanval uit te voer, is **Domain Admin-regte 'n vereiste**, en die aanvaller moet elke domeinbeheerder teiken om 'n omvattende oortreding te verseker. Die aanval se effek is egter tydelik, aangesien **die herlaai van die domeinbeheerder die kwaadwillige sagteware uitwis**, wat 'n herimplementering vir volgehoue toegang noodsaaklik maak.

**Die uitvoering van die aanval** vereis 'n enkele bevel: `misc::skeleton`.

## Versagtings

Versagtingsstrategieë teen sulke aanvalle sluit in die monitering van spesifieke gebeurtenis-ID's wat die installasie van dienste of die gebruik van sensitiewe bevoegdhede aandui. Spesifiek kan die soek na Stelsel-gebeurtenis-ID 7045 of Sekuriteit-gebeurtenis-ID 4673 verdagte aktiwiteite aan die lig bring. Daarbenewens kan die uitvoering van `lsass.exe` as 'n beskermde proses aansienlik aanvallers se pogings belemmer, aangesien dit vereis dat hulle 'n kernelmodusbestuurder gebruik, wat die aanval se kompleksiteit verhoog.

Hier is die PowerShell-opdragte om sekuriteitsmaatreëls te versterk:

- Om die installasie van verdagte dienste op te spoor, gebruik: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- Spesifiek, om Mimikatz se bestuurder op te spoor, kan die volgende opdrag gebruik word: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- Om `lsass.exe` te versterk, word dit aanbeveel om dit as 'n beskermde proses in te skakel: `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

Verifikasie na 'n stelselherlaai is noodsaaklik om te verseker dat die beskermingsmaatreëls suksesvol toegepas is. Dit kan bereik word deur: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## Verwysings
* [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
