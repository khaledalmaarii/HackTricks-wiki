# macOS फ़ाइल एक्सटेंशन और URL स्कीम एप्लिकेशन हैंडलर

{% hint style="success" %}
AWS हैकिंग सीखें और अभ्यास करें:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम एक्सपर्ट (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCP हैकिंग सीखें और अभ्यास करें: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम एक्सपर्ट (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricks का समर्थन करें</summary>

* [**सदस्यता योजनाएँ**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 पर **फ़ॉलो** करें [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में।

</details>
{% endhint %}

## LaunchServices डेटाबेस

यह macOS में स्थापित सभी एप्लिकेशनों का एक डेटाबेस है जिसे क्वेरी किया जा सकता है ताकि प्रत्येक स्थापित एप्लिकेशन के बारे में जानकारी मिल सके जैसे कि यह किस URL स्कीम का समर्थन करता है और MIME प्रकार।

इस डेटाबेस को डंप करना संभव है:

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

या उपकरण [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) का उपयोग करें।

**`/usr/libexec/lsd`** डेटाबेस का मस्तिष्क है। यह **कई XPC सेवाएं** प्रदान करता है जैसे `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, और अधिक। लेकिन यह भी **कुछ entitlements की आवश्यकता है** एप्लिकेशन को उदाहरण के लिए `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler` जैसी उदाहरण को उपयोग करने के लिए जो डिफ़ॉल्ट एप्लिकेशन को mime types या url schemes और अन्य के लिए बदल सकता है।

**`/System/Library/CoreServices/launchservicesd`** सेवा `com.apple.coreservices.launchservicesd` का दावा करता है और चल रहे एप्लिकेशनों के बारे में जानकारी प्राप्त करने के लिए पूछा जा सकता है। इसे सिस्टम उपकरण /**`usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) के साथ पूछा जा सकता है।

## फ़ाइल एक्सटेंशन और URL स्कीम एप्लिकेशन हैंडलर्स

निम्नलिखित पंक्ति उपयोगी हो सकती है फ़ाइल खोलने वाले एप्लिकेशनों को खोजने के लिए जो एक्सटेंशन पर निर्भर करते हैं:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
{% endcode %}

या कुछ इस तरह का उपयोग करें [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
आप एक एप्लिकेशन द्वारा समर्थित एक्सटेंशन की जांच भी कर सकते हैं:
```
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
{% hint style="success" %}
**AWS हैकिंग सीखें और अभ्यास करें:**<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण AWS रेड टीम विशेषज्ञ (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
**GCP हैकिंग सीखें और अभ्यास करें:** <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks प्रशिक्षण GCP रेड टीम विशेषज्ञ (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>हैकट्रिक्स का समर्थन करें</summary>

* [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जाँच करें!
* **शामिल हों** 💬 [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)** पर फॉलो** करें।
* **हैकिंग ट्रिक्स साझा करें, हैकट्रिक्स**](https://github.com/carlospolop/hacktricks) और [**हैकट्रिक्स क्लाउड**](https://github.com/carlospolop/hacktricks-cloud) github रेपो में PR जमा करके।

</details>
{% endhint %}
