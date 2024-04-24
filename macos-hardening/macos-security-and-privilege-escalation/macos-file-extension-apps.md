# macOS फ़ाइल एक्सटेंशन और URL स्कीम एप्लिकेशन हैंडलर

<details>

<summary><strong>जीरो से हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स देखें**](https://github.com/sponsors/carlospolop)!
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **Twitter** पर **फ़ॉलो** करें 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें** द्वारा PRs सबमिट करके [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>

## LaunchServices डेटाबेस

यह macOS में स्थापित सभी एप्लिकेशनों का एक डेटाबेस है जिसे क्वेरी किया जा सकता है ताकि प्रत्येक स्थापित एप्लिकेशन के बारे में जानकारी प्राप्त की जा सके जैसे कि यह किस URL स्कीम का समर्थन करता है और MIME types।

इस डेटाबेस को डंप करना संभव है:

{% code overflow="wrap" %}
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
{% endcode %}

या उपकरण [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) का उपयोग करें।

**`/usr/libexec/lsd`** डेटाबेस का मस्तिष्क है। यह **कई XPC सेवाएं** प्रदान करता है जैसे `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, और अधिक। लेकिन यह भी **कुछ entitlements की आवश्यकता है** एप्लिकेशन को उदाहरण के लिए `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler` जैसी उदाहरण के लिए डिफ़ॉल्ट एप्लिकेशन को mime types या url schemes के लिए बदलने के लिए उपयोग किए जाने वाले XPC कार्यों का उपयोग करने के लिए।

**`/System/Library/CoreServices/launchservicesd`** सेवा `com.apple.coreservices.launchservicesd` का दावा करता है और चल रहे एप्लिकेशनों के बारे में जानकारी प्राप्त करने के लिए पूछा जा सकता है। इसे सिस्टम उपकरण /**`usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) के साथ पूछा जा सकता है।

## फ़ाइल एक्सटेंशन और URL स्कीम एप्लिकेशन हैंडलर्स

निम्नलिखित पंक्ति उपयोगी हो सकती है फ़ाइलों को खोलने वाले एप्लिकेशनों को खोजने के लिए जो एक्सटेंशन पर निर्भर करते हैं:
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
<details>

<summary><strong>जानें AWS हैकिंग को शून्य से हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

दूसरे तरीके HackTricks का समर्थन करने के लिए:

* अगर आप अपनी **कंपनी का विज्ञापन HackTricks में देखना चाहते हैं** या **HackTricks को PDF में डाउनलोड करना चाहते हैं** तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* हमारे विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) कलेक्शन, [**The PEASS Family**](https://opensea.io/collection/the-peass-family) खोजें
* **शामिल हों** 💬 [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या हमें **ट्विटर** पर **फॉलो** करें 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में।

</details>
