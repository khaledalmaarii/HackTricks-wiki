# macOS सैंडबॉक्स

<details>

<summary><strong> AWS हैकिंग सीखें शून्य से लेकर हीरो तक </strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **अपनी हैकिंग ट्रिक्स साझा करें, HackTricks** और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके.

</details>

## मूल जानकारी

macOS सैंडबॉक्स (मूल रूप से Seatbelt कहलाता है) **एप्लिकेशन्स को सीमित करता है** जो सैंडबॉक्स के अंदर चल रहे होते हैं, उन्हें केवल **सैंडबॉक्स प्रोफाइल में निर्दिष्ट अनुमत क्रियाओं तक ही सीमित रखता है** जिसके साथ ऐप चल रहा होता है। यह सुनिश्चित करता है कि **एप्लिकेशन केवल अपेक्षित संसाधनों तक ही पहुँच रहा हो**।

किसी भी ऐप के पास **entitlement** **`com.apple.security.app-sandbox`** होगा, वह सैंडबॉक्स के अंदर निष्पादित होगा। **Apple binaries** आमतौर पर सैंडबॉक्स के अंदर निष्पादित होते हैं और **App Store** के अंदर प्रकाशित करने के लिए, **यह entitlement अनिवार्य है**। इसलिए अधिकांश एप्लिकेशन्स सैंडबॉक्स के अंदर निष्पादित होंगे।

यह नियंत्रित करने के लिए कि प्रक्रिया क्या कर सकती है या नहीं कर सकती, **सैंडबॉक्स में हुक्स होते हैं** जो कर्नेल के भर में सभी **syscalls** में होते हैं। **एप्लिकेशन की entitlements पर निर्भर करते हुए**, सैंडबॉक्स कुछ क्रियाओं को **अनुमति देगा**।

सैंडबॉक्स के कुछ महत्वपूर्ण घटक हैं:

* कर्नेल एक्सटेंशन `/System/Library/Extensions/Sandbox.kext`
* निजी फ्रेमवर्क `/System/Library/PrivateFrameworks/AppSandbox.framework`
* यूजरलैंड में चल रहा एक **daemon** `/usr/libexec/sandboxd`
* कंटेनर्स `~/Library/Containers`

कंटेनर्स फोल्डर के अंदर आप प्रत्येक ऐप के लिए एक फोल्डर पा सकते हैं जो सैंडबॉक्स्ड के साथ निष्पादित होता है, बंडल आईडी के नाम से:
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
प्रत्येक bundle id फ़ोल्डर के अंदर आप ऐप की **plist** और **Data directory** पा सकते हैं:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
{% hint style="danger" %}
ध्यान दें कि यदि सिम्लिंक्स वहाँ हैं "एस्केप" करने के लिए सैंडबॉक्स से और अन्य फोल्डर्स तक पहुँचने के लिए, ऐप को अभी भी उन तक पहुँचने के लिए **अनुमतियाँ** होनी चाहिए। ये अनुमतियाँ **`.plist`** के अंदर होती हैं।
{% endhint %}
```bash
# Get permissions
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
{% hint style="warning" %}
Sandboxed एप्लिकेशन द्वारा बनाई या संशोधित की गई हर चीज में **quarantine attribute** होगा। यह Gatekeeper को सक्रिय करके sandbox स्थान की सुरक्षा करेगा अगर sandbox एप्लिकेशन **`open`** का उपयोग करके कुछ निष्पादित करने की कोशिश करता है।
{% endhint %}

### Sandbox प्रोफाइल

Sandbox प्रोफाइल कॉन्फ़िगरेशन फ़ाइलें होती हैं जो यह निर्दिष्ट करती हैं कि **Sandbox** में क्या **अनुमति/निषेध** किया जाएगा। इसमें **Sandbox Profile Language (SBPL)** का उपयोग होता है, जो [**Scheme**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) प्रोग्रामिंग भाषा का प्रयोग करता है।

यहाँ आप एक उदाहरण पा सकते हैं:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
{% hint style="success" %}
इस [**शोध**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) को देखें ताकि आप और अधिक क्रियाओं की जांच कर सकें जो अनुमति दी जा सकती हैं या इनकार की जा सकती हैं।
{% endhint %}

महत्वपूर्ण **सिस्टम सेवाएं** भी अपने स्वयं के कस्टम **सैंडबॉक्स** में चलती हैं जैसे कि `mdnsresponder` सेवा। आप इन कस्टम **सैंडबॉक्स प्रोफाइल्स** को निम्नलिखित में देख सकते हैं:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* अन्य सैंडबॉक्स प्रोफाइल्स की जांच [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) पर की जा सकती है।

**App Store** ऐप्स **प्रोफाइल** **`/System/Library/Sandbox/Profiles/application.sb`** का उपयोग करते हैं। आप इस प्रोफाइल में जांच सकते हैं कि कैसे एंटाइटलमेंट्स जैसे कि **`com.apple.security.network.server`** एक प्रक्रिया को नेटवर्क का उपयोग करने की अनुमति देता है।

SIP एक सैंडबॉक्स प्रोफाइल है जिसे platform_profile कहा जाता है जो /System/Library/Sandbox/rootless.conf में है

### सैंडबॉक्स प्रोफाइल उदाहरण

किसी एप्लिकेशन को **विशिष्ट सैंडबॉक्स प्रोफाइल** के साथ शुरू करने के लिए आप उपयोग कर सकते हैं:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% tabs %}
{% tab title="स्पर्श" %}
{% code title="touch.sb" %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
Since the provided text does not contain any English content to translate, there is no translation to provide. The text is a closing tag for a code block in markdown syntax. If you have any actual content that needs translation, please provide it, and I'll be happy to translate it for you.
```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```
Since the content you've provided does not contain any English text that needs to be translated into Hindi, there is nothing to translate. If you provide the English text that needs translation, I can then translate it into Hindi for you, maintaining the markdown and HTML syntax as requested.
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```
The provided text does not contain any English content that needs to be translated into Hindi. It only includes markdown syntax and a filename, which should not be translated as per the instructions. If you have any English content that needs translation, please provide it, and I will translate it accordingly.
```scheme
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="info" %}
ध्यान दें कि **Windows** पर चलने वाले **Apple-लिखित** **सॉफ्टवेयर** में अतिरिक्त सुरक्षा उपाय नहीं होते हैं, जैसे कि एप्लिकेशन सैंडबॉक्सिंग।
{% endhint %}

Bypasses उदाहरण:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (वे सैंडबॉक्स के बाहर `~$` से शुरू होने वाले फाइलों को लिखने में सक्षम हैं)।

### MacOS Sandbox Profiles

macOS सिस्टम सैंडबॉक्स प्रोफाइल्स को दो स्थानों पर संग्रहीत करता है: **/usr/share/sandbox/** और **/System/Library/Sandbox/Profiles**।

और यदि कोई तृतीय-पक्ष एप्लिकेशन _**com.apple.security.app-sandbox**_ एंटाइटलमेंट ले जाता है, तो सिस्टम उस प्रक्रिया पर **/System/Library/Sandbox/Profiles/application.sb** प्रोफाइल लागू करता है।

### **iOS Sandbox Profile**

डिफ़ॉल्ट प्रोफाइल का नाम **container** है और हमारे पास SBPL टेक्स्ट प्रतिनिधित्व नहीं है। मेमोरी में, यह सैंडबॉक्स प्रत्येक अनुमतियों के लिए Allow/Deny बाइनरी ट्री के रूप में प्रतिनिधित्व किया जाता है।

### Debug & Bypass Sandbox

**macOS पर प्रक्रियाएं सैंडबॉक्स में नहीं बनती हैं: iOS के विपरीत**, जहां सैंडबॉक्स कर्नेल द्वारा किसी प्रोग्राम के पहले निर्देश को निष्पादित करने से पहले लागू किया जाता है, macOS पर **एक प्रक्रिया को स्वयं को सैंडबॉक्स में रखने का चुनाव करना पड़ता है।**

प्रक्रियाएं स्वचालित रूप से यूजरलैंड से सैंडबॉक्स में शुरू होती हैं जब उनके पास एंटाइटलमेंट होता है: `com.apple.security.app-sandbox`। इस प्रक्रिया की विस्तृत व्याख्या के लिए देखें:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **Check PID Privileges**

[**इसके अनुसार**](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (यह एक `__mac_syscall` है), किसी निश्चित PID में सैंडबॉक्स द्वारा किसी ऑपरेशन की अनुमति है या नहीं यह जांच सकता है।

[**टूल sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) यह जांच सकता है कि क्या एक PID किसी निश्चित क्रिया को कर सकता है:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### ऐप स्टोर ऐप्स में कस्टम SBPL

कंपनियों के लिए यह संभव हो सकता है कि वे अपने ऐप्स को **कस्टम सैंडबॉक्स प्रोफाइल्स के साथ** चलाएं (डिफ़ॉल्ट वाले के बजाय)। उन्हें इसके लिए एंटाइटलमेंट **`com.apple.security.temporary-exception.sbpl`** का उपयोग करना होगा जिसे एप्पल द्वारा अधिकृत किया जाना चाहिए।

इस एंटाइटलमेंट की परिभाषा को **`/System/Library/Sandbox/Profiles/application.sb:`** में जांचा जा सकता है।
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
```markdown
यह **इस एंटाइटलमेंट के बाद की गई स्ट्रिंग का मूल्यांकन करेगा** एक सैंडबॉक्स प्रोफाइल के रूप में।

<details>

<summary><strong>शून्य से लेकर हीरो तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong> के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर मुझे 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) **का अनुसरण करें**।
* **अपनी हैकिंग ट्रिक्स साझा करें, HackTricks** [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके।

</details>
```
