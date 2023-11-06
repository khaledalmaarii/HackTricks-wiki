# macOS सैंडबॉक्स

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की इच्छा है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या **फॉलो** करें मुझे **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>

## मूलभूत जानकारी

MacOS सैंडबॉक्स (पहले सीटबेल्ट कहलाया) **सैंडबॉक्स प्रोफ़ाइल में निर्दिष्ट अनुमतियों के साथ सैंडबॉक्स के अंदर चल रहे अनुप्रयोगों को सीमित करता है**। इससे सुनिश्चित होता है कि **अनुप्रयोग केवल उम्मीदित संसाधनों तक ही पहुंचेगा**।

**`com.apple.security.app-sandbox`** इंटाइटलमेंट के साथ कोई ऐप सैंडबॉक्स के अंदर निष्पादित किया जाएगा। **Apple बाइनरी** आमतौर पर सैंडबॉक्स के अंदर निष्पादित होते हैं और **ऐप स्टोर** में प्रकाशित करने के लिए **यह इंटाइटलमेंट अनिवार्य है**। इसलिए अधिकांश अनुप्रयोग सैंडबॉक्स के अंदर निष्पादित होंगे।

प्रक्रिया को क्या करने या क्या नहीं करने के लिए नियंत्रित करने के लिए सैंडबॉक्स में **हुक्स** होते हैं। सैंडबॉक्स के अनुमतियों पर निर्भर करके सैंडबॉक्स निश्चित कार्रवाई करेगा।

सैंडबॉक्स के कुछ महत्वपूर्ण घटक हैं:

* **कर्नल एक्सटेंशन** `/System/Library/Extensions/Sandbox.kext`
* **निजी फ्रेमवर्क** `/System/Library/PrivateFrameworks/AppSandbox.framework`
* **उपयोगकर्ता भूमि में चल रहा** एक **डेमन** `/usr/libexec/sandboxd`
* **कंटेनर्स** `~/Library/Containers`

कंटेनर्स फ़ोल्डर के अंदर आपको **हर सैंडबॉक्स में निष्पादित होने वाले हर ऐप के लिए एक फ़ोल्डर** मिलेगा जिसका नाम बंडल आईडी होगा:
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
प्रत्येक बंडल आईडी फ़ोल्डर के अंदर आप ऐप की **प्लिस्ट** और **डेटा निर्देशिका** पाएंगे:
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
ध्यान दें कि यदि सिमलिंक्स सैंडबॉक्स से "बाहर निकलने" और अन्य फ़ोल्डरों तक पहुंचने के लिए मौजूद हैं, तो ऐप को उन फ़ोल्डरों तक पहुंचने की अनुमति होनी चाहिए। ये अनुमतियाँ **`.plist`** फ़ाइल में होती हैं।
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
सभी सैंडबॉक्स एप्लिकेशन द्वारा बनाए गए / संशोधित किए गए सभी वस्तुएं **क्वारंटीन गुणधर्म** प्राप्त करेंगी। यह सैंडबॉक्स ऐप को कुछ **`open`** के साथ कुछ चलाने की कोशिश करने पर गेटकीपर को ट्रिगर करके सैंडबॉक्स स्थान को रोकेगा।
{% endhint %}

### सैंडबॉक्स प्रोफ़ाइल

सैंडबॉक्स प्रोफ़ाइल कॉन्फ़िगरेशन फ़ाइलें हैं जो इसका इंगित करती हैं कि उस सैंडबॉक्स में क्या **अनुमति / निषिद्ध** होगा। इसमें सैंडबॉक्स प्रोफ़ाइल भाषा (SBPL) का उपयोग किया जाता है, जो [**स्कीम**](https://en.wikipedia.org/wiki/Scheme\_\(programming\_language\)) प्रोग्रामिंग भाषा का उपयोग करती है।

यहां आप एक उदाहरण ढूंढ सकते हैं:
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
इस [**अनुसंधान**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) की जांच करें **जिसमें और कार्रवाई जो अनुमति दी जा सकती है या नहीं दी जा सकती है।**
{% endhint %}

महत्वपूर्ण **सिस्टम सेवाएं** भी अपने खुद के **संदूकची** में चलती हैं जैसे `mdnsresponder` सेवा। आप इन खुद के **संदूकची प्रोफ़ाइल** को निम्नलिखित स्थानों पर देख सकते हैं:

* **`/usr/share/sandbox`**
* **`/System/Library/Sandbox/Profiles`**&#x20;
* अन्य संदूकची प्रोफ़ाइल यहां देख सकते हैं [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**ऐप स्टोर** ऐप्स **प्रोफ़ाइल** **`/System/Library/Sandbox/Profiles/application.sb`** का उपयोग करते हैं। आप इस प्रोफ़ाइल में देख सकते हैं कि **`com.apple.security.network.server`** जैसे entitlements एक प्रक्रिया को नेटवर्क का उपयोग करने की अनुमति देते हैं।

SIP एक संदूकची प्रोफ़ाइल है जिसे platform\_profile कहा जाता है और यह /System/Library/Sandbox/rootless.conf में होती है।

### संदूकची प्रोफ़ाइल उदाहरण

एक **निश्चित संदूकची प्रोफ़ाइल** के साथ एक ऐप्लिकेशन को शुरू करने के लिए आप इस्तेमाल कर सकते हैं:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
```
{% code title="touch.sb" %}

```plaintext
(version 1)
(deny default)
(allow file-read-metadata)
(allow file-write-metadata)
(allow file-read-data (literal "/path/to/file"))
(allow file-write-data (literal "/path/to/file"))
```

टच.sb

```plaintext
(संस्करण 1)
(डिनाई डिफॉल्ट)
(अनुमति फ़ाइल-पठन-मेटाडेटा)
(अनुमति फ़ाइल-लेख-मेटाडेटा)
(अनुमति फ़ाइल-पठन-डेटा (शब्दांश "/पथ/से/फ़ाइल"))
(अनुमति फ़ाइल-लेख-डेटा (शब्दांश "/पथ/से/फ़ाइल"))
```
{% endcode %}
{% endtab %}
{% endtabs %}
```scheme
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```
{% endcode %}
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
{% code title="touch2.sb" %}
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
{% code title="touch3.sb" %}
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
ध्यान दें कि **Windows पर चलने वाले Apple द्वारा लिखित सॉफ़्टवेयर** में ऐप्लिकेशन सैंडबॉक्सिंग जैसी अतिरिक्त सुरक्षा सावधानियां नहीं होती हैं।
{% endhint %}

उदाहरणों को छोड़कर:

* [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (उन्हें `~$` से शुरू होने वाले सैंडबॉक्स के बाहर फ़ाइलें लिखने की अनुमति होती है।)

### MacOS सैंडबॉक्स प्रोफ़ाइल

macOS सिस्टम सैंडबॉक्स प्रोफ़ाइल को दो स्थानों पर संग्रहीत करता है: **/usr/share/sandbox/** और **/System/Library/Sandbox/Profiles**।

और यदि किसी थर्ड-पार्टी एप्लिकेशन में _**com.apple.security.app-sandbox**_ अधिकार होता है, तो सिस्टम उस प्रक्रिया पर **/System/Library/Sandbox/Profiles/application.sb** प्रोफ़ाइल लागू करता है।

### **iOS सैंडबॉक्स प्रोफ़ाइल**

डिफ़ॉल्ट प्रोफ़ाइल को **कंटेनर** कहा जाता है और हमारे पास SBPL पाठ प्रतिनिधित्व नहीं है। मेमोरी में, यह सैंडबॉक्स हर अनुमति के लिए Allow/Deny बाइनरी ट्री के रूप में प्रतिष्ठित है।

### सैंडबॉक्स की डीबग और बाइपास

**प्रक्रियाएं macOS पर सैंडबॉक्स के साथ जन्म नहीं लेती हैं: iOS की तरह**, जहां पहले निर्देश का प्रोग्राम निष्पादन से पहले कर्नल द्वारा सैंडबॉक्स लागू की जाती है, macOS पर **प्रक्रिया को सैंडबॉक्स में रखने के लिए खुद को चुनना होता है।**

प्रक्रियाएं उपयोगकर्ता भूमि से स्वचालित रूप से सैंडबॉक्स में संगठित हो जाती हैं जब वे शुरू होती हैं अगर उनमें यह अधिकार होता है: `com.apple.security.app-sandbox`। इस प्रक्रिया की विस्तृत व्याख्या के लिए इस प्रक्रिया की जांच करें:

{% content-ref url="macos-sandbox-debug-and-bypass/" %}
[macos-sandbox-debug-and-bypass](macos-sandbox-debug-and-bypass/)
{% endcontent-ref %}

### **PID विशेषाधिकारों की जांच करें**

[इसके अनुसार](https://www.youtube.com/watch?v=mG715HcDgO8\&t=3011s), **`sandbox_check`** (यह एक `__mac_syscall` है), एक निश्चित PID में सैंडबॉक्स द्वारा किसी ऑपरेशन की अनुमति है या नहीं जांच सकता है।

[**टूल sbtool**](http://newosxbook.com/src.jl?tree=listings\&file=sbtool.c) यह जांच सकता है कि क्या एक PID एक निश्चित कार्रवाई कर सकता है:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explaination of the sandbox profile
sbtool <pid> all
```
### ऐप स्टोर ऐप्स में कस्टम SBPL

कंपनियों के लिए संभव हो सकता है कि उनके ऐप्स **कस्टम सैंडबॉक्स प्रोफ़ाइल के साथ** चलें (डिफ़ॉल्ट वाले के बजाय में)। उन्हें एप्पल द्वारा अधिकृत करने के लिए एंटाइटलमेंट **`com.apple.security.temporary-exception.sbpl`** का उपयोग करना होगा।

इस एंटाइटलमेंट की परिभाषा की जांच **`/System/Library/Sandbox/Profiles/application.sb:`** में की जा सकती है।
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
यह **इंटाइटलमेंट के बाद की स्ट्रिंग को एक सैंडबॉक्स प्रोफ़ाइल के रूप में मूल्यांकन करेगा**।

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ हैकट्रिक्स क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित करना** चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करने की आवश्यकता है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**द पीएस फैमिली**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS और HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks रेपो**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud रेपो**](https://github.com/carlospolop/hacktricks-cloud) **को**।

</details>
