# macOS XPC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **हैकट्रिक्स में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहते हैं? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS और HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) या मुझे **ट्विटर** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें द्वारा PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>

## मूलभूत जानकारी

XPC, जो macOS द्वारा उपयोग किया जाने वाले कर्नल XNU के बीच इंटर-प्रोसेस संचार के लिए खड़ा किया गया है, **macOS और iOS पर प्रक्रियाओं के बीच संचार के लिए एक ढांचा है**। XPC सिस्टम पर विभिन्न प्रक्रियाओं के बीच **सुरक्षित, असिंक्रोनस विधि कॉल बनाने के लिए एक तंत्र प्रदान करता है**। यह Apple के सुरक्षा परिदृश्य का हिस्सा है, जो **विशेषाधिकार-अलग किए गए अनुप्रयोगों** के निर्माण की अनुमति देता है जहां प्रत्येक **घटक** अपने काम करने के लिए **केवल उन अनुमतियों के साथ चलता है** जो उसे चाहिए, इससे एक संकटित प्रक्रिया से होने वाले संभावित क्षति की सीमा कम होती है।

XPC एक इंटर-प्रोसेस संचार (IPC) के रूप में एक प्रकार का उपयोग करता है, जो समान सिस्टम पर चल रहे विभिन्न कार्यक्रमों को डेटा भेजने और प्राप्त करने के लिए विभिन्न विधियों का सेट है।

XPC के प्रमुख लाभ हैं:

1. **सुरक्षा**: कार्य को विभाजित करके, प्रत्येक प्रक्रिया को केवल उन अनुमतियों की प्रदान की जा सकती है जो उसे चाहिए। इसका मतलब है कि यदि कोई प्रक्रिया प्रभावित हो जाती है, तो उसे क्षति पहुंचाने की सीमित क्षमता होती है।
2. **स्थिरता**: XPC सहायता से क्रैश को उस कंपोनेंट तक सीमित किया जा सकता है जहां वे होते हैं। यदि कोई प्रक्रिया क्रैश हो जाती है, तो उसे पुनः प्रारंभ किया जा सकता है बिना प्रभावित किए हुए सिस्टम के बाकी हिस्से पर।
3. **प्रदर्शन**: XPC आसानी से संयोज्यता की अनुमति देता है, क्योंकि विभिन्न कार्यों को विभिन्न प्रक्रियाओं में समयानुसार चलाया जा सकता है।

एकमात्र **हानि** यह है कि **एक अनुप्रयोग को कई प्रक्रियाओं में विभाजित करना** जिसे XPC के माध्यम से संचार कराया जाता है, **कम दक्ष** होता है। लेकिन आज के सिस्टम में यह लगभग दिखाई नहीं देता है और लाभ अधिक होते हैं।

## अनुप्रयोग विशेष XPC सेवाएं

एक अनुप्रयोग के XPC घटक **अनुप्रयोग के भीतर होते हैं**। उदाहरण के लिए, Safari में आप उन्हें **`/Applications/Safari.app/Contents/XPCServices`** में ढूंढ सकते हैं। उनमें **`.xpc`** एक्सटेंशन होता है (जैसे **`com.apple.Safari.SandboxBroker.xpc`**) और इसके साथ मुख्य बाइनरी के साथ भी **बंडल** होता है: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` और एक `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

जैसा कि आप सोच रहे होंगे, **एक XPC घटक के पास अन्य XPC घटकों या मुख्य अनुप्रयोग बाइनरी की तुलना में विभिन्न अधिकाराधिकार और विशेषाधिकार** होंगे। केवल तभी नहीं, यदि एक XPC
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
जो **`LaunchDameons`** में हैं, वे root द्वारा चलाए जाते हैं। इसलिए, अनधिकृत प्रक्रिया यदि इनमें से किसी के साथ बात कर सकती है, तो यह विशेषाधिकारों को बढ़ा सकती है।

## XPC घटना संदेश

अनुप्रयोग विभिन्न घटना संदेशों की **सदस्यता** कर सकते हैं, जिससे उन्हें ऐसी घटनाओं के होने पर **आवश्यकता अनुसार प्रारंभ किया जा सकता है**। इन सेवाओं के लिए **सेटअप** **`LaunchEvent`** कुंजी सहित **launchd plist फ़ाइलों** में किया जाता है, जो **पिछली वाली वाली डायरेक्टरी में स्थित** होती हैं।

### XPC कनेक्टिंग प्रक्रिया जांच

जब कोई प्रक्रिया XPC कनेक्शन के माध्यम से एक विधि को कॉल करने की कोशिश करती है, तो **XPC सेवा को यह जांचनी चाहिए कि क्या उस प्रक्रिया को कनेक्ट करने की अनुमति है**। यहां इसे जांचने और सामान्य गड़बड़ियों को देखने के लिए आम तरीके हैं:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC अधिकृतता

Apple अनुप्रयोगों को भी कुछ अधिकारों को **कॉन्फ़िगर करने और उन्हें प्राप्त करने के तरीके** की अनुमति देता है, ताकि यदि कॉल करने वाली प्रक्रिया में वे हों, तो वह XPC सेवा से एक विधि को **कॉल करने की अनुमति** हो:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC स्निफर

XPC संदेशों को स्निफ करने के लिए आप [**xpcspy**](https://github.com/hot3eed/xpcspy) का उपयोग कर सकते हैं, जो **Frida** का उपयोग करता है।
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## XPC संचार C कोड उदाहरण

{% tabs %}
{% tab title="xpc_server.c" %}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{% tab title="xpc_client.c" %}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{% tab title="xyz.hacktricks.service.plist" %}xyz.hacktricks.service.plist एक प्लिस्ट फ़ाइल है जो macOS पर एक XPC सेवा को कॉन्फ़िगर करती है। XPC (Inter-Process Communication) एक सुरक्षित और अनुक्रमिक तरीके से प्रक्रियाओं के बीच संचार करने की अनुमति देता है। यह फ़ाइल एक नामित पाइपलाइन और एक एक्सटर्नल बाउंडल संदर्भ के साथ एक XPC सेवा को निर्दिष्ट करती है। इस फ़ाइल में विभिन्न पैरामीटर जैसे कि एक्सटर्नल बाउंडल का पथ, एक्सटर्नल बाउंडल का नाम, एक्सटर्नल बाउंडल का बंडल आईडी, एक्सटर्नल बाउंडल का बंडल वर्ज़न, एक्सटर्नल बाउंडल का संस्करण आदि निर्दिष्ट किए जा सकते हैं। इस फ़ाइल को उपयोग करके आप XPC सेवा को कॉन्फ़िगर कर सकते हैं और उसे अनुक्रमिक तरीके से प्रक्रियाओं के साथ संचार करने की अनुमति दे सकते हैं।

यहां एक उदाहरण दिया गया है:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>xyz.hacktricks.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/external/bundle</string>
        <string>--argument1</string>
        <string>value1</string>
        <string>--argument2</string>
        <string>value2</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

इस उदाहरण में, `xyz.hacktricks.service` नामक XPC सेवा को `/path/to/external/bundle` बाउंडल के साथ कॉन्फ़िगर किया गया है। इसमें `--argument1` और `--argument2` नामक दो पैरामीटर भी हैं जिनके मान `value1` और `value2` हैं। इस XPC सेवा को `RunAtLoad` और `KeepAlive` पैरामीटर से स्वचालित रूप से चालू रखा जाएगा।

आप इस फ़ाइल को उपयोग करके अपनी एप्लिकेशन को सुरक्षित बना सकते हैं और उसे अनुक्रमिक तरीके से प्रक्रियाओं के साथ संचार करने की अनुमति दे सकते हैं।
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
## XPC संचार Objective-C कोड उदाहरण

{% tabs %}
{% tab title="oc_xpc_server.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{% tab title="oc_xpc_client.m" %}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{% tab title="xyz.hacktricks.svcoc.plist" %}xyz.hacktricks.svcoc.plist एक प्रोपर्टी लिस्ट (plist) फ़ाइल है जो macOS में XPC सेवा के रूप में रजिस्टर होती है। यह फ़ाइल सेवा के लिए विभिन्न पैरामीटर और विन्यास सेट करने की अनुमति देती है। इस plist फ़ाइल को /Library/LaunchDaemons या /Library/LaunchAgents में स्थापित किया जा सकता है ताकि यह सिस्टम शुरू होने पर स्वचालित रूप से लोड हो सके।

यदि आपको इस plist फ़ाइल को बनाने की जानकारी नहीं है, तो आप इसे निम्नलिखित कमांड का उपयोग करके बना सकते हैं:

```plaintext
sudo nano /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
```

फ़ाइल को खोलने के बाद, आपको निम्नलिखित XML कोड को फ़ाइल में पेस्ट करना होगा:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>xyz.hacktricks.svcoc</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/your/program</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

ध्यान दें कि आपको `<string>/path/to/your/program</string>` को अपनी वास्तविक प्रोग्राम के पथ के साथ बदलना होगा।

फ़ाइल को सहेजने के लिए `Ctrl + X` दबाएं, फिर `Y` दबाएं और अंत में `Enter` दबाएं।

अब, आपको निम्नलिखित कमांड का उपयोग करके इस plist फ़ाइल को लोड करना होगा:

```plaintext
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
```

इसके बाद, आपका XPC सेवा सिस्टम शुरू होने पर स्वचालित रूप से चलेगा।

यदि आपको इस XPC सेवा को बंद करने की जरूरत होती है, तो आप निम्नलिखित कमांड का उपयोग करके इसे अनलोड कर सकते हैं:

```plaintext
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
```

ध्यान दें कि आपको `/Library/LaunchDaemons/xyz.hacktricks.svcoc.plist` को अपनी वास्तविक plist फ़ाइल के साथ बदलना होगा।

इस तरह, आप XPC सेवा को अपने macOS सिस्टम में रजिस्टर कर सकते हैं और उसे स्वचालित रूप से लोड और अनलोड कर सकते हैं।
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## डायलब कोड के भीतर क्लाइंट

The client code inside a Dylb is responsible for establishing a connection with the server and sending requests for specific tasks. It acts as a bridge between the user and the server, facilitating communication and data exchange.

डायलब के भीतर क्लाइंट कोड का कार्य होता है सर्वर के साथ एक संबंध स्थापित करना और विशेष कार्यों के लिए अनुरोध भेजना। यह उपयोगकर्ता और सर्वर के बीच एक सेतु की तरह कार्य करता है, संचार और डेटा विनिमय को सुविधाजनक बनाता है।
```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
NSString*  _serviceName = @"xyz.hacktricks.svcoc";

NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

[_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

[_agentConnection resume];

[[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
(void)error;
NSLog(@"Connection Failure");
}] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}    ];
NSLog(@"Done!");

return;
}
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी कंपनी को **HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड** करने का उपयोग करना है? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में **या** मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करें** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
