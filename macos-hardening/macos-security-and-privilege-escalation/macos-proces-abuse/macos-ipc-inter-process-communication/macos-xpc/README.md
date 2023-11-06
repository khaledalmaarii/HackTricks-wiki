# macOS XPC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS की नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) की जांच करें!
* खोजें [**The PEASS Family**](https://opensea.io/collection/the-peass-family), हमारा विशेष संग्रह [**NFTs**](https://opensea.io/collection/the-peass-family)
* प्राप्त करें [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**telegram समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें और PRs सबमिट करें** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को**

</details>

## मूलभूत जानकारी

XPC, जो macOS द्वारा उपयोग किया जाने वाले कर्नल XNU के बीच इंटर-प्रोसेस संचार के लिए खड़ा किया गया है, **macOS और iOS पर प्रक्रियाओं के बीच संचार** के लिए एक ढांचा है। XPC सिस्टम पर अलग-अलग प्रक्रियाओं के बीच **सुरक्षित, असिंक्रोनस विधि कॉल** करने के लिए एक तंत्र प्रदान करता है। यह Apple के सुरक्षा परिदृश्य का हिस्सा है, जो **विशेषाधिकार-अलग** अनुप्रयोगों के निर्माण की अनुमति देता है जहां प्रत्येक **घटक** अपने काम करने के लिए **केवल उन अनुमतियों के साथ चलता है** जो उसे चाहिए, इससे एक संकटित प्रक्रिया से होने वाले संभावित क्षति की सीमा सीमित होती है।

XPC एक इंटर-प्रोसेस संचार (IPC) का उपयोग करता है, जो समान सिस्टम पर चल रहे विभिन्न कार्यक्रमों को डेटा भेजने और प्राप्त करने के लिए एक सेट के रूप में होता है।

XPC के प्रमुख लाभ हैं:

1. **सुरक्षा**: कार्य को अलग-अलग प्रक्रियाओं में विभाजित करके, प्रत्येक प्रक्रिया को केवल उन अनुमतियों की प्रदान की जा सकती है जो उसे चाहिए। इसका मतलब है कि यदि कोई प्रक्रिया प्रभावित हो जाती है, तो उसकी क्षमता कोई हानि पहुंचाने की सीमित होती है।
2. **स्थिरता**: XPC संक्रमण को उस कंपोनेंट तक सीमित करने में मदद करता है जहां वे होते हैं। यदि कोई प्रक्रिया क्रैश हो जाती है, तो उसे पुनः प्रारंभ किया जा सकता है बिना सिस्टम के बाकी हिस्से को प्रभावित किए।
3. **प्रदर्शन**: XPC आसानी से समय-समय पर संगठन की अनुमति देता है, क्योंकि विभिन्न कार्यों को विभिन्न प्रक्रियाओं में समयानुसार चलाया जा सकता है।

एकमात्र **हानिकारकता** यह है कि **एक अनुप्रयोग को कई प्रक्रियाओं में विभाजित करना** जिसके माध्यम से वे XPC के माध्यम से संवाद करते हैं, **कम दक्ष** होता है। लेकिन आज के सिस्टम में यह लगभग दिखाई नहीं देता है और लाभ अधिक होते हैं।

## अनुप्रयोग विशेष XPC सेवाएं

एक अनुप्रयोग के XPC घटक **अनुप्रयोग के भीतर होते हैं।** उदाहरण के लिए, Safari में आप उन्हें **`/Applications/Safari.app/Contents/XPCServices`** में ढूंढ सकते हैं। उनमें **`.xpc`** एक्सटेंशन होता है (जैसे **`com.apple.Safari.SandboxBroker.xpc`**) और इसके भीतर मुख्य बाइनरी के साथ एक बंडल भी होता है: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` और एक `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

जैसा कि आप सोच रहे होंगे, **एक XPC घटक के पास अन्य XPC घटकों या मुख्य ऐप बाइनरी की तुलना में विभिन्न अधिकार और विशेषाधिकार** होंगे। यही कारण है कि एक XPC सेवा [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) के साथ कॉन
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
**`LaunchDameons`** में वह रूट द्वारा चलाए जाते हैं। इसलिए, अनधिकृत प्रक्रिया यदि इनमें से किसी के साथ बात कर सकती है तो यह विशेषाधिकार बढ़ा सकती है।

## XPC ईवेंट संदेश

अनुप्रयोग विभिन्न ईवेंट संदेशों की **सदस्यता** कर सकते हैं, जिससे उन्हें ऐसे ईवेंट होने पर **आवश्यकता अनुसार प्रारंभ किया जा सकता है**। इन सेवाओं के लिए **सेटअप** **`LaunchEvent`** कुंजी समेत **लॉन्चडी प्लिस्ट फ़ाइलों** में किया जाता है, जो **पिछले वाले वाले निर्देशिकाओं के समान निर्देशिकाओं में स्थित होती हैं**।

### XPC कनेक्टिंग प्रक्रिया जांच

जब कोई प्रक्रिया एक XPC कनेक्शन के माध्यम से एक मेथड को कॉल करने की कोशिश करती है, तो **XPC सेवा को यह जांचनी चाहिए कि क्या उस प्रक्रिया को कनेक्ट करने की अनुमति है**। यहां इसे जांचने और सामान्य गड़बड़ीयों को देखने के लिए आम तरीके हैं:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC अधिकारीकरण

एप्पल भी ऐप्स को कुछ अधिकारों को **कैसे कॉन्फ़िगर करने** और उन्हें प्राप्त करने के तरीकों को सेट करने की अनुमति देता है, ताकि यदि कॉल करने वाली प्रक्रिया में वे अधिकार हों तो वह XPC सेवा को **मेथड कॉल करने की अनुमति** हो।

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
## सी कोड उदाहरण

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
{% tab title="xyz.hacktricks.service.plist" %}xyz.hacktricks.service.plist नामक फ़ाइल में आपकी XPC सेवा का विवरण होना चाहिए। यह फ़ाइल आपकी सेवा को बूट टाइम पर स्वचालित रूप से शुरू करने के लिए उपयोग की जाती है। इस फ़ाइल में आपको निम्नलिखित विन्यास विन्यास को शामिल करना होगा:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>xyz.hacktricks.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/your/executable</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

यहां, आपको `xyz.hacktricks.service` को अपनी सेवा के नाम से बदलना होगा और `/path/to/your/executable` को आपके निष्पादन के पथ से बदलना होगा। इसके अलावा, आपको अन्य विन्यास विकल्पों को अपनी आवश्यकतानुसार समायोजित करना होगा।

इस फ़ाइल को `/Library/LaunchDaemons/` या `/Library/LaunchAgents/` में सहेजें ताकि यह सिस्टम बूट के समय स्वचालित रूप से शुरू हो सके। आपको उपयोगकर्ता अनुमतियों को ध्यान में रखते हुए इस फ़ाइल को सहेजने के लिए उचित अनुमतियाँ सेट करनी चाहिए।

इसके बाद, आपको निम्नलिखित कमांड का उपयोग करके आपकी सेवा को शुरू करना होगा:

```bash
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist
```

आप इसे बंद करने के लिए निम्नलिखित कमांड का उपयोग कर सकते हैं:

```bash
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
```

यहां, `xyz.hacktricks.service.plist` को अपनी सेवा की फ़ाइल के नाम से बदलें।

आपकी सेवा अब सिस्टम बूट के साथ स्वचालित रूप से शुरू होगी और आप इसे बंद कर सकते हैं जब आप चाहें।

ध्यान दें कि आपको अपनी सेवा को उचित अनुमतियों के साथ संचालित करना चाहिए और सुरक्षा के मामले में सतर्क रहना चाहिए।
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
## उद्देश्य-सी कोड उदाहरण

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
{% tab title="xyz.hacktricks.svcoc.plist" %}xyz.hacktricks.svcoc.plist एक प्रोपर्टी लिस्ट (plist) फ़ाइल है जो macOS में XPC सेवा के रूप में रजिस्टर होती है। यह फ़ाइल एक विशेष नामस्थान में संग्रहीत होती है और इसे उपयोगकर्ता या सिस्टम सेवा के रूप में चलाया जा सकता है।

इस plist फ़ाइल में, आपको XPC सेवा के लिए विभिन्न पैरामीटर और विन्यास सेट करने की अनुमति होती है। इन पैरामीटरों के माध्यम से, आप XPC सेवा के लिए अनुमतियों को सेट कर सकते हैं, जैसे कि कौन सी विधि या विधियाँ उपयोगकर्ता या सिस्टम सेवा को उपयोग कर सकती हैं।

इस plist फ़ाइल को बदलकर, आप XPC सेवा के लिए नई अनुमतियों को जोड़ सकते हैं या मौजूदा अनुमतियों को संशोधित कर सकते हैं। इसके अलावा, आप इसे उपयोग करके XPC सेवा को अनुमतियों के साथ चला सकते हैं जो मौजूदा नहीं हैं।

यदि आपको इस plist फ़ाइल को बदलने की अनुमति है, तो आप XPC सेवा के लिए नई अनुमतियों को जोड़ सकते हैं और उपयोगकर्ता या सिस्टम सेवा को अधिकार दे सकते हैं। इसके अलावा, आप इसे उपयोग करके XPC सेवा को अनुमतियों के साथ चला सकते हैं जो मौजूदा नहीं हैं।

ध्यान दें कि इस plist फ़ाइल को संशोधित करने के लिए आपको उच्च स्तरीय अनुमतियाँ होनी चाहिए, जैसे कि रूट या सुपरयूज़र अनुमतियाँ। इसलिए, इसे संशोधित करने से पहले सुनिश्चित करें कि आपके पास उच्च स्तरीय अनुमतियाँ हैं और आप इसे सावधानीपूर्वक कर रहे हैं।

यदि आपको इस plist फ़ाइल को संशोधित करने की अनुमति है, तो आप XPC सेवा के लिए नई अनुमतियों को जोड़ सकते हैं और उपयोगकर्ता या सिस्टम सेवा को अधिकार दे सकते हैं। इसके अलावा, आप इसे उपयोग करके XPC सेवा को अनुमतियों के साथ चला सकते हैं जो मौजूदा नहीं हैं।

ध्यान दें कि इस plist फ़ाइल को संशोधित करने के लिए आपको उच्च स्तरीय अनुमतियाँ होनी चाहिए, जैसे कि रूट या सुपरयूज़र अनुमतियाँ। इसलिए, इसे संशोधित करने से पहले सुनिश्चित करें कि आपके पास उच्च स्तरीय अनुमतियाँ हैं और आप इसे सावधानीपूर्वक कर रहे हैं।
{% endtab %}
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
## डाइलब कोड के भीतर क्लाइंट

The client code inside a Dylb is responsible for establishing a connection with the server and sending requests. It is an essential component of the inter-process communication (IPC) mechanism in macOS.

### Usage

To use the client code inside a Dylb, follow these steps:

1. Import the necessary libraries and frameworks.
2. Create an instance of the client.
3. Set the appropriate properties and configurations.
4. Connect to the server using the `connect` method.
5. Send requests to the server using the `send` method.
6. Handle the server's responses.

### Example

Here is an example of how to use the client code inside a Dylb:

```objective-c
#import <Foundation/Foundation.h>
#import <Dylb/Dylb.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // Create an instance of the client
        DylbClient *client = [[DylbClient alloc] init];
        
        // Set properties and configurations
        client.host = @"example.com";
        client.port = 1234;
        
        // Connect to the server
        [client connect];
        
        // Send requests
        [client send:@"Hello, server!"];
        
        // Handle responses
        NSString *response = [client receive];
        NSLog(@"%@", response);
        
        // Close the connection
        [client disconnect];
    }
    return 0;
}
```

### Conclusion

The client code inside a Dylb is a crucial component for establishing communication with a server in macOS. By following the steps mentioned above, you can effectively use the client code to send requests and handle responses.
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

* क्या आप किसी **साइबर सुरक्षा कंपनी** में काम करते हैं? क्या आप अपनी **कंपनी को HackTricks में विज्ञापित** देखना चाहते हैं? या क्या आपको **PEASS के नवीनतम संस्करण या HackTricks को PDF में डाउनलोड करने का उपयोग** करना चाहिए? [**सदस्यता योजनाएं**](https://github.com/sponsors/carlospolop) की जांच करें!
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFT संग्रह**](https://opensea.io/collection/the-peass-family)
* [**आधिकारिक PEASS & HackTricks swag**](https://peass.creator-spring.com) प्राप्त करें
* **शामिल हों** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord समूह**](https://discord.gg/hRep4RUj7f) या [**टेलीग्राम समूह**](https://t.me/peass) में या मुझे **Twitter** पर **फ़ॉलो** करें [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **अपने हैकिंग ट्रिक्स साझा करें, PRs सबमिट करके** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **और** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **को।**

</details>
