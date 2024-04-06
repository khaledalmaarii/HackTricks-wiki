# macOS XPC

## macOS XPC

<details>

<summary><strong>शून्य से नायक तक AWS हैकिंग सीखें</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग प्राप्त करें**](https://peass.creator-spring.com)
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा एक्सक्लूसिव [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** पर 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) को **फॉलो करें**.
* **HackTricks** के [**github repos**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) में PRs सबमिट करके अपनी हैकिंग ट्रिक्स साझा करें.

</details>

### मूल जानकारी

XPC, जिसका पूरा नाम XNU (macOS द्वारा प्रयुक्त कर्नेल) inter-Process Communication है, macOS और iOS पर **प्रक्रियाओं के बीच संचार** के लिए एक फ्रेमवर्क है। XPC एक तंत्र प्रदान करता है जो **सुरक्षित, असिंक्रोनस मेथड कॉल्स को विभिन्न प्रक्रियाओं के बीच** बनाने के लिए है। यह Apple की सुरक्षा पैराडाइम का एक हिस्सा है, जो **विशेषाधिकार-विभाजित अनुप्रयोगों के निर्माण** की अनुमति देता है जहां प्रत्येक **घटक** केवल उन्हीं अनुमतियों के साथ चलता है जो उसे अपना काम करने के लिए आवश्यक हैं, इस प्रकार समझौता की गई प्रक्रिया से संभावित क्षति को सीमित करता है।

XPC एक प्रकार का Inter-Process Communication (IPC) का उपयोग करता है, जो एक ही सिस्टम पर चल रहे विभिन्न प्रोग्रामों के बीच डेटा भेजने और प्राप्त करने के लिए तरीकों का एक सेट है।

XPC के प्राथमिक लाभ हैं:

1. **सुरक्षा**: अलग-अलग प्रक्रियाओं में काम को विभाजित करके, प्रत्येक प्रक्रिया को केवल वही अनुमतियां दी जा सकती हैं जो उसे चाहिए। इसका मतलब है कि यदि कोई प्रक्रिया समझौता की जाती है, तो उसकी हानि करने की क्षमता सीमित होती है।
2. **स्थिरता**: XPC दुर्घटनाओं को उस घटक तक सीमित करने में मदद करता है जहां वे होते हैं। यदि कोई प्रक्रिया क्रैश होती है, तो इसे बिना सिस्टम के बाकी हिस्सों को प्रभावित किए बिना पुनः आरंभ किया जा सकता है।
3. **प्रदर्शन**: XPC आसान समानांतरता की अनुमति देता है, क्योंकि विभिन्न कार्य विभिन्न प्रक्रियाओं में एक साथ चलाए जा सकते हैं।

एकमात्र **दोष** यह है कि **एक अनुप्रयोग को कई प्रक्रियाओं में विभाजित करना** और उन्हें XPC के माध्यम से संवाद करना **कम कुशल** है। लेकिन आज की प्रणालियों में यह लगभग ध्यान देने योग्य नहीं है और लाभ बेहतर हैं।

### अनुप्रयोग विशिष्ट XPC सेवाएँ

एक अनुप्रयोग के XPC घटक **अनुप्रयोग स्वयं के अंदर होते हैं।** उदाहरण के लिए, Safari में आप उन्हें **`/Applications/Safari.app/Contents/XPCServices`** में पा सकते हैं। उनका एक्सटेंशन **`.xpc`** होता है (जैसे **`com.apple.Safari.SandboxBroker.xpc`**) और वे **बंडल भी होते हैं** मुख्य बाइनरी के साथ इसके अंदर: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` और एक `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

जैसा कि आप सोच रहे होंगे एक **XPC घटक के अलग अधिकार और विशेषाधिकार** होंगे अन्य XPC घटकों या मुख्य अनुप्रयोग बाइनरी से। इसके अलावा अगर XPC सेवा [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession) को इसकी **Info.plist** फाइल में "True" के रूप में सेट किया गया है। इस मामले में, XPC सेवा **उसी सुरक्षा सत्र में चलेगी जैसे अनुप्रयोग** जिसने इसे कॉल किया।

XPC सेवाएँ **शुरू की जाती हैं** **launchd** द्वारा जब आवश्यक होती हैं और **बंद कर दी जाती हैं** एक बार सभी कार्य **पूरे** हो जाने के बाद सिस्टम संसाधनों को मुक्त करने के लिए। **अनुप्रयोग-विशिष्ट XPC घटक केवल अनुप्रयोग द्वारा ही उपयोग किए जा सकते हैं**, इस प्रकार संभावित कमजोरियों से जुड़े जोखिम को कम करते हैं।

### सिस्टम वाइड XPC सेवाएँ

सिस्टम-वाइड XPC सेवाएँ सभी उपयोगकर्ताओं के लिए सुलभ होती हैं। ये सेवाएँ, चाहे launchd हों या Mach-प्रकार की, उन्हें **plist** फाइलों में **परिभाषित किया जाना चाहिए** जो निर्दिष्ट निर्देशिकाओं जैसे **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, या **`/Library/LaunchAgents`** में स्थित होती हैं।

इन plist फाइलों में एक कुंजी **`MachServices`** होगी जिसमें सेवा का नाम होगा, और एक कुंजी **`Program`** जिसमें बाइनरी का पथ होगा:

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

**`LaunchDameons`** में जो होते हैं वे root द्वारा चलाए जाते हैं। इसलिए यदि कोई अनाधिकृत प्रक्रिया इनमें से किसी से बात कर सकती है, तो वह संभवतः अधिकार बढ़ा सकती है।

### XPC इवेंट संदेश

एप्लिकेशन विभिन्न इवेंट **संदेशों** की **सदस्यता** ले सकते हैं, जिससे वे ऐसी घटनाओं के होने पर **मांग पर प्रारंभ** किए जा सकते हैं। इन सेवाओं की **सेटअप** **launchd plist फाइलों** में की जाती है, जो **पिछले वालों के समान निर्देशिकाओं** में स्थित होती हैं और इनमें एक अतिरिक्त **`LaunchEvent`** कुंजी होती है।

#### XPC कनेक्टिंग प्रक्रिया जांच

जब कोई प्रक्रिया XPC कनेक्शन के माध्यम से किसी मेथड को कॉल करने का प्रयास करती है, तो **XPC सेवा को जांचना चाहिए कि उस प्रक्रिया को कनेक्ट करने की अनुमति है या नहीं**। यहाँ उसे जांचने के सामान्य तरीके और सामान्य गलतियाँ हैं:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

### XPC अधिकारीकरण

Apple एप्लिकेशन को कुछ अधिकारों को **कॉन्फ़िगर करने और उन्हें प्राप्त करने का तरीका** भी अनुमति देता है, इसलिए यदि कॉल करने वाली प्रक्रिया के पास वे होते हैं तो उसे **XPC सेवा से मेथड कॉल करने की अनुमति होगी**:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

### XPC स्निफर

XPC संदेशों को स्निफ करने के लिए आप [**xpcspy**](https://github.com/hot3eed/xpcspy) का उपयोग कर सकते हैं जो **Frida** का उपयोग करता है।

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

### XPC संचार C कोड उदाहरण

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

The provided text appears to be part of a markdown file used for documentation or instructional content, specifically it seems to be closing syntax for tabbed content. Since there is no actual content to translate, only markdown syntax is present, which should not be translated. Therefore, there is nothing to translate in the provided text. If you have any actual English content that needs translation into Hindi, please provide the text.

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

### XPC संचार Objective-C कोड उदाहरण

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
{% endtab %}

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
{% endtab %}

{% tab title="xyz.hacktricks.svcoc.plist" %}
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

\`\`\`bash # Compile the server & client gcc -framework Foundation oc\_xpc\_server.m -o oc\_xpc\_server gcc -framework Foundation oc\_xpc\_client.m -o oc\_xpc\_client

## Save server on it's location

cp oc\_xpc\_server /tmp

## Load daemon

sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

## Call client

./oc\_xpc\_client

## Clean

sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc\_xpc\_server

````
## क्लाइंट एक Dylb कोड के अंदर
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
````

<details>

<summary><strong>AWS हैकिंग सीखें शून्य से लेकर हीरो तक</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a> <strong>के साथ!</strong></summary>

HackTricks का समर्थन करने के अन्य तरीके:

* यदि आप चाहते हैं कि आपकी **कंपनी का विज्ञापन HackTricks में दिखाई दे** या **HackTricks को PDF में डाउनलोड करें**, तो [**सब्सक्रिप्शन प्लान्स**](https://github.com/sponsors/carlospolop) देखें!
* [**आधिकारिक PEASS & HackTricks स्वैग**](https://peass.creator-spring.com) प्राप्त करें
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) की खोज करें, हमारा विशेष [**NFTs**](https://opensea.io/collection/the-peass-family) संग्रह
* 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) में **शामिल हों** या [**telegram group**](https://t.me/peass) में या **Twitter** 🐦 पर मुझे **फॉलो** करें [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* [**HackTricks**](https://github.com/carlospolop/hacktricks) और [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos में PRs सबमिट करके अपनी हैकिंग ट्रिक्स शेयर करें।

</details>
