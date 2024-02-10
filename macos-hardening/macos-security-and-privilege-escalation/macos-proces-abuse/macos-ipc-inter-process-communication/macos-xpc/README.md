# macOS XPC

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>에서 <strong>제로부터 영웅이 되는 AWS 해킹</strong>을 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)을 **팔로우**하세요.
* **Hacking 트릭을 공유하려면** [**HackTricks**](https://github.com/carlospolop/hacktricks) 및 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github 저장소에 PR을 제출하세요.

</details>

## 기본 정보

XPC는 macOS와 iOS에서 **프로세스 간 통신**을 위한 XNU(맥 운영체제에서 사용되는 커널) 인터프로세스 통신 프레임워크입니다. XPC는 시스템 내에서 **안전하고 비동기적인 메서드 호출**을 통해 서로 다른 프로세스 간 통신을 제공합니다. 이는 Apple의 보안 패러다임의 일부로, **권한이 분리된 애플리케이션의 생성**을 허용하여 각 **구성 요소**가 **필요한 권한만 가지고** 작업을 수행하도록 제한하여, 감염된 프로세스로부터 발생할 수 있는 잠재적인 피해를 제한합니다.

XPC는 동일한 시스템에서 실행되는 다른 프로그램들이 데이터를 주고받기 위한 방법을 나타내는 **프로세스 간 통신(IPC)의 형태**를 사용합니다.

XPC의 주요 이점은 다음과 같습니다:

1. **보안**: 작업을 다른 프로세스로 분리함으로써 각 프로세스에 필요한 권한만 부여할 수 있습니다. 이는 프로세스가 감염되더라도 피해를 제한하는 한정된 능력만 가지게 됨을 의미합니다.
2. **안정성**: XPC는 충돌을 해당 구성 요소로 격리시켜 안정성을 유지합니다. 프로세스가 충돌하면 시스템의 나머지 부분에 영향을 주지 않고 다시 시작될 수 있습니다.
3. **성능**: XPC는 다른 프로세스에서 동시에 여러 작업을 쉽게 수행할 수 있도록 하여 쉬운 동시성을 제공합니다.

유일한 **단점**은 애플리케이션을 **여러 프로세스로 분리**하여 XPC를 통해 통신하게 만드는 것이 **덜 효율적**이라는 것입니다. 하지만 현재의 시스템에서는 이를 거의 알아채지 못하고 이점이 더 큽니다.

## 애플리케이션별 XPC 서비스

애플리케이션의 XPC 구성 요소는 **애플리케이션 자체 내에 있습니다.** 예를 들어, Safari에서는 **`/Applications/Safari.app/Contents/XPCServices`**에서 찾을 수 있습니다. 이들은 **`.xpc`** 확장자를 가지며 (예: **`com.apple.Safari.SandboxBroker.xpc`**), **메인 이진 파일과 함께 번들**로 제공됩니다: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 및 `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

XPC 구성 요소는 다른 XPC 구성 요소나 메인 앱 이진 파일과는 다른 **권한과 특권**을 가집니다. 단, XPC 서비스가 **Info.plist** 파일에서 [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/xpcservice/joinexistingsession)을 "True"로 설정한 경우, XPC 서비스는 호출한 애플리케이션과 **동일한 보안 세션에서 실행**됩니다.

XPC 서비스는 필요할 때 **launchd**에 의해 **시작**되고 모든 작업이 **완료**되면 **종료**되어 시스템 리소스를 해제합니다. **애플리케이션별 XPC 구성 요소는 애플리케이션에 의해서만 사용**될 수 있으므로 잠재적인 취약점과 관련된 위험을 줄입니다.

## 시스템 전체 XPC 서비스

시스템 전체 XPC 서비스는 모든 사용자가 접근할 수 있습니다. 이러한 서비스는 launchd 또는 Mach 유형이며, **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, 또는 **`/Library/LaunchAgents`**와 같은 지정된 디렉토리에 위치한 plist 파일에 **정의**되어야 합니다.

이 plist 파일에는 서비스의 이름을 나타내는 **`MachServices`** 키와 이진 파일의 경로를 나타내는 **`Program`** 키가 있을 것입니다:
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
**`LaunchDameons`**에 있는 것들은 root로 실행됩니다. 따라서 권한이 없는 프로세스가 이들 중 하나와 통신할 수 있다면 권한 상승이 가능할 수 있습니다.

## XPC 이벤트 메시지

응용 프로그램은 다양한 이벤트 메시지에 **구독**하여 해당 이벤트가 발생할 때 **요청에 따라 초기화**될 수 있습니다. 이러한 서비스의 설정은 **이전과 동일한 디렉토리에 있는** **`LaunchEvent`** 키를 포함하는 **launchd plist 파일**에 의해 수행됩니다.

### XPC 연결 프로세스 확인

프로세스가 XPC 연결을 통해 메서드를 호출하려고 할 때, **XPC 서비스는 해당 프로세스가 연결할 수 있는지 확인**해야 합니다. 이를 확인하는 일반적인 방법과 주의해야 할 일반적인 함정은 다음과 같습니다:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC 권한 부여

Apple은 앱이 **일부 권한과 그 획득 방법을 구성**할 수 있도록 허용합니다. 따라서 호출하는 프로세스가 해당 권한을 가지고 있다면 XPC 서비스에서 **메서드를 호출할 수 있습니다**:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC 스니퍼

XPC 메시지를 스니핑하기 위해 [**xpcspy**](https://github.com/hot3eed/xpcspy)를 사용할 수 있습니다. 이는 **Frida**를 사용합니다.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
## XPC 통신 C 코드 예제

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
```c
#include <stdio.h>
#include <xpc/xpc.h>

int main(int argc, const char * argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.securityd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        
        if (type == XPC_TYPE_DICTIONARY) {
            const char *description = xpc_dictionary_get_string(event, "description");
            printf("Received event: %s\n", description);
        }
    });
    
    xpc_connection_resume(connection);
    
    sleep(10);
    
    xpc_release(connection);
    
    return 0;
}
```
{% endtab %}

{% tab title="xpc_server.c" %}
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
{% tab title="xyz.hacktricks.service.plist" %}
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
## XPC 통신 Objective-C 코드 예제

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
{% tab title="xyz.hacktricks.svcoc.plist" %}xyz.hacktricks.svcoc.plist 파일은 macOS에서 XPC 서비스를 실행하기 위해 사용되는 속성 목록 파일입니다. XPC는 macOS에서 프로세스 간 통신을 위한 프레임워크입니다. 이 plist 파일은 XPC 서비스의 구성을 정의하고 실행할 때 필요한 매개 변수를 설정합니다.

이 파일은 일반적으로 /Library/LaunchDaemons 또는 ~/Library/LaunchAgents 디렉토리에 위치합니다. 이 디렉토리에 plist 파일을 배치하면 시스템이 부팅될 때 또는 사용자가 로그인할 때 해당 XPC 서비스가 자동으로 시작됩니다.

xyz.hacktricks.svcoc.plist 파일을 수정하여 XPC 서비스의 동작을 변경할 수 있습니다. 예를 들어, 실행할 바이너리 파일, 환경 변수, 실행 권한 등을 설정할 수 있습니다. 이를 통해 XPC 서비스를 악용하여 권한 상승 등의 공격을 수행할 수 있습니다.

따라서, 시스템 보안을 강화하기 위해 xyz.hacktricks.svcoc.plist 파일을 신중하게 관리해야 합니다. 불필요한 XPC 서비스를 비활성화하거나 악의적인 변경을 방지하기 위해 파일의 권한을 제한하는 것이 좋습니다.
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
## Dylb 코드 내부의 클라이언트

The client code inside the Dylb is responsible for establishing a connection with the server and sending requests. It is an essential component of the inter-process communication (IPC) mechanism used in macOS.

Dylb is a lightweight library that provides a simplified interface for working with XPC (eXtensible Procedure Call) in macOS. XPC is a high-level API that allows processes to communicate with each other securely.

To use the Dylb library, you need to include the necessary headers and link against the Dylb framework. Once the library is set up, you can create an instance of the client and configure it with the appropriate server endpoint.

The client code typically consists of the following steps:

1. Create an XPC connection using the `xpc_connection_create` function.
2. Set the event handler for the connection using the `xpc_connection_set_event_handler` function.
3. Set the target endpoint for the connection using the `xpc_connection_set_target_endpoint` function.
4. Resume the connection using the `xpc_connection_resume` function.
5. Send requests to the server using the `xpc_connection_send_message` function.

The client code can also handle responses from the server by implementing the event handler. This allows for bidirectional communication between the client and the server.

Overall, the client code inside the Dylb plays a crucial role in establishing and maintaining communication between processes in macOS. It enables secure and efficient inter-process communication, facilitating various functionalities and capabilities in macOS applications.
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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong>를 통해 AWS 해킹을 처음부터 전문가까지 배워보세요<strong>!</strong></summary>

HackTricks를 지원하는 다른 방법:

* **회사를 HackTricks에서 광고하거나 HackTricks를 PDF로 다운로드**하려면 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)를 확인하세요!
* [**공식 PEASS & HackTricks 스웨그**](https://peass.creator-spring.com)를 얻으세요.
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)를 발견하세요. 독점적인 [**NFTs**](https://opensea.io/collection/the-peass-family) 컬렉션입니다.
* 💬 [**Discord 그룹**](https://discord.gg/hRep4RUj7f) 또는 [**텔레그램 그룹**](https://t.me/peass)에 **참여**하거나 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)를 **팔로우**하세요.
* **Hacking 트릭을 공유하려면 PR을** [**HackTricks**](https://github.com/carlospolop/hacktricks) **및** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **github 저장소에 제출하세요.**

</details>
