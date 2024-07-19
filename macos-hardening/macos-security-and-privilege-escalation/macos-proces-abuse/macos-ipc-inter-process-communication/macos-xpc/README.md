# macOS XPC

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

## Basic Information

XPC는 macOS에서 사용되는 XNU(커널) 간의 프로세스 통신을 위한 프레임워크로, macOS 및 iOS에서 **프로세스 간의 통신**을 제공합니다. XPC는 시스템의 서로 다른 프로세스 간에 **안전하고 비동기적인 메서드 호출**을 수행하는 메커니즘을 제공합니다. 이는 Apple의 보안 패러다임의 일부로, 각 **구성 요소**가 작업을 수행하는 데 필요한 **권한만**으로 실행되는 **권한 분리 애플리케이션**의 **생성**을 가능하게 하여, 손상된 프로세스에서 발생할 수 있는 잠재적 피해를 제한합니다.

XPC는 동일한 시스템에서 실행되는 서로 다른 프로그램이 데이터를 주고받기 위한 일련의 방법인 프로세스 간 통신(IPC)의 한 형태를 사용합니다.

XPC의 주요 이점은 다음과 같습니다:

1. **보안**: 작업을 서로 다른 프로세스로 분리함으로써 각 프로세스는 필요한 권한만 부여받을 수 있습니다. 이는 프로세스가 손상되더라도 피해를 줄일 수 있음을 의미합니다.
2. **안정성**: XPC는 충돌을 발생한 구성 요소로 격리하는 데 도움을 줍니다. 프로세스가 충돌하면 시스템의 나머지 부분에 영향을 주지 않고 재시작할 수 있습니다.
3. **성능**: XPC는 서로 다른 작업을 동시에 다른 프로세스에서 실행할 수 있도록 하여 쉽게 동시성을 허용합니다.

유일한 **단점**은 **애플리케이션을 여러 프로세스로 분리**하고 XPC를 통해 통신하게 만드는 것이 **효율성이 떨어진다는** 것입니다. 그러나 오늘날 시스템에서는 거의 눈에 띄지 않으며 이점이 더 큽니다.

## Application Specific XPC services

애플리케이션의 XPC 구성 요소는 **애플리케이션 자체 내부에** 있습니다. 예를 들어, Safari에서는 **`/Applications/Safari.app/Contents/XPCServices`**에서 찾을 수 있습니다. 이들은 **`.xpc`** 확장자를 가지며(예: **`com.apple.Safari.SandboxBroker.xpc`**) 주 이진 파일과 함께 번들로 제공됩니다: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` 및 `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

당신이 생각할 수 있듯이 **XPC 구성 요소는 다른 XPC 구성 요소나 주 애플리케이션 이진 파일과 다른 권한과 특권을 가집니다.** 단, XPC 서비스가 **Info.plist** 파일에서 **JoinExistingSession**을 “True”로 설정하여 구성된 경우는 제외입니다. 이 경우, XPC 서비스는 호출한 애플리케이션과 **같은 보안 세션**에서 실행됩니다.

XPC 서비스는 필요할 때 **launchd**에 의해 **시작**되며, 모든 작업이 **완료**되면 시스템 리소스를 해제하기 위해 **종료**됩니다. **애플리케이션 전용 XPC 구성 요소는 애플리케이션에 의해서만 사용될 수** 있어 잠재적인 취약성과 관련된 위험을 줄입니다.

## System Wide XPC services

시스템 전역 XPC 서비스는 모든 사용자에게 접근 가능합니다. 이러한 서비스는 launchd 또는 Mach 유형으로, **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`**, 또는 **`/Library/LaunchAgents`**와 같은 지정된 디렉토리에 위치한 plist 파일에 **정의**되어야 합니다.

이 plist 파일에는 서비스의 이름을 가진 **`MachServices`**라는 키와 이진 파일의 경로를 가진 **`Program`**이라는 키가 포함됩니다:
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
The ones in **`LaunchDameons`**는 root에 의해 실행됩니다. 따라서 권한이 없는 프로세스가 이들 중 하나와 통신할 수 있다면 권한 상승이 가능할 수 있습니다.

## XPC 객체

* **`xpc_object_t`**

모든 XPC 메시지는 직렬화 및 역직렬화를 단순화하는 사전 객체입니다. 게다가, `libxpc.dylib`는 대부분의 데이터 유형을 선언하므로 수신된 데이터가 예상된 유형인지 확인할 수 있습니다. C API에서 모든 객체는 `xpc_object_t`이며(그 유형은 `xpc_get_type(object)`를 사용하여 확인할 수 있습니다).\
또한, `xpc_copy_description(object)` 함수를 사용하여 디버깅 목적으로 유용한 객체의 문자열 표현을 얻을 수 있습니다.\
이 객체들은 `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`와 같은 호출할 수 있는 몇 가지 메서드를 가지고 있습니다...

`xpc_object_t`는 `xpc_<objetType>_create` 함수를 호출하여 생성되며, 이 함수는 내부적으로 `_xpc_base_create(Class, Size)`를 호출하여 객체의 클래스 유형(하나의 `XPC_TYPE_*`)과 크기를 지정합니다(메타데이터를 위해 추가 40B가 크기에 추가됩니다). 이는 객체의 데이터가 40B 오프셋에서 시작됨을 의미합니다.\
따라서 `xpc_<objectType>_t`는 `xpc_object_t`의 하위 클래스와 같은 것이며, 이는 `os_object_t*`의 하위 클래스가 됩니다.

{% hint style="warning" %}
개발자가 `xpc_dictionary_[get/set]_<objectType>`를 사용하여 키의 유형과 실제 값을 가져오거나 설정해야 한다는 점에 유의하십시오.
{% endhint %}

* **`xpc_pipe`**

**`xpc_pipe`**는 프로세스가 통신하는 데 사용할 수 있는 FIFO 파이프입니다(통신은 Mach 메시지를 사용합니다).\
특정 Mach 포트를 사용하여 XPC 서버를 생성하려면 `xpc_pipe_create()` 또는 `xpc_pipe_create_from_port()`를 호출할 수 있습니다. 그런 다음 메시지를 수신하려면 `xpc_pipe_receive` 및 `xpc_pipe_try_receive`를 호출할 수 있습니다.

**`xpc_pipe`** 객체는 두 개의 Mach 포트와 이름(있는 경우)에 대한 정보가 포함된 **`xpc_object_t`**입니다. 예를 들어, plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`에 있는 데몬 `secinitd`는 `com.apple.secinitd`라는 파이프를 구성합니다.

**`xpc_pipe`**의 예는 **`launchd`**에 의해 생성된 **bootstrap pipe**로, Mach 포트를 공유할 수 있게 합니다.

* **`NSXPC*`**

이들은 XPC 연결의 추상을 허용하는 Objective-C 고급 객체입니다.\
또한, 이러한 객체는 이전 객체보다 DTrace로 디버깅하기가 더 쉽습니다.

* **`GCD Queues`**

XPC는 메시지를 전달하기 위해 GCD를 사용하며, `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`와 같은 특정 디스패치 큐를 생성합니다.

## XPC 서비스

이들은 다른 프로젝트의 **`XPCServices`** 폴더에 위치한 **`.xpc`** 확장자를 가진 번들입니다. `Info.plist`에서 `CFBundlePackageType`이 **`XPC!`**로 설정되어 있습니다.\
이 파일에는 Application, User, System 또는 `_SandboxProfile`과 같은 다른 구성 키가 있으며, 이는 샌드박스를 정의하거나 `_AllowedClients`는 서비스에 연락하는 데 필요한 권한 또는 ID를 나타낼 수 있습니다. 이러한 구성 옵션은 서비스가 시작될 때 구성하는 데 유용합니다.

### 서비스 시작하기

앱은 `xpc_connection_create_mach_service`를 사용하여 XPC 서비스에 **연결**을 시도하고, 그런 다음 launchd는 데몬을 찾고 **`xpcproxy`**를 시작합니다. **`xpcproxy`**는 구성된 제한을 시행하고 제공된 FD 및 Mach 포트로 서비스를 생성합니다.

XPC 서비스 검색 속도를 개선하기 위해 캐시가 사용됩니다.

`xpcproxy`의 작업을 추적할 수 있습니다:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
The XPC 라이브러리는 `kdebug`를 사용하여 `xpc_ktrace_pid0` 및 `xpc_ktrace_pid1`를 호출하는 작업을 기록합니다. 사용하는 코드는 문서화되어 있지 않으므로 `/usr/share/misc/trace.codes`에 추가해야 합니다. 이들은 `0x29` 접두사를 가지며, 예를 들어 하나는 `0x29000004`: `XPC_serializer_pack`입니다.\
유틸리티 `xpcproxy`는 `0x22` 접두사를 사용하며, 예를 들어: `0x2200001c: xpcproxy:will_do_preexec`입니다.

## XPC 이벤트 메시지

응용 프로그램은 다양한 이벤트 **메시지**에 **구독**할 수 있으며, 이러한 이벤트가 발생할 때 **온디맨드로 시작**될 수 있습니다. 이러한 서비스의 **설정**은 **이전과 동일한 디렉토리**에 위치한 **launchd plist 파일**에서 수행되며, 추가 **`LaunchEvent`** 키를 포함합니다.

### XPC 연결 프로세스 확인

프로세스가 XPC 연결을 통해 메서드를 호출하려고 할 때, **XPC 서비스는 해당 프로세스가 연결할 수 있는지 확인해야 합니다**. 이를 확인하는 일반적인 방법과 일반적인 함정은 다음과 같습니다:

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
{% endcontent-ref %}

## XPC 권한 부여

Apple은 또한 앱이 **일부 권한을 구성하고 이를 얻는 방법을 설정**할 수 있도록 허용하므로, 호출 프로세스가 이를 가지고 있다면 **XPC 서비스의 메서드를 호출할 수 있도록 허용됩니다**:

{% content-ref url="macos-xpc-authorization.md" %}
[macos-xpc-authorization.md](macos-xpc-authorization.md)
{% endcontent-ref %}

## XPC 스니퍼

XPC 메시지를 스니핑하려면 [**xpcspy**](https://github.com/hot3eed/xpcspy)를 사용할 수 있으며, 이는 **Frida**를 사용합니다.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
또 다른 가능한 도구는 [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html)입니다.

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
{% endtab %}

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
{% endtab %}

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
## Remote XPC

`RemoteXPC.framework` (from `libxpc`)에서 제공하는 이 기능은 서로 다른 호스트를 통해 XPC로 통신할 수 있게 해줍니다.\
원격 XPC를 지원하는 서비스는 `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`와 같이 plist에 UsesRemoteXPC 키를 가집니다. 그러나 서비스가 `launchd`에 등록되더라도, 기능을 제공하는 것은 `com.apple.remoted.plugin` 및 `com.apple.remoteservicediscovery.events.plugin` 플러그인을 가진 `UserEventAgent`입니다.

게다가, `RemoteServiceDiscovery.framework`는 `com.apple.remoted.plugin`에서 `get_device`, `get_unique_device`, `connect`와 같은 함수를 노출하여 정보를 가져올 수 있게 해줍니다.

`connect`가 사용되고 서비스의 소켓 `fd`가 수집되면, `remote_xpc_connection_*` 클래스를 사용할 수 있습니다.

원격 서비스에 대한 정보를 얻으려면 `/usr/libexec/remotectl` CLI 도구를 사용하여 다음과 같은 매개변수를 사용할 수 있습니다:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
BridgeOS와 호스트 간의 통신은 전용 IPv6 인터페이스를 통해 이루어집니다. `MultiverseSupport.framework`는 통신에 사용될 `fd`를 가진 소켓을 설정할 수 있게 해줍니다.\
`netstat`, `nettop` 또는 오픈 소스 옵션인 `netbottom`을 사용하여 이러한 통신을 찾을 수 있습니다.

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
